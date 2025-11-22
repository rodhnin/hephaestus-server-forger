"""
Hephaestus TLS/SSL Checker

Validates TLS/SSL configuration:
- Certificate validation (expiration, hostname, self-signed)
- Protocol versions (SSLv3, TLS 1.0/1.1/1.2/1.3)
- Advanced checks with SSLyze (optional, Pro feature)

Modes:
- Basic checks: Always performed (using ssl/cryptography)
- Advanced checks: Only if sslyze installed (Pro feature)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from sslyze import (
        ServerNetworkLocation,
        ServerConnectivityTester,
        Scanner,
        ServerScanRequest,
        ScanCommand
    )
    HAS_SSLYZE = True
except ImportError:
    HAS_SSLYZE = False

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class TLSChecker:
    """
    Checks TLS/SSL configuration.
    """
    
    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.http_client = http_client
        
        # Protocol version mapping (compatible with Python 3.9+ and 3.10+)
        # Python 3.10+ removed PROTOCOL_SSLv3, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1
        self.protocol_versions = {}
        
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            self.protocol_versions[ssl.PROTOCOL_SSLv3] = 'SSLv3'
        
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            self.protocol_versions[ssl.PROTOCOL_TLSv1] = 'TLS 1.0'
        
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            self.protocol_versions[ssl.PROTOCOL_TLSv1_1] = 'TLS 1.1'
        
        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            self.protocol_versions[ssl.PROTOCOL_TLSv1_2] = 'TLS 1.2'
        
        # Check if TLS 1.3 is available (Python 3.7+)
        if hasattr(ssl, 'PROTOCOL_TLS_CLIENT'):
            self.has_tls13 = True
        else:
            self.has_tls13 = False
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Execute TLS/SSL checks.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        
        Note: TLS errors (SSL handshake, cert invalid) are converted to findings.
              Only connection errors (timeout, refused) are propagated.
        """
        findings = []
        
        # Parse target to get hostname and port
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.path
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Skip if not HTTPS
        if parsed.scheme != 'https' and port != 443:
            logger.info("Target is not HTTPS, skipping TLS checks")
            return findings
        
        logger.info(f"Checking TLS/SSL configuration for {hostname}:{port}")
        
        # BASIC CHECKS (always performed)
        if HAS_CRYPTOGRAPHY:
            findings.extend(self._check_certificate(hostname, port))
            findings.extend(self._check_tls_protocols(hostname, port))
        else:
            logger.warning("cryptography not installed, skipping basic TLS checks")
            findings.append({
                'id': 'HEPH-TLS-999',
                'title': 'Basic TLS checks unavailable (missing cryptography)',
                'severity': 'info',
                'confidence': 'high',
                'description': 'cryptography library not installed, cannot perform basic certificate checks',
                'recommendation': 'Install cryptography: pip install cryptography>=41.0.0',
            })
        
        # ADVANCED CHECKS (only if sslyze installed and enabled)
        if HAS_SSLYZE and self.config.tls_advanced_enabled:
            findings.extend(self._check_advanced_sslyze(hostname, port))
        elif self.config.tls_advanced_enabled and not HAS_SSLYZE:
            logger.warning("SSLyze not installed, skipping advanced TLS checks")
            findings.append({
                'id': 'HEPH-TLS-998',
                'title': 'Advanced TLS checks unavailable (missing sslyze)',
                'severity': 'info',
                'confidence': 'high',
                'description': 'SSLyze not installed, cannot perform advanced cipher suite and vulnerability checks',
                'recommendation': 'Install sslyze for Pro features: pip install sslyze>=5.0.0',
            })
        
        if not findings:
            logger.info("No TLS/SSL issues detected")
        else:
            logger.info(f"Found {len(findings)} TLS/SSL finding(s)")
        
        return findings
    
    def _check_certificate(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """
        Check certificate validity (expiration, hostname, self-signed).
        
        Args:
            hostname: Target hostname
            port: Target port
        
        Returns:
            List of findings
        
        Note: SSL errors are converted to findings, not exceptions.
              Only socket/connection errors are propagated.
        """
        findings = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.config.timeout_connect) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
            
            # Parse certificate with cryptography
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Check expiration
            expiration = cert.not_valid_after_utc
            now = datetime.now(timezone.utc)
            
            if expiration < now:
                # Certificate expired
                days_expired = (now - expiration).days
                
                findings.append({
                    'id': 'HEPH-TLS-001',
                    'title': 'SSL/TLS certificate expired',
                    'severity': 'critical',
                    'confidence': 'high',
                    'description': (
                        f"SSL/TLS certificate for {hostname} expired {days_expired} days ago. "
                        f"Browsers will show security warnings and block access."
                    ),
                    'evidence': {
                        'type': 'other',
                        'value': f"Expired: {expiration.isoformat()}",
                        'context': f"Days expired: {days_expired}"
                    },
                    'recommendation': 'Renew SSL/TLS certificate immediately via Certificate Authority',
                    'references': [
                        'https://letsencrypt.org/',
                        'https://www.ssllabs.com/ssltest/'
                    ],
                    'affected_component': f'{hostname}:{port}'
                })
            
            elif (expiration - now).days < 30:
                # Certificate expiring soon
                days_remaining = (expiration - now).days
                
                findings.append({
                    'id': 'HEPH-TLS-002',
                    'title': 'SSL/TLS certificate expiring soon',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': f"SSL/TLS certificate expires in {days_remaining} days",
                    'evidence': {
                        'type': 'other',
                        'value': f"Expires: {expiration.isoformat()}",
                        'context': f"Days remaining: {days_remaining}"
                    },
                    'recommendation': 'Renew certificate before expiration to avoid service disruption',
                    'references': ['https://letsencrypt.org/'],
                    'affected_component': f'{hostname}:{port}'
                })
            
            # Check hostname match
            if cert_dict:
                sans = []
                if 'subjectAltName' in cert_dict:
                    sans = [name[1] for name in cert_dict['subjectAltName'] if name[0] == 'DNS']
                
                # Extract CN from subject tuple
                common_name = None
                if 'subject' in cert_dict:
                    # subject is a tuple of tuples: ((('CN', 'example.com'),),)
                    for rdn in cert_dict['subject']:
                        for name_type, name_value in rdn:
                            if name_type == 'commonName':
                                common_name = name_value
                                break
                
                # Check if hostname matches certificate
                hostname_matches = (
                    hostname in sans or
                    hostname == common_name or
                    any(self._wildcard_match(hostname, san) for san in sans)
                )
                
                if not hostname_matches:
                    cert_names = sans if sans else ([common_name] if common_name else [])
                    findings.append({
                        'id': 'HEPH-TLS-003',
                        'title': 'SSL/TLS certificate hostname mismatch',
                        'severity': 'high',
                        'confidence': 'high',
                        'description': (
                            f"Certificate does not match hostname {hostname}. "
                            f"Certificate is valid for: {', '.join(cert_names) if cert_names else 'N/A'}"
                        ),
                        'evidence': {
                            'type': 'other',
                            'value': f"Certificate names: {', '.join(cert_names) if cert_names else 'N/A'}",
                            'context': f"Requested: {hostname}"
                        },
                        'recommendation': 'Obtain certificate with correct hostname/SAN entries',
                        'affected_component': f'{hostname}:{port}'
                    })
            
            # Check self-signed
            if cert.issuer == cert.subject:
                findings.append({
                    'id': 'HEPH-TLS-004',
                    'title': 'Self-signed SSL/TLS certificate',
                    'severity': 'high',
                    'confidence': 'high',
                    'description': (
                        'Certificate is self-signed, browsers will show security warnings. '
                        'Not suitable for production environments.'
                    ),
                    'evidence': {
                        'type': 'other',
                        'value': f"Issuer: {cert.issuer.rfc4514_string()}",
                        'context': 'Self-signed (issuer == subject)'
                    },
                    'recommendation': 'Obtain certificate from trusted Certificate Authority (e.g., Let\'s Encrypt)',
                    'references': ['https://letsencrypt.org/'],
                    'affected_component': f'{hostname}:{port}'
                })
        
        except ssl.SSLError as e:
            logger.warning(f"SSL error checking certificate: {e}")
            findings.append({
                'id': 'HEPH-TLS-005',
                'title': 'SSL/TLS handshake failed',
                'severity': 'high',
                'confidence': 'medium',
                'description': f"SSL/TLS handshake failed: {str(e)}",
                'evidence': {
                    'type': 'other',
                    'value': str(e),
                },
                'recommendation': 'Check SSL/TLS configuration and certificate validity',
                'affected_component': f'{hostname}:{port}'
            })
        
        except socket.timeout:
            # Socket timeout - this is a CONNECTION error, PROPAGATE
            logger.error(f"Connection timeout to {hostname}:{port}")
            raise  # Let scanner handle this as connection failure
        
        except (ConnectionRefusedError, ConnectionError) as e:
            # Connection error - PROPAGATE
            logger.error(f"Connection error to {hostname}:{port}: {e}")
            raise  # Let scanner handle this
        
        except OSError as e:
            # Network error (e.g., ECONNREFUSED) - PROPAGATE
            if e.errno in (111, 61):
                logger.error(f"Connection refused to {hostname}:{port}")
                raise ConnectionRefusedError(f"Connection refused to {hostname}:{port}") from e
            else:
                logger.error(f"OS error checking certificate: {e}")
                findings.append({
                    'id': 'HEPH-TLS-006',
                    'title': 'TLS connection error',
                    'severity': 'high',
                    'confidence': 'medium',
                    'description': f"Could not establish TLS connection: {str(e)}",
                    'evidence': {'type': 'other', 'value': str(e)},
                    'recommendation': 'Verify server is reachable and TLS is configured correctly',
                    'affected_component': f'{hostname}:{port}'
                })
        
        except Exception as e:
            # Unexpected error - log but don't propagate
            logger.error(f"Unexpected error checking certificate: {e}")
        
        return findings
    
    def _check_tls_protocols(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """
        Check supported TLS protocol versions.
        
        Args:
            hostname: Target hostname
            port: Target port
        
        Returns:
            List of findings
        
        Note: Connection errors during protocol testing are logged but don't fail scan.
              We already checked basic connectivity in _check_certificate.
        """
        findings = []
        
        # Protocols to test (weakest to strongest)
        protocols_to_test = []
        
        # SSLv3 check (only if available in Python version)
        if self.config.tls_check_sslv3 and hasattr(ssl, 'PROTOCOL_SSLv3'):
            protocols_to_test.append(('SSLv3', ssl.PROTOCOL_SSLv3, 'critical'))
        
        # TLS 1.0 check (only if available in Python version)
        if self.config.tls_check_tls10 and hasattr(ssl, 'PROTOCOL_TLSv1'):
            protocols_to_test.append(('TLS 1.0', ssl.PROTOCOL_TLSv1, 'high'))
        
        # TLS 1.1 check (only if available in Python version)
        if self.config.tls_check_tls11 and hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            protocols_to_test.append(('TLS 1.1', ssl.PROTOCOL_TLSv1_1, 'high'))
        
        # TLS 1.2 check (should always be available)
        if self.config.tls_check_tls12 and hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            protocols_to_test.append(('TLS 1.2', ssl.PROTOCOL_TLSv1_2, 'info'))
        
        # Log if some protocols can't be tested due to Python version
        if self.config.tls_check_sslv3 and not hasattr(ssl, 'PROTOCOL_SSLv3'):
            logger.info("SSLv3 testing not available (Python 3.10+ removed support)")
        
        if self.config.tls_check_tls10 and not hasattr(ssl, 'PROTOCOL_TLSv1'):
            logger.info("TLS 1.0 testing not available (Python 3.10+ removed support)")
        
        if self.config.tls_check_tls11 and not hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            logger.info("TLS 1.1 testing not available (Python 3.10+ removed support)")
        
        weak_protocols = []
        
        for protocol_name, protocol_const, severity in protocols_to_test:
            try:
                # Try to connect with specific protocol
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=self.config.timeout_connect) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # Connection successful, protocol is supported
                        if severity in ('critical', 'high'):
                            weak_protocols.append((protocol_name, severity))
                        
                        logger.debug(f"{protocol_name} is supported on {hostname}:{port}")
            
            except ssl.SSLError:
                # Protocol not supported (good for weak protocols, bad for strong ones)
                logger.debug(f"{protocol_name} not supported on {hostname}:{port}")
            
            except socket.timeout:
                # Timeout during protocol test - log but don't fail scan
                logger.debug(f"Timeout testing {protocol_name}")
            
            except (ConnectionRefusedError, ConnectionError):
                # Connection error during protocol test - log but don't fail
                # We already verified connectivity in _check_certificate
                logger.debug(f"Connection error testing {protocol_name}")
            
            except Exception as e:
                # Other errors during protocol test
                logger.debug(f"Error testing {protocol_name}: {e}")
        
        # Generate findings for weak protocols
        for protocol_name, severity in weak_protocols:
            finding_id = f"HEPH-TLS-{10 + len(findings):03d}"
            
            if protocol_name == 'SSLv3':
                description = (
                    'SSLv3 is supported but critically insecure (POODLE vulnerability CVE-2014-3566). '
                    'Should be disabled immediately.'
                )
                recommendation = (
                    'Disable SSLv3:\n'
                    'Apache: SSLProtocol all -SSLv3\n'
                    'Nginx: ssl_protocols TLSv1.2 TLSv1.3;'
                )
                cve = ['CVE-2014-3566']
            
            elif protocol_name == 'TLS 1.0':
                description = (
                    'TLS 1.0 is outdated (released 1999) and has known vulnerabilities. '
                    'PCI DSS prohibits its use. Modern browsers are deprecating support.'
                )
                recommendation = (
                    'Disable TLS 1.0 and 1.1, enable only TLS 1.2+:\n'
                    'Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3\n'
                    'Nginx: ssl_protocols TLSv1.2 TLSv1.3;'
                )
                cve = []
            
            elif protocol_name == 'TLS 1.1':
                description = (
                    'TLS 1.1 is outdated (released 2006) and deprecated. '
                    'Major browsers have removed support. Should be disabled.'
                )
                recommendation = (
                    'Disable TLS 1.1, enable only TLS 1.2+:\n'
                    'Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3\n'
                    'Nginx: ssl_protocols TLSv1.2 TLSv1.3;'
                )
                cve = []
            
            else:
                description = f'{protocol_name} is supported but considered weak'
                recommendation = 'Upgrade to TLS 1.2 or TLS 1.3'
                cve = []
            
            finding = {
                'id': finding_id,
                'title': f'Weak TLS protocol supported: {protocol_name}',
                'severity': severity,
                'confidence': 'high',
                'description': description,
                'evidence': {
                    'type': 'other',
                    'value': f'{protocol_name} supported',
                    'context': f'Host: {hostname}:{port}'
                },
                'recommendation': recommendation,
                'references': [
                    'https://www.ssllabs.com/ssltest/',
                    'https://wiki.mozilla.org/Security/Server_Side_TLS'
                ],
                'affected_component': f'{hostname}:{port}'
            }
            
            if cve:
                finding['cve'] = cve
            
            findings.append(finding)
        
        return findings
    
    def _check_advanced_sslyze(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """
        Advanced TLS checks using SSLyze (Pro feature).
        
        Args:
            hostname: Target hostname
            port: Target port
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Create server location
            server_location = ServerNetworkLocation(hostname, port)
            
            # Test connectivity
            tester = ServerConnectivityTester()
            server_info = tester.perform(server_location)
            
            # Create scanner
            scanner = Scanner()
            
            # Queue scans
            scan_request = ServerScanRequest(
                server_info=server_info,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                }
            )
            
            scanner.queue_scan(scan_request)
            
            # Get results
            for result in scanner.get_results():
                # Analyze cipher suites
                # (Implementation would be more detailed in production)
                logger.info("Advanced SSLyze scan completed")
        
        except Exception as e:
            # SSLyze errors are not critical - log and continue
            logger.error(f"SSLyze scan failed: {e}")
        
        return findings
    
    def _wildcard_match(self, hostname: str, pattern: str) -> bool:
        """
        Check if hostname matches wildcard pattern.
        
        Args:
            hostname: Hostname to check
            pattern: Pattern (e.g., *.example.com)
        
        Returns:
            True if matches
        """
        if not pattern.startswith('*.'):
            return hostname == pattern
        
        # Remove *. from pattern
        domain_suffix = pattern[2:]
        
        # Check if hostname ends with domain suffix
        return hostname.endswith(domain_suffix)


if __name__ == "__main__":
    # Test TLS checker
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    config.expand_paths()
    
    http_client = create_http_client(mode='safe', config=config)
    checker = TLSChecker(config, http_client)
    
    # Test against a target
    target = "https://example.com"
    findings = checker.scan(target)
    
    print(f"\nTLS Check Results for {target}:")
    print(f"Found {len(findings)} finding(s)\n")
    
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['title']}")
        if 'evidence' in finding:
            print(f"  Evidence: {finding['evidence'].get('value', 'N/A')}")
        print()