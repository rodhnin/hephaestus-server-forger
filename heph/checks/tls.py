"""
Hephaestus TLS/SSL Checker — Deep Analysis (v0.2.0 IMPROV-002)

Validates TLS/SSL configuration:
- Certificate validation (expiration, hostname, self-signed)
- Protocol versions (SSLv3, TLS 1.0/1.1/1.2/1.3)
- Cipher suite analysis with SSLyze (weak ciphers, CVE correlation)
- SSL Labs-style grading (A+/A/B/C/D/F)
- CVE enrichment for POODLE, Sweet32, BEAST, RC4, DROWN, FREAK

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from sslyze import (
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
        ScanCommand,
    )
    HAS_SSLYZE = True
except ImportError:
    HAS_SSLYZE = False

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)

# ─── CVE data for known TLS vulnerabilities ───────────────────────────────────
CVE_REGISTRY = {
    'drown': {
        'cve_id': 'CVE-2016-0800',
        'title': 'DROWN Attack (SSLv2)',
        'description': (
            'DROWN allows attackers to decrypt TLS connections by exploiting SSLv2 '
            'on the same key. Any server sharing private keys with an SSLv2-enabled '
            'server is vulnerable.'
        ),
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-0800',
        'cvss_score': 5.9,
        'cwe_id': 'CWE-310',
        'cwe_name': 'Cryptographic Issues',
    },
    'poodle': {
        'cve_id': 'CVE-2014-3566',
        'title': 'POODLE Attack (SSLv3)',
        'description': (
            'POODLE allows a MITM attacker to decrypt encrypted data by forcing '
            'SSLv3 connections and exploiting CBC padding oracle behavior.'
        ),
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2014-3566',
        'cvss_score': 3.4,
        'cwe_id': 'CWE-310',
        'cwe_name': 'Cryptographic Issues',
    },
    'sweet32': {
        'cve_id': 'CVE-2016-2183',
        'title': 'Sweet32 Birthday Attack (3DES)',
        'description': (
            'Sweet32 exploits 64-bit block cipher birthday attacks. Servers using '
            '3DES cipher suites are vulnerable when long-lived connections are '
            'maintained (e.g., video streaming, long HTTPS sessions).'
        ),
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-2183',
        'cvss_score': 7.5,
        'cwe_id': 'CWE-326',
        'cwe_name': 'Inadequate Encryption Strength',
    },
    'freak': {
        'cve_id': 'CVE-2015-0204',
        'title': 'FREAK Attack (EXPORT ciphers)',
        'description': (
            'FREAK allows MITM attackers to force RSA_EXPORT cipher suites, '
            'enabling factorization of the weak 512-bit RSA key and session decryption.'
        ),
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-0204',
        'cvss_score': 4.3,
        'cwe_id': 'CWE-326',
        'cwe_name': 'Inadequate Encryption Strength',
    },
    'logjam': {
        'cve_id': 'CVE-2015-4000',
        'title': 'Logjam Attack (DHE_EXPORT)',
        'description': (
            'Logjam allows MITM attackers to downgrade TLS connections to 512-bit '
            'export-grade Diffie-Hellman key exchange, allowing decryption of the session.'
        ),
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-4000',
        'cvss_score': 3.7,
        'cwe_id': 'CWE-326',
        'cwe_name': 'Inadequate Encryption Strength',
    },
    'rc4': {
        'cve_id': 'CVE-2013-2566',
        'title': 'RC4 Cipher Suite Weakness',
        'description': (
            'RC4 has serious statistical biases that allow passive attackers to '
            'recover plaintext. IETF RFC 7465 prohibits use of RC4 in TLS.'
        ),
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2013-2566',
        'cvss_score': 4.3,
        'cwe_id': 'CWE-326',
        'cwe_name': 'Inadequate Encryption Strength',
    },
    'rc4_2015': {
        'cve_id': 'CVE-2015-2808',
        'title': 'Bar Mitzvah Attack (RC4)',
        'description': (
            'The "Bar Mitzvah" attack exploits the RC4 biases in SSL/TLS sessions '
            'to partially decrypt HTTPS traffic.'
        ),
        'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-2808',
        'cvss_score': 4.3,
        'cwe_id': 'CWE-310',
        'cwe_name': 'Cryptographic Issues',
    },
}

# ─── Weak cipher patterns ─────────────────────────────────────────────────────
RC4_PATTERNS    = ('_RC4_', '_ARCFOUR_', 'RC4_')
DES3_PATTERNS   = ('_3DES_', '_DES_EDE_', 'DES_EDE3_')
NULL_PATTERNS   = ('_NULL_', '_WITH_NULL', 'NULL_')
EXPORT_PATTERNS = ('_EXPORT_', '_EXPORT1024_', 'EXP_', 'EXP1024_')
ANON_PATTERNS   = ('_anon_', '_ANON_', 'ADH_', 'AECDH_', 'DH_anon')


def _cipher_matches(name: str, patterns: tuple) -> bool:
    return any(p in name for p in patterns)


class TLSChecker:
    """
    Checks TLS/SSL configuration — basic + deep analysis with SSLyze (IMPROV-002).
    """

    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.http_client = http_client

        self.protocol_versions = {}
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            self.protocol_versions[ssl.PROTOCOL_SSLv3] = 'SSLv3'
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            self.protocol_versions[ssl.PROTOCOL_TLSv1] = 'TLS 1.0'
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            self.protocol_versions[ssl.PROTOCOL_TLSv1_1] = 'TLS 1.1'
        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            self.protocol_versions[ssl.PROTOCOL_TLSv1_2] = 'TLS 1.2'
        self.has_tls13 = hasattr(ssl, 'PROTOCOL_TLS_CLIENT')

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Execute TLS/SSL checks.

        Args:
            target: Target URL

        Returns:
            List of findings
        """
        findings = []

        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.path
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        if parsed.scheme != 'https' and port != 443:
            logger.info("Target is not HTTPS, skipping TLS checks")
            return findings

        logger.info(f"Checking TLS/SSL configuration for {hostname}:{port}")

        # BASIC CHECKS (always)
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
                'description': 'cryptography library not installed',
                'recommendation': 'Install cryptography: pip install cryptography>=41.0.0',
            })

        # DEEP CHECKS (sslyze) — IMPROV-002
        if HAS_SSLYZE and self.config.tls_advanced_enabled:
            deep_findings = self._check_advanced_sslyze(hostname, port)
            findings.extend(deep_findings)
        elif self.config.tls_advanced_enabled and not HAS_SSLYZE:
            logger.warning("SSLyze not installed, skipping deep TLS checks")
            findings.append({
                'id': 'HEPH-TLS-998',
                'title': 'Deep TLS checks unavailable (missing sslyze)',
                'severity': 'info',
                'confidence': 'high',
                'description': 'SSLyze not installed, cannot analyse cipher suites or compute TLS grade',
                'recommendation': 'Install sslyze: pip install sslyze>=5.0.0',
            })

        if not findings:
            logger.info("No TLS/SSL issues detected")
        else:
            logger.info(f"Found {len(findings)} TLS/SSL finding(s)")

        return findings

    # ─── Basic checks ─────────────────────────────────────────────────────────

    def _check_certificate(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Check certificate validity (expiration, hostname, self-signed)."""
        findings = []

        # Step 1: get the certificate (with fallback to unverified context for self-signed)
        cert_der = None
        cert_dict = None
        verify_failed = False

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.config.timeout_connect) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

        except ssl.SSLError as e:
            # Verification failed — retry without verification to inspect the cert
            logger.warning(f"SSL error checking certificate: {e}")
            verify_failed = True
            try:
                no_verify_ctx = ssl.create_default_context()
                no_verify_ctx.check_hostname = False
                no_verify_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=self.config.timeout_connect) as sock:
                    with no_verify_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert_dict = ssock.getpeercert()
            except Exception as e2:
                logger.warning(f"SSL fallback also failed: {e2}")
                findings.append({
                    'id': 'HEPH-TLS-005',
                    'title': 'SSL/TLS handshake failed',
                    'severity': 'high',
                    'confidence': 'medium',
                    'description': f"SSL/TLS handshake failed: {str(e)}",
                    'evidence': {'type': 'other', 'value': str(e)},
                    'recommendation': 'Check SSL/TLS configuration and certificate validity.',
                    'affected_component': f'{hostname}:{port}',
                })
                return findings

        except socket.timeout:
            logger.error(f"Connection timeout to {hostname}:{port}")
            raise

        except (ConnectionRefusedError, ConnectionError) as e:
            logger.error(f"Connection error to {hostname}:{port}: {e}")
            raise

        except OSError as e:
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
                    'recommendation': 'Verify server is reachable and TLS is correctly configured.',
                    'affected_component': f'{hostname}:{port}',
                })
                return findings

        except Exception as e:
            logger.error(f"Unexpected error checking certificate: {e}")
            return findings

        if not cert_der:
            return findings

        # Step 2: analyse the certificate
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            # Expiration check
            expiration = cert.not_valid_after_utc
            now = datetime.now(timezone.utc)

            if expiration < now:
                days_expired = (now - expiration).days
                findings.append({
                    'id': 'HEPH-TLS-001',
                    'title': 'SSL/TLS certificate expired',
                    'severity': 'critical',
                    'confidence': 'high',
                    'description': (
                        f"SSL/TLS certificate for {hostname} expired {days_expired} days ago. "
                        "Browsers will show security warnings and block access."
                    ),
                    'evidence': {
                        'type': 'other',
                        'value': f"Expired: {expiration.isoformat()}",
                        'context': f"Days expired: {days_expired}",
                    },
                    'recommendation': 'Renew SSL/TLS certificate immediately via your Certificate Authority.',
                    'references': ['https://letsencrypt.org/', 'https://www.ssllabs.com/ssltest/'],
                    'affected_component': f'{hostname}:{port}',
                    'cvss': 7.5,
                })

            elif (expiration - now).days < 30:
                days_remaining = (expiration - now).days
                findings.append({
                    'id': 'HEPH-TLS-002',
                    'title': 'SSL/TLS certificate expiring soon',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': f"SSL/TLS certificate expires in {days_remaining} days.",
                    'evidence': {
                        'type': 'other',
                        'value': f"Expires: {expiration.isoformat()}",
                        'context': f"Days remaining: {days_remaining}",
                    },
                    'recommendation': 'Renew certificate before expiration to avoid service disruption.',
                    'references': ['https://letsencrypt.org/'],
                    'affected_component': f'{hostname}:{port}',
                    'cvss': 4.3,
                })

            # Hostname mismatch (only meaningful when cert_dict is populated)
            if cert_dict:
                sans = [name[1] for name in cert_dict.get('subjectAltName', []) if name[0] == 'DNS']
                common_name = None
                for rdn in cert_dict.get('subject', []):
                    for name_type, name_value in rdn:
                        if name_type == 'commonName':
                            common_name = name_value
                            break

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
                            f"Valid for: {', '.join(cert_names) if cert_names else 'N/A'}"
                        ),
                        'evidence': {
                            'type': 'other',
                            'value': f"Certificate names: {', '.join(cert_names) if cert_names else 'N/A'}",
                            'context': f"Requested: {hostname}",
                        },
                        'recommendation': 'Obtain certificate with correct hostname/SAN entries.',
                        'affected_component': f'{hostname}:{port}',
                        'cvss': 6.5,
                    })

            # Self-signed
            if cert.issuer == cert.subject:
                findings.append({
                    'id': 'HEPH-TLS-004',
                    'title': 'Self-signed SSL/TLS certificate',
                    'severity': 'high',
                    'confidence': 'high',
                    'description': (
                        'Certificate is self-signed — browsers will display security warnings. '
                        'Not suitable for production environments.'
                    ),
                    'evidence': {
                        'type': 'other',
                        'value': f"Issuer: {cert.issuer.rfc4514_string()}",
                        'context': 'Self-signed (issuer == subject)',
                    },
                    'recommendation': "Obtain a certificate from a trusted CA (e.g., Let's Encrypt).",
                    'references': ['https://letsencrypt.org/'],
                    'affected_component': f'{hostname}:{port}',
                    'cvss': 6.5,
                })

        except Exception as e:
            logger.error(f"Error analysing certificate: {e}")

        return findings

    def _check_tls_protocols(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Check supported TLS protocol versions via Python ssl module."""
        findings = []

        # Map: (protocol_name, ssl_const, severity, fixed_id)
        protocols_to_test = []

        if self.config.tls_check_sslv3 and hasattr(ssl, 'PROTOCOL_SSLv3'):
            protocols_to_test.append(('SSLv3', ssl.PROTOCOL_SSLv3, 'critical', 'HEPH-TLS-010'))
        if self.config.tls_check_tls10 and hasattr(ssl, 'PROTOCOL_TLSv1'):
            protocols_to_test.append(('TLS 1.0', ssl.PROTOCOL_TLSv1, 'high', 'HEPH-TLS-011'))
        if self.config.tls_check_tls11 and hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            protocols_to_test.append(('TLS 1.1', ssl.PROTOCOL_TLSv1_1, 'high', 'HEPH-TLS-012'))
        if self.config.tls_check_tls12 and hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            protocols_to_test.append(('TLS 1.2', ssl.PROTOCOL_TLSv1_2, 'info', 'HEPH-TLS-013'))

        for protocol_name, ssl_const, severity, finding_id in protocols_to_test:
            try:
                context = ssl.SSLContext(ssl_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=self.config.timeout_connect) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        # Connected — protocol is supported
                        if severity in ('critical', 'high'):
                            description, recommendation, cve = self._protocol_finding_details(protocol_name)
                            finding = {
                                'id': finding_id,
                                'title': f'Weak TLS protocol supported: {protocol_name}',
                                'severity': severity,
                                'confidence': 'high',
                                'description': description,
                                'evidence': {
                                    'type': 'other',
                                    'value': f'{protocol_name} accepted',
                                    'context': f'Host: {hostname}:{port}',
                                },
                                'recommendation': recommendation,
                                'references': [
                                    'https://www.ssllabs.com/ssltest/',
                                    'https://wiki.mozilla.org/Security/Server_Side_TLS',
                                ],
                                'affected_component': f'{hostname}:{port}',
                                'cvss': 6.5 if protocol_name != 'SSLv3' else 7.5,
                            }
                            if cve:
                                finding['cve'] = cve
                            findings.append(finding)

            except ssl.SSLError:
                logger.debug(f"{protocol_name} not supported on {hostname}:{port}")
            except (socket.timeout, ConnectionRefusedError, ConnectionError):
                logger.debug(f"Connection issue testing {protocol_name}")
            except Exception as e:
                logger.debug(f"Error testing {protocol_name}: {e}")

        return findings

    def _protocol_finding_details(self, protocol_name: str):
        if protocol_name == 'SSLv3':
            return (
                'SSLv3 is critically insecure (POODLE vulnerability CVE-2014-3566) and must be disabled.',
                'Apache: SSLProtocol all -SSLv3\nNginx: ssl_protocols TLSv1.2 TLSv1.3;',
                ['CVE-2014-3566'],
            )
        elif protocol_name == 'TLS 1.0':
            return (
                'TLS 1.0 (1999) has known vulnerabilities. PCI DSS prohibits its use after 2018.',
                'Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3\nNginx: ssl_protocols TLSv1.2 TLSv1.3;',
                [],
            )
        elif protocol_name == 'TLS 1.1':
            return (
                'TLS 1.1 (2006) is deprecated. Major browsers removed support in 2020.',
                'Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3\nNginx: ssl_protocols TLSv1.2 TLSv1.3;',
                [],
            )
        return (f'{protocol_name} is supported but considered weak.', 'Upgrade to TLS 1.2 or TLS 1.3.', [])

    # ─── Deep analysis with SSLyze (IMPROV-002) ───────────────────────────────

    def _check_advanced_sslyze(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """
        Deep TLS analysis using SSLyze:
        - Cipher suite enumeration (SSLv2, SSLv3, TLS 1.0-1.3)
        - Weak cipher detection (RC4, 3DES, NULL, EXPORT, ANON)
        - CVE enrichment (DROWN, POODLE, Sweet32, FREAK, RC4)
        - SSL Labs-style grade (A+/A/B/C/D/F)
        """
        findings = []

        try:
            location = ServerNetworkLocation(hostname, port)
            scanner = Scanner()

            request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                },
            )
            scanner.queue_scans([request])

            for result in scanner.get_results():
                if result.scan_result is None:
                    logger.warning(f"SSLyze returned no result for {hostname}:{port}")
                    continue

                findings.extend(self._analyse_sslyze_result(result, hostname, port))

        except Exception as e:
            logger.error(f"SSLyze scan failed: {e}")

        return findings

    def _analyse_sslyze_result(self, result, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Parse SSLyze scan result and generate findings."""
        findings = []
        sr = result.scan_result

        # Gather accepted ciphers per protocol
        proto_ciphers = {}
        for cmd, attr, label in [
            (ScanCommand.SSL_2_0_CIPHER_SUITES, 'ssl_2_0_cipher_suites', 'SSLv2'),
            (ScanCommand.SSL_3_0_CIPHER_SUITES, 'ssl_3_0_cipher_suites', 'SSLv3'),
            (ScanCommand.TLS_1_0_CIPHER_SUITES, 'tls_1_0_cipher_suites', 'TLS 1.0'),
            (ScanCommand.TLS_1_1_CIPHER_SUITES, 'tls_1_1_cipher_suites', 'TLS 1.1'),
            (ScanCommand.TLS_1_2_CIPHER_SUITES, 'tls_1_2_cipher_suites', 'TLS 1.2'),
            (ScanCommand.TLS_1_3_CIPHER_SUITES, 'tls_1_3_cipher_suites', 'TLS 1.3'),
        ]:
            try:
                scan_attempt = getattr(sr, attr, None)
                if scan_attempt and not isinstance(getattr(scan_attempt, 'result', None), type(None)):
                    accepted = scan_attempt.result.accepted_cipher_suites
                    if accepted:
                        proto_ciphers[label] = [c.cipher_suite.name for c in accepted]
            except Exception as e:
                logger.debug(f"Error reading {label} ciphers: {e}")

        has_ssl2    = 'SSLv2'   in proto_ciphers
        has_ssl3    = 'SSLv3'   in proto_ciphers
        has_tls10   = 'TLS 1.0' in proto_ciphers
        has_tls11   = 'TLS 1.1' in proto_ciphers
        has_tls12   = 'TLS 1.2' in proto_ciphers
        has_tls13   = 'TLS 1.3' in proto_ciphers

        all_ciphers = []
        for ciphers in proto_ciphers.values():
            all_ciphers.extend(ciphers)

        # Detect weak cipher categories
        rc4_ciphers   = [c for c in all_ciphers if _cipher_matches(c, RC4_PATTERNS)]
        des3_ciphers  = [c for c in all_ciphers if _cipher_matches(c, DES3_PATTERNS)]
        null_ciphers  = [c for c in all_ciphers if _cipher_matches(c, NULL_PATTERNS)]
        exp_ciphers   = [c for c in all_ciphers if _cipher_matches(c, EXPORT_PATTERNS)]
        anon_ciphers  = [c for c in all_ciphers if _cipher_matches(c, ANON_PATTERNS)]

        # ── SSLv2 supported (DROWN) ─────────────────────────────────────────
        if has_ssl2:
            cve = CVE_REGISTRY['drown']
            findings.append({
                'id': 'HEPH-TLS-020',
                'title': 'SSLv2 cipher suites accepted (DROWN attack)',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    'The server accepts SSLv2 connections, enabling the DROWN attack. '
                    'An attacker can decrypt modern TLS sessions by performing MITM and '
                    'exploiting the SSLv2 handshake on the same RSA key.'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"SSLv2 ciphers: {', '.join(proto_ciphers['SSLv2'][:5])}",
                    'context': f'Host: {hostname}:{port}',
                },
                'recommendation': (
                    'Disable SSLv2 immediately:\n'
                    'Apache: SSLProtocol all -SSLv2 -SSLv3\n'
                    'Nginx: ssl_protocols TLSv1.2 TLSv1.3;'
                ),
                'references': ['https://drownattack.com/', cve['link']],
                'cve': [cve['cve_id']],
                'vulnerabilities': [cve],
                'cvss': cve['cvss_score'],
                'affected_component': f'{hostname}:{port}',
            })

        # ── SSLv3 supported (POODLE) ────────────────────────────────────────
        if has_ssl3:
            cve = CVE_REGISTRY['poodle']
            findings.append({
                'id': 'HEPH-TLS-021',
                'title': 'SSLv3 cipher suites accepted (POODLE attack)',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    'The server accepts SSLv3 connections, enabling the POODLE attack. '
                    'Attackers can force SSLv3 and exploit CBC padding oracle behavior '
                    'to decrypt encrypted data.'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"SSLv3 ciphers: {', '.join(proto_ciphers['SSLv3'][:5])}",
                    'context': f'Host: {hostname}:{port}',
                },
                'recommendation': (
                    'Disable SSLv3:\n'
                    'Apache: SSLProtocol all -SSLv2 -SSLv3\n'
                    'Nginx: ssl_protocols TLSv1.2 TLSv1.3;'
                ),
                'references': ['https://poodlebleed.com/', cve['link']],
                'cve': [cve['cve_id']],
                'vulnerabilities': [cve],
                'cvss': cve['cvss_score'],
                'affected_component': f'{hostname}:{port}',
            })

        # ── RC4 ciphers ─────────────────────────────────────────────────────
        if rc4_ciphers:
            cve1 = CVE_REGISTRY['rc4']
            cve2 = CVE_REGISTRY['rc4_2015']
            findings.append({
                'id': 'HEPH-TLS-022',
                'title': 'RC4 cipher suites enabled',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    'RC4 cipher suites are enabled. RC4 has serious statistical biases '
                    'allowing passive decryption. RFC 7465 prohibits RC4 in TLS.'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"RC4 ciphers: {', '.join(rc4_ciphers[:5])}",
                    'context': f'Host: {hostname}:{port}',
                },
                'recommendation': (
                    'Disable all RC4 cipher suites:\n'
                    'Apache: SSLCipherSuite !RC4:HIGH:!aNULL:!MD5\n'
                    'Nginx: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...'
                ),
                'references': [cve1['link'], cve2['link']],
                'cve': [cve1['cve_id'], cve2['cve_id']],
                'vulnerabilities': [cve1, cve2],
                'cvss': cve1['cvss_score'],
                'affected_component': f'{hostname}:{port}',
            })

        # ── 3DES / Sweet32 ──────────────────────────────────────────────────
        if des3_ciphers:
            cve = CVE_REGISTRY['sweet32']
            findings.append({
                'id': 'HEPH-TLS-023',
                'title': '3DES cipher suites enabled (Sweet32 attack)',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    '3DES cipher suites (64-bit block size) are vulnerable to the Sweet32 '
                    'birthday attack. Attackers can decrypt long-lived HTTPS connections '
                    'after ~785 GB of encrypted data.'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"3DES ciphers: {', '.join(des3_ciphers[:5])}",
                    'context': f'Host: {hostname}:{port}',
                },
                'recommendation': (
                    'Disable 3DES cipher suites:\n'
                    'Apache: SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!3DES\n'
                    'Nginx: ssl_ciphers EECDH+AESGCM:EDH+AESGCM;'
                ),
                'references': ['https://sweet32.info/', cve['link']],
                'cve': [cve['cve_id']],
                'vulnerabilities': [cve],
                'cvss': cve['cvss_score'],
                'affected_component': f'{hostname}:{port}',
            })

        # ── NULL ciphers ────────────────────────────────────────────────────
        if null_ciphers:
            findings.append({
                'id': 'HEPH-TLS-024',
                'title': 'NULL cipher suites enabled (no encryption)',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    'NULL cipher suites provide authentication but no encryption. '
                    'Traffic is transmitted in plaintext, fully visible to any eavesdropper.'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"NULL ciphers: {', '.join(null_ciphers[:5])}",
                    'context': f'Host: {hostname}:{port}',
                },
                'recommendation': (
                    'Remove all NULL cipher suites from server configuration:\n'
                    'Apache: SSLCipherSuite HIGH:!NULL:!aNULL:!MD5\n'
                    'Nginx: ssl_ciphers EECDH+AESGCM:EDH+AESGCM;'
                ),
                'affected_component': f'{hostname}:{port}',
                'cvss': 9.1,
            })

        # ── EXPORT ciphers (FREAK / Logjam) ─────────────────────────────────
        if exp_ciphers:
            cve_freak  = CVE_REGISTRY['freak']
            cve_logjam = CVE_REGISTRY['logjam']
            findings.append({
                'id': 'HEPH-TLS-025',
                'title': 'EXPORT cipher suites enabled (FREAK/Logjam attacks)',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    'EXPORT-grade cipher suites (≤512-bit RSA or DH) allow MITM attackers '
                    'to force weak key exchange and decrypt traffic (FREAK & Logjam attacks).'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"EXPORT ciphers: {', '.join(exp_ciphers[:5])}",
                    'context': f'Host: {hostname}:{port}',
                },
                'recommendation': (
                    'Disable EXPORT cipher suites:\n'
                    'Apache: SSLCipherSuite HIGH:!EXPORT:!aNULL:!MD5\n'
                    'Nginx: ssl_ciphers EECDH+AESGCM:EDH+AESGCM;'
                ),
                'references': [cve_freak['link'], cve_logjam['link']],
                'cve': [cve_freak['cve_id'], cve_logjam['cve_id']],
                'vulnerabilities': [cve_freak, cve_logjam],
                'cvss': max(cve_freak['cvss_score'], cve_logjam['cvss_score']),
                'affected_component': f'{hostname}:{port}',
            })

        # ── ANONYMOUS ciphers ────────────────────────────────────────────────
        if anon_ciphers:
            findings.append({
                'id': 'HEPH-TLS-026',
                'title': 'Anonymous (unauthenticated) cipher suites enabled',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    'Anonymous cipher suites provide no server authentication, allowing '
                    'full MITM attacks without any certificate.'
                ),
                'evidence': {
                    'type': 'other',
                    'value': f"ANON ciphers: {', '.join(anon_ciphers[:5])}",
                    'context': f'Host: {hostname}:{port}',
                },
                'recommendation': (
                    'Remove all anonymous cipher suites:\n'
                    'Apache: SSLCipherSuite HIGH:!aNULL:!eNULL:!NULL\n'
                    'Nginx: ssl_ciphers EECDH+AESGCM:EDH+AESGCM;'
                ),
                'affected_component': f'{hostname}:{port}',
                'cvss': 9.1,
            })

        # ── TLS grade summary ────────────────────────────────────────────────
        grade = self._calculate_grade(
            has_ssl2=has_ssl2,
            has_ssl3=has_ssl3,
            has_tls10=has_tls10,
            has_tls11=has_tls11,
            has_tls12=has_tls12,
            has_tls13=has_tls13,
            has_rc4=bool(rc4_ciphers),
            has_3des=bool(des3_ciphers),
            has_null=bool(null_ciphers),
            has_export=bool(exp_ciphers),
            has_anon=bool(anon_ciphers),
            cert_findings=findings,
        )

        grade_severity = 'info' if grade in ('A+', 'A') else ('medium' if grade == 'B' else 'high')
        proto_supported = ', '.join(
            p for p, present in [
                ('SSLv2', has_ssl2), ('SSLv3', has_ssl3),
                ('TLS 1.0', has_tls10), ('TLS 1.1', has_tls11),
                ('TLS 1.2', has_tls12), ('TLS 1.3', has_tls13),
            ] if present
        ) or 'None detected'

        findings.append({
            'id': 'HEPH-TLS-027',
            'title': f'TLS configuration grade: {grade}',
            'severity': grade_severity,
            'confidence': 'high',
            'description': (
                f'SSL Labs-style TLS grade for {hostname}:{port} is {grade}. '
                f'Protocols accepted: {proto_supported}.'
            ),
            'evidence': {
                'type': 'other',
                'value': f'Grade: {grade}',
                'context': f'Protocols: {proto_supported}',
            },
            'recommendation': (
                'Target grade A or A+:\n'
                '1. Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1\n'
                '2. Enable only TLS 1.2 and TLS 1.3\n'
                '3. Use strong cipher suites (ECDHE + AES-GCM)\n'
                '4. Enable HSTS with preload'
            ),
            'references': [
                'https://www.ssllabs.com/ssltest/',
                'https://wiki.mozilla.org/Security/Server_Side_TLS',
            ],
            'affected_component': f'{hostname}:{port}',
            'tls_grade': grade,
        })

        return findings

    def _calculate_grade(
        self,
        has_ssl2: bool, has_ssl3: bool,
        has_tls10: bool, has_tls11: bool,
        has_tls12: bool, has_tls13: bool,
        has_rc4: bool, has_3des: bool,
        has_null: bool, has_export: bool, has_anon: bool,
        cert_findings: list,
    ) -> str:
        """Calculate SSL Labs-style grade (A+ to F)."""
        # F conditions
        if has_ssl2 or has_null or has_anon:
            return 'F'
        cert_ids = [f.get('id') for f in cert_findings]
        if 'HEPH-TLS-001' in cert_ids:  # Expired cert
            return 'F'

        # D conditions
        if has_ssl3 or has_export:
            return 'D'

        # C conditions
        if has_rc4 or has_3des:
            return 'C'

        # B conditions — TLS 1.0 or 1.1 still enabled
        if has_tls10 or has_tls11:
            return 'B'

        # A conditions
        if has_tls12:
            # A+ requires TLS 1.3 AND TLS 1.2 only
            if has_tls13:
                return 'A+'
            return 'A'

        # TLS 1.3 only
        if has_tls13:
            return 'A+'

        return 'B'  # Can't determine, be conservative

    # ─── Wildcard helper ──────────────────────────────────────────────────────

    def _wildcard_match(self, hostname: str, pattern: str) -> bool:
        if not pattern.startswith('*.'):
            return hostname == pattern
        return hostname.endswith(pattern[2:])


if __name__ == "__main__":
    from ..core.config import Config
    from ..core.http_client import create_http_client

    config = Config.load()
    config.expand_paths()

    http_client = create_http_client(mode='safe', config=config)
    checker = TLSChecker(config, http_client)

    target = "https://example.com"
    findings = checker.scan(target)

    print(f"\nTLS Check Results for {target}:")
    print(f"Found {len(findings)} finding(s)\n")
    for finding in findings:
        grade = f" [Grade: {finding.get('tls_grade')}]" if finding.get('tls_grade') else ""
        print(f"[{finding['severity'].upper()}] {finding['title']}{grade}")
