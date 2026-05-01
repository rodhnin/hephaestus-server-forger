"""
Unsafe HTTP Methods Check

Detects dangerous HTTP methods that should not be enabled on production servers.

Checks:
- OPTIONS (list allowed methods)
- PUT (file upload capability)
- DELETE (resource deletion)
- TRACE (XST attack vector)
- CONNECT, PATCH (rarely needed)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from typing import List, Dict, Any
import secrets

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class HTTPMethodsChecker:
    """
    Detects unsafe HTTP methods enabled on server.
    """
    
    # Methods that should NOT be enabled on production
    UNSAFE_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
    
    # Severity mapping
    SEVERITY_MAP = {
        'PUT': 'high',      # Can upload files
        'DELETE': 'high',   # Can delete resources
        'TRACE': 'medium',  # XST attack
        'CONNECT': 'low',   # Proxy functionality
        'PATCH': 'low',     # Partial updates
    }
    
    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.http_client = http_client
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan target for unsafe HTTP methods.
        
        Args:
            target: Target URL (e.g., https://example.com)
        
        Returns:
            List of findings
        
        Raises:
            requests.exceptions.RequestException: For connection issues
        """
        findings = []
        
        logger.info(f"Checking HTTP methods: {target}")
        
        try:
            # 1. Use OPTIONS to list allowed methods
            findings.extend(self._check_options(target))
            
            # 2. In aggressive mode, test PUT/DELETE directly
            # (only if consent token verified - handled by scanner)
            if self.config.default_mode == 'aggressive' and self.config.probe_unsafe_methods:
                findings.extend(self._probe_put(target))
                findings.extend(self._probe_delete(target))
            
            # 3. Test TRACE (always check, it's passive)
            findings.extend(self._check_trace(target))
        
        except requests.exceptions.ConnectionError as e:
            # Connection failed - propagate to scanner
            logger.error(f"Connection failed to {target}: {e}")
            raise
        
        except requests.exceptions.Timeout as e:
            # Timeout - propagate to scanner
            logger.error(f"Request timeout for {target}: {e}")
            raise
        
        except requests.exceptions.RequestException as e:
            # Other connection issues - propagate to scanner
            logger.error(f"Request failed for {target}: {e}")
            raise
        
        except Exception as e:
            # Unexpected errors - log but don't propagate
            logger.exception(f"Unexpected error checking HTTP methods: {e}")
        
        return findings
    
    def _check_options(self, target: str) -> List[Dict[str, Any]]:
        """
        Check allowed methods via OPTIONS request.
        
        Raises:
            requests.exceptions.RequestException: For connection issues
        """
        findings = []
        
        # Let exceptions propagate - don't catch RequestException here
        response = self.http_client.request(
            'OPTIONS',
            target,
            timeout=(self.config.timeout_connect, self.config.timeout_read),
            allow_redirects=False
        )
        
        # Check Allow header
        if 'Allow' in response.headers:
            allowed_methods = response.headers['Allow'].upper().split(',')
            allowed_methods = [m.strip() for m in allowed_methods]
            
            logger.debug(f"Allowed methods: {', '.join(allowed_methods)}")
            
            # Check for unsafe methods
            for method in self.UNSAFE_METHODS:
                if method in allowed_methods:
                    severity = self.SEVERITY_MAP.get(method, 'medium')
                    
                    findings.append({
                        'id': f'HEPH-HTTP-{self.UNSAFE_METHODS.index(method)+1:03d}',
                        'title': f'Unsafe HTTP method enabled: {method}',
                        'severity': severity,
                        'confidence': 'high',
                        'description': self._get_method_description(method),
                        'evidence': {
                            'type': 'header',
                            'value': f"Allow: {response.headers['Allow']}",
                            'context': f"HTTP OPTIONS response from {target}"
                        },
                        'recommendation': self._get_method_recommendation(method),
                        'references': [
                            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods',
                        ],
                        'affected_component': f'HTTP {method}'
                    })
            
            # If only safe methods, that's good (info finding)
            safe_methods = [m for m in allowed_methods if m not in self.UNSAFE_METHODS]
            if safe_methods and not any(m in allowed_methods for m in self.UNSAFE_METHODS):
                findings.append({
                    'id': 'HEPH-HTTP-999',
                    'title': 'HTTP methods properly restricted',
                    'severity': 'info',
                    'confidence': 'high',
                    'description': (
                        f"Only safe HTTP methods are enabled: {', '.join(safe_methods)}. "
                        f"This is a security best practice."
                    ),
                    'evidence': {
                        'type': 'header',
                        'value': f"Allow: {response.headers['Allow']}",
                        'context': f"HTTP OPTIONS response from {target}"
                    },
                    'recommendation': 'Maintain this configuration.'
                })
        
        else:
            logger.debug("No Allow header in OPTIONS response")
        
        return findings
    
    def _probe_put(self, target: str) -> List[Dict[str, Any]]:
        """
        Probe if PUT method actually works (aggressive mode only).
        
        Note: Catches RequestException because PUT probing is optional.
              If PUT probe fails, it's not a scan failure.
        """
        findings = []
        
        test_file = f"{target}/hephaestus-test-{secrets.token_hex(4)}.txt"
        test_content = "Hephaestus security test - safe to delete"
        
        try:
            response = self.http_client.request(
                'PUT',
                test_file,
                data=test_content,
                timeout=(self.config.timeout_connect, self.config.timeout_read)
            )
            
            # If PUT succeeds (201 Created or 200 OK), that's critical
            if response.status_code in [200, 201, 204]:
                findings.append({
                    'id': 'HEPH-HTTP-006',
                    'title': 'PUT method allows file upload',
                    'severity': 'critical',
                    'confidence': 'high',
                    'description': (
                        f"PUT method is enabled and allows uploading files to the server. "
                        f"This was confirmed by successfully uploading a test file. "
                        f"Attackers can upload malicious files (shells, malware)."
                    ),
                    'evidence': {
                        'type': 'other',
                        'value': f"PUT {test_file}: HTTP {response.status_code}",
                        'context': "Test file upload succeeded"
                    },
                    'recommendation': (
                        "CRITICAL - Disable PUT method immediately:\n"
                        "Apache:\n"
                        "  <LimitExcept GET POST HEAD>\n"
                        "    Require all denied\n"
                        "  </LimitExcept>\n\n"
                        "Nginx:\n"
                        "  if ($request_method !~ ^(GET|POST|HEAD)$ ) {\n"
                        "    return 405;\n"
                        "  }"
                    ),
                    'affected_component': 'HTTP PUT'
                })
                
                # Try to clean up test file
                try:
                    self.http_client.request('DELETE', test_file)
                except:
                    pass
        
        except requests.exceptions.RequestException as e:
            # PUT probe failure is expected/OK - don't propagate
            logger.debug(f"PUT probe failed (expected): {e}")
        
        return findings
    
    def _probe_delete(self, target: str) -> List[Dict[str, Any]]:
        """
        Probe if DELETE method works (aggressive mode only).
        
        Note: Catches RequestException because DELETE probing is optional.
        """
        findings = []
        
        try:
            response = self.http_client.request(
                'DELETE',
                target,
                timeout=(self.config.timeout_connect, self.config.timeout_read)
            )
            
            # If server accepts DELETE (not 405 Method Not Allowed), flag it
            if response.status_code != 405:
                findings.append({
                    'id': 'HEPH-HTTP-007',
                    'title': 'DELETE method enabled',
                    'severity': 'high',
                    'confidence': 'medium',
                    'description': (
                        f"DELETE method is enabled (HTTP {response.status_code}). "
                        f"While the probe did not delete anything, the method is accepted. "
                        f"This allows attackers to attempt resource deletion."
                    ),
                    'evidence': {
                        'type': 'other',
                        'value': f"DELETE {target}: HTTP {response.status_code}",
                        'context': "Server accepted DELETE request"
                    },
                    'recommendation': (
                        "Disable DELETE method:\n"
                        "Apache: Use <LimitExcept> directive\n"
                        "Nginx: Add method checking in location block"
                    ),
                    'affected_component': 'HTTP DELETE'
                })
        
        except requests.exceptions.RequestException as e:
            # DELETE probe failure is expected/OK - don't propagate
            logger.debug(f"DELETE probe failed (expected): {e}")
        
        return findings
    
    def _check_trace(self, target: str) -> List[Dict[str, Any]]:
        """
        Check if TRACE method is enabled (XST vulnerability).
        
        Note: Catches RequestException because TRACE check is secondary.
              If TRACE fails, it's likely just disabled (good).
        """
        findings = []
        
        try:
            response = self.http_client.request(
                'TRACE',
                target,
                timeout=(self.config.timeout_connect, self.config.timeout_read)
            )
            
            # If TRACE is enabled (200 OK), flag it
            if response.status_code == 200:
                findings.append({
                    'id': 'HEPH-HTTP-008',
                    'title': 'TRACE method enabled (XST vulnerability)',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': (
                        "TRACE method is enabled, which can be exploited for Cross-Site Tracing (XST) attacks. "
                        "XST allows attackers to bypass HTTPOnly cookie protection and steal session cookies."
                    ),
                    'evidence': {
                        'type': 'other',
                        'value': f"TRACE {target}: HTTP 200 OK",
                        'context': "TRACE request succeeded"
                    },
                    'recommendation': (
                        "Disable TRACE method:\n\n"
                        "Apache:\n"
                        "  TraceEnable Off\n\n"
                        "Nginx:\n"
                        "  (TRACE is disabled by default in Nginx)"
                    ),
                    'references': [
                        'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
                    ],
                    'affected_component': 'HTTP TRACE',
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                })
        
        except requests.exceptions.RequestException as e:
            # TRACE failure is expected/good - don't propagate
            logger.debug(f"TRACE request failed (good): {e}")
        
        return findings
    
    def _get_method_description(self, method: str) -> str:
        """Get description for specific HTTP method."""
        descriptions = {
            'PUT': (
                "PUT method is enabled, which allows uploading files to the server. "
                "This can be exploited to upload malicious files (web shells, malware). "
                "PUT should be disabled unless specifically required by the application."
            ),
            'DELETE': (
                "DELETE method is enabled, allowing resource deletion. "
                "This can be exploited to delete files or application data. "
                "DELETE should be disabled unless required."
            ),
            'TRACE': (
                "TRACE method is enabled, which echoes back the request. "
                "This can be exploited for Cross-Site Tracing (XST) attacks to steal cookies. "
                "TRACE should always be disabled."
            ),
            'CONNECT': (
                "CONNECT method is enabled, which is used for proxy tunneling. "
                "This is rarely needed and can be exploited to bypass firewall rules."
            ),
            'PATCH': (
                "PATCH method is enabled, allowing partial resource updates. "
                "Unless explicitly required by your application, this should be disabled."
            ),
        }
        return descriptions.get(method, f"{method} method is enabled but should be disabled.")
    
    def _get_method_recommendation(self, method: str) -> str:
        """Get remediation recommendation for specific method."""
        return (
            f"Disable {method} method if not explicitly required:\n\n"
            f"Apache:\n"
            f"  <LimitExcept GET POST HEAD>\n"
            f"    Require all denied\n"
            f"  </LimitExcept>\n\n"
            f"Nginx:\n"
            f"  if ($request_method !~ ^(GET|POST|HEAD)$ ) {{\n"
            f"    return 405;\n"
            f"  }}\n\n"
            f"Verify after configuration: curl -X {method} https://example.com\n"
            f"Expected response: HTTP 405 Method Not Allowed"
        )


if __name__ == "__main__":
    # Test the checker
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    config.expand_paths()
    
    http_client = create_http_client(mode='safe', config=config)
    checker = HTTPMethodsChecker(config, http_client)
    
    findings = checker.scan("https://example.com")
    
    print(f"Found {len(findings)} HTTP method issues:")
    for finding in findings:
        print(f"  [{finding['severity'].upper()}] {finding['title']}")