"""
Server Information Disclosure Check

Detects server software versions exposed via HTTP headers and error pages.

Checks:
- Server header (Apache, Nginx, IIS versions)
- X-Powered-By header (PHP versions)
- Via header (proxies)
- Error page fingerprinting

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class ServerInfoChecker:
    """
    Detects server version disclosure vulnerabilities.
    """
    
    # Known server signatures in headers
    SERVER_PATTERNS = {
        'apache': re.compile(r'Apache/([0-9.]+)', re.IGNORECASE),
        'nginx': re.compile(r'nginx/([0-9.]+)', re.IGNORECASE),
        'iis': re.compile(r'Microsoft-IIS/([0-9.]+)', re.IGNORECASE),
        'lighttpd': re.compile(r'lighttpd/([0-9.]+)', re.IGNORECASE),
        'tomcat': re.compile(r'Apache-Coyote/([0-9.]+)', re.IGNORECASE),
    }
    
    PHP_PATTERN = re.compile(r'PHP/([0-9.]+)', re.IGNORECASE)
    
    # Error page signatures for fingerprinting
    ERROR_SIGNATURES = {
        'apache': [
            r'Apache/([0-9.]+) .* Server at',
            r'Apache Server at',
        ],
        'nginx': [
            r'nginx/([0-9.]+)',
            r'<center>nginx</center>',
        ],
        'iis': [
            r'Microsoft-IIS/([0-9.]+)',
            r'Server Error in .* Application',
        ],
    }
    
    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.http_client = http_client
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan target for server version disclosure.
        
        Args:
            target: Target URL (e.g., https://example.com)
        
        Returns:
            List of findings
        
        Raises:
            requests.exceptions.ConnectionError: If target unreachable
            requests.exceptions.Timeout: If target doesn't respond
            requests.exceptions.RequestException: For other connection issues
        """
        findings = []
        
        logger.info(f"Checking server information disclosure: {target}")
        
        try:
            # 1. Check main page headers
            findings.extend(self._check_headers(target))
            
            # 2. Check error page (404) for fingerprinting
            findings.extend(self._check_error_pages(target))
            
        except requests.exceptions.ConnectionError as e:
            # Connection failed (refused, network unreachable, etc.)
            logger.error(f"Connection failed to {target}: {e}")
            raise  # Propagate to scanner for fail-fast behavior
        
        except requests.exceptions.Timeout as e:
            # Timeout (connect or read timeout)
            logger.error(f"Request timeout for {target}: {e}")
            raise  # Propagate to scanner for fail-fast behavior
        
        except requests.exceptions.RequestException as e:
            # Other connection issues (DNS resolution, SSL errors, etc.)
            logger.error(f"Request failed for {target}: {e}")
            raise  # Propagate to scanner for fail-fast behavior
        
        except Exception as e:
            # Unexpected errors (should be rare)
            logger.exception(f"Unexpected error checking server info: {e}")
            # Don't propagate generic exceptions - let scanner handle them
            # But log with full traceback for debugging
        
        return findings
    
    def _check_headers(self, target: str) -> List[Dict[str, Any]]:
        """
        Check HTTP headers for version disclosure.
        
        Raises:
            requests.exceptions.RequestException: For connection issues
        """
        findings = []
        
        # Let exceptions propagate - don't catch RequestException here
        response = self.http_client.get(
            target,
            timeout=(self.config.timeout_connect, self.config.timeout_read),
            allow_redirects=False
        )
        
        headers = response.headers
        
        # Check Server header
        if 'Server' in headers and self.config.check_server_header:
            server_value = headers['Server']
            
            # Detect server type and version
            for server_type, pattern in self.SERVER_PATTERNS.items():
                match = pattern.search(server_value)
                if match:
                    version = match.group(1) if match.groups() else 'unknown'
                    
                    findings.append({
                        'id': 'HEPH-SRV-001',
                        'title': f'{server_type.capitalize()} server version disclosed',
                        'severity': 'high',
                        'confidence': 'high',
                        'description': (
                            f"Server header discloses {server_type.capitalize()} version {version}. "
                            f"Version disclosure helps attackers identify known vulnerabilities "
                            f"for targeted exploitation."
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': f"Server: {server_value}",
                            'context': f"HTTP response header from {target}"
                        },
                        'recommendation': (
                            f"Hide {server_type.capitalize()} version information:\n"
                            f"- Apache: Set 'ServerTokens Prod' and 'ServerSignature Off' in apache2.conf\n"
                            f"- Nginx: Set 'server_tokens off;' in nginx.conf\n"
                            f"- IIS: Remove 'Server' header via URL Rewrite module"
                        ),
                        'references': [
                            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
                            'https://httpd.apache.org/docs/2.4/mod/core.html#servertokens',
                            'https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens',
                        ],
                        'affected_component': f"{server_type.capitalize()} {version}"
                    })
                    break
        
        # Check X-Powered-By header (PHP)
        if 'X-Powered-By' in headers and self.config.check_x_powered_by:
            powered_value = headers['X-Powered-By']
            
            match = self.PHP_PATTERN.search(powered_value)
            if match:
                php_version = match.group(1)
                
                findings.append({
                    'id': 'HEPH-SRV-002',
                    'title': 'PHP version disclosed',
                    'severity': 'high',
                    'confidence': 'high',
                    'description': (
                        f"X-Powered-By header discloses PHP version {php_version}. "
                        f"This information allows attackers to target known PHP vulnerabilities."
                    ),
                    'evidence': {
                        'type': 'header',
                        'value': f"X-Powered-By: {powered_value}",
                        'context': f"HTTP response header from {target}"
                    },
                    'recommendation': (
                        "Disable PHP version disclosure:\n"
                        "1. Set 'expose_php = Off' in php.ini\n"
                        "2. Remove X-Powered-By header via Apache/Nginx config\n"
                        "3. Restart web server and PHP-FPM"
                    ),
                    'references': [
                        'https://www.php.net/manual/en/ini.core.php#ini.expose-php',
                    ],
                    'affected_component': f"PHP {php_version}"
                })
        
        # Check Via header (proxy disclosure)
        if 'Via' in headers:
            via_value = headers['Via']
            
            findings.append({
                'id': 'HEPH-SRV-003',
                'title': 'Proxy information disclosed',
                'severity': 'low',
                'confidence': 'high',
                'description': (
                    f"Via header discloses proxy/CDN information: {via_value}. "
                    f"This reveals infrastructure topology."
                ),
                'evidence': {
                    'type': 'header',
                    'value': f"Via: {via_value}",
                    'context': f"HTTP response header from {target}"
                },
                'recommendation': (
                    "Consider removing Via header if not required:\n"
                    "- Apache: Use mod_headers to unset Via\n"
                    "- Nginx: Use proxy_hide_header directive"
                ),
                'references': [
                    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via',
                ]
            })
        
        # If no server header at all, that's good (info finding)
        if 'Server' not in headers:
            findings.append({
                'id': 'HEPH-SRV-999',
                'title': 'Server header hidden (good)',
                'severity': 'info',
                'confidence': 'high',
                'description': (
                    "Server header is not present in HTTP responses. "
                    "This is a security best practice that prevents server fingerprinting."
                ),
                'evidence': {
                    'type': 'header',
                    'value': 'Server: [not present]',
                    'context': f"HTTP response from {target}"
                },
                'recommendation': 'Maintain this configuration.'
            })
        
        return findings
    
    def _check_error_pages(self, target: str) -> List[Dict[str, Any]]:
        """
        Check error pages for server fingerprinting.
        
        Note: Catches RequestException here because 404 pages are optional.
        If we can't fetch error page, it's not a scan failure.
        """
        findings = []
        
        # Try to trigger 404 error
        parsed = urlparse(target)
        error_url = f"{parsed.scheme}://{parsed.netloc}/this-page-does-not-exist-hephaestus-test"
        
        try:
            response = self.http_client.get(
                error_url,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=False
            )
            
            if response.status_code == 404:
                body = response.text[:2000]
                
                # Check for server signatures in error page
                for server_type, patterns in self.ERROR_SIGNATURES.items():
                    for pattern in patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.groups() else 'unknown'
                            
                            findings.append({
                                'id': 'HEPH-SRV-004',
                                'title': f'{server_type.capitalize()} disclosed in error page',
                                'severity': 'medium',
                                'confidence': 'medium',
                                'description': (
                                    f"Error page (404) discloses {server_type.capitalize()} server information. "
                                    f"Custom error pages should not reveal server details."
                                ),
                                'evidence': {
                                    'type': 'body',
                                    'value': match.group(0),
                                    'context': f"404 error page at {error_url}"
                                },
                                'recommendation': (
                                    "Configure custom error pages without server information:\n"
                                    "- Apache: Use ErrorDocument directive with custom HTML\n"
                                    "- Nginx: Use error_page directive with custom HTML"
                                ),
                                'references': [
                                    'https://httpd.apache.org/docs/2.4/custom-error.html',
                                    'https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page',
                                ]
                            })
                            break
        
        except requests.exceptions.RequestException as e:
            # Error page check is optional - don't fail scan if it doesn't work
            logger.debug(f"Could not check error page for {target}: {e}")
            # Don't raise - this is a secondary check
        
        return findings


if __name__ == "__main__":
    # Test the checker
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    config.expand_paths()
    
    http_client = create_http_client(mode='safe', config=config)
    checker = ServerInfoChecker(config, http_client)
    
    # Test against example.com
    findings = checker.scan("https://example.com")
    
    print(f"Found {len(findings)} issues:")
    for finding in findings:
        print(f"  [{finding['severity'].upper()}] {finding['title']}")