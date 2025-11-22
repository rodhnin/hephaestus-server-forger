"""
Security Headers Check (Deep Analysis)

More comprehensive than Argus - focuses on server-level security headers.

Checks:
- HSTS (HTTP Strict Transport Security)
- Content Security Policy (CSP)
- X-Frame-Options (Clickjacking)
- X-Content-Type-Options (MIME sniffing)
- X-XSS-Protection (legacy but still checked)
- Referrer-Policy
- Permissions-Policy
- Cookie security (Secure, HttpOnly, SameSite)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from typing import List, Dict, Any
from urllib.parse import urlparse

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class SecurityHeadersChecker:
    """
    Deep analysis of security headers (server-focused).
    """
    
    # Header definitions with severity
    HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'medium',
            'name': 'HSTS',
            'description': 'Forces browsers to use HTTPS, preventing protocol downgrade attacks',
            'recommendation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        },
        'Content-Security-Policy': {
            'severity': 'medium',
            'name': 'CSP',
            'description': 'Mitigates XSS and code injection attacks',
            'recommendation': 'Add header: Content-Security-Policy: default-src \'self\'; script-src \'self\'',
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'name': 'X-Frame-Options',
            'description': 'Prevents clickjacking attacks',
            'recommendation': 'Add header: X-Frame-Options: SAMEORIGIN',
        },
        'X-Content-Type-Options': {
            'severity': 'low',
            'name': 'X-Content-Type-Options',
            'description': 'Prevents MIME-sniffing attacks',
            'recommendation': 'Add header: X-Content-Type-Options: nosniff',
        },
        'Referrer-Policy': {
            'severity': 'low',
            'name': 'Referrer-Policy',
            'description': 'Controls how much referrer information is sent',
            'recommendation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        },
        'Permissions-Policy': {
            'severity': 'low',
            'name': 'Permissions-Policy',
            'description': 'Controls which browser features can be used',
            'recommendation': 'Add header: Permissions-Policy: geolocation=(), camera=(), microphone=()',
        },
    }
    
    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.http_client = http_client
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan target for security headers.
        
        Args:
            target: Target URL (e.g., https://example.com)
        
        Returns:
            List of findings
        
        Raises:
            requests.exceptions.RequestException: For connection issues
            
        Note: If Phase 1 succeeded, this should also succeed.
              But we still propagate exceptions for consistency.
        """
        findings = []
        
        logger.info(f"Checking security headers: {target}")
        
        try:
            # Get response headers
            response = self.http_client.get(
                target,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=True
            )
            
            headers = response.headers
            
            # 1. Check for missing security headers
            findings.extend(self._check_missing_headers(target, headers))
            
            # 2. Check HSTS configuration (if present)
            findings.extend(self._check_hsts(target, headers))
            
            # 3. Check CSP configuration (if present)
            findings.extend(self._check_csp(target, headers))
            
            # 4. Check X-Frame-Options (if present)
            findings.extend(self._check_xfo(target, headers))
            
            # 5. Check cookie security
            findings.extend(self._check_cookies(target, headers))
            
            # 6. Check for legacy/deprecated headers
            findings.extend(self._check_deprecated_headers(target, headers))
        
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
            # Unexpected errors (parsing, etc.) - log but don't propagate
            logger.exception(f"Unexpected error checking headers: {e}")
            # Don't propagate generic exceptions
        
        return findings
    
    def _check_missing_headers(self, target: str, headers: dict) -> List[Dict[str, Any]]:
        """Check for missing security headers."""
        findings = []
        
        for header_name, header_info in self.HEADERS.items():
            if header_name not in headers:
                finding_id = f"HEPH-HDR-{list(self.HEADERS.keys()).index(header_name)+1:03d}"
                
                findings.append({
                    'id': finding_id,
                    'title': f'Missing security header: {header_info["name"]}',
                    'severity': header_info['severity'],
                    'confidence': 'high',
                    'description': (
                        f"{header_name} header is not set. "
                        f"{header_info['description']}."
                    ),
                    'evidence': {
                        'type': 'header',
                        'value': f'{header_name}: [not set]',
                        'context': f'HTTP response from {target}'
                    },
                    'recommendation': header_info['recommendation'],
                    'references': [
                        'https://owasp.org/www-project-secure-headers/',
                        'https://securityheaders.com/',
                    ]
                })
        
        return findings
    
    def _check_hsts(self, target: str, headers: dict) -> List[Dict[str, Any]]:
        """Check HSTS configuration details."""
        findings = []
        
        if 'Strict-Transport-Security' in headers:
            hsts_value = headers['Strict-Transport-Security']
            
            # Check max-age
            if 'max-age' not in hsts_value:
                findings.append({
                    'id': 'HEPH-HDR-101',
                    'title': 'HSTS missing max-age directive',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': 'HSTS header is present but missing max-age directive',
                    'evidence': {
                        'type': 'header',
                        'value': f'Strict-Transport-Security: {hsts_value}',
                        'context': f'HTTP response from {target}'
                    },
                    'recommendation': 'Add max-age directive: Strict-Transport-Security: max-age=31536000',
                })
            
            else:
                # Check if max-age is too short
                import re
                match = re.search(r'max-age=(\d+)', hsts_value)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        findings.append({
                            'id': 'HEPH-HDR-102',
                            'title': 'HSTS max-age too short',
                            'severity': 'low',
                            'confidence': 'high',
                            'description': f'HSTS max-age is {max_age} seconds (< 1 year). Recommended: 31536000 (1 year)',
                            'evidence': {
                                'type': 'header',
                                'value': f'Strict-Transport-Security: {hsts_value}',
                                'context': f'HTTP response from {target}'
                            },
                            'recommendation': 'Increase max-age to at least 31536000 (1 year)',
                        })
            
            # Check for includeSubDomains
            if 'includeSubDomains' not in hsts_value:
                findings.append({
                    'id': 'HEPH-HDR-103',
                    'title': 'HSTS missing includeSubDomains',
                    'severity': 'low',
                    'confidence': 'high',
                    'description': 'HSTS should include includeSubDomains directive to protect subdomains',
                    'evidence': {
                        'type': 'header',
                        'value': f'Strict-Transport-Security: {hsts_value}',
                        'context': f'HTTP response from {target}'
                    },
                    'recommendation': 'Add includeSubDomains: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                })
        
        return findings
    
    def _check_csp(self, target: str, headers: dict) -> List[Dict[str, Any]]:
        """Check CSP configuration details."""
        findings = []
        
        if 'Content-Security-Policy' in headers:
            csp_value = headers['Content-Security-Policy']
            
            # Check for unsafe directives
            if 'unsafe-inline' in csp_value:
                findings.append({
                    'id': 'HEPH-HDR-201',
                    'title': 'CSP allows unsafe-inline scripts',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': 'CSP contains unsafe-inline directive, which weakens XSS protection',
                    'evidence': {
                        'type': 'header',
                        'value': f'Content-Security-Policy: {csp_value[:200]}...',
                        'context': f'HTTP response from {target}'
                    },
                    'recommendation': 'Remove unsafe-inline and use nonces or hashes for inline scripts',
                    'references': [
                        'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                    ]
                })
            
            if 'unsafe-eval' in csp_value:
                findings.append({
                    'id': 'HEPH-HDR-202',
                    'title': 'CSP allows unsafe-eval',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': 'CSP contains unsafe-eval directive, which allows eval() usage',
                    'evidence': {
                        'type': 'header',
                        'value': f'Content-Security-Policy: {csp_value[:200]}...',
                        'context': f'HTTP response from {target}'
                    },
                    'recommendation': 'Remove unsafe-eval to prevent eval() exploitation',
                })
        
        return findings
    
    def _check_xfo(self, target: str, headers: dict) -> List[Dict[str, Any]]:
        """Check X-Frame-Options configuration."""
        findings = []
        
        if 'X-Frame-Options' in headers:
            xfo_value = headers['X-Frame-Options'].upper()
            
            # Check for weak configuration
            if xfo_value == 'ALLOW-FROM':
                findings.append({
                    'id': 'HEPH-HDR-301',
                    'title': 'X-Frame-Options uses deprecated ALLOW-FROM',
                    'severity': 'low',
                    'confidence': 'high',
                    'description': 'ALLOW-FROM directive is deprecated. Use CSP frame-ancestors instead',
                    'evidence': {
                        'type': 'header',
                        'value': f'X-Frame-Options: {headers["X-Frame-Options"]}',
                        'context': f'HTTP response from {target}'
                    },
                    'recommendation': 'Use Content-Security-Policy: frame-ancestors \'self\' instead',
                })
        
        return findings
    
    def _check_cookies(self, target: str, headers: dict) -> List[Dict[str, Any]]:
        """Check cookie security attributes."""
        findings = []
        
        if 'Set-Cookie' in headers:
            cookies = headers.get_all('Set-Cookie') if hasattr(headers, 'get_all') else [headers.get('Set-Cookie')]
            
            for cookie in cookies:
                if not cookie:
                    continue
                
                cookie_lower = cookie.lower()
                cookie_name = cookie.split('=')[0]
                
                # Check Secure flag (HTTPS sites only)
                parsed = urlparse(target)
                if parsed.scheme == 'https':
                    if 'secure' not in cookie_lower:
                        findings.append({
                            'id': 'HEPH-HDR-401',
                            'title': f'Cookie without Secure flag: {cookie_name}',
                            'severity': 'medium',
                            'confidence': 'high',
                            'description': (
                                f'Cookie "{cookie_name}" lacks Secure flag. '
                                f'Cookies without Secure flag can be transmitted over HTTP, '
                                f'allowing interception.'
                            ),
                            'evidence': {
                                'type': 'header',
                                'value': f'Set-Cookie: {cookie_name}=... [Secure missing]',
                                'context': f'HTTP response from {target}'
                            },
                            'recommendation': 'Add Secure flag to all cookies on HTTPS sites',
                        })
                
                # Check HttpOnly flag
                if 'httponly' not in cookie_lower:
                    findings.append({
                        'id': 'HEPH-HDR-402',
                        'title': f'Cookie without HttpOnly flag: {cookie_name}',
                        'severity': 'medium',
                        'confidence': 'high',
                        'description': (
                            f'Cookie "{cookie_name}" lacks HttpOnly flag. '
                            f'Cookies without HttpOnly can be accessed via JavaScript, '
                            f'enabling XSS-based cookie theft.'
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': f'Set-Cookie: {cookie_name}=... [HttpOnly missing]',
                            'context': f'HTTP response from {target}'
                        },
                        'recommendation': 'Add HttpOnly flag to prevent JavaScript access',
                    })
                
                # Check SameSite attribute
                if 'samesite' not in cookie_lower:
                    findings.append({
                        'id': 'HEPH-HDR-403',
                        'title': f'Cookie without SameSite attribute: {cookie_name}',
                        'severity': 'low',
                        'confidence': 'high',
                        'description': (
                            f'Cookie "{cookie_name}" lacks SameSite attribute. '
                            f'This makes the site vulnerable to CSRF attacks.'
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': f'Set-Cookie: {cookie_name}=... [SameSite missing]',
                            'context': f'HTTP response from {target}'
                        },
                        'recommendation': 'Add SameSite=Strict or SameSite=Lax attribute',
                    })
        
        return findings
    
    def _check_deprecated_headers(self, target: str, headers: dict) -> List[Dict[str, Any]]:
        """Check for deprecated/legacy headers."""
        findings = []
        
        # X-XSS-Protection is deprecated (modern browsers use CSP)
        if 'X-XSS-Protection' in headers:
            xss_value = headers['X-XSS-Protection']
            
            # It's actually better to have it set to 0 (disabled) now
            if xss_value != '0':
                findings.append({
                    'id': 'HEPH-HDR-007',
                    'title': 'X-XSS-Protection header is deprecated',
                    'severity': 'info',
                    'confidence': 'high',
                    'description': (
                        'X-XSS-Protection header is deprecated and can introduce vulnerabilities. '
                        'Modern browsers rely on Content-Security-Policy instead.'
                    ),
                    'evidence': {
                        'type': 'header',
                        'value': f'X-XSS-Protection: {xss_value}',
                        'context': f'HTTP response from {target}'
                    },
                    'recommendation': 'Remove X-XSS-Protection header and use CSP instead',
                    'references': [
                        'https://owasp.org/www-community/Security_Headers',
                    ]
                })
        
        return findings


if __name__ == "__main__":
    # Test the checker
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    config.expand_paths()
    
    http_client = create_http_client(mode='safe', config=config)
    checker = SecurityHeadersChecker(config, http_client)
    
    findings = checker.scan("https://example.com")
    
    print(f"Found {len(findings)} header issues:")
    for finding in findings:
        print(f"  [{finding['severity'].upper()}] {finding['title']}")