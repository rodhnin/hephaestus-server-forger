"""
Global Cookie Security Checker

Collects cookies from multiple endpoints and flags missing security attributes.
Complements headers.py (which checks only the main page).

Safe mode:   checks main + /login /signin /account /dashboard /api/
Aggressive:  also checks /register /signup /admin /api/auth /api/login /user/profile

Finding codes:
  HEPH-COO-001  Session cookie without Secure flag
  HEPH-COO-002  Session cookie without HttpOnly flag
  HEPH-COO-003  Cookie without SameSite attribute
  HEPH-COO-004  SameSite=None without Secure flag (critical)
  HEPH-COO-005  Insecure session cookie (all 3 flags missing)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urljoin, urlparse

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)

# Session cookie name patterns (case-insensitive)
SESSION_COOKIE_PATTERNS = re.compile(
    r'^(phpsessid|jsessionid|asp\.net_sessionid|asp\.net_session|'
    r'aspsessionid\w*|laravel_session|ci_session|rack\.session|'
    r'connect\.sid|_session|session_id|sessid|sid|user_session|'
    r'auth_token|access_token|remember_token|_token|csrftoken|'
    r'cgisessid|django_csrftoken|symfony_session|yii_session)$',
    re.I
)

# Paths to check in safe mode
SAFE_PATHS = [
    '/login',
    '/signin',
    '/account',
    '/dashboard',
    '/api/',
    '/api/v1/',
    '/user',
]

# Additional paths for aggressive mode
AGGRESSIVE_EXTRA_PATHS = [
    '/register',
    '/signup',
    '/admin',
    '/api/auth',
    '/api/login',
    '/api/v1/auth',
    '/user/profile',
    '/profile',
    '/me',
    '/auth',
    '/auth/login',
]


class CookieSecurityChecker:
    """
    Multi-endpoint cookie security analyzer.

    Collects Set-Cookie headers from authentication and API endpoints
    where session cookies typically appear, flagging missing security attributes.

    Note: The main page cookies are already checked by SecurityHeadersChecker
    (HEPH-HDR-401/402/403). This checker extends coverage to auth endpoints.
    """

    def __init__(self, config=None, http_client=None, mode: str = 'safe'):
        self.config = config or get_config()
        self.http_client = http_client
        self.mode = mode

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan multiple endpoints for cookie security issues.
        """
        findings = []
        base = target.rstrip('/')

        paths = list(SAFE_PATHS)
        if self.mode == 'aggressive':
            paths.extend(AGGRESSIVE_EXTRA_PATHS)

        # Track cookies already seen by name to avoid duplicate findings
        seen_cookies: Dict[str, str] = {}  # cookie_name → endpoint

        for path in paths:
            url = base + path
            try:
                resp = self.http_client.get(
                    url,
                    timeout=(self.config.timeout_connect, self.config.timeout_read),
                    allow_redirects=True
                )
                # Only process if the server responded meaningfully
                if resp.status_code in (200, 301, 302, 401, 403):
                    new_findings = self._analyze_cookies(resp, url, seen_cookies)
                    findings.extend(new_findings)
            except requests.exceptions.RequestException:
                # Endpoint doesn't exist or refused — skip silently
                pass
            except Exception as e:
                logger.debug(f"Cookie check failed for {url}: {e}")

        return findings

    def _analyze_cookies(
        self,
        response: requests.Response,
        url: str,
        seen_cookies: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Analyze Set-Cookie headers from a response."""
        findings = []
        raw_cookies = self._get_all_cookies(response)

        for raw_cookie in raw_cookies:
            if not raw_cookie:
                continue

            name, flags = self._parse_cookie(raw_cookie)
            if not name:
                continue

            # Skip if we already reported this cookie name from another endpoint
            if name.lower() in seen_cookies:
                continue
            seen_cookies[name.lower()] = url

            is_session = bool(SESSION_COOKIE_PATTERNS.match(name))
            is_https = urlparse(url).scheme == 'https'

            secure = flags.get('secure', False)
            httponly = flags.get('httponly', False)
            samesite = flags.get('samesite', '')

            # --- HEPH-COO-004: SameSite=None without Secure (critical) ---
            if samesite.lower() == 'none' and not secure:
                findings.append({
                    'id': 'HEPH-COO-004',
                    'title': f'Cookie with SameSite=None but missing Secure flag: {name}',
                    'severity': 'high',
                    'confidence': 'high',
                    'description': (
                        f'Cookie "{name}" is configured with SameSite=None but lacks the Secure flag. '
                        f'SameSite=None requires the Secure flag per RFC 6265bis — browsers will '
                        f'reject this cookie in modern versions. Additionally, the cookie can be '
                        f'sent over unencrypted HTTP, enabling interception.'
                    ),
                    'evidence': {
                        'type': 'header',
                        'value': url,
                        'context': f'Set-Cookie: {name}=...; SameSite=None (Secure flag missing)'
                    },
                    'recommendation': 'Add the Secure flag: Set-Cookie: name=value; SameSite=None; Secure',
                    'references': [
                        'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite',
                        'https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis',
                    ],
                })

            # --- HEPH-COO-005: Session cookie missing all 3 flags (combined) ---
            elif is_session and not secure and not httponly and not samesite:
                findings.append({
                    'id': 'HEPH-COO-005',
                    'title': f'Session cookie with no security flags: {name}',
                    'severity': 'high',
                    'confidence': 'high',
                    'description': (
                        f'Session cookie "{name}" is missing all security attributes: '
                        f'Secure, HttpOnly, and SameSite. This is a session identified by name '
                        f'pattern and likely used for authentication. Without these flags, it is '
                        f'vulnerable to: XSS theft (no HttpOnly), CSRF (no SameSite), '
                        f'and plaintext transmission (no Secure).'
                    ),
                    'evidence': {
                        'type': 'header',
                        'value': url,
                        'context': f'Set-Cookie: {name}=...; (no Secure, no HttpOnly, no SameSite)'
                    },
                    'recommendation': (
                        f'Add all three security flags to {name}:\n'
                        f'Set-Cookie: {name}=value; Secure; HttpOnly; SameSite=Strict\n\n'
                        f'Apache:\nHeader edit Set-Cookie ^(.*)$ $1;Secure;HttpOnly;SameSite=Strict\n\n'
                        f'Nginx:\nproxy_cookie_flags ~ secure httponly samesite=strict;'
                    ),
                    'references': [
                        'https://owasp.org/www-community/controls/SecureFlag',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
                    ],
                })

            else:
                # Individual flag checks for non-session cookies or partial issues
                if is_https and not secure and is_session:
                    findings.append({
                        'id': 'HEPH-COO-001',
                        'title': f'Session cookie missing Secure flag: {name}',
                        'severity': 'medium',
                        'confidence': 'high',
                        'description': (
                            f'Session cookie "{name}" lacks the Secure flag. '
                            f'Without it, the cookie may be sent over unencrypted HTTP, '
                            f'enabling interception on mixed-content pages or downgrade attacks.'
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': url,
                            'context': f'Set-Cookie: {name}=...; [Secure missing]'
                        },
                        'recommendation': f'Add the Secure flag to {name}: Set-Cookie: {name}=value; Secure',
                        'references': ['https://owasp.org/www-community/controls/SecureFlag'],
                    })

                if not httponly and is_session:
                    findings.append({
                        'id': 'HEPH-COO-002',
                        'title': f'Session cookie missing HttpOnly flag: {name}',
                        'severity': 'medium',
                        'confidence': 'high',
                        'description': (
                            f'Session cookie "{name}" lacks the HttpOnly flag. '
                            f'Without HttpOnly, JavaScript can read the cookie value, '
                            f'enabling XSS-based session hijacking.'
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': url,
                            'context': f'Set-Cookie: {name}=...; [HttpOnly missing]'
                        },
                        'recommendation': f'Add HttpOnly flag: Set-Cookie: {name}=value; HttpOnly',
                        'references': ['https://owasp.org/www-community/HttpOnly'],
                    })

                if not samesite:
                    findings.append({
                        'id': 'HEPH-COO-003',
                        'title': f'Cookie missing SameSite attribute: {name}',
                        'severity': 'low',
                        'confidence': 'medium',
                        'description': (
                            f'Cookie "{name}" has no SameSite attribute. '
                            f'Without SameSite, browsers send this cookie on cross-site requests, '
                            f'making the application vulnerable to CSRF attacks.'
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': url,
                            'context': f'Set-Cookie: {name}=...; [SameSite missing]'
                        },
                        'recommendation': 'Add SameSite=Strict (or Lax): Set-Cookie: name=value; SameSite=Strict',
                        'references': [
                            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite',
                        ],
                    })

        return findings

    def _get_all_cookies(self, response: requests.Response) -> List[str]:
        """Extract all Set-Cookie headers from a response."""
        raw = response.raw
        if hasattr(raw, 'headers') and hasattr(raw.headers, 'getlist'):
            cookies = raw.headers.getlist('Set-Cookie')
            if cookies:
                return cookies
        # Fallback: single Set-Cookie header
        cookie = response.headers.get('Set-Cookie', '')
        if cookie:
            return [cookie]
        # Also check response.cookies
        result = []
        for c in response.cookies:
            parts = [f'{c.name}={c.value}']
            if c.secure:
                parts.append('Secure')
            if c.has_nonstandard_attr('httponly'):
                parts.append('HttpOnly')
            if c.get_nonstandard_attr('samesite'):
                parts.append(f'SameSite={c.get_nonstandard_attr("samesite")}')
            result.append('; '.join(parts))
        return result

    def _parse_cookie(self, raw: str) -> Tuple[Optional[str], Dict]:
        """Parse a raw Set-Cookie string into (name, {flag: value}) dict."""
        parts = [p.strip() for p in raw.split(';')]
        if not parts:
            return None, {}

        # First part is name=value
        name_val = parts[0]
        if '=' in name_val:
            name = name_val.split('=', 1)[0].strip()
        else:
            name = name_val.strip()

        if not name:
            return None, {}

        flags = {}
        for part in parts[1:]:
            lower = part.lower()
            if lower == 'secure':
                flags['secure'] = True
            elif lower == 'httponly':
                flags['httponly'] = True
            elif lower.startswith('samesite='):
                flags['samesite'] = part.split('=', 1)[1].strip()
            elif lower.startswith('path='):
                flags['path'] = part.split('=', 1)[1].strip()
            elif lower.startswith('domain='):
                flags['domain'] = part.split('=', 1)[1].strip()

        return name, flags
