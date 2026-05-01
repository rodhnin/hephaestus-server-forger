"""
CORS Misconfiguration Detection

Safe mode:
  - Inspects ACAO headers from all responses already made during scan
  - Checks for Access-Control-Allow-Origin: * with/without ACAC: true

Aggressive mode (additional):
  - Sends probing requests with Origin: https://evil-attacker.com
  - Detects CORS reflection (server mirrors the Origin back)
  - Tests main URL + /api/ + /api/v1/ + discovered API endpoints

Finding codes:
  HEPH-COR-001  ACAO=* + ACAC=true  (critical)
  HEPH-COR-002  ACAO=* alone         (medium)
  HEPH-COR-003  CORS reflection + ACAC=true  (critical)
  HEPH-COR-004  CORS reflection alone         (high)
  HEPH-COR-005  ACAO=null + ACAC=true  (critical — null-origin exploitation via sandboxed iframe)
  HEPH-COR-006  ACAO=null alone         (medium)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)

# Probe origin used to detect CORS reflection
CORS_PROBE_ORIGIN = 'https://evil-attacker-cors-test.com'

# Endpoints to probe in aggressive mode
AGGRESSIVE_PROBE_PATHS = [
    '/',
    '/api/',
    '/api/v1/',
    '/api/v2/',
    '/graphql',
    '/rest/',
    '/v1/',
]


class CORSChecker:
    """
    CORS misconfiguration detector.

    Detects overly permissive CORS policies that could allow cross-origin
    credential theft or data exfiltration.
    """

    def __init__(self, config=None, http_client=None, mode: str = 'safe'):
        self.config = config or get_config()
        self.http_client = http_client
        self.mode = mode
        # Deduplication: don't report same URL+finding twice
        self._reported: set = set()

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan target for CORS misconfigurations.

        Safe mode: check main page + /api/ static paths
        Aggressive mode: also send reflection probes to multiple endpoints
        """
        findings = []
        base = target.rstrip('/')

        # --- Safe mode: check headers on main page + common API paths ---
        safe_paths = ['/', '/api/', '/api/v1/', '/graphql']
        for path in safe_paths:
            url = base + path if path != '/' else base
            try:
                resp = self.http_client.get(
                    url,
                    timeout=(self.config.timeout_connect, self.config.timeout_read),
                    allow_redirects=True
                )
                findings.extend(self._check_static_cors(resp, url))
            except requests.exceptions.RequestException:
                pass
            except Exception as e:
                logger.debug(f"CORS safe check failed for {url}: {e}")

        # --- Null-origin probe on main URL (always, not aggressive-only) ---
        try:
            null_resp = self.http_client.get(
                base,
                headers={'Origin': 'null'},
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=True
            )
            null_acao = null_resp.headers.get('Access-Control-Allow-Origin', '')
            if null_acao.lower() == 'null':
                findings.extend(self._check_static_cors(null_resp, base))
        except Exception as e:
            logger.debug(f"CORS null-origin probe failed for {base}: {e}")

        # --- Aggressive mode: CORS reflection probe ---
        if self.mode == 'aggressive':
            probe_paths = AGGRESSIVE_PROBE_PATHS
            for path in probe_paths:
                url = base + path if path != '/' else base
                try:
                    findings.extend(self._probe_cors_reflection(url))
                except requests.exceptions.RequestException:
                    pass
                except Exception as e:
                    logger.debug(f"CORS reflection probe failed for {url}: {e}")

        # Deduplicate by finding id+url
        seen = set()
        unique = []
        for f in findings:
            key = (f['id'], f['evidence']['value'])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _check_static_cors(self, response: requests.Response, url: str) -> List[Dict[str, Any]]:
        """Check ACAO header value in an existing response."""
        findings = []
        headers = response.headers
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '').lower()

        if not acao:
            return findings

        if acao == '*' and acac == 'true':
            # Critical: wildcard + credentials
            findings.append(self._make_finding(
                'HEPH-COR-001', 'critical',
                'CORS wildcard origin with credentials enabled',
                (
                    'Access-Control-Allow-Origin: * combined with '
                    'Access-Control-Allow-Credentials: true. '
                    'Per the CORS spec, browsers reject this combination — but some '
                    'frameworks and HTTP clients ignore this restriction, allowing '
                    'cross-origin requests to steal authenticated session data.'
                ),
                url,
                f'Access-Control-Allow-Origin: {acao}\n'
                f'Access-Control-Allow-Credentials: {headers.get("Access-Control-Allow-Credentials")}',
                'Remove the wildcard origin. Use an explicit allowlist:\n'
                'Access-Control-Allow-Origin: https://trusted-domain.com\n'
                'Never combine ACAO: * with ACAC: true.',
                ['https://portswigger.net/web-security/cors',
                 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#credentialed_requests_and_wildcards'],
                'A01',
            ))
        elif acao == '*':
            # Medium: wildcard without credentials
            findings.append(self._make_finding(
                'HEPH-COR-002', 'medium',
                'CORS wildcard origin (Access-Control-Allow-Origin: *)',
                (
                    'Access-Control-Allow-Origin is set to * (wildcard), allowing any '
                    'origin to read responses from this server. This exposes non-sensitive '
                    'endpoints to cross-origin reads, and can be critical if combined with '
                    'sensitive data or if credentials are added later.'
                ),
                url,
                f'Access-Control-Allow-Origin: {acao}',
                'Replace the wildcard with an explicit allowlist of trusted origins:\n'
                'Access-Control-Allow-Origin: https://trusted-domain.com\n'
                'Implement origin validation on the server side.',
                ['https://portswigger.net/web-security/cors'],
                'A01',
            ))
        elif acao.lower() == 'null' and acac == 'true':
            # Critical: null origin + credentials — exploitable via sandboxed iframe or file:// page
            findings.append(self._make_finding(
                'HEPH-COR-005', 'critical',
                'CORS null-origin with credentials enabled — exploitable via sandboxed iframe',
                (
                    'Access-Control-Allow-Origin: null combined with '
                    'Access-Control-Allow-Credentials: true. '
                    'The "null" origin is sent by browsers from sandboxed iframes (<iframe sandbox>), '
                    'file:// pages, and data: URIs. An attacker can host a page that embeds a sandboxed '
                    'iframe to make credentialed cross-origin requests to this server, '
                    'potentially stealing authenticated session data.'
                ),
                url,
                f'Access-Control-Allow-Origin: {acao}\n'
                f'Access-Control-Allow-Credentials: {headers.get("Access-Control-Allow-Credentials")}',
                'Never reflect "null" as an allowed origin. Use an explicit allowlist:\n'
                'Access-Control-Allow-Origin: https://trusted-domain.com\n'
                'The "null" origin is semantically meaningless as a trust boundary.',
                ['https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-with-credentials',
                 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
                'A01',
            ))
        elif acao.lower() == 'null':
            # Medium: null origin without credentials
            findings.append(self._make_finding(
                'HEPH-COR-006', 'medium',
                'CORS null-origin allowed (Access-Control-Allow-Origin: null)',
                (
                    'Access-Control-Allow-Origin is set to "null", which is sent by browsers '
                    'from sandboxed iframes, file:// pages, and data: URIs. Any page can '
                    'embed a sandboxed iframe to send requests with a null origin and read '
                    'cross-origin responses from this server.'
                ),
                url,
                f'Access-Control-Allow-Origin: {acao}',
                'Remove "null" from allowed CORS origins. Use an explicit allowlist of trusted domains.\n'
                'The null origin should never be trusted as it can be generated by any page.',
                ['https://portswigger.net/web-security/cors',
                 'https://www.w3.org/TR/cors/#null-origin'],
                'A01',
            ))

        return findings

    def _probe_cors_reflection(self, url: str) -> List[Dict[str, Any]]:
        """
        Send a request with a controlled Origin header and check if reflected.
        CORS reflection means the server mirrors back whatever Origin was sent —
        effectively allowing any origin to make cross-origin requests.
        """
        findings = []

        try:
            resp = self.http_client.get(
                url,
                headers={'Origin': CORS_PROBE_ORIGIN},
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=True
            )
        except requests.exceptions.RequestException:
            return findings

        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()
        vary = resp.headers.get('Vary', '')

        # Reflected: server mirrors our evil origin back
        if acao == CORS_PROBE_ORIGIN or (acao and acao != '*' and 'evil' in acao.lower()):
            if acac == 'true':
                findings.append(self._make_finding(
                    'HEPH-COR-003', 'critical',
                    'CORS origin reflection with credentials — cross-origin session theft possible',
                    (
                        f'Server reflects arbitrary Origin headers back in ACAO, '
                        f'combined with Access-Control-Allow-Credentials: true. '
                        f'An attacker can host a malicious page at any domain, '
                        f'make cross-origin requests to this server, and steal '
                        f'authenticated session data (cookies, auth tokens).'
                    ),
                    url,
                    f'Request Origin: {CORS_PROBE_ORIGIN}\n'
                    f'Response ACAO: {acao}\n'
                    f'Response ACAC: {resp.headers.get("Access-Control-Allow-Credentials")}',
                    'Implement a strict origin allowlist. Never reflect arbitrary Origins:\n\n'
                    'Python (Flask):\n'
                    'ALLOWED_ORIGINS = ["https://trusted.com"]\n'
                    'if request.headers.get("Origin") in ALLOWED_ORIGINS:\n'
                    '    response.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]\n\n'
                    'Also validate the Origin on every request, not just preflight.',
                    ['https://portswigger.net/web-security/cors/lab-reflect-arbitrary-origins',
                     'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing'],
                    'A01',
                ))
            else:
                findings.append(self._make_finding(
                    'HEPH-COR-004', 'high',
                    'CORS origin reflection — server mirrors arbitrary Origin headers',
                    (
                        f'Server reflects the requesting Origin back in Access-Control-Allow-Origin '
                        f'without validating it. Any website can read cross-origin responses from '
                        f'this server. If authenticated endpoints exist, adding credentials to '
                        f'requests would immediately escalate to critical.'
                    ),
                    url,
                    f'Request Origin: {CORS_PROBE_ORIGIN}\n'
                    f'Response ACAO: {acao}',
                    'Replace dynamic origin reflection with a strict allowlist. '
                    'Validate the Origin header against known trusted domains before reflecting it.',
                    ['https://portswigger.net/web-security/cors'],
                    'A01',
                ))

        return findings

    def _make_finding(
        self,
        finding_id: str,
        severity: str,
        title: str,
        description: str,
        url: str,
        evidence_context: str,
        recommendation: str,
        references: List[str],
        owasp_id: str,
    ) -> Dict[str, Any]:
        owasp_names = {
            'A01': 'Broken Access Control',
            'A02': 'Cryptographic Failures',
            'A05': 'Security Misconfiguration',
        }
        return {
            'id': finding_id,
            'title': title,
            'severity': severity,
            'confidence': 'high',
            'description': description,
            'evidence': {
                'type': 'header',
                'value': url,
                'context': evidence_context,
            },
            'recommendation': recommendation,
            'references': references,
            'owasp': {'id': owasp_id, 'name': owasp_names.get(owasp_id, '')},
        }
