"""
Server Information Disclosure & Framework Detection Check

Detects server software versions and frameworks exposed via HTTP headers,
cookies, and error pages.

Checks:
- Server header (Apache, Nginx, IIS, Lighttpd, Tomcat versions)
- X-Powered-By header (PHP, ASP.NET, Express, etc.)
- Via header (proxy disclosure)
- Error page fingerprinting
- Framework detection: Laravel, Django, Rails, Node.js, ASP.NET MVC,
  Spring Boot, Flask (no extra requests in safe mode — reuses existing response)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

import requests

from ..core.logging import get_logger
from ..core.config import get_config
from ..core.cve_lookup import enrich_finding_with_cves

logger = get_logger(__name__)


class ServerInfoChecker:
    """
    Detects server version disclosure and framework fingerprinting.
    """

    # ─── Server header patterns ───────────────────────────────────────────────
    SERVER_PATTERNS = {
        'apache':    re.compile(r'Apache/([0-9.]+)', re.IGNORECASE),
        'nginx':     re.compile(r'nginx/([0-9.]+)', re.IGNORECASE),
        'iis':       re.compile(r'Microsoft-IIS/([0-9.]+)', re.IGNORECASE),
        'lighttpd':  re.compile(r'lighttpd/([0-9.]+)', re.IGNORECASE),
        'tomcat':    re.compile(r'Apache-Coyote/([0-9.]+)', re.IGNORECASE),
        'caddy':     re.compile(r'Caddy(?:/([0-9.]+))?', re.IGNORECASE),
    }

    # ─── Component patterns embedded within Server header ─────────────────────
    SERVER_COMPONENT_PATTERNS = [
        ('php',     'PHP',      'HEPH-SRV-016', re.compile(r'PHP/([0-9.]+)', re.IGNORECASE)),
        ('openssl', 'OpenSSL',  'HEPH-SRV-017', re.compile(r'OpenSSL/([0-9a-z.]+)', re.IGNORECASE)),
        ('tomcat',  'Tomcat',   'HEPH-SRV-018', re.compile(r'Tomcat/([0-9.]+)', re.IGNORECASE)),
        ('mod_ssl', 'mod_ssl',  'HEPH-SRV-019', re.compile(r'mod_ssl/([0-9.]+)', re.IGNORECASE)),
    ]

    PHP_PATTERN = re.compile(r'PHP/([0-9.]+)', re.IGNORECASE)

    # ─── Error page signatures ────────────────────────────────────────────────
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

    # ─── Framework cookie patterns ────────────────────────────────────────────
    FRAMEWORK_COOKIES = {
        'laravel_session': ('Laravel',  'HEPH-SRV-005'),
        'csrftoken':       ('Django',   'HEPH-SRV-006'),
        '_rails_session':  ('Rails',    'HEPH-SRV-007'),
        'JSESSIONID':      ('Java/Tomcat', 'HEPH-SRV-008'),
        'PHPSESSID':       ('PHP',      'HEPH-SRV-009'),
        '__RequestVerificationToken': ('ASP.NET', 'HEPH-SRV-010'),
    }

    # ─── X-Powered-By / response header framework patterns ───────────────────
    FRAMEWORK_HEADERS = [
        # (header_name, regex_or_value, framework_name, finding_id)
        ('X-Powered-By',        re.compile(r'PHP/([0-9.]+)', re.I),       'PHP',          'HEPH-SRV-002'),
        ('X-Powered-By',        re.compile(r'Express', re.I),             'Node.js/Express', 'HEPH-SRV-011'),
        ('X-Powered-By',        re.compile(r'ASP\.NET', re.I),            'ASP.NET',       'HEPH-SRV-012'),
        ('X-AspNetMvc-Version', re.compile(r'([0-9.]+)', re.I),           'ASP.NET MVC',   'HEPH-SRV-013'),
        ('X-AspNet-Version',    re.compile(r'([0-9.]+)', re.I),           'ASP.NET',       'HEPH-SRV-012'),
        ('X-Runtime',           re.compile(r'([0-9.]+)', re.I),           'Rails',         'HEPH-SRV-007'),
        ('X-Generator',         re.compile(r'(.+)', re.I),                'CMS/Generator', 'HEPH-SRV-014'),
        ('X-Drupal-Cache',      re.compile(r'(.+)', re.I),                'Drupal',        'HEPH-SRV-015'),
        ('X-Joomla-.*',         re.compile(r'(.+)', re.I),                'Joomla',        'HEPH-SRV-015'),
        ('Liferay-Portal',      re.compile(r'(.+)', re.I),                'Liferay',       'HEPH-SRV-014'),
        ('X-Spring-App',        re.compile(r'(.+)', re.I),                'Spring Boot',   'HEPH-SRV-014'),
    ]

    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.http_client = http_client

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan target for server version and framework disclosure.

        Args:
            target: Target URL (e.g., https://example.com)

        Returns:
            List of findings
        """
        findings = []

        logger.info(f"Checking server information disclosure: {target}")

        try:
            findings.extend(self._check_headers(target))
            findings.extend(self._check_error_pages(target))

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection failed to {target}: {e}")
            raise

        except requests.exceptions.Timeout as e:
            logger.error(f"Request timeout for {target}: {e}")
            raise

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {target}: {e}")
            raise

        except Exception as e:
            logger.exception(f"Unexpected error checking server info: {e}")

        return findings

    def _check_headers(self, target: str) -> List[Dict[str, Any]]:
        """
        Check HTTP headers for version disclosure and framework detection.
        Reuses the single main-page response for all header analysis —
        no extra HTTP requests in safe mode.
        """
        findings = []
        seen_frameworks = set()  # Avoid duplicate findings for same framework

        response = self.http_client.get(
            target,
            timeout=(self.config.timeout_connect, self.config.timeout_read),
            allow_redirects=False,
        )

        headers = response.headers

        # ── Server header ─────────────────────────────────────────────────────
        if 'Server' in headers and self.config.check_server_header:
            server_value = headers['Server']

            for server_type, pattern in self.SERVER_PATTERNS.items():
                match = pattern.search(server_value)
                if match:
                    version = match.group(1) if match.lastindex else 'unknown'
                    srv_finding = {
                        'id': 'HEPH-SRV-001',
                        'title': f'{server_type.capitalize()} server version disclosed ({version})',
                        'severity': 'high',
                        'confidence': 'high',
                        'description': (
                            f"Server header discloses {server_type.capitalize()} version {version}. "
                            "Version disclosure helps attackers identify and target known CVEs."
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': f"Server: {server_value}",
                            'context': f"HTTP response header from {target}",
                        },
                        'recommendation': (
                            f"Hide {server_type.capitalize()} version:\n"
                            "- Apache: ServerTokens Prod + ServerSignature Off in httpd.conf\n"
                            "- Nginx:  server_tokens off; in nginx.conf\n"
                            "- IIS:    Remove Server header via URL Rewrite"
                        ),
                        'references': [
                            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
                            'https://httpd.apache.org/docs/2.4/mod/core.html#servertokens',
                            'https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens',
                        ],
                        'affected_component': f"{server_type.capitalize()} {version}",
                        'cvss': 5.3,
                        'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    }
                    # Enrich with live CVE data from NVD
                    if version != 'unknown':
                        try:
                            enrich_finding_with_cves(srv_finding, server_type, version)
                        except Exception as e:
                            logger.debug(f"CVE enrichment failed for {server_type} {version}: {e}")
                    findings.append(srv_finding)

                    # Extract additional software components from Server header
                    # e.g. "Apache/2.4.54 (Debian) PHP/7.4.33 OpenSSL/1.1.1n"
                    for cve_key, display, comp_fid, comp_pattern in self.SERVER_COMPONENT_PATTERNS:
                        comp_match = comp_pattern.search(server_value)
                        if not comp_match:
                            continue
                        comp_version = comp_match.group(1)
                        comp_finding = {
                            'id': comp_fid,
                            'title': f'{display} {comp_version} disclosed in Server header',
                            'severity': 'high',
                            'confidence': 'high',
                            'description': (
                                f"Server header exposes {display} version {comp_version}. "
                                f"Version disclosure allows attackers to target known {display} CVEs precisely."
                            ),
                            'evidence': {
                                'type': 'header',
                                'value': f"Server: {server_value}",
                                'context': f"HTTP response header from {target}",
                            },
                            'recommendation': (
                                "Remove component version from Server header:\n"
                                "- Apache: ServerTokens Prod in httpd.conf suppresses all component versions\n"
                                "- PHP: expose_php = Off in php.ini removes PHP from Server header"
                            ),
                            'references': [
                                'https://httpd.apache.org/docs/2.4/mod/core.html#servertokens',
                            ],
                            'affected_component': f"{display} {comp_version}",
                            'cvss': 5.3,
                            'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                        }
                        try:
                            enrich_finding_with_cves(comp_finding, cve_key, comp_version)
                        except Exception as e:
                            logger.debug(f"CVE enrichment failed for {display} {comp_version}: {e}")
                        findings.append(comp_finding)
                        seen_frameworks.add(display)
                    break

        elif 'Server' not in headers:
            findings.append({
                'id': 'HEPH-SRV-999',
                'title': 'Server header hidden (good practice)',
                'severity': 'info',
                'confidence': 'high',
                'description': (
                    "Server header is absent from HTTP responses — "
                    "a security best practice that prevents server fingerprinting."
                ),
                'evidence': {
                    'type': 'header',
                    'value': 'Server: [not present]',
                    'context': f"HTTP response from {target}",
                },
                'recommendation': 'Maintain this configuration.',
            })

        # ── X-Powered-By (PHP version disclosure) ─────────────────────────────
        if 'X-Powered-By' in headers and self.config.check_x_powered_by:
            powered_value = headers['X-Powered-By']
            match = self.PHP_PATTERN.search(powered_value)
            if match:
                php_version = match.group(1)
                # Skip if PHP already detected via Server header component extraction
                if 'PHP' in seen_frameworks:
                    logger.debug(f"PHP {php_version} already detected via Server header, skipping X-Powered-By")
                else:
                    seen_frameworks.add('PHP')
                    php_finding = {
                        'id': 'HEPH-SRV-002',
                        'title': f'PHP version disclosed via X-Powered-By ({php_version})',
                        'severity': 'high',
                        'confidence': 'high',
                        'description': (
                            f"X-Powered-By header discloses PHP version {php_version}. "
                            "Attackers can target known PHP CVEs for this exact version."
                        ),
                        'evidence': {
                            'type': 'header',
                            'value': f"X-Powered-By: {powered_value}",
                            'context': f"HTTP response header from {target}",
                        },
                        'recommendation': (
                            "Disable PHP version disclosure:\n"
                            "1. Set 'expose_php = Off' in php.ini\n"
                            "2. Or: Header unset X-Powered-By  (Apache mod_headers)\n"
                            "3. Or: more_clear_headers 'X-Powered-By';  (Nginx headers_more)"
                        ),
                        'references': ['https://www.php.net/manual/en/ini.core.php#ini.expose-php'],
                        'affected_component': f"PHP {php_version}",
                        'cvss': 5.3,
                        'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    }
                    # Enrich with live CVE data from NVD
                    try:
                        enrich_finding_with_cves(php_finding, 'php', php_version)
                    except Exception as e:
                        logger.debug(f"CVE enrichment failed for PHP {php_version}: {e}")
                    findings.append(php_finding)

        # ── Via header (proxy disclosure) ──────────────────────────────────────
        if 'Via' in headers:
            via_value = headers['Via']
            findings.append({
                'id': 'HEPH-SRV-003',
                'title': 'Proxy/CDN infrastructure disclosed via Via header',
                'severity': 'low',
                'confidence': 'high',
                'description': (
                    f"Via header discloses proxy or CDN chain: {via_value}. "
                    "Infrastructure topology information helps attackers plan targeted attacks."
                ),
                'evidence': {
                    'type': 'header',
                    'value': f"Via: {via_value}",
                    'context': f"HTTP response header from {target}",
                },
                'recommendation': (
                    "Remove Via header where not required:\n"
                    "- Apache: Header unset Via\n"
                    "- Nginx: proxy_hide_header Via;"
                ),
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via'],
            })

        # ── Framework detection from headers ──────────────────────────────────
        for header_name, pattern, framework, finding_id in self.FRAMEWORK_HEADERS:
            header_match_key = header_name.rstrip('.*')
            header_value = None
            # Support partial header name matching (e.g., X-Joomla-.*)
            if '.*' in header_name:
                for h in headers:
                    if re.match(header_name, h, re.I):
                        header_value = headers[h]
                        break
            else:
                header_value = headers.get(header_name)

            if not header_value:
                continue

            match = pattern.search(header_value)
            if not match:
                continue

            # Skip PHP — already handled as HEPH-SRV-002
            if framework == 'PHP' and 'PHP' in seen_frameworks:
                continue

            # Skip if we already have a finding for this framework
            if framework in seen_frameworks:
                continue
            seen_frameworks.add(framework)

            version_str = match.group(1) if match.lastindex else header_value.strip()
            self._add_framework_finding(
                findings, finding_id, framework, header_name, header_value,
                version_str, target, 'header',
            )

        # ── Framework detection from Set-Cookie ───────────────────────────────
        set_cookie_headers = []
        # requests combines multiple Set-Cookie into a comma-sep string or stores separately
        if 'Set-Cookie' in response.headers:
            set_cookie_headers.append(response.headers['Set-Cookie'])
        # Access raw response cookies for multi-header scenarios
        for cookie_name, cookie_value in response.cookies.items():
            cookie_lc = cookie_name.lower()
            for pattern_key, (framework, finding_id) in self.FRAMEWORK_COOKIES.items():
                if cookie_lc == pattern_key.lower():
                    if framework in seen_frameworks:
                        break
                    if framework == 'PHP' and 'PHP' in seen_frameworks:
                        break
                    seen_frameworks.add(framework)
                    self._add_framework_finding(
                        findings, finding_id, framework,
                        'Set-Cookie', f"{cookie_name}={cookie_value[:30]}…",
                        None, target, 'header',
                    )
                    break

        # Also scan raw cookie header text for patterns
        for raw_cookie in set_cookie_headers:
            for pattern_key, (framework, finding_id) in self.FRAMEWORK_COOKIES.items():
                if pattern_key.lower() in raw_cookie.lower():
                    if framework in seen_frameworks:
                        continue
                    seen_frameworks.add(framework)
                    self._add_framework_finding(
                        findings, finding_id, framework,
                        'Set-Cookie', raw_cookie[:80],
                        None, target, 'header',
                    )

        # ── Laravel via X-Powered-By: PHP + laravel_session cookie check ──────
        # Check for Laravel error page signature in response body
        if response.status_code in (500, 419, 200):
            body_snippet = response.text[:3000] if response.text else ''
            if ('Laravel' in seen_frameworks or
                    re.search(r'(laravel|Illuminate\\)', body_snippet, re.I)):
                if 'Laravel' not in seen_frameworks:
                    seen_frameworks.add('Laravel')
                    self._add_framework_finding(
                        findings, 'HEPH-SRV-005', 'Laravel',
                        'Response body', 'Laravel signature in HTML',
                        None, target, 'body',
                    )

        # ── Django via debug page / CSRF token ────────────────────────────────
        if 'Django' not in seen_frameworks:
            body_snippet = response.text[:3000] if response.text else ''
            if re.search(r'(Django|<title>.*Django.*</title>|csrfmiddlewaretoken)', body_snippet):
                seen_frameworks.add('Django')
                self._add_framework_finding(
                    findings, 'HEPH-SRV-006', 'Django',
                    'Response body', 'Django signature detected',
                    None, target, 'body',
                )

        return findings

    def _add_framework_finding(
        self,
        findings: list,
        finding_id: str,
        framework: str,
        source: str,
        evidence_value: str,
        version: Optional[str],
        target: str,
        evidence_type: str,
    ) -> None:
        """Append a framework detection finding."""
        version_str = f" {version}" if version and version != evidence_value else ""
        findings.append({
            'id': finding_id,
            'title': f'Framework detected: {framework}{version_str}',
            'severity': 'info',
            'confidence': 'medium',
            'description': (
                f"{framework} framework fingerprinted via {source}. "
                "Framework disclosure helps attackers identify version-specific "
                "vulnerabilities or conduct targeted exploitation."
            ),
            'evidence': {
                'type': evidence_type,
                'value': evidence_value,
                'context': f"Detected from {source} in response from {target}",
            },
            'recommendation': (
                f"Remove or obfuscate {framework} framework indicators:\n"
                "- Remove or suppress framework-specific headers\n"
                "- Rename/rename session cookie names to generic values\n"
                "- Implement custom error pages that do not reveal the framework"
            ),
            'references': [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application',
            ],
            'affected_component': f"{framework}{version_str}",
        })

    def _check_error_pages(self, target: str) -> List[Dict[str, Any]]:
        """
        Check 404 error pages for server fingerprinting.
        Error page check is optional — does not fail scan on connection error.
        """
        findings = []

        parsed = urlparse(target)
        error_url = f"{parsed.scheme}://{parsed.netloc}/this-page-does-not-exist-hephaestus-test"

        try:
            response = self.http_client.get(
                error_url,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=False,
            )

            if response.status_code == 404:
                body = response.text[:2000]

                for server_type, patterns in self.ERROR_SIGNATURES.items():
                    for pattern in patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.lastindex else 'unknown'
                            findings.append({
                                'id': 'HEPH-SRV-004',
                                'title': f'{server_type.capitalize()} version disclosed in error page',
                                'severity': 'medium',
                                'confidence': 'medium',
                                'description': (
                                    f"404 error page discloses {server_type.capitalize()} server information. "
                                    "Custom error pages should not reveal server details."
                                ),
                                'evidence': {
                                    'type': 'body',
                                    'value': match.group(0),
                                    'context': f"404 error page at {error_url}",
                                },
                                'recommendation': (
                                    "Configure custom error pages without server information:\n"
                                    "- Apache: ErrorDocument 404 /custom-404.html\n"
                                    "- Nginx: error_page 404 /custom-404.html;"
                                ),
                                'references': [
                                    'https://httpd.apache.org/docs/2.4/custom-error.html',
                                    'https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page',
                                ],
                                'cvss': 3.7,
                            })
                            break  # One finding per server type

        except requests.exceptions.RequestException as e:
            logger.debug(f"Could not check error page for {target}: {e}")

        return findings


if __name__ == "__main__":
    from ..core.config import Config
    from ..core.http_client import create_http_client

    config = Config.load()
    config.expand_paths()

    http_client = create_http_client(mode='safe', config=config)
    checker = ServerInfoChecker(config, http_client)

    findings = checker.scan("https://example.com")
    print(f"Found {len(findings)} issues:")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['title']}")
