"""
phpinfo() Deep Parsing & PHP.ini Runtime Analysis

Parses accessible phpinfo() pages to extract:
- PHP module versions with CVE enrichment
- Dangerous PHP runtime settings (display_errors, allow_url_fopen, etc.)

Safe mode:  checks /phpinfo.php, /info.php, /test.php, /phpi.php
Aggressive: also tries /phpinformation.php, /php_info.php, /_info.php, /phpinfo.php5

Finding codes: HEPH-PHP-001 to HEPH-PHP-009

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)

# --- Paths to check ---
PHPINFO_PATHS_SAFE = [
    '/phpinfo.php',
    '/info.php',
    '/test.php',
    '/phpi.php',
]

PHPINFO_PATHS_AGGRESSIVE = PHPINFO_PATHS_SAFE + [
    '/phpinformation.php',
    '/php_info.php',
    '/_info.php',
    '/phpinfo.php5',
    '/php.php',
    '/server-info.php',
]

# --- Dangerous php.ini settings to detect ---
# (setting_name, dangerous_value_pattern, finding_code, severity, title, description, recommendation)
DANGEROUS_SETTINGS = [
    (
        'expose_php', re.compile(r'^on$', re.I),
        'HEPH-PHP-001', 'low',
        'PHP version exposed via X-Powered-By',
        'expose_php=On causes PHP to add the X-Powered-By header, revealing the PHP version to attackers.',
        'Set expose_php = Off in php.ini'
    ),
    (
        'display_errors', re.compile(r'^on$', re.I),
        'HEPH-PHP-002', 'medium',
        'PHP error messages exposed to users (display_errors=On)',
        'display_errors=On shows full PHP errors, stack traces, and file paths to end users, '
        'revealing application internals and sensitive file paths.',
        'Set display_errors = Off in php.ini. Log errors to file instead with log_errors = On'
    ),
    (
        'allow_url_fopen', re.compile(r'^on$', re.I),
        'HEPH-PHP-003', 'medium',
        'PHP allows remote URL file access (allow_url_fopen=On)',
        'allow_url_fopen=On allows PHP file functions (file_get_contents, include) to access remote URLs, '
        'enabling Server-Side Request Forgery (SSRF) and Remote File Inclusion if input is not sanitized.',
        'Set allow_url_fopen = Off unless specifically required. Use curl for intentional HTTP requests.'
    ),
    (
        'allow_url_include', re.compile(r'^on$', re.I),
        'HEPH-PHP-004', 'high',
        'PHP Remote File Inclusion enabled (allow_url_include=On)',
        'allow_url_include=On allows include/require to load remote URLs, enabling Remote File Inclusion (RFI) '
        'attacks. An attacker who controls a variable passed to include() can execute arbitrary code.',
        'Set allow_url_include = Off in php.ini. This is critical — no legitimate production use case requires it.'
    ),
    (
        'disable_functions', re.compile(r'^$'),
        'HEPH-PHP-005', 'medium',
        'No PHP dangerous functions disabled (disable_functions is empty)',
        'disable_functions is empty, meaning dangerous PHP functions like exec(), system(), passthru(), '
        'shell_exec(), popen(), proc_open() are all available. If an attacker achieves code execution, '
        'these functions enable full OS command execution.',
        'Disable dangerous functions in php.ini:\n'
        'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pclose'
    ),
    (
        'open_basedir', re.compile(r'^(no value|)$', re.I),
        'HEPH-PHP-006', 'medium',
        'PHP open_basedir not configured (unrestricted filesystem access)',
        'open_basedir is not set, allowing PHP scripts to access any file on the filesystem. '
        'Combined with a file traversal or inclusion vulnerability, this enables reading /etc/passwd, '
        'config files, and other sensitive system files.',
        'Set open_basedir in php.ini to restrict PHP file access:\n'
        'open_basedir = /var/www/html:/tmp'
    ),
    (
        'session.cookie_secure', re.compile(r'^(0|off|no value|)$', re.I),
        'HEPH-PHP-007', 'medium',
        'PHP session cookies sent over HTTP (session.cookie_secure=Off)',
        'session.cookie_secure is Off (or unset, which defaults to Off). '
        'This allows PHP session cookies to be transmitted over unencrypted HTTP, '
        'enabling session hijacking on mixed-content pages or HTTP connections.',
        'Set session.cookie_secure = On in php.ini (requires HTTPS)'
    ),
    (
        'session.cookie_httponly', re.compile(r'^(0|off|no value|)$', re.I),
        'HEPH-PHP-008', 'medium',
        'PHP session cookies accessible via JavaScript (session.cookie_httponly=Off)',
        'session.cookie_httponly is Off (or unset, which defaults to Off). '
        'This allows JavaScript to read the PHP session cookie, '
        'enabling session theft via XSS attacks.',
        'Set session.cookie_httponly = On in php.ini'
    ),
    (
        'session.cookie_samesite', re.compile(r'^(no value|)$', re.I),
        'HEPH-PHP-009', 'low',
        'PHP session cookies missing SameSite attribute',
        'session.cookie_samesite is not configured, making PHP sessions vulnerable to CSRF attacks.',
        'Set session.cookie_samesite = Strict (or Lax) in php.ini'
    ),
]

# --- PHP modules to extract versions from ---
MODULE_VERSION_PATTERNS = {
    'curl': [
        re.compile(r'cURL Information.*?(\d+\.\d+[\.\d]*)', re.I | re.S),
        re.compile(r'libcurl/(\d+\.\d+[\.\d]*)'),
    ],
    'openssl': [
        re.compile(r'OpenSSL Library Version.*?OpenSSL\s+(\d+\.\d+[\.\d\w]*)'),
        re.compile(r'OpenSSL\s+(\d+\.\d+[\.\d\w]*)', re.I),
    ],
    'libxml': [
        re.compile(r'libXML Version.*?(\d+\.\d+[\.\d]*)'),
        re.compile(r'libxml2 Version.*?(\d+\.\d+[\.\d]*)'),
    ],
    'GD': [
        re.compile(r'GD Version.*?(\d+\.\d+[\.\d]*)'),
        re.compile(r'bundled \((\d+\.\d+[\.\d]*) compatible\)'),
    ],
    'mbstring': [
        re.compile(r'Multibyte Support.*?(enabled|bundled|active)', re.I),
    ],
    'mysqlnd': [
        re.compile(r'mysqlnd\s+(\d+\.\d+[\.\d]*)'),
        re.compile(r'Client API version.*?mysqlnd\s+(\d+\.\d+[\.\d]*)'),
    ],
    'Zend': [
        re.compile(r'Zend Engine v(\d+\.\d+[\.\d]*)'),
    ],
}

# Modules to CVE-enrich (vendor, product mapping for NVD)
MODULE_CVE_VENDORS = {
    'curl': ('haxx', 'curl'),
    'openssl': ('openssl', 'openssl'),
    'libxml': ('xmlsoft', 'libxml2'),
    'GD': ('libgd', 'gd'),
    'mysqlnd': ('php', 'php'),
    'Zend': ('zend', 'zend_engine'),
}


class PhpinfoChecker:
    """
    Deep phpinfo() page analysis.
    Extracts PHP module versions and dangerous runtime settings.
    """

    def __init__(self, config=None, http_client=None, mode: str = 'safe'):
        self.config = config or get_config()
        self.http_client = http_client
        self.mode = mode

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Attempt to find and parse phpinfo() pages.

        Args:
            target: Base URL (e.g. http://localhost:8080)

        Returns:
            List of findings from phpinfo analysis
        """
        findings = []

        paths = PHPINFO_PATHS_AGGRESSIVE if self.mode == 'aggressive' else PHPINFO_PATHS_SAFE

        for path in paths:
            url = target.rstrip('/') + path
            try:
                resp = self.http_client.get(
                    url,
                    timeout=(self.config.timeout_connect, self.config.timeout_read),
                    allow_redirects=False
                )
                if resp.status_code == 200 and 'phpinfo' in resp.text.lower():
                    logger.info(f"phpinfo page found: {url}")
                    findings.extend(self._parse_phpinfo(resp.text, url))
                    break  # Parse first accessible one
            except requests.exceptions.RequestException:
                pass
            except Exception as e:
                logger.debug(f"phpinfo check failed for {url}: {e}")

        return findings

    def _parse_phpinfo(self, html: str, url: str) -> List[Dict[str, Any]]:
        """Parse phpinfo() HTML and generate findings."""
        findings = []

        # Extract PHP version
        php_version = self._extract_php_version(html)

        # Check dangerous settings
        settings = self._extract_settings(html)
        for setting_name, danger_pattern, code, severity, title, desc, rec in DANGEROUS_SETTINGS:
            value = settings.get(setting_name, '').strip()
            if danger_pattern.match(value):
                findings.append({
                    'id': code,
                    'title': title,
                    'severity': severity,
                    'confidence': 'high',
                    'description': desc,
                    'evidence': {
                        'type': 'url',
                        'value': url,
                        'context': f'{setting_name} = {value if value else "(empty)"}  (detected via phpinfo())'
                    },
                    'recommendation': rec,
                    'references': [
                        'https://www.php.net/manual/en/ini.core.php',
                        'https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html',
                    ],
                    'affected_component': f'PHP {php_version}' if php_version else 'PHP',
                })

        # Extract module versions + CVE enrich
        findings.extend(self._extract_module_findings(html, url, php_version))

        if findings:
            logger.info(f"phpinfo analysis: {len(findings)} findings from {url}")
        else:
            logger.info(f"phpinfo analysis: no dangerous settings found at {url}")

        return findings

    def _extract_php_version(self, html: str) -> Optional[str]:
        """Extract PHP version from phpinfo HTML."""
        patterns = [
            re.compile(r'PHP Version\s+(\d+\.\d+[\.\d]*)'),
            re.compile(r'<title>phpinfo\(\)</title>.*?PHP Version\s+(\d+\.\d+[\.\d]*)', re.S),
            re.compile(r'<h1[^>]*>\s*PHP Version\s+(\d+\.\d+[\.\d]*)'),
        ]
        for p in patterns:
            m = p.search(html)
            if m:
                return m.group(1)
        return None

    def _extract_settings(self, html: str) -> Dict[str, str]:
        """
        Extract PHP configuration settings from phpinfo tables.
        Returns dict of {setting_name: local_value}.
        """
        settings = {}
        # phpinfo table pattern: <td class="e">setting</td><td class="v">value</td>
        pattern = re.compile(
            r'<td\s+class="e">([^<]+)</td>\s*<td\s+class="v">([^<]*)</td>',
            re.I
        )
        for m in pattern.finditer(html):
            key = m.group(1).strip()
            val = m.group(2).strip()
            # Remove HTML tags from value
            val = re.sub(r'<[^>]+>', '', val).strip()
            settings[key] = val

        return settings

    def _extract_module_findings(
        self, html: str, url: str, php_version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Extract module versions from phpinfo and attempt CVE enrichment."""
        findings = []

        try:
            from ..core.cve_lookup import lookup_cves
            has_cve_lookup = True
        except ImportError:
            has_cve_lookup = False

        for module_name, patterns in MODULE_VERSION_PATTERNS.items():
            version = None
            for p in patterns:
                m = p.search(html)
                if m:
                    version = m.group(1) if m.lastindex else None
                    break

            if not version or version.lower() in ('enabled', 'bundled', 'active'):
                continue

            # Try CVE enrichment
            cves = []
            if has_cve_lookup and module_name in MODULE_CVE_VENDORS:
                vendor, product = MODULE_CVE_VENDORS[module_name]
                try:
                    cves = lookup_cves(product, version, vendor=vendor)
                except Exception:
                    pass

            if cves:
                max_cvss = max((c.get('cvss_score', 0) for c in cves), default=0)
                severity = 'critical' if max_cvss >= 9.0 else 'high' if max_cvss >= 7.0 else 'medium' if max_cvss >= 4.0 else 'low'
                findings.append({
                    'id': 'HEPH-PHP-010',
                    'title': f'Vulnerable PHP module: {module_name} {version}',
                    'severity': severity,
                    'confidence': 'medium',
                    'description': (
                        f'{module_name} version {version} has {len(cves)} known CVE(s). '
                        f'Highest CVSS: {max_cvss}. Update to latest version.'
                    ),
                    'evidence': {
                        'type': 'url',
                        'value': url,
                        'context': f'{module_name} {version} detected via phpinfo()'
                    },
                    'recommendation': f'Update {module_name} to the latest stable version.',
                    'references': [f'https://nvd.nist.gov/vuln/search/results?query={module_name}+{version}'],
                    'affected_component': f'{module_name} {version}',
                    'cvss': max_cvss,
                    'vulnerabilities': cves[:5],
                })

        return findings


def parse_phpinfo_html(html: str) -> Dict[str, Any]:
    """
    Utility: parse phpinfo HTML and return structured data.
    Useful for testing and standalone use.
    """
    checker = PhpinfoChecker()
    version = checker._extract_php_version(html)
    settings = checker._extract_settings(html)

    modules = {}
    for module_name, patterns in MODULE_VERSION_PATTERNS.items():
        for p in patterns:
            m = p.search(html)
            if m and m.lastindex:
                modules[module_name] = m.group(1)
                break

    return {
        'php_version': version,
        'settings': settings,
        'modules': modules,
    }
