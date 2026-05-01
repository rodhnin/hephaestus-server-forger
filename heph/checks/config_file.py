"""
Apache/Nginx/PHP.ini Configuration File Parser (IMPROV-005 + Bloque 2)

Offline analysis of httpd.conf / nginx.conf / php.ini files.
Detects security misconfigurations without making any HTTP requests.

Checks (Apache):
  - ServerTokens Full/OS/Minor/Major (should be Prod)
  - ServerSignature On (should be Off)
  - TraceEnable On (should be Off)
  - Options +Indexes / Options Indexes (directory listing)
  - expose_php On
  - SSLProtocol including SSLv2/SSLv3/TLSv1/TLSv1.1
  - SSLCipherSuite with weak ciphers (RC4, MD5, DES, EXPORT)
  - AllowOverride All (overly permissive)
  - LimitRequestBody 0 (no upload size limit)
  - Missing security headers (X-Frame-Options, X-Content-Type-Options, etc.)

Checks (Nginx):
  - server_tokens on
  - autoindex on
  - ssl_protocols with SSLv2/SSLv3/TLSv1/TLSv1.1
  - ssl_ciphers with weak ciphers
  - client_max_body_size not set or very large (>100M)
  - Missing add_header security directives

Checks (PHP.ini):
  - expose_php = On
  - display_errors = On
  - allow_url_fopen = On
  - allow_url_include = On
  - disable_functions empty
  - open_basedir not set
  - session.cookie_secure = Off
  - session.cookie_httponly = Off
  - session.cookie_samesite empty
  - upload_max_filesize > 50M
  - magic_quotes_gpc On (legacy risk)
  - register_globals On (critical — legacy)

Finding codes: HEPH-CFG-010 through HEPH-CFG-099

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from ..core.logging import get_logger

logger = get_logger(__name__)

# Weak ciphers/protocols patterns
WEAK_PROTOCOLS = {'sslv2', 'sslv3', 'tlsv1', 'tlsv1.0', 'tlsv1.1'}
WEAK_CIPHER_PATTERNS = re.compile(
    r'\b(RC4|MD5|DES|3DES|EXPORT|NULL|ANON|aNULL|eNULL|ADH|AECDH|LOW|MEDIUM)\b',
    re.IGNORECASE
)


class ConfigFileParser:
    """
    Parses Apache httpd.conf / Nginx nginx.conf files offline
    and detects security misconfigurations.
    """

    def __init__(self, config=None):
        self.config = config

    def analyze(self, config_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a config file and return findings.

        Args:
            config_path: Absolute or relative path to httpd.conf / nginx.conf

        Returns:
            List of finding dicts in standard Hephaestus schema
        """
        path = Path(config_path).expanduser().resolve()

        if not path.exists():
            logger.error(f"Config file not found: {path}")
            return [{
                'id': 'HEPH-CFG-010',
                'title': 'Config file not found',
                'severity': 'info',
                'confidence': 'high',
                'description': f"Config file does not exist: {path}",
                'evidence': {
                    'type': 'path',
                    'value': str(path),
                    'context': 'File not found'
                },
                'recommendation': 'Provide a valid path to httpd.conf or nginx.conf.',
            }]

        try:
            raw = path.read_text(encoding='utf-8', errors='replace')
        except OSError as e:
            logger.error(f"Cannot read config file {path}: {e}")
            return []

        logger.info(f"Analyzing config file: {path} ({len(raw)} bytes)")

        # Auto-detect server type
        server_type = self._detect_server_type(path.name, raw)
        logger.info(f"Detected server type: {server_type}")

        findings: List[Dict[str, Any]] = []

        if server_type == 'apache':
            findings.extend(self._check_apache(raw, str(path)))
        elif server_type == 'nginx':
            findings.extend(self._check_nginx(raw, str(path)))
        elif server_type == 'php':
            findings.extend(self._check_phpini(raw, str(path)))
        else:
            # Try all parsers and merge
            findings.extend(self._check_apache(raw, str(path)))
            findings.extend(self._check_nginx(raw, str(path)))

        # Always run generic checks
        findings.extend(self._check_generic(raw, str(path)))

        if not findings:
            findings.append({
                'id': 'HEPH-CFG-099',
                'title': 'Configuration file has no detected issues',
                'severity': 'info',
                'confidence': 'medium',
                'description': (
                    f"No security misconfigurations detected in {path.name}. "
                    "Manual review is still recommended."
                ),
                'evidence': {
                    'type': 'path',
                    'value': str(path),
                    'context': f"{server_type.capitalize()} config analyzed — no issues found"
                },
                'recommendation': 'Continue with regular security reviews.',
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
            })

        logger.info(f"Config file analysis complete: {len(findings)} finding(s)")
        return findings

    # ─── Server type detection ────────────────────────────────────────────────

    def _detect_server_type(self, filename: str, content: str) -> str:
        """Detect whether config is Apache, Nginx, or PHP.ini."""
        name_lower = filename.lower()

        # Filename hints
        if any(x in name_lower for x in ('httpd', 'apache2', 'apache')):
            return 'apache'
        if 'nginx' in name_lower:
            return 'nginx'
        if name_lower == 'php.ini' or name_lower.startswith('php.ini') or name_lower.endswith('.ini'):
            # Confirm it's PHP.ini by content
            php_score = len(re.findall(
                r'(expose_php|display_errors|allow_url_fopen|disable_functions|'
                r'session\.cookie|memory_limit|upload_max_filesize|max_execution_time)',
                content, re.IGNORECASE
            ))
            if php_score >= 2:
                return 'php'

        # Content scoring
        apache_score = len(re.findall(
            r'\b(ServerTokens|ServerSignature|TraceEnable|AllowOverride|DocumentRoot|VirtualHost|mod_)\b',
            content, re.IGNORECASE
        ))
        nginx_score = len(re.findall(
            r'\b(server_tokens|worker_processes|upstream|proxy_pass|sendfile|gzip|keepalive_timeout)\b',
            content, re.IGNORECASE
        ))
        php_score = len(re.findall(
            r'(expose_php|display_errors|allow_url_fopen|disable_functions|'
            r'session\.cookie|memory_limit|upload_max_filesize)',
            content, re.IGNORECASE
        ))

        scores = {'apache': apache_score, 'nginx': nginx_score, 'php': php_score}
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            return best
        return 'unknown'

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _strip_comments(self, content: str, comment_char: str = '#') -> str:
        """Remove comment lines."""
        lines = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith(comment_char):
                continue
            # Inline comment removal (only outside quotes — simple approach)
            if comment_char in line:
                line = line[:line.index(comment_char)]
            lines.append(line)
        return '\n'.join(lines)

    def _find_directive(self, content: str, directive: str) -> Optional[re.Match]:
        """Find first occurrence of a directive (case-insensitive)."""
        pattern = re.compile(
            rf'^\s*{re.escape(directive)}\s+(.+?)$',
            re.IGNORECASE | re.MULTILINE
        )
        return pattern.search(content)

    def _find_all_directives(self, content: str, directive: str) -> List[re.Match]:
        """Find all occurrences of a directive."""
        pattern = re.compile(
            rf'^\s*{re.escape(directive)}\s+(.+?)$',
            re.IGNORECASE | re.MULTILINE
        )
        return list(pattern.finditer(content))

    def _get_line_number(self, content: str, match: re.Match) -> int:
        """Get line number for a regex match."""
        return content[:match.start()].count('\n') + 1

    def _evidence(self, path: str, line: int, value: str) -> Dict[str, str]:
        return {
            'type': 'path',
            'value': f"{path}:{line}",
            'context': value.strip()
        }

    # ─── Apache checks ────────────────────────────────────────────────────────

    def _check_apache(self, raw: str, path: str) -> List[Dict[str, Any]]:
        """Run all Apache-specific checks."""
        content = self._strip_comments(raw)
        findings: List[Dict[str, Any]] = []

        findings.extend(self._apache_server_tokens(raw, content, path))
        findings.extend(self._apache_server_signature(raw, content, path))
        findings.extend(self._apache_trace_enable(raw, content, path))
        findings.extend(self._apache_indexes(raw, content, path))
        findings.extend(self._apache_expose_php(raw, content, path))
        findings.extend(self._apache_ssl_protocol(raw, content, path))
        findings.extend(self._apache_ssl_ciphers(raw, content, path))
        findings.extend(self._apache_allow_override(raw, content, path))
        findings.extend(self._apache_limit_request_body(raw, content, path))
        findings.extend(self._apache_security_headers(raw, content, path))

        return findings

    def _apache_server_tokens(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'ServerTokens')
        if not match:
            return [{
                'id': 'HEPH-CFG-011',
                'title': 'ServerTokens directive not set (defaults to Full)',
                'severity': 'medium',
                'confidence': 'medium',
                'description': (
                    "ServerTokens is not explicitly set. Apache defaults to 'Full', "
                    "which reveals the OS and module versions in HTTP response headers. "
                    "Attackers use this to target known CVEs."
                ),
                'evidence': {'type': 'path', 'value': path, 'context': 'Directive missing'},
                'recommendation': "Add 'ServerTokens Prod' to your Apache config.",
                'references': ['https://httpd.apache.org/docs/2.4/mod/core.html#servertokens'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'ServerTokens',
            }]

        value = match.group(1).strip().lower()
        if value in ('full', 'os', 'minor', 'major'):
            line = self._get_line_number(raw, match)
            return [{
                'id': 'HEPH-CFG-011',
                'title': f'ServerTokens set to {value.capitalize()} (reveals server info)',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    f"ServerTokens is set to '{value}', which reveals version information "
                    "in HTTP response headers (Server: Apache/2.4.54 Ubuntu). "
                    "Attackers use this to identify and exploit known CVEs."
                ),
                'evidence': self._evidence(path, line, f"ServerTokens {match.group(1)}"),
                'recommendation': (
                    "Change to 'ServerTokens Prod' in httpd.conf:\n"
                    "  ServerTokens Prod\n\n"
                    "This shows only 'Server: Apache' without version details."
                ),
                'references': ['https://httpd.apache.org/docs/2.4/mod/core.html#servertokens'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'ServerTokens',
            }]
        return []

    def _apache_server_signature(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'ServerSignature')
        if not match:
            return []
        value = match.group(1).strip().lower()
        if value == 'on':
            line = self._get_line_number(raw, match)
            return [{
                'id': 'HEPH-CFG-012',
                'title': 'ServerSignature is On (version in error pages)',
                'severity': 'low',
                'confidence': 'high',
                'description': (
                    "ServerSignature On adds Apache version/OS info to error pages "
                    "and directory listings. This aids attackers in fingerprinting."
                ),
                'evidence': self._evidence(path, line, f"ServerSignature {match.group(1)}"),
                'recommendation': "Set 'ServerSignature Off' in httpd.conf.",
                'references': ['https://httpd.apache.org/docs/2.4/mod/core.html#serversignature'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'ServerSignature',
            }]
        return []

    def _apache_trace_enable(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'TraceEnable')
        if not match:
            return []
        value = match.group(1).strip().lower()
        if value == 'on':
            line = self._get_line_number(raw, match)
            return [{
                'id': 'HEPH-CFG-013',
                'title': 'TraceEnable is On (XST vulnerability)',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    "TraceEnable On enables the HTTP TRACE method, which can be used "
                    "in Cross-Site Tracing (XST) attacks to steal cookies even when "
                    "HttpOnly is set."
                ),
                'evidence': self._evidence(path, line, f"TraceEnable {match.group(1)}"),
                'recommendation': "Set 'TraceEnable Off' in httpd.conf.",
                'references': [
                    'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
                    'https://httpd.apache.org/docs/2.4/mod/core.html#traceenable',
                ],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'TraceEnable',
            }]
        return []

    def _apache_indexes(self, raw: str, content: str, path: str) -> List[Dict]:
        """Detect Options +Indexes or Options Indexes (without -)."""
        pattern = re.compile(
            r'^\s*Options\s+([^#\n]+)',
            re.IGNORECASE | re.MULTILINE
        )
        findings = []
        for m in pattern.finditer(raw):
            opts = m.group(1)
            # Check for Indexes without a leading minus
            if re.search(r'(?<!\-)\bIndexes\b', opts, re.IGNORECASE):
                line = self._get_line_number(raw, m)
                findings.append({
                    'id': 'HEPH-CFG-014',
                    'title': 'Directory listing enabled (Options Indexes)',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': (
                        "Options Indexes is enabled, allowing Apache to generate directory "
                        "listings when no index file exists. This exposes file structure "
                        "and may reveal sensitive files."
                    ),
                    'evidence': self._evidence(path, line, f"Options {opts.strip()}"),
                    'recommendation': (
                        "Remove Indexes from the Options directive or explicitly deny it:\n"
                        "  Options -Indexes\n\n"
                        "Or restrict specific directories in your <Directory> blocks."
                    ),
                    'references': ['https://httpd.apache.org/docs/2.4/mod/core.html#options'],
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    'affected_component': 'Options Indexes',
                })
        return findings

    def _apache_expose_php(self, raw: str, content: str, path: str) -> List[Dict]:
        """Detect expose_php = On."""
        pattern = re.compile(
            r'^\s*(?:php_(?:value|flag|admin_value|admin_flag)\s+)?expose_php\s+(On|1)\b',
            re.IGNORECASE | re.MULTILINE
        )
        m = pattern.search(raw)
        if m:
            line = self._get_line_number(raw, m)
            return [{
                'id': 'HEPH-CFG-015',
                'title': 'expose_php is On (PHP version disclosure)',
                'severity': 'low',
                'confidence': 'high',
                'description': (
                    "expose_php = On adds the PHP version to the X-Powered-By response header "
                    "(e.g. X-Powered-By: PHP/7.4.33), making it easy for attackers to identify "
                    "the exact PHP version and target known CVEs."
                ),
                'evidence': self._evidence(path, line, m.group(0).strip()),
                'recommendation': (
                    "Set 'expose_php = Off' in php.ini or via Apache config:\n"
                    "  php_flag expose_php Off\n\n"
                    "Or edit /etc/php/*/apache2/php.ini:\n"
                    "  expose_php = Off"
                ),
                'references': ['https://www.php.net/manual/en/ini.core.php#ini.expose-php'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'PHP expose_php',
            }]
        return []

    def _apache_ssl_protocol(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'SSLProtocol')
        if not match:
            return []
        value = match.group(1).strip()
        # Parse what's enabled (handle +/- prefixes)
        protocols_enabled = set()
        for part in value.split():
            p = part.lstrip('+-').lower()
            if part.startswith('-'):
                protocols_enabled.discard(p)
            else:
                protocols_enabled.add(p)

        # Check for "all" which includes old protocols
        if 'all' in protocols_enabled:
            protocols_enabled.update({'sslv2', 'sslv3', 'tlsv1', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'})

        weak = protocols_enabled & WEAK_PROTOCOLS
        if weak:
            line = self._get_line_number(raw, match)
            weak_str = ', '.join(sorted(weak, key=lambda x: x.upper()))
            return [{
                'id': 'HEPH-CFG-016',
                'title': f'Weak SSL/TLS protocols enabled: {weak_str}',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    f"SSLProtocol includes deprecated and insecure protocols: {weak_str}. "
                    "SSLv2/SSLv3 are cryptographically broken (POODLE, DROWN). "
                    "TLSv1.0/1.1 are deprecated by RFC 8996 and fail PCI DSS compliance."
                ),
                'evidence': self._evidence(path, line, f"SSLProtocol {value}"),
                'recommendation': (
                    "Enable only TLS 1.2 and 1.3:\n"
                    "  SSLProtocol -all +TLSv1.2 +TLSv1.3\n\n"
                    "Also set: SSLHonorCipherOrder on"
                ),
                'references': [
                    'https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslprotocol',
                    'https://tools.ietf.org/html/rfc8996',
                ],
                'owasp': {'id': 'A02', 'name': 'Cryptographic Failures'},
                'affected_component': 'SSLProtocol',
            }]
        return []

    def _apache_ssl_ciphers(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'SSLCipherSuite')
        if not match:
            return []
        value = match.group(1).strip()
        # Only flag cipher components that are NOT negated (no leading !)
        parts_enabled = [p.strip() for p in value.replace(',', ':').split(':') if not p.strip().startswith('!')]
        enabled_str = ':'.join(parts_enabled)
        weak_matches = WEAK_CIPHER_PATTERNS.findall(enabled_str)
        if weak_matches:
            line = self._get_line_number(raw, match)
            unique_weak = list(dict.fromkeys(w.upper() for w in weak_matches))
            return [{
                'id': 'HEPH-CFG-017',
                'title': f'Weak SSL ciphers in SSLCipherSuite: {", ".join(unique_weak)}',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    f"SSLCipherSuite includes weak/broken cipher components: {', '.join(unique_weak)}. "
                    "RC4 is broken, MD5 is collision-prone, EXPORT ciphers intentionally weak, "
                    "NULL ciphers provide no encryption."
                ),
                'evidence': self._evidence(path, line, f"SSLCipherSuite {value[:80]}..."),
                'recommendation': (
                    "Use a modern cipher suite:\n"
                    "  SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256\n"
                    "  SSLHonorCipherOrder on"
                ),
                'references': [
                    'https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslciphersuite',
                    'https://wiki.mozilla.org/Security/Server_Side_TLS',
                ],
                'owasp': {'id': 'A02', 'name': 'Cryptographic Failures'},
                'affected_component': 'SSLCipherSuite',
            }]
        return []

    def _apache_allow_override(self, raw: str, content: str, path: str) -> List[Dict]:
        """Detect AllowOverride All in root or wide directory blocks."""
        pattern = re.compile(r'^\s*AllowOverride\s+(All)\b', re.IGNORECASE | re.MULTILINE)
        findings = []
        for m in pattern.finditer(raw):
            line = self._get_line_number(raw, m)
            findings.append({
                'id': 'HEPH-CFG-018',
                'title': 'AllowOverride All — overly permissive .htaccess',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    "AllowOverride All allows .htaccess files to override any server directive. "
                    "If an attacker can write a .htaccess file (e.g., via file upload), "
                    "they can enable PHP execution, change authentication, or modify security settings."
                ),
                'evidence': self._evidence(path, line, m.group(0).strip()),
                'recommendation': (
                    "Restrict AllowOverride to only what is needed:\n"
                    "  AllowOverride None    # most secure\n"
                    "  AllowOverride AuthConfig Indexes  # if .htaccess is needed\n\n"
                    "Move all configuration to httpd.conf or virtual host config."
                ),
                'references': ['https://httpd.apache.org/docs/2.4/mod/core.html#allowoverride'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'AllowOverride',
            })
        return findings

    def _apache_limit_request_body(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'LimitRequestBody')
        if not match:
            return [{
                'id': 'HEPH-CFG-019',
                'title': 'LimitRequestBody not set (unlimited upload size)',
                'severity': 'low',
                'confidence': 'medium',
                'description': (
                    "LimitRequestBody is not configured. Apache defaults to 0 (unlimited), "
                    "which allows attackers to upload arbitrarily large files, potentially "
                    "causing disk exhaustion or denial of service."
                ),
                'evidence': {'type': 'path', 'value': path, 'context': 'Directive missing'},
                'recommendation': (
                    "Set a reasonable request body limit:\n"
                    "  LimitRequestBody 10485760  # 10 MB\n\n"
                    "Adjust to your application's needs."
                ),
                'references': ['https://httpd.apache.org/docs/2.4/mod/core.html#limitrequestbody'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'LimitRequestBody',
            }]
        try:
            limit = int(match.group(1).strip())
            if limit == 0:
                line = self._get_line_number(raw, match)
                return [{
                    'id': 'HEPH-CFG-019',
                    'title': 'LimitRequestBody set to 0 (unlimited upload size)',
                    'severity': 'low',
                    'confidence': 'high',
                    'description': (
                        "LimitRequestBody 0 means no limit on request body size. "
                        "Attackers can upload arbitrarily large files causing disk exhaustion."
                    ),
                    'evidence': self._evidence(path, line, f"LimitRequestBody {limit}"),
                    'recommendation': "Set 'LimitRequestBody 10485760' (10MB) or per your app requirements.",
                    'references': ['https://httpd.apache.org/docs/2.4/mod/core.html#limitrequestbody'],
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    'affected_component': 'LimitRequestBody',
                }]
        except ValueError:
            pass
        return []

    def _apache_security_headers(self, raw: str, content: str, path: str) -> List[Dict]:
        """Check for missing security header directives in Apache config."""
        findings = []
        headers_to_check = [
            ('X-Frame-Options', 'HEPH-CFG-020', 'Clickjacking protection'),
            ('X-Content-Type-Options', 'HEPH-CFG-021', 'MIME-type sniffing protection'),
            ('Strict-Transport-Security', 'HEPH-CFG-022', 'HTTP Strict Transport Security (HSTS)'),
            ('Content-Security-Policy', 'HEPH-CFG-023', 'Content Security Policy (XSS protection)'),
            ('Referrer-Policy', 'HEPH-CFG-024', 'Referrer information control'),
        ]
        for header, fid, desc in headers_to_check:
            # Look for Header (always) set <HeaderName>
            pattern = re.compile(
                rf'^\s*Header\s+(?:always\s+)?(?:set|append|add)\s+{re.escape(header)}\b',
                re.IGNORECASE | re.MULTILINE
            )
            if not pattern.search(raw):
                findings.append({
                    'id': fid,
                    'title': f'Security header not configured: {header}',
                    'severity': 'low',
                    'confidence': 'medium',
                    'description': (
                        f"{header} is not set in the Apache configuration. "
                        f"This header provides {desc}."
                    ),
                    'evidence': {
                        'type': 'path',
                        'value': path,
                        'context': f"'Header always set {header}' not found in config"
                    },
                    'recommendation': (
                        f"Add to your VirtualHost or global config:\n"
                        f"  Header always set {header} \"<value>\"\n\n"
                        f"Requires mod_headers to be enabled: a2enmod headers"
                    ),
                    'references': [
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}"
                    ],
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    'affected_component': f'Header {header}',
                })
        return findings

    # ─── Nginx checks ─────────────────────────────────────────────────────────

    def _check_nginx(self, raw: str, path: str) -> List[Dict[str, Any]]:
        """Run all Nginx-specific checks."""
        content = self._strip_comments(raw)
        findings: List[Dict[str, Any]] = []

        findings.extend(self._nginx_server_tokens(raw, content, path))
        findings.extend(self._nginx_autoindex(raw, content, path))
        findings.extend(self._nginx_ssl_protocols(raw, content, path))
        findings.extend(self._nginx_ssl_ciphers(raw, content, path))
        findings.extend(self._nginx_client_max_body(raw, content, path))
        findings.extend(self._nginx_security_headers(raw, content, path))

        return findings

    def _nginx_server_tokens(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'server_tokens')
        if not match:
            return [{
                'id': 'HEPH-CFG-030',
                'title': 'server_tokens not set (defaults to on)',
                'severity': 'low',
                'confidence': 'medium',
                'description': (
                    "server_tokens is not configured. Nginx defaults to 'on', "
                    "which reveals the Nginx version in the Server response header "
                    "and error pages."
                ),
                'evidence': {'type': 'path', 'value': path, 'context': 'Directive missing'},
                'recommendation': (
                    "Add to http {} block in nginx.conf:\n"
                    "  server_tokens off;"
                ),
                'references': ['https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'server_tokens',
            }]
        value = match.group(1).strip().rstrip(';').lower()
        if value == 'on':
            line = self._get_line_number(raw, match)
            return [{
                'id': 'HEPH-CFG-030',
                'title': 'server_tokens is on (Nginx version disclosure)',
                'severity': 'low',
                'confidence': 'high',
                'description': (
                    "server_tokens on reveals the Nginx version in the Server response header "
                    "(e.g. Server: nginx/1.18.0) and in error pages. "
                    "Attackers use this to identify and exploit known CVEs."
                ),
                'evidence': self._evidence(path, line, f"server_tokens {match.group(1)}"),
                'recommendation': "Set 'server_tokens off;' in the http {} block.",
                'references': ['https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'server_tokens',
            }]
        return []

    def _nginx_autoindex(self, raw: str, content: str, path: str) -> List[Dict]:
        pattern = re.compile(r'^\s*autoindex\s+on\s*;', re.IGNORECASE | re.MULTILINE)
        matches = list(pattern.finditer(raw))
        if not matches:
            return []
        # Report once with all line numbers listed
        lines = [self._get_line_number(raw, m) for m in matches]
        line_str = ', '.join(str(ln) for ln in lines)
        count = len(matches)
        loc_note = f"Found in {count} location(s): lines {line_str}" if count > 1 else f"Line {lines[0]}"
        return [{
            'id': 'HEPH-CFG-031',
            'title': f'autoindex is on (directory listing enabled, {count} location(s))',
            'severity': 'medium',
            'confidence': 'high',
            'description': (
                f"autoindex on is set in {count} location block(s), enabling Nginx directory listing "
                "when no index file exists. This exposes file structure and may reveal sensitive files."
            ),
            'evidence': {
                'type': 'path',
                'value': f"{path}:{lines[0]}",
                'context': loc_note
            },
            'recommendation': (
                "Set 'autoindex off;' in every server {} and location {} block:\n"
                "  autoindex off;"
            ),
            'references': ['https://nginx.org/en/docs/http/ngx_http_autoindex_module.html'],
            'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
            'affected_component': 'autoindex',
        }]

    def _nginx_ssl_protocols(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'ssl_protocols')
        if not match:
            return []
        value = match.group(1).strip().rstrip(';')
        protocols = {p.lower() for p in value.split()}
        weak = protocols & WEAK_PROTOCOLS
        if weak:
            line = self._get_line_number(raw, match)
            weak_str = ' '.join(sorted(weak, key=str.upper))
            return [{
                'id': 'HEPH-CFG-032',
                'title': f'Weak SSL/TLS protocols in ssl_protocols: {weak_str}',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    f"ssl_protocols includes deprecated protocols: {weak_str}. "
                    "SSLv3 is vulnerable to POODLE; TLSv1/TLSv1.1 are deprecated "
                    "by RFC 8996 and fail PCI DSS compliance."
                ),
                'evidence': self._evidence(path, line, f"ssl_protocols {value};"),
                'recommendation': (
                    "Enable only modern protocols:\n"
                    "  ssl_protocols TLSv1.2 TLSv1.3;"
                ),
                'references': [
                    'https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols',
                    'https://tools.ietf.org/html/rfc8996',
                ],
                'owasp': {'id': 'A02', 'name': 'Cryptographic Failures'},
                'affected_component': 'ssl_protocols',
            }]
        return []

    def _nginx_ssl_ciphers(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'ssl_ciphers')
        if not match:
            return []
        value = match.group(1).strip().rstrip(';').strip('"\'')
        # Only check cipher components that are NOT negated (no leading !)
        # Split on : and filter out negated parts
        parts_enabled = [p.strip() for p in value.replace(',', ':').split(':') if not p.strip().startswith('!')]
        enabled_str = ':'.join(parts_enabled)
        weak_matches = WEAK_CIPHER_PATTERNS.findall(enabled_str)
        if weak_matches:
            line = self._get_line_number(raw, match)
            unique_weak = list(dict.fromkeys(w.upper() for w in weak_matches))
            return [{
                'id': 'HEPH-CFG-033',
                'title': f'Weak SSL ciphers in ssl_ciphers: {", ".join(unique_weak)}',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    f"ssl_ciphers includes weak/broken cipher components: {', '.join(unique_weak)}. "
                    "These are cryptographically broken or intentionally weakened."
                ),
                'evidence': self._evidence(path, line, f"ssl_ciphers {value[:80]}"),
                'recommendation': (
                    "Use a modern cipher suite:\n"
                    "  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\n"
                    "  ssl_prefer_server_ciphers on;"
                ),
                'references': [
                    'https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_ciphers',
                    'https://wiki.mozilla.org/Security/Server_Side_TLS',
                ],
                'owasp': {'id': 'A02', 'name': 'Cryptographic Failures'},
                'affected_component': 'ssl_ciphers',
            }]
        return []

    def _nginx_client_max_body(self, raw: str, content: str, path: str) -> List[Dict]:
        match = self._find_directive(raw, 'client_max_body_size')
        if not match:
            return [{
                'id': 'HEPH-CFG-034',
                'title': 'client_max_body_size not set (default 1M)',
                'severity': 'info',
                'confidence': 'low',
                'description': (
                    "client_max_body_size is not explicitly configured. "
                    "Nginx defaults to 1M, which may be too restrictive or too permissive "
                    "depending on the application. Ensure it is set to the minimum needed."
                ),
                'evidence': {'type': 'path', 'value': path, 'context': 'Directive missing'},
                'recommendation': (
                    "Set an explicit upload limit in nginx.conf:\n"
                    "  client_max_body_size 10M;"
                ),
                'references': ['https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size'],
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                'affected_component': 'client_max_body_size',
            }]

        value = match.group(1).strip().rstrip(';').lower()
        try:
            multipliers = {'k': 1024, 'm': 1024**2, 'g': 1024**3}
            if value[-1] in multipliers:
                size_bytes = int(value[:-1]) * multipliers[value[-1]]
            else:
                size_bytes = int(value)

            if size_bytes == 0:
                line = self._get_line_number(raw, match)
                return [{
                    'id': 'HEPH-CFG-034',
                    'title': 'client_max_body_size set to 0 (unlimited)',
                    'severity': 'medium',
                    'confidence': 'high',
                    'description': (
                        "client_max_body_size 0 disables the upload size limit, "
                        "allowing attackers to upload arbitrarily large files."
                    ),
                    'evidence': self._evidence(path, self._get_line_number(raw, match),
                                               f"client_max_body_size {match.group(1)}"),
                    'recommendation': "Set a reasonable limit such as 'client_max_body_size 10M;'",
                    'references': ['https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size'],
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    'affected_component': 'client_max_body_size',
                }]

            if size_bytes > 100 * 1024 * 1024:  # > 100MB
                line = self._get_line_number(raw, match)
                return [{
                    'id': 'HEPH-CFG-034',
                    'title': f'client_max_body_size is very large: {value.upper()}',
                    'severity': 'low',
                    'confidence': 'medium',
                    'description': (
                        f"client_max_body_size is set to {value.upper()} (>{size_bytes // 1024 // 1024}MB). "
                        "Large upload limits increase the risk of disk exhaustion DoS attacks."
                    ),
                    'evidence': self._evidence(path, line, f"client_max_body_size {match.group(1)}"),
                    'recommendation': "Reduce to the minimum size your application requires.",
                    'references': ['https://nginx.org/en/docs/http/ngx_http_core_module.html#client_max_body_size'],
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    'affected_component': 'client_max_body_size',
                }]
        except (ValueError, IndexError):
            pass
        return []

    def _nginx_security_headers(self, raw: str, content: str, path: str) -> List[Dict]:
        """Check for missing add_header security directives in Nginx config."""
        findings = []
        headers_to_check = [
            ('X-Frame-Options', 'HEPH-CFG-040', 'Clickjacking protection'),
            ('X-Content-Type-Options', 'HEPH-CFG-041', 'MIME-type sniffing protection'),
            ('Strict-Transport-Security', 'HEPH-CFG-042', 'HTTP Strict Transport Security (HSTS)'),
            ('Content-Security-Policy', 'HEPH-CFG-043', 'Content Security Policy'),
            ('Referrer-Policy', 'HEPH-CFG-044', 'Referrer information control'),
        ]
        for header, fid, desc in headers_to_check:
            pattern = re.compile(
                rf'^\s*add_header\s+{re.escape(header)}\b',
                re.IGNORECASE | re.MULTILINE
            )
            if not pattern.search(raw):
                findings.append({
                    'id': fid,
                    'title': f'Security header not configured: {header}',
                    'severity': 'low',
                    'confidence': 'medium',
                    'description': (
                        f"{header} is not set in the Nginx configuration. "
                        f"This header provides {desc}."
                    ),
                    'evidence': {
                        'type': 'path',
                        'value': path,
                        'context': f"'add_header {header}' not found in config"
                    },
                    'recommendation': (
                        f"Add to your server {{}} block:\n"
                        f"  add_header {header} \"<value>\" always;\n\n"
                        f"The 'always' parameter ensures the header is sent on error responses too."
                    ),
                    'references': [
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}"
                    ],
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                    'affected_component': f'add_header {header}',
                })
        return findings

    # ─── Generic checks (both Apache and Nginx) ───────────────────────────────

    def _check_generic(self, raw: str, path: str) -> List[Dict[str, Any]]:
        """Checks applicable to both Apache and Nginx."""
        findings: List[Dict[str, Any]] = []
        findings.extend(self._generic_hardcoded_credentials(raw, path))
        return findings

    def _generic_hardcoded_credentials(self, raw: str, path: str) -> List[Dict]:
        """Look for obvious hardcoded passwords/secrets in config."""
        patterns = [
            re.compile(r'^\s*(?:auth_basic_user_file|htpasswd)\s+(.+)', re.IGNORECASE | re.MULTILINE),
            re.compile(r'password\s*[=:]\s*["\']?(?!your_password|change_me|placeholder)\S{6,}["\']?',
                       re.IGNORECASE | re.MULTILINE),
        ]
        findings = []
        for pattern in patterns:
            for m in pattern.finditer(raw):
                line = self._get_line_number(raw, m)
                val = m.group(0).strip()
                # Skip obviously templated values
                if any(x in val.lower() for x in ('example', 'change_me', 'your_', 'placeholder', 'xxx')):
                    continue
                findings.append({
                    'id': 'HEPH-CFG-050',
                    'title': 'Possible hardcoded credential in config file',
                    'severity': 'medium',
                    'confidence': 'low',
                    'description': (
                        "A line in the config file may contain a hardcoded credential or "
                        "reference to a password file. Review to ensure no secrets are exposed."
                    ),
                    'evidence': self._evidence(path, line, val[:100]),
                    'recommendation': (
                        "Use environment variables or secrets management tools instead of "
                        "hardcoded credentials. Ensure password files are outside the web root "
                        "and have restrictive permissions (chmod 600)."
                    ),
                    'owasp': {'id': 'A02', 'name': 'Cryptographic Failures'},
                    'affected_component': 'Authentication config',
                })
        # Deduplicate by line evidence
        seen = set()
        deduped = []
        for f in findings:
            key = f['evidence']['value']
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    # ─── PHP.ini checks ───────────────────────────────────────────────────────

    def _check_phpini(self, raw: str, path: str) -> List[Dict[str, Any]]:
        """Run all PHP.ini security checks."""
        findings = []
        findings.extend(self._php_expose_php(raw, path))
        findings.extend(self._php_display_errors(raw, path))
        findings.extend(self._php_allow_url_fopen(raw, path))
        findings.extend(self._php_allow_url_include(raw, path))
        findings.extend(self._php_disable_functions(raw, path))
        findings.extend(self._php_open_basedir(raw, path))
        findings.extend(self._php_session_cookie_secure(raw, path))
        findings.extend(self._php_session_cookie_httponly(raw, path))
        findings.extend(self._php_session_cookie_samesite(raw, path))
        findings.extend(self._php_upload_size(raw, path))
        findings.extend(self._php_register_globals(raw, path))
        return findings

    def _phpini_directive(self, raw: str, key: str) -> Optional[str]:
        """Extract value of a php.ini directive (key = value)."""
        pattern = re.compile(
            rf'^\s*{re.escape(key)}\s*=\s*(.+?)(\s*;.*)?$',
            re.IGNORECASE | re.MULTILINE
        )
        m = pattern.search(raw)
        if m:
            return m.group(1).strip().strip('"').strip("'")
        return None

    def _php_expose_php(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'expose_php')
        if val and val.lower() == 'on':
            line = self._get_line_number(raw, re.search(r'expose_php\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-060',
                'title': 'PHP version exposed in HTTP headers (expose_php = On)',
                'severity': 'low',
                'confidence': 'high',
                'description': 'expose_php=On adds X-Powered-By: PHP/x.x.x to all responses, revealing the exact PHP version.',
                'evidence': self._evidence(path, line, f'expose_php = {val}'),
                'recommendation': 'Set expose_php = Off in php.ini',
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
            }]
        return []

    def _php_display_errors(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'display_errors')
        if val and val.lower() in ('on', '1', 'stdout', 'stderr'):
            line = self._get_line_number(raw, re.search(r'display_errors\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-061',
                'title': 'PHP error messages displayed to users (display_errors = On)',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    'display_errors=On shows PHP errors, stack traces, and file paths to end users, '
                    'revealing application internals and sensitive paths.'
                ),
                'evidence': self._evidence(path, line, f'display_errors = {val}'),
                'recommendation': 'Set display_errors = Off and log_errors = On in php.ini',
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
            }]
        return []

    def _php_allow_url_fopen(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'allow_url_fopen')
        if val and val.lower() in ('on', '1'):
            line = self._get_line_number(raw, re.search(r'allow_url_fopen\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-062',
                'title': 'PHP allows remote URL file access (allow_url_fopen = On)',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    'allow_url_fopen=On enables file_get_contents() and similar functions to '
                    'fetch remote URLs, enabling SSRF if user-controlled input reaches these functions.'
                ),
                'evidence': self._evidence(path, line, f'allow_url_fopen = {val}'),
                'recommendation': 'Set allow_url_fopen = Off unless explicitly needed. Use curl for intentional HTTP requests.',
                'owasp': {'id': 'A10', 'name': 'Server-Side Request Forgery (SSRF)'},
            }]
        return []

    def _php_allow_url_include(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'allow_url_include')
        if val and val.lower() in ('on', '1'):
            line = self._get_line_number(raw, re.search(r'allow_url_include\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-063',
                'title': 'PHP Remote File Inclusion enabled (allow_url_include = On)',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    'allow_url_include=On allows include/require to load remote URLs, '
                    'enabling Remote File Inclusion (RFI). An attacker who controls a variable '
                    'passed to include() can execute arbitrary PHP code.'
                ),
                'evidence': self._evidence(path, line, f'allow_url_include = {val}'),
                'recommendation': 'Set allow_url_include = Off immediately. No legitimate production use case requires this.',
                'owasp': {'id': 'A03', 'name': 'Injection'},
            }]
        return []

    def _php_disable_functions(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'disable_functions')
        if val is not None and val.strip() == '':
            line = self._get_line_number(raw, re.search(r'disable_functions\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-064',
                'title': 'No PHP dangerous functions disabled (disable_functions is empty)',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    'disable_functions is empty, leaving exec(), system(), passthru(), '
                    'shell_exec(), popen(), and proc_open() available. '
                    'If an attacker achieves code execution, these functions enable full OS command execution.'
                ),
                'evidence': self._evidence(path, line, 'disable_functions = (empty)'),
                'recommendation': (
                    'Disable dangerous functions:\n'
                    'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pclose'
                ),
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
            }]
        return []

    def _php_open_basedir(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'open_basedir')
        # Not set = dangerous; empty string = dangerous
        if val is None or val.strip() == '':
            m = re.search(r'open_basedir\s*=', raw, re.I)
            line = self._get_line_number(raw, m) if m else 1
            return [{
                'id': 'HEPH-CFG-065',
                'title': 'PHP open_basedir not configured (unrestricted filesystem access)',
                'severity': 'medium',
                'confidence': 'medium',
                'description': (
                    'open_basedir is not set, allowing PHP scripts to read any file on the '
                    'filesystem. Combined with a file traversal vulnerability, this enables '
                    'reading /etc/passwd, config files, and other sensitive files.'
                ),
                'evidence': self._evidence(path, line, 'open_basedir = (not set)'),
                'recommendation': (
                    'Set open_basedir to restrict PHP filesystem access:\n'
                    'open_basedir = /var/www/html:/tmp'
                ),
                'owasp': {'id': 'A01', 'name': 'Broken Access Control'},
            }]
        return []

    def _php_session_cookie_secure(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'session.cookie_secure')
        if val is not None and val.lower() in ('0', 'off', 'false'):
            line = self._get_line_number(raw, re.search(r'session\.cookie_secure\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-066',
                'title': 'PHP session cookies not restricted to HTTPS (session.cookie_secure = Off)',
                'severity': 'medium',
                'confidence': 'high',
                'description': 'session.cookie_secure=Off allows PHP session cookies to be sent over HTTP, enabling interception.',
                'evidence': self._evidence(path, line, f'session.cookie_secure = {val}'),
                'recommendation': 'Set session.cookie_secure = On in php.ini (requires HTTPS)',
                'owasp': {'id': 'A02', 'name': 'Cryptographic Failures'},
            }]
        return []

    def _php_session_cookie_httponly(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'session.cookie_httponly')
        if val is not None and val.lower() in ('0', 'off', 'false'):
            line = self._get_line_number(raw, re.search(r'session\.cookie_httponly\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-067',
                'title': 'PHP session cookies accessible via JavaScript (session.cookie_httponly = Off)',
                'severity': 'medium',
                'confidence': 'high',
                'description': 'session.cookie_httponly=Off allows JavaScript to steal the PHP session cookie via XSS.',
                'evidence': self._evidence(path, line, f'session.cookie_httponly = {val}'),
                'recommendation': 'Set session.cookie_httponly = On in php.ini',
                'owasp': {'id': 'A07', 'name': 'Identification and Authentication Failures'},
            }]
        return []

    def _php_session_cookie_samesite(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'session.cookie_samesite')
        if val is None or val.strip() == '':
            m = re.search(r'session\.cookie_samesite\s*=', raw, re.I)
            line = self._get_line_number(raw, m) if m else 1
            return [{
                'id': 'HEPH-CFG-068',
                'title': 'PHP session cookies missing SameSite attribute',
                'severity': 'low',
                'confidence': 'medium',
                'description': 'session.cookie_samesite is not set, leaving PHP sessions vulnerable to CSRF attacks.',
                'evidence': self._evidence(path, line, 'session.cookie_samesite = (not set)'),
                'recommendation': 'Set session.cookie_samesite = Strict in php.ini (PHP 7.3+)',
                'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
            }]
        return []

    def _php_upload_size(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'upload_max_filesize')
        if val:
            # Convert to MB
            size_mb = self._parse_size_to_mb(val)
            if size_mb is not None and size_mb > 50:
                line = self._get_line_number(raw, re.search(r'upload_max_filesize\s*=', raw, re.I))
                return [{
                    'id': 'HEPH-CFG-069',
                    'title': f'PHP upload_max_filesize is very large ({val})',
                    'severity': 'low',
                    'confidence': 'medium',
                    'description': (
                        f'upload_max_filesize is set to {val} ({size_mb:.0f} MB). '
                        'Large upload limits enable resource exhaustion (DoS) and may allow '
                        'large malicious file uploads.'
                    ),
                    'evidence': self._evidence(path, line, f'upload_max_filesize = {val}'),
                    'recommendation': 'Set upload_max_filesize to the minimum needed (e.g., 10M) and validate file types server-side.',
                    'owasp': {'id': 'A05', 'name': 'Security Misconfiguration'},
                }]
        return []

    def _php_register_globals(self, raw: str, path: str) -> List[Dict[str, Any]]:
        val = self._phpini_directive(raw, 'register_globals')
        if val and val.lower() in ('on', '1'):
            line = self._get_line_number(raw, re.search(r'register_globals\s*=', raw, re.I))
            return [{
                'id': 'HEPH-CFG-070',
                'title': 'PHP register_globals enabled (critical legacy setting)',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    'register_globals=On is an extremely dangerous legacy PHP setting that was '
                    'removed in PHP 5.4. If somehow enabled, it automatically creates global '
                    'variables from user input (GET, POST, COOKIE), enabling trivial variable '
                    'injection attacks.'
                ),
                'evidence': self._evidence(path, line, f'register_globals = {val}'),
                'recommendation': 'Remove register_globals immediately. This setting should never be enabled.',
                'owasp': {'id': 'A03', 'name': 'Injection'},
            }]
        return []

    def _parse_size_to_mb(self, val: str) -> Optional[float]:
        """Parse PHP size string (128M, 1G, 512K) to MB."""
        val = val.strip().upper()
        m = re.match(r'^(\d+\.?\d*)\s*([KMG]?)$', val)
        if not m:
            return None
        num = float(m.group(1))
        unit = m.group(2)
        if unit == 'K':
            return num / 1024
        if unit == 'M':
            return num
        if unit == 'G':
            return num * 1024
        return num / (1024 * 1024)  # bytes to MB
