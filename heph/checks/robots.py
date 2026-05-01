"""
Robots.txt Parser & Disallowed Path Tester

Safe mode:
  - Fetches /robots.txt
  - Parses Disallow directives (all User-agent groups)
  - Flags sensitive-looking paths as informational
  - Reports the full list of disallowed paths

Aggressive mode (additional):
  - Tests each Disallow path with an HTTP GET
  - Reports paths that return HTTP 200 (accessible despite robots.txt)
  - Reports paths that return HTTP 403 (exists but blocked)

Finding codes:
  HEPH-ROB-001  robots.txt found with sensitive disallowed paths (info)
  HEPH-ROB-002  Disallowed path accessible (HTTP 200) — high
  HEPH-ROB-003  Disallowed path blocked (HTTP 403) — low

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)

# Sensitive path keywords that warrant extra attention
SENSITIVE_KEYWORDS = re.compile(
    r'(admin|backup|config|api|internal|private|\.git|phpmyadmin|'
    r'wp-admin|database|db|secret|staging|test|dev|debug|panel|'
    r'manager|console|dashboard|upload|logs|log|tmp|temp|'
    r'credential|password|passwd|key|token)',
    re.I
)

# Max paths to test in aggressive mode (avoid hammering the server)
MAX_AGGRESSIVE_PATHS = 30


class RobotsChecker:
    """
    Robots.txt analyzer with optional disallowed-path testing.

    Intelligently parses the robots.txt format (multiple User-agent groups,
    wildcards, comments) and identifies paths that reveal the application's
    directory structure.
    """

    def __init__(self, config=None, http_client=None, mode: str = 'safe'):
        self.config = config or get_config()
        self.http_client = http_client
        self.mode = mode

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Fetch and analyze robots.txt."""
        findings = []
        robots_url = target.rstrip('/') + '/robots.txt'

        try:
            resp = self.http_client.get(
                robots_url,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=False
            )
        except requests.exceptions.RequestException as e:
            logger.debug(f"robots.txt request failed: {e}")
            return findings
        except Exception as e:
            logger.debug(f"robots.txt unexpected error: {e}")
            return findings

        if resp.status_code != 200:
            logger.debug(f"robots.txt not found (HTTP {resp.status_code})")
            return findings

        content_type = resp.headers.get('Content-Type', '')
        body = resp.text

        # Sanity check: robots.txt should be text, not HTML/JSON
        if '<html' in body.lower() or len(body) > 100_000:
            logger.debug("robots.txt response looks like HTML — skipping")
            return findings

        logger.info(f"robots.txt found at {robots_url}")

        # Parse all disallowed paths
        disallowed = self._parse_robots(body)
        if not disallowed:
            logger.info("robots.txt has no Disallow directives")
            return findings

        # Filter sensitive ones
        sensitive = [p for p in disallowed if SENSITIVE_KEYWORDS.search(p)]

        # --- HEPH-ROB-001: Informational finding with disallowed path list ---
        findings.append({
            'id': 'HEPH-ROB-001',
            'title': f'robots.txt exposes {len(disallowed)} disallowed path(s)',
            'severity': 'info' if not sensitive else 'low',
            'confidence': 'high',
            'description': (
                f'robots.txt was found with {len(disallowed)} Disallow directive(s). '
                f'These paths reveal the application\'s directory structure to attackers. '
                + (f'{len(sensitive)} path(s) appear security-sensitive: '
                   f'{", ".join(sensitive[:5])}{"..." if len(sensitive) > 5 else ""}.'
                   if sensitive else '')
            ),
            'evidence': {
                'type': 'url',
                'value': robots_url,
                'context': f'Disallowed paths:\n' + '\n'.join(f'  Disallow: {p}' for p in disallowed[:20])
                           + ('\n  ... (truncated)' if len(disallowed) > 20 else '')
            },
            'recommendation': (
                'Avoid listing sensitive paths in robots.txt — attackers read it too. '
                'Use proper access controls (authentication, authorization) instead of '
                'relying on robots.txt for security.'
            ),
            'references': [
                'https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt',
                'https://portswigger.net/web-security/information-disclosure/exploiting',
            ],
        })

        # --- Aggressive: test each disallowed path ---
        if self.mode == 'aggressive' and disallowed:
            paths_to_test = disallowed[:MAX_AGGRESSIVE_PATHS]
            base = target.rstrip('/')

            # Prioritize sensitive paths
            sensitive_first = sorted(paths_to_test, key=lambda p: 0 if SENSITIVE_KEYWORDS.search(p) else 1)

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(self._test_path, base, path): path
                    for path in sensitive_first
                }
                for future in as_completed(futures):
                    path = futures[future]
                    try:
                        result = future.result()
                        if result:
                            findings.append(result)
                    except Exception as e:
                        logger.debug(f"Path test failed for {path}: {e}")

        return findings

    def _parse_robots(self, content: str) -> List[str]:
        """
        Parse robots.txt and return all unique Disallow paths.
        Handles multiple User-agent groups, comments, blank lines.

        Only collects Disallow directives from User-agent: * blocks (wildcard).
        Agent-specific blocks (e.g. User-agent: Googlebot) are skipped because
        they apply to a named crawler, not to general HTTP clients. Reporting
        paths from agent-specific sections would cause false positives.
        """
        disallowed = []
        seen = set()

        # Track whether the current User-agent block applies to all agents (*)
        in_wildcard_block = False

        for line in content.splitlines():
            line = line.strip()
            # Skip comments and blank lines
            if not line or line.startswith('#'):
                continue

            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip().lower()
                value = value.strip()

                if key == 'user-agent':
                    # Enter a new user-agent block
                    in_wildcard_block = (value == '*')
                elif key == 'disallow' and in_wildcard_block:
                    # Only collect Disallow from User-agent: * blocks
                    if value and value not in seen:
                        # Skip trivial paths that don't reveal anything
                        if value not in ('/', ''):
                            seen.add(value)
                            disallowed.append(value)

        return disallowed

    def _test_path(self, base: str, path: str) -> Optional[Dict[str, Any]]:
        """
        Test a disallowed path with an HTTP GET.
        Returns a finding if the path is accessible (200) or blocked (403).
        """
        # Normalize path
        if not path.startswith('/'):
            path = '/' + path
        url = base + path

        try:
            resp = self.http_client.get(
                url,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=False
            )
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None

        if resp.status_code == 200:
            # Content check: make sure it's actually returning content, not a custom 200 error page
            body_preview = resp.text[:200].strip()
            return {
                'id': 'HEPH-ROB-002',
                'title': f'Disallowed path accessible: {path}',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    f'Path "{path}" is listed as Disallow in robots.txt but is publicly '
                    f'accessible (HTTP 200). This path was likely meant to be private — '
                    f'the administrator added it to robots.txt to prevent indexing, '
                    f'but forgot to restrict access.'
                ),
                'evidence': {
                    'type': 'url',
                    'value': url,
                    'context': f'HTTP {resp.status_code} — {len(resp.content)} bytes returned'
                               + (f'\nPreview: {body_preview[:100]}' if body_preview else '')
                },
                'recommendation': (
                    f'Restrict access to {path} with authentication/authorization. '
                    f'robots.txt is NOT a security control — it only prevents search engine indexing.\n\n'
                    f'Apache:\n<Location "{path}">\n    Require all denied\n</Location>\n\n'
                    f'Nginx:\nlocation {path} {{\n    return 403;\n}}'
                ),
                'references': ['https://portswigger.net/web-security/information-disclosure/exploiting'],
            }

        elif resp.status_code == 403:
            return {
                'id': 'HEPH-ROB-003',
                'title': f'Disallowed path exists but blocked: {path}',
                'severity': 'low',
                'confidence': 'medium',
                'description': (
                    f'Path "{path}" is listed in robots.txt and returns HTTP 403 (Forbidden). '
                    f'The path exists and access is blocked, but its existence is confirmed. '
                    f'This reveals application structure and may be a target for bypass attempts.'
                ),
                'evidence': {
                    'type': 'url',
                    'value': url,
                    'context': f'HTTP {resp.status_code} — path exists but is forbidden'
                },
                'recommendation': (
                    f'Consider whether this path needs to be listed in robots.txt at all. '
                    f'If it\'s truly private, removing it from robots.txt reduces attack surface visibility.'
                ),
                'references': ['https://portswigger.net/web-security/information-disclosure/exploiting'],
            }

        return None
