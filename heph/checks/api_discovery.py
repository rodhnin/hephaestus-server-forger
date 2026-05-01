"""
API Discovery & Documentation Exposure Checker

Safe mode:
  - Checks ~30 common API/documentation paths
  - Detects exposed Swagger UI, OpenAPI specs, GraphQL endpoints, REST API roots
  - Content-type aware: validates JSON/YAML responses

Aggressive mode (additional):
  - Parses found OpenAPI/Swagger specs and extracts all endpoint paths
  - Sends GraphQL introspection query to map the full schema
  - Probes discovered endpoints to identify unauthenticated access

Finding codes:
  HEPH-API-001  Swagger/OpenAPI spec exposed (high)
  HEPH-API-002  GraphQL endpoint exposed (medium)
  HEPH-API-003  API directory accessible (medium)
  HEPH-API-004  Unauthenticated API endpoint (high) — aggressive only
  HEPH-API-005  GraphQL introspection enabled (medium) — aggressive only

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import json
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)

# --- Static paths to check ---
SWAGGER_PATHS = [
    '/swagger.json',
    '/swagger.yaml',
    '/swagger/v1/swagger.json',
    '/swagger/v2/swagger.json',
    '/swagger/index.html',
    '/swagger-ui/',
    '/swagger-ui.html',
    '/swagger-ui/index.html',
    '/api/swagger.json',
    '/api/swagger',
    '/api-docs',
    '/api-docs/',
    '/api-docs/swagger.json',
    '/openapi.json',
    '/openapi.yaml',
    '/api/openapi.json',
    '/.well-known/openapi',
    '/redoc',
    '/redoc/',
    '/docs/',
    '/docs/api',
    '/api/docs',
    '/v1/api-docs',
    '/v2/api-docs',
    '/v3/api-docs',
    '/api/v1/swagger',
    '/api/v2/swagger',
]

GRAPHQL_PATHS = [
    '/graphql',
    '/graphiql',
    '/graphql/console',
    '/graphql/playground',
    '/api/graphql',
    '/query',
    '/gql',
]

API_ROOT_PATHS = [
    '/api/',
    '/api/v1/',
    '/api/v2/',
    '/api/v3/',
    '/rest/',
    '/rest/v1/',
    '/v1/',
    '/v2/',
    '/v3/',
    '/services/',
    '/ws/',
]

# GraphQL introspection query
GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name kind}}}"}'

# Max endpoints to probe from parsed OpenAPI spec
MAX_SPEC_ENDPOINTS = 20


class APIDiscoveryChecker:
    """
    API surface discovery checker.

    Intelligently detects exposed API documentation, GraphQL endpoints,
    and accessible REST API directories that reveal the application's
    attack surface.
    """

    def __init__(self, config=None, http_client=None, mode: str = 'safe'):
        self.config = config or get_config()
        self.http_client = http_client
        self.mode = mode

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Discover exposed API endpoints and documentation."""
        findings = []
        base = target.rstrip('/')

        # Track found specs/endpoints for aggressive follow-up
        found_specs = []

        # --- Check Swagger/OpenAPI paths ---
        for path in SWAGGER_PATHS:
            url = base + path
            result = self._check_swagger_path(url, path)
            if result:
                findings.append(result)
                if result.get('_spec_url'):
                    found_specs.append(result['_spec_url'])
                    del result['_spec_url']

        # --- Check GraphQL paths ---
        graphql_url = None
        for path in GRAPHQL_PATHS:
            url = base + path
            result = self._check_graphql_path(url, path)
            if result:
                findings.append(result)
                graphql_url = url
                break  # One GraphQL endpoint is enough to flag

        # --- Check API root directories ---
        for path in API_ROOT_PATHS:
            url = base + path
            result = self._check_api_root(url, path)
            if result:
                findings.append(result)
                break  # Report first accessible API root only

        # --- Aggressive: parse specs + probe endpoints ---
        if self.mode == 'aggressive':
            if found_specs:
                for spec_url in found_specs[:2]:  # Max 2 specs
                    extra = self._probe_spec_endpoints(base, spec_url)
                    findings.extend(extra)

            if graphql_url:
                result = self._test_graphql_introspection(graphql_url)
                if result:
                    findings.append(result)

        # Remove internal fields
        for f in findings:
            f.pop('_spec_url', None)

        return findings

    def _check_swagger_path(self, url: str, path: str) -> Optional[Dict[str, Any]]:
        """Check if a Swagger/OpenAPI path is accessible and valid."""
        try:
            resp = self.http_client.get(
                url,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=True
            )
        except requests.exceptions.RequestException:
            return None
        except Exception as e:
            logger.debug(f"API swagger check error for {url}: {e}")
            return None

        if resp.status_code != 200:
            return None

        content_type = resp.headers.get('Content-Type', '').lower()
        body = resp.text[:5000]

        # Validate it's actually a spec or Swagger UI
        is_json_spec = ('json' in content_type or url.endswith('.json')) and self._looks_like_openapi(body)
        is_yaml_spec = ('yaml' in content_type or url.endswith('.yaml')) and ('openapi:' in body or 'swagger:' in body)
        is_swagger_ui = 'swagger-ui' in body.lower() or 'swagger' in body.lower() and '<html' in body.lower()
        is_redoc = 'redoc' in body.lower() and '<html' in body.lower()

        if not (is_json_spec or is_yaml_spec or is_swagger_ui or is_redoc):
            return None

        # Determine what was found
        if is_json_spec or is_yaml_spec:
            title_match = re.search(r'"title"\s*:\s*"([^"]+)"', body)
            api_title = title_match.group(1) if title_match else 'API'
            desc = (
                f'API specification ({api_title}) is publicly accessible at {url}. '
                f'This document reveals all API endpoints, parameters, request/response '
                f'schemas, and authentication methods. Attackers use this to map the '
                f'full attack surface without needing to discover endpoints manually.'
            )
            spec_url = url
        else:
            desc = (
                f'Swagger UI / API documentation interface is publicly accessible at {url}. '
                f'This interactive interface reveals all API endpoints and allows '
                f'testing them directly from the browser without authentication.'
            )
            spec_url = None

        finding = {
            'id': 'HEPH-API-001',
            'title': f'API documentation exposed: {path}',
            'severity': 'high',
            'confidence': 'high',
            'description': desc,
            'evidence': {
                'type': 'url',
                'value': url,
                'context': f'HTTP {resp.status_code} — {len(resp.content)} bytes\n'
                           f'Content-Type: {content_type}'
            },
            'recommendation': (
                'Restrict access to API documentation to internal networks or authenticated users.\n\n'
                'Nginx:\nlocation /swagger {\n    allow 10.0.0.0/8;\n    deny all;\n}\n\n'
                'Or require authentication before serving documentation.'
            ),
            'references': [
                'https://portswigger.net/web-security/api-testing',
                'https://owasp.org/www-project-api-security/',
            ],
        }

        if spec_url:
            finding['_spec_url'] = spec_url

        logger.info(f"API documentation found: {url}")
        return finding

    def _check_graphql_path(self, url: str, path: str) -> Optional[Dict[str, Any]]:
        """Check if a GraphQL endpoint is accessible."""
        try:
            # Try POST with minimal query first (more reliable)
            resp = self.http_client.post(
                url,
                json={'query': '{__typename}'},
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=True
            )
        except requests.exceptions.RequestException:
            return None
        except Exception as e:
            logger.debug(f"GraphQL check error for {url}: {e}")
            return None

        if resp.status_code not in (200, 400):
            return None

        body = resp.text
        content_type = resp.headers.get('Content-Type', '').lower()

        # GraphQL always returns JSON with 'data' or 'errors' key
        is_graphql = (
            'json' in content_type and
            ('"data"' in body or '"errors"' in body or '__typename' in body)
        )

        if not is_graphql:
            # Try GET for GraphiQL interface
            try:
                resp_get = self.http_client.get(
                    url,
                    timeout=(self.config.timeout_connect, self.config.timeout_read),
                    allow_redirects=True
                )
                if resp_get.status_code == 200 and 'graphiql' in resp_get.text.lower():
                    is_graphql = True
                    body = resp_get.text
            except Exception:
                pass

        if not is_graphql:
            return None

        logger.info(f"GraphQL endpoint found: {url}")
        return {
            'id': 'HEPH-API-002',
            'title': f'GraphQL endpoint accessible: {path}',
            'severity': 'medium',
            'confidence': 'high',
            'description': (
                f'GraphQL endpoint is publicly accessible at {url}. '
                f'GraphQL endpoints are powerful — if introspection is enabled, '
                f'attackers can discover the entire schema (all types, queries, mutations). '
                f'GraphQL also requires careful authorization on every resolver to prevent '
                f'unauthorized data access.'
            ),
            'evidence': {
                'type': 'url',
                'value': url,
                'context': f'HTTP {resp.status_code} — GraphQL response detected\n{body[:200]}'
            },
            'recommendation': (
                'Disable introspection in production:\n\n'
                'Apollo Server: introspection: false\n'
                'Strawberry/Ariadne: Set disable_introspection=True\n\n'
                'Implement depth limiting, query complexity limits, and field-level authorization.'
            ),
            'references': [
                'https://owasp.org/www-project-api-security/',
                'https://www.apollographql.com/docs/router/configuration/persisted-queries/',
            ],
        }

    def _check_api_root(self, url: str, path: str) -> Optional[Dict[str, Any]]:
        """Check if an API root directory returns meaningful data."""
        try:
            resp = self.http_client.get(
                url,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
                allow_redirects=True
            )
        except requests.exceptions.RequestException:
            return None
        except Exception as e:
            logger.debug(f"API root check error for {url}: {e}")
            return None

        if resp.status_code != 200:
            return None

        content_type = resp.headers.get('Content-Type', '').lower()
        body = resp.text[:1000]

        # Only flag if it returns JSON (a real API) or directory listing
        is_json_api = 'json' in content_type and ('{' in body or '[' in body)
        is_directory_listing = ('index of' in body.lower() or 'directory listing' in body.lower())

        if not (is_json_api or is_directory_listing):
            return None

        logger.info(f"API root accessible: {url}")
        return {
            'id': 'HEPH-API-003',
            'title': f'API root directory accessible: {path}',
            'severity': 'medium',
            'confidence': 'medium',
            'description': (
                f'API root at {url} is publicly accessible and returns '
                f'{"JSON data" if is_json_api else "directory listing"}. '
                f'This reveals the API structure and may allow enumeration of endpoints, '
                f'versions, and data without authentication.'
            ),
            'evidence': {
                'type': 'url',
                'value': url,
                'context': f'HTTP {resp.status_code} — {content_type}\nPreview: {body[:200]}'
            },
            'recommendation': (
                'Ensure API endpoints require authentication. '
                'Remove directory listings and implement proper access control on API roots.'
            ),
            'references': ['https://owasp.org/www-project-api-security/'],
        }

    def _probe_spec_endpoints(self, base: str, spec_url: str) -> List[Dict[str, Any]]:
        """
        Parse an OpenAPI/Swagger spec and probe discovered endpoints.
        Aggressive mode only.
        """
        findings = []

        try:
            resp = self.http_client.get(
                spec_url,
                timeout=(self.config.timeout_connect, self.config.timeout_read),
            )
            if resp.status_code != 200:
                return findings
            spec = resp.json()
        except Exception as e:
            logger.debug(f"Failed to parse spec at {spec_url}: {e}")
            return findings

        # Extract paths from OpenAPI 3.x or Swagger 2.x
        paths = spec.get('paths', {})
        if not paths:
            return findings

        # Extract base path for Swagger 2.x
        base_path = spec.get('basePath', '')
        if not base_path.startswith('/'):
            base_path = '/' + base_path

        # Test GET endpoints (safe methods only — no POST/DELETE)
        tested = 0
        for path, methods in paths.items():
            if tested >= MAX_SPEC_ENDPOINTS:
                break
            if 'get' not in {k.lower() for k in methods.keys()}:
                continue
            # Reconstruct URL — replace path params with test values
            clean_path = re.sub(r'\{[^}]+\}', '1', path)
            url = base.rstrip('/') + base_path.rstrip('/') + clean_path

            try:
                r = self.http_client.get(
                    url,
                    timeout=(self.config.timeout_connect, self.config.timeout_read),
                    allow_redirects=False
                )
                tested += 1
                if r.status_code == 200:
                    content_type = r.headers.get('Content-Type', '').lower()
                    if 'json' in content_type:
                        findings.append({
                            'id': 'HEPH-API-004',
                            'title': f'Unauthenticated API endpoint: {path}',
                            'severity': 'high',
                            'confidence': 'medium',
                            'description': (
                                f'API endpoint "{path}" (from OpenAPI spec at {spec_url}) '
                                f'is accessible without authentication and returns JSON data. '
                                f'Sensitive data may be exposed.'
                            ),
                            'evidence': {
                                'type': 'url',
                                'value': url,
                                'context': f'HTTP {r.status_code} — {r.headers.get("Content-Type", "")}\n'
                                           f'Preview: {r.text[:200]}'
                            },
                            'recommendation': (
                                f'Implement authentication on all API endpoints. '
                                f'Review whether "{path}" should be publicly accessible.'
                            ),
                            'references': ['https://owasp.org/www-project-api-security/'],
                        })
            except Exception:
                pass

        return findings

    def _test_graphql_introspection(self, graphql_url: str) -> Optional[Dict[str, Any]]:
        """Test if GraphQL introspection is enabled."""
        try:
            resp = self.http_client.post(
                graphql_url,
                json=json.loads(GRAPHQL_INTROSPECTION),
                timeout=(self.config.timeout_connect, self.config.timeout_read),
            )
        except Exception as e:
            logger.debug(f"GraphQL introspection test failed: {e}")
            return None

        if resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        # Introspection returns types array
        types = data.get('data', {}).get('__schema', {}).get('types', [])
        if not types:
            return None

        type_names = [t.get('name', '') for t in types[:10]]
        logger.info(f"GraphQL introspection enabled: {len(types)} types found")

        return {
            'id': 'HEPH-API-005',
            'title': 'GraphQL introspection enabled in production',
            'severity': 'medium',
            'confidence': 'high',
            'description': (
                f'GraphQL introspection is enabled, revealing the complete API schema. '
                f'{len(types)} types discovered including: {", ".join(t for t in type_names if t)}. '
                f'Attackers use introspection to discover all queries, mutations, fields, '
                f'and data types — the equivalent of a full API documentation leak.'
            ),
            'evidence': {
                'type': 'url',
                'value': graphql_url,
                'context': f'Introspection returned {len(types)} schema types\n'
                           f'Types: {", ".join(type_names)}'
            },
            'recommendation': (
                'Disable introspection in production environments:\n\n'
                'Apollo Server:\nintrospection: process.env.NODE_ENV !== "production"\n\n'
                'Strawberry (Python):\n@strawberry.type\nclass Query:\n    ...\nschema = strawberry.Schema(query=Query)\n'
                '# Use DisableIntrospection extension\n\n'
                'Use persisted queries to limit what clients can execute.'
            ),
            'references': [
                'https://owasp.org/www-project-api-security/',
                'https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/',
            ],
        }

    def _looks_like_openapi(self, body: str) -> bool:
        """Quick check if body looks like an OpenAPI/Swagger JSON spec."""
        return any(k in body for k in ('"openapi"', '"swagger"', '"paths"', '"info"'))
