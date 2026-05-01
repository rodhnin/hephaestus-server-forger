"""
OWASP Top 10 2021 Compliance Mapping for Hephaestus Findings

Maps each HEPH-XXX-XXX finding ID to its corresponding OWASP Top 10 2021 category.
Applied automatically during report generation — no changes needed in check modules.

Reference: https://owasp.org/Top10/

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

# OWASP Top 10 2021 categories
OWASP_CATEGORIES = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery (SSRF)',
}

# Mapping: finding ID → OWASP category ID
FINDING_TO_OWASP = {
    # =========================================================================
    # HEPH-SRV: Server Information Disclosure
    # =========================================================================
    'HEPH-SRV-001': 'A05',   # Server version disclosed — security misconfiguration
    'HEPH-SRV-002': 'A05',   # PHP version disclosed — security misconfiguration
    'HEPH-SRV-003': 'A05',   # Proxy information disclosed — info leakage
    'HEPH-SRV-004': 'A05',   # Server disclosed in error page — misconfiguration
    'HEPH-SRV-005': 'A05',   # Framework detected (Laravel/Django/Rails) — info disclosure
    'HEPH-SRV-006': 'A05',   # CMS/platform detected — info disclosure
    'HEPH-SRV-007': 'A06',   # Outdated server software — vulnerable component
    'HEPH-SRV-008': 'A05',   # Reverse proxy disclosed — topology leakage
    'HEPH-SRV-009': 'A05',   # WAF detected (info disclosure)
    'HEPH-SRV-010': 'A05',   # ASP.NET version disclosed
    'HEPH-SRV-016': 'A05',   # PHP version disclosed in Server header
    'HEPH-SRV-017': 'A05',   # OpenSSL version disclosed in Server header
    'HEPH-SRV-999': 'A05',   # Server header hidden (informational - good practice)

    # =========================================================================
    # HEPH-FILE: Sensitive File Exposure
    # =========================================================================
    'HEPH-FILE-001': 'A05',  # .env file exposed — critical misconfiguration
    'HEPH-FILE-002': 'A05',  # .git repository exposed — critical misconfiguration
    'HEPH-FILE-003': 'A05',  # phpinfo.php exposed — information disclosure
    'HEPH-FILE-004': 'A05',  # server-status / server-info exposed
    'HEPH-FILE-005': 'A05',  # .htpasswd exposed — credentials disclosure
    'HEPH-FILE-006': 'A05',  # web.config / nginx.conf exposed
    'HEPH-FILE-007': 'A05',  # composer.json / package.json exposed
    'HEPH-FILE-008': 'A05',  # backup file exposed (.zip, .sql, .tar.gz)
    'HEPH-FILE-009': 'A05',  # Log file exposed
    'HEPH-FILE-010': 'A05',  # Database dump exposed
    'HEPH-FILE-011': 'A05',  # SSH private key exposed
    'HEPH-FILE-012': 'A05',  # Certificate/key file exposed
    'HEPH-FILE-013': 'A05',  # Admin panel exposed (accessible)
    'HEPH-FILE-014': 'A05',  # Debug/diagnostic endpoint exposed
    'HEPH-FILE-015': 'A05',  # API credentials / config exposed
    'HEPH-FILE-403': 'A01',  # Sensitive path exists but access denied (confirms presence)
    'HEPH-FILE-999': 'A05',  # Other sensitive file exposed (catch-all)

    # =========================================================================
    # HEPH-HDR: Security Headers
    # =========================================================================
    'HEPH-HDR-001': 'A02',  # Missing HSTS — cryptographic/transport failure
    'HEPH-HDR-002': 'A05',  # Missing Content-Security-Policy — misconfiguration
    'HEPH-HDR-003': 'A05',  # Missing X-Frame-Options — clickjacking risk
    'HEPH-HDR-004': 'A05',  # Missing X-Content-Type-Options — MIME sniffing
    'HEPH-HDR-005': 'A05',  # Missing Referrer-Policy — info leakage
    'HEPH-HDR-006': 'A05',  # Missing Permissions-Policy — feature abuse
    'HEPH-HDR-007': 'A05',  # Missing X-XSS-Protection — XSS risk (legacy)
    'HEPH-HDR-008': 'A05',  # Insecure cookie flags (missing HttpOnly/Secure/SameSite)
    'HEPH-HDR-009': 'A05',  # CORS misconfiguration — access control bypass
    'HEPH-HDR-010': 'A05',  # Cache-Control missing — sensitive data caching
    'HEPH-HDR-401': 'A02',  # Cookie without Secure flag — cryptographic/transport failure
    'HEPH-HDR-402': 'A07',  # Cookie without HttpOnly flag — authentication failure
    'HEPH-HDR-403': 'A05',  # Cookie without SameSite — CSRF risk (misconfiguration)

    # =========================================================================
    # HEPH-HTTP: HTTP Methods
    # =========================================================================
    'HEPH-HTTP-001': 'A05',  # PUT method enabled — unauthorized write access
    'HEPH-HTTP-002': 'A05',  # DELETE method enabled — unauthorized delete access
    'HEPH-HTTP-003': 'A05',  # TRACE method enabled — cross-site tracing (XST)
    'HEPH-HTTP-004': 'A05',  # CONNECT method enabled — proxy abuse
    'HEPH-HTTP-005': 'A05',  # PATCH method enabled — unintended write access
    'HEPH-HTTP-006': 'A05',  # PUT method confirmed working (file upload)
    'HEPH-HTTP-007': 'A05',  # DELETE method confirmed working
    'HEPH-HTTP-008': 'A05',  # TRACE enabled via direct probe (XST)
    'HEPH-HTTP-009': 'A05',  # OPTIONS method discloses dangerous methods

    # =========================================================================
    # HEPH-TLS: TLS/SSL Configuration
    # =========================================================================
    'HEPH-TLS-000': 'A02',  # No TLS (plain HTTP) — cryptographic failure
    'HEPH-TLS-001': 'A02',  # Certificate expired — cryptographic failure
    'HEPH-TLS-002': 'A02',  # Certificate expiring soon
    'HEPH-TLS-003': 'A02',  # Certificate hostname mismatch
    'HEPH-TLS-004': 'A02',  # Self-signed certificate
    'HEPH-TLS-005': 'A02',  # TLS handshake failure
    'HEPH-TLS-006': 'A02',  # TLS connection error
    'HEPH-TLS-007': 'A02',  # SSLv3 supported (POODLE)
    'HEPH-TLS-008': 'A02',  # TLS 1.0 supported (deprecated)
    'HEPH-TLS-009': 'A02',  # TLS 1.1 supported (deprecated)
    'HEPH-TLS-010': 'A02',  # Weak cipher suite — inadequate encryption
    'HEPH-TLS-011': 'A02',  # No TLS 1.3 support — missing modern protocol
    'HEPH-TLS-012': 'A02',  # HSTS preload not configured
    'HEPH-TLS-013': 'A02',  # Certificate weak key (< 2048 RSA, < 256 ECDSA)
    'HEPH-TLS-014': 'A02',  # Certificate uses weak signature algorithm (SHA-1)
    'HEPH-TLS-015': 'A02',  # Missing OCSP stapling
    'HEPH-TLS-016': 'A02',  # Heartbleed vulnerability
    'HEPH-TLS-027': 'A02',  # TLS configuration grade (SSLyze computed)

    # =========================================================================
    # HEPH-CFG: Server Configuration
    # =========================================================================
    'HEPH-CFG-001': 'A05',  # Directory listing enabled — unauthorized file browsing
    'HEPH-CFG-002': 'A05',  # Server tokens full disclosure
    'HEPH-CFG-003': 'A05',  # mod_status exposed
    'HEPH-CFG-004': 'A05',  # Weak file permissions (config readable)
    'HEPH-CFG-005': 'A05',  # Default credentials / default page
    'HEPH-CFG-006': 'A09',  # Insufficient logging configuration
    'HEPH-CFG-007': 'A05',  # Open redirect via misconfiguration

    # =========================================================================
    # HEPH-CFG: PHP.ini offline analysis (Bloque 2)
    # =========================================================================
    'HEPH-CFG-060': 'A05',  # expose_php = On
    'HEPH-CFG-061': 'A05',  # display_errors = On
    'HEPH-CFG-062': 'A10',  # allow_url_fopen = On (SSRF risk)
    'HEPH-CFG-063': 'A03',  # allow_url_include = On (RFI)
    'HEPH-CFG-064': 'A05',  # disable_functions empty
    'HEPH-CFG-065': 'A01',  # open_basedir not set
    'HEPH-CFG-066': 'A02',  # session.cookie_secure = Off
    'HEPH-CFG-067': 'A07',  # session.cookie_httponly = Off
    'HEPH-CFG-068': 'A05',  # session.cookie_samesite not set
    'HEPH-CFG-069': 'A05',  # upload_max_filesize too large
    'HEPH-CFG-070': 'A03',  # register_globals = On (critical)

    # =========================================================================
    # HEPH-PHP: phpinfo() deep parsing (Bloque 2)
    # =========================================================================
    'HEPH-PHP-001': 'A05',  # expose_php = On (runtime)
    'HEPH-PHP-002': 'A05',  # display_errors = On (runtime)
    'HEPH-PHP-003': 'A10',  # allow_url_fopen = On (SSRF)
    'HEPH-PHP-004': 'A03',  # allow_url_include = On (RFI)
    'HEPH-PHP-005': 'A05',  # disable_functions empty
    'HEPH-PHP-006': 'A01',  # open_basedir not set
    'HEPH-PHP-007': 'A02',  # session.cookie_secure = Off
    'HEPH-PHP-008': 'A07',  # session.cookie_httponly = Off
    'HEPH-PHP-009': 'A05',  # session.cookie_samesite empty
    'HEPH-PHP-010': 'A06',  # Vulnerable PHP module version

    # =========================================================================
    # HEPH-COO: Cookie security global check (Bloque 2)
    # =========================================================================
    'HEPH-COO-001': 'A02',  # Session cookie missing Secure flag
    'HEPH-COO-002': 'A07',  # Session cookie missing HttpOnly flag
    'HEPH-COO-003': 'A05',  # Cookie missing SameSite
    'HEPH-COO-004': 'A02',  # SameSite=None without Secure (critical)
    'HEPH-COO-005': 'A07',  # Session cookie missing all flags

    # =========================================================================
    # HEPH-COR: CORS misconfiguration (Bloque 2)
    # =========================================================================
    'HEPH-COR-001': 'A01',  # ACAO=* + ACAC=true (critical)
    'HEPH-COR-002': 'A01',  # ACAO=* alone (medium)
    'HEPH-COR-003': 'A01',  # CORS reflection + credentials (critical)
    'HEPH-COR-004': 'A01',  # CORS reflection alone (high)
    'HEPH-COR-005': 'A01',  # ACAO=null + ACAC=true (critical — null-origin exploitation)
    'HEPH-COR-006': 'A01',  # ACAO=null alone (medium)

    # =========================================================================
    # HEPH-ROB: Robots.txt analysis (Bloque 2)
    # =========================================================================
    'HEPH-ROB-001': 'A05',  # Robots.txt with sensitive disallowed paths
    'HEPH-ROB-002': 'A01',  # Disallowed path accessible (HTTP 200)
    'HEPH-ROB-003': 'A05',  # Disallowed path blocked (HTTP 403)

    # =========================================================================
    # HEPH-WAF: WAF detection (Bloque 2)
    # =========================================================================
    'HEPH-WAF-001': 'A05',  # WAF detected via headers (info)
    'HEPH-WAF-002': 'A05',  # WAF confirmed by blocking behavior (info)

    # =========================================================================
    # HEPH-API: API discovery (Bloque 2)
    # =========================================================================
    'HEPH-API-001': 'A05',  # Swagger/OpenAPI spec exposed
    'HEPH-API-002': 'A05',  # GraphQL endpoint accessible
    'HEPH-API-003': 'A05',  # API root directory accessible
    'HEPH-API-004': 'A01',  # Unauthenticated API endpoint
    'HEPH-API-005': 'A05',  # GraphQL introspection enabled
}


def get_owasp(finding_id: str) -> dict:
    """
    Return OWASP Top 10 2021 mapping for a finding ID.

    Returns a dict with 'id' and 'name', or None if no mapping exists.

    Example:
        get_owasp('HEPH-TLS-001')
        → {'id': 'A02', 'name': 'Cryptographic Failures'}
    """
    category_id = FINDING_TO_OWASP.get(finding_id)
    if category_id is None:
        return None
    return {
        'id': category_id,
        'name': OWASP_CATEGORIES[category_id],
    }


def enrich_findings_with_owasp(findings: list) -> list:
    """
    Add 'owasp' field to each finding that has a known mapping.
    Modifies findings in-place and returns the list.
    """
    for finding in findings:
        fid = finding.get('id', '')
        mapping = get_owasp(fid)
        if mapping:
            finding['owasp'] = mapping
    return findings
