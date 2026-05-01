# Changelog

All notable changes to Hephaestus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-04-01

**Bloque 1 — Deep Detection & AI Enhancement** 🔥

This release doubles Hephaestus's detection surface and adds full AI cost tracking, streaming, agent mode, and multi-model comparison. Every v0.2.0 ticket has been implemented, tested against Apache and Nginx Docker labs, and validated against the JSON schema.

---

### Added

#### Deep TLS/SSL Analysis (IMPROV-002)

- Full cipher suite analysis via SSLyze integration
- SSL Labs-style grading: A+ / A / B / C / D / F per finding
- Protocol detection: TLS 1.3, 1.2, 1.1, 1.0, SSLv3, SSLv2
- Certificate validation: expiry, self-signed, hostname mismatch, SHA-1/MD5 signatures
- Vulnerability checks: POODLE, DROWN, BEAST, CRIME, Heartbleed, ROBOT, FREAK, Logjam
- Forward secrecy detection (ECDHE/DHE)
- CVE enrichment per cipher/protocol finding with CVSS scores
- New finding codes: `HEPH-TLS-002` to `HEPH-TLS-010`
- New field `tls_grade` added to findings schema

#### Framework & Module Detection (IMPROV-003)

- Web framework detection: Laravel, Django, Ruby on Rails, Node.js/Express, ASP.NET, Spring
- Application server detection: Tomcat, Gunicorn, uWSGI, Phusion Passenger
- Reverse proxy detection: Cloudflare, AWS CloudFront, Nginx proxy cache
- Apache module hints from `server-info` page and response headers
- Detection by headers, cookies, error pages, and response patterns — zero extra requests in safe mode
- New finding codes under `HEPH-SRV-005+`

#### Enhanced HTML Report (IMPROV-004)

- **Filter bar**: filter findings by severity (All / Critical / High / Medium / Low / Info) with live counts
- **CVE/CWE badges**: inline badges on each finding with NVD links
- **OWASP Top 10 2021 badges**: A01–A10 tags on each applicable finding
- **AI analysis tabs**: Standard (executive + technical), Agent, and Compare mode rendered as tabs
- **Diff section**: "N New / N Fixed / N Persisting" summary with color-coded counters at top of report
- **Markdown → HTML conversion**: agent analysis and compare mode results render with proper formatting
- **path-type evidence**: config file paths render as `<code>` blocks instead of plain text
- Expandable finding cards with smooth animations
- Self-contained (all CSS/JS inline — no external dependencies)

#### Apache/Nginx Configuration File Parser (IMPROV-005)

New `--config-file PATH` flag for offline analysis without a live server:

**Apache httpd.conf checks:**

- `ServerTokens` not set to `Prod`/`ProductOnly` (`HEPH-CFG-011`)
- `ServerSignature On` (`HEPH-CFG-012`)
- `TraceEnable On` — XST vulnerability (`HEPH-CFG-013`)
- `Options Indexes` — directory listing (`HEPH-CFG-014`)
- `expose_php = On` (`HEPH-CFG-015`)
- Weak `SSLProtocol` (includes TLSv1.0, SSLv3, SSLv2) (`HEPH-CFG-016`)
- Weak `SSLCipherSuite` (RC4, 3DES, NULL, EXPORT, MD5, aNULL, eNULL) (`HEPH-CFG-017`)
- `AllowOverride All` — unrestricted .htaccess (`HEPH-CFG-018`)
- Missing `LimitRequestBody` — DoS risk (`HEPH-CFG-019`)
- Missing security headers via `mod_headers` (`HEPH-CFG-020` to `HEPH-CFG-024`)

**Nginx nginx.conf checks:**

- `server_tokens on` (`HEPH-CFG-030`)
- `autoindex on` — deduplicated across all location blocks with line numbers (`HEPH-CFG-031`)
- Weak `ssl_protocols` (`HEPH-CFG-032`)
- Weak `ssl_ciphers` (`HEPH-CFG-033`)
- Missing `client_max_body_size` — DoS risk (`HEPH-CFG-034`)
- Missing security headers via `add_header` (`HEPH-CFG-040` to `HEPH-CFG-044`)

**Generic (both server types):**

- Hardcoded credentials detection — passwords, secrets, API keys in config (`HEPH-CFG-050`)
- `HEPH-CFG-099`: info finding when config is clean

**Modes:**

- Standalone: `heph --config-file /etc/nginx/nginx.conf` (offline, no target needed)
- Combined: `heph --target http://... --config-file /etc/httpd/httpd.conf` (live scan + offline config)
- Auto-detects Apache vs Nginx by filename and content scoring
- Report `mode` field set to `"offline"` for standalone analysis

#### AI Cost Tracking & Budget (IMPROV-006)

- `--ai-budget FLOAT`: set max USD spend per scan
- 80% warning threshold shown during scan
- 100% exceeded message with exact cost and percentage
- Cost written to `~/.argos/costs.json` with `tool: "hephaestus"` field
- Cost stored in `ai_costs` table in shared `~/.argos/argos.db`
- `ai_analysis.cost` object in JSON report: `total_usd`, `provider`, `model`
- `AICostTracker` class tracks input/output tokens per call

#### AI Streaming Responses (IMPROV-007)

- `--ai-stream`: stream AI output token-by-token to console during generation
- Live progress visible — no more waiting blind for 30+ seconds
- Works with OpenAI and Anthropic providers
- Streaming output captured and written to report after completion

#### AI Agent Mode (IMPROV-008)

- `--ai-agent`: LangChain agent with NVD CVE lookup tool
- Agent performs real NVD API v2 calls during analysis (7 calls typical per scan)
- CVE IDs, CVSS scores, and descriptions enriched in agent output
- Agent analysis stored in `ai_analysis.agent_analysis` field
- Rendered in HTML report as dedicated "Agent Analysis" tab

#### AI Compare Mode (NEW)

- `--ai-compare PROVIDER1:MODEL1,PROVIDER2:MODEL2`: run two providers in parallel
- Results stored as `ai_analysis.results` per-provider dict
- Rendered as tabbed comparison in HTML report
- `ai_analysis.comparison_mode: true` and `providers_compared` array in JSON

#### Live CVE Lookup (NEW — not in original roadmap)

- `heph/core/cve_lookup.py`: NVD API v2 primary + CIRCL.lu fallback
- CPE vendor normalization for nginx (`f5`), mysql (`oracle`), redis (`redis`)
- Empty version guard — no false CVEs for undetected components
- Called automatically during server fingerprinting, TLS, and port scanning phases

#### Port Scanner (NEW — not in original roadmap)

- `heph/checks/ports.py`: 37 common ports
- Banner grabbing on open ports
- Web framework detection on HTTP ports
- CVE enrichment for detected service versions

#### Multi-Component Server Header Parsing (NEW)

- PHP version and OpenSSL version extracted from Apache `Server:` header
- Generates separate findings `HEPH-SRV-016` (PHP) and `HEPH-SRV-017` (OpenSSL) with full CVE enrichment

#### CORS Misconfiguration Detection — Phase 8 (NEW)

- `heph/checks/cors.py`: dedicated CORS analysis phase running in parallel with other checks
- **Static analysis**: checks `Access-Control-Allow-Origin` on main page and common API paths (`/`, `/api/`, `/api/v1/`, `/graphql`)
- **Null-origin probe**: actively sends `Origin: null` to detect servers that reflect null (exploitable via sandboxed iframes and `file://` pages)
- **Reflection probe** (aggressive mode): sends controlled evil origin and checks if server mirrors it back
- Finding codes:
    - `HEPH-COR-001` (critical): ACAO=`*` + ACAC=`true` — wildcard with credentials
    - `HEPH-COR-002` (medium): ACAO=`*` alone
    - `HEPH-COR-003` (critical): origin reflection + credentials — session theft possible
    - `HEPH-COR-004` (high): origin reflection without credentials
    - `HEPH-COR-005` (critical): ACAO=`null` + ACAC=`true` — null-origin with credentials
    - `HEPH-COR-006` (medium): ACAO=`null` alone
- Deduplication by `(finding_id, evidence_url)` — same misconfiguration on different endpoints reported separately

#### Robots.txt Intelligence — Phase 9 (NEW)

- `heph/checks/robots.py`: parses `robots.txt` and cross-references disallowed paths with live accessibility
- **User-agent aware parsing**: only analyzes `User-agent: *` blocks — bot-specific rules (Googlebot, etc.) are ignored to prevent false positives
- **Safe mode**: reports sensitive path names disclosed in `Disallow` directives
- **Aggressive mode**: probes each disallowed path to determine if it's actually accessible (200) or blocked (403/404)
- Finding codes:
    - `HEPH-ROB-001` (low): robots.txt discloses N sensitive paths (admin, backup, api, config, etc.)
    - `HEPH-ROB-002` (high): disallowed path is publicly accessible — security through obscurity failed
    - `HEPH-ROB-003` (low): disallowed path exists but is properly blocked (confirms presence)
- Sensitive path keyword matching: admin, backup, config, api, internal, database, private, staging, git, phpmyadmin

#### WAF Detection — Phase 10 (NEW)

- `heph/checks/waf.py`: detects Web Application Firewalls via header fingerprinting and behavioral analysis
- **13 WAF signatures**: Cloudflare, AWS CloudFront, AWS WAF, Sucuri, ModSecurity, Imperva/Incapsula, Akamai, Barracuda, F5 BIG-IP, Nginx ModSecurity, Reblaze, StackPath, Fastly
- **Detection methods**: response headers, `Server` header pattern, `X-Protected-By` header, request blocking behavior (sends probe with SQL injection pattern)
- **Confidence levels**: high (multiple matching headers), medium (single proprietary header), low (behavioral only)
- Finding codes:
    - `HEPH-WAF-001` (info): WAF detected via header analysis — identifies vendor by name
    - `HEPH-WAF-002` (info): WAF confirmed by blocking behavior (probe request was intercepted)
- Informational severity — WAF is a security positive, reported for asset mapping context

#### API Discovery — Phase 11 (NEW)

- `heph/checks/api_discovery.py`: discovers exposed API documentation and unauthenticated endpoints
- **Probes 7 paths**: `/swagger.json`, `/swagger-ui.html`, `/openapi.json`, `/api-docs`, `/graphql`, `/api/`, `/api/v1/`
- **Content validation**: validates OpenAPI/Swagger JSON structure before flagging (no false positives on files that return 200 with HTML)
- **GraphQL introspection**: sends `{__schema{types{name}}}` POST query and checks if `types` array is returned
- Finding codes:
    - `HEPH-API-001` (high): Swagger/OpenAPI specification exposed — full API surface disclosed
    - `HEPH-API-002` (high): GraphQL endpoint accessible
    - `HEPH-API-003` (medium): API root directory accessible without authentication
    - `HEPH-API-004` (high): unauthenticated API endpoint responding with data
    - `HEPH-API-005` (medium): GraphQL introspection enabled — full schema enumerable

#### Cookie Security Analysis — Phase 12 (NEW)

- `heph/checks/cookies.py`: dedicated cookie security phase scanning multiple authenticated paths
- **Multi-cookie detection**: uses `response.raw.headers.getlist('Set-Cookie')` to correctly enumerate all cookies from a response (prevents missed cookies when server sets 3+ cookies)
- **Deduplication**: tracks cookie names seen across paths via `seen_cookies` set — same cookie from multiple paths reported once
- **Context-aware Secure flag**: only flags missing `Secure` on HTTPS targets (HTTP targets: flag not applicable)
- **Probes 7 paths**: `/`, `/login`, `/dashboard`, `/account`, `/admin`, `/api/`, `/api/v1/`
- Finding codes:
    - `HEPH-COO-001` (high): session cookie missing `Secure` flag (HTTPS target only)
    - `HEPH-COO-002` (medium): session cookie missing `HttpOnly` flag
    - `HEPH-COO-003` (low): cookie missing `SameSite` attribute
    - `HEPH-COO-004` (critical): `SameSite=None` without `Secure` flag
    - `HEPH-COO-005` (high): session cookie missing all three security flags
- Also raises `HEPH-HDR-401/402/403` from the headers phase for cookies found on the root response

#### phpinfo() Deep Analysis — Phase 13 (NEW)

- `heph/checks/phpinfo.py`: fetches and parses `phpinfo()` output for dangerous PHP configuration
- **Content validation**: checks that the fetched page actually contains phpinfo output before parsing (prevents false positives on pages that happen to be named `phpinfo.php` but return generic HTML)
- **Probes common paths**: `phpinfo.php`, `info.php`, `phpinfo/`, `test.php?phpinfo=1`
- **Detects 9 dangerous settings** with pattern matching against phpinfo table output:
    - `expose_php = On` → `HEPH-PHP-001` (low): PHP version disclosed via `X-Powered-By`
    - `display_errors = On` → `HEPH-PHP-002` (medium): stack traces exposed to users
    - `allow_url_fopen = On` → `HEPH-PHP-003` (medium): remote URL file access enabled (SSRF risk)
    - `allow_url_include = On` → `HEPH-PHP-004` (high): Remote File Inclusion enabled (RFI)
    - `disable_functions` empty → `HEPH-PHP-005` (medium): no dangerous functions blocked
    - `open_basedir` not set → `HEPH-PHP-006` (medium): unrestricted filesystem access
    - `session.cookie_secure = Off` (or `no value`) → `HEPH-PHP-007` (medium): session cookies over HTTP
    - `session.cookie_httponly = Off` (or `no value`) → `HEPH-PHP-008` (medium): session cookies JS-accessible
    - `session.cookie_samesite` empty → `HEPH-PHP-009` (low): no SameSite on session cookies
- Handles PHP 7.x `no value` display (unset settings that default to Off)

#### Diff Reports

- `--diff last` or `--diff SCAN_ID`: compare current scan against a previous one
- Reports new findings, fixed findings, and persisting findings
- Cross-tool protection: rejects diff against Argus/other tool scan IDs with clear error
- `diff` section added to JSON report top-level (schema v0.2.0)
- HTML report shows diff summary badges at the top

#### OWASP Top 10 2021 Mapping

- `heph/core/owasp.py`: maps all HEPH-\* finding codes to OWASP categories
- `owasp` field (`id` + `name`) on every finding in JSON output
- Rendered as badges in HTML report

---

### Changed

- Default AI model updated to `gpt-4o-mini-2024-07-18` (same as Argus)
- `--ai-provider` and `--ai-model` now available as CLI flags (previously YAML-only)
- AI `--ai-tone` now defaults to `both` when `--use-ai` is passed without `--ai-tone`
- Schema `mode` enum updated from `["safe", "aggressive"]` to `["safe", "aggressive", "offline"]`
- HTML report template fully redesigned — filter bar, badges, AI tabs, diff section
- Scan now runs **13 parallel phases** vs 5 in v0.1.0 — 8 new phases added (Ports, CORS, Robots, WAF, API Discovery, Cookies, phpinfo, plus enhanced TLS)

---

### Fixed

- `compute_diff()` ran before `add_finding()` — diff was always empty (fixed in `scanner.py`)
- `lookup_cves('apache', '')` returned results for empty version strings — now guarded
- Missing OWASP mapping for `HEPH-HTTP-008`, `HEPH-FILE-999`, `HEPH-FILE-403`
- Nginx `ssl_ciphers ALL:!aNULL:!eNULL` incorrectly flagged as weak — negated cipher parts now stripped before pattern matching
- `autoindex on` reported multiple times (once per location block) — deduplicated into single finding with all line numbers

---

## [0.1.0] - 2026-01-21

**Initial Production Release** 🎉

Hephaestus v0.1.0 is a comprehensive server security auditor with ethical scanning practices, AI-powered hardening guides, and professional reporting. This release includes 6 security check modules covering 34+ vulnerability types, multi-provider AI integration, and robust error handling.

---

### Added

#### Core Security Scanner

**Server Fingerprinting**

- Multi-method detection via HTTP headers, error pages, and behavior analysis
- Accurate identification of Apache, Nginx, and IIS
- Version disclosure detection in:
    - Server headers
    - Error pages (404, 403, 500)
    - Default server pages
- Zero false positives in controlled testing

**Sensitive File Detection**

- 70+ critical file paths monitored:
    - **Environment files**: `.env`, `.env.local`, `.env.production`, `.env.development`
    - **Configuration backups**: `httpd.conf.bak`, `nginx.conf.old`, `apache2.conf~`, `.htaccess.save`
    - **Version control**: `.git/`, `.git/HEAD`, `.git/config`, `.svn/`, `.hg/`
    - **Database credentials**: `database.yml`, `config.php`, `wp-config.php`
    - **Server status pages**: `/server-status`, `/server-info`, `/nginx_status`
    - **PHP information**: `phpinfo.php`, `info.php`, `test.php`
    - **Development artifacts**: `composer.json`, `composer.lock`, `package.json`, `package-lock.json`, `.idea/`, `.vscode/`
    - **Backup archives**: `backup.zip`, `backup.tar.gz`, `database.sql`, `dump.sql`
- Evidence preservation with full HTTP responses

**HTTP Methods Testing**

- Detection of unsafe HTTP methods:
    - TRACE (XST vulnerability - CVE-2003-1567)
    - PUT (arbitrary file upload)
    - DELETE (file deletion)
    - OPTIONS (method enumeration)
- RFC 7231 compliance verification
- Evidence collection via OPTIONS response

**Security Headers Analysis**

- Comprehensive evaluation of 6 critical headers:
    - **HSTS** (HTTP Strict Transport Security): SSL stripping protection
    - **CSP** (Content Security Policy): XSS and data injection prevention
    - **X-Frame-Options**: Clickjacking protection
    - **X-Content-Type-Options**: MIME sniffing prevention
    - **Referrer-Policy**: Referrer leakage control
    - **Permissions-Policy**: Feature policy enforcement
- OWASP Secure Headers Project compliance
- Server-specific recommendations (Apache/Nginx/IIS)

**TLS/SSL Configuration**

- Protocol version detection:
    - TLS 1.3 (modern, secure)
    - TLS 1.2 (acceptable)
    - TLS 1.0/1.1 (deprecated, high severity)
    - SSLv2/SSLv3 (critical vulnerability)
- Certificate validation (when available)
- Missing TLS detection (HTTP-only sites)

**Directory Listing Detection**

- Apache `Options Indexes` misconfiguration
- Nginx `autoindex on` misconfiguration
- Evidence: HTML directory listing page content
- CVSS 5.3 (Medium severity, CWE-548)

---

#### AI-Powered Hardening Guides

**Multi-Provider Support**

- **OpenAI GPT-4 Turbo**: Premium quality, ~35 seconds per analysis, $0.25/scan
- **Anthropic Claude**: Enhanced privacy, ~45 seconds, $0.30/scan
- **Ollama (Local Models)**: 100% offline, ~28 minutes CPU / ~75 seconds GPU, free

**Analysis Modes**

- **Technical Tone**:
    - Apache/Nginx/IIS configuration snippets
    - CLI commands and step-by-step instructions
    - File paths and directory structures
    - Restart procedures
- **Non-Technical Tone**:
    - Executive risk summaries
    - Business impact assessments
    - Plain-language recommendations
    - Stakeholder-friendly explanations
- **Both Modes**: Combined technical + executive analysis in single report

**Security & Privacy**

- Automatic sanitization removes sensitive data before AI processing:
    - Consent tokens
    - API keys and credentials
    - Private keys and certificates
    - Internal IP addresses
    - Database credentials
- No PII sent to AI providers
- Configurable via environment variables and YAML

**Standalone Testing**

```bash
# Test AI providers before scanning
python -m heph.core.ai openai
python -m heph.core.ai anthropic
python -m heph.core.ai ollama
```

---

#### Infrastructure & Reporting

**Ethical Scanning Framework**

- **Consent Token System**: Verify server ownership before aggressive scanning
    - HTTP verification (`.well-known/verify-{token}.txt`)
    - DNS TXT record verification (`hephaestus-verify={token}`)
    - 48-hour token expiration
    - Database tracking of verified domains
- **Safe Mode** (default): Non-intrusive, no consent required, 3 req/s
- **Aggressive Mode**: Deep probing, consent required, 8 req/s

**Dual Report Formats**

- **JSON Reports**: Machine-readable with schema validation
    - Complete scan metadata (tool, version, target, mode)
    - Structured findings with evidence
    - AI hardening guides (when enabled)
    - Severity breakdown summary
    - ~15-25KB per scan

- **HTML Reports**: Professional, forge-themed (⚒️ blacksmith aesthetic)
    - Responsive design with orange/red gradients
    - Self-contained (inline CSS, no external dependencies)
    - Severity-color-coded findings (critical=red, high=orange, etc.)
    - Expandable evidence sections
    - AI analysis beautifully formatted with syntax highlighting
    - Mobile-friendly layout
    - ~50-70KB per scan

**Shared Database Persistence**

- SQLite database: `~/.argos/argos.db` (shared with Argus suite)
- Tracks all scans across Hephaestus, Argus, Asterion, Pythia, and other tools
- Schema includes:
    - `scans` table: Scan history with metadata
    - `findings` table: All discovered vulnerabilities
    - `consent_tokens` table: Verified domain tracking
    - Foreign key constraints enforced
    - Indices for fast queries (5-50ms)
- Automatic corruption recovery
- Read-only mode support for locked databases
- Cross-tool integration capabilities

**Advanced Logging**

- Automatic secret redaction (API keys, tokens, credentials)
- Multiple verbosity levels:
    - Default: INFO + WARNING + ERROR
    - `-v`: DEBUG messages
    - `-vv`: HTTP request/response details
    - `-vvv`: TRACE-level debugging
- JSON and text format support
- Timestamped with severity levels
- Color-coded console output

---

#### Performance & Control

**Rate Limiting**

- Configurable request throttling (1-10 req/s)
- Thread-safe implementation with token bucket algorithm
- Respects server load
- Default: 3 req/s (safe) / 8 req/s (aggressive)

**Concurrent Scanning**

- Thread pool management (1-20 workers)
- Parallel checks for faster scans:
    - Sensitive files checked concurrently
    - Security headers analyzed in parallel
    - HTTP methods tested simultaneously
- Intelligent retry logic (exponential backoff)
- Graceful degradation on individual check failures

**Scan Modes**

- **Safe Mode** (default):
    - Non-intrusive checks
    - No consent required
    - 3 req/s rate limit
    - 5 worker threads
- **Aggressive Mode**:
    - Deep probing
    - Requires verified consent token
    - 8 req/s rate limit
    - 10 worker threads
    - Extended file checks

---

#### Docker Support

**Production-Ready Container**

- Optimized multi-stage build
- Non-root user execution (security best practice)
- Volume mounts for reports and database
- Environment variable configuration
- Compatible with Docker Compose
- ~150MB final image size

**Vulnerable Server Labs**

- **Apache Lab** (port 8080):
    - Apache 2.4.54 on Ubuntu
    - 9 sensitive files planted (.env, 2x.git, 2xphpinfo.php, server-status, backup files)
    - Directory listing enabled
    - Security headers missing
    - TRACE method enabled
    - Expected: 21 findings (6 critical, 2 high, 8 medium, 5 low)

- **Nginx Lab** (port 8081):
    - Nginx 1.18.0 on Alpine
    - 3 sensitive files planted (.env, 2x.git)
    - Autoindex enabled
    - Security headers missing
    - Version disclosure in headers
    - Expected: 13 findings (3 critical, 2 high, 5 medium, 3 low)

- Docker Compose setup for easy deployment
- Safe testing environment without targeting real servers

---

#### Error Handling & Resilience

**Connection Error Management**

- Handles network failures gracefully:
    - DNS resolution failures
    - Connection refused (port closed/unreachable)
    - Connection timeouts
    - SSL/TLS handshake errors
    - HTTP protocol errors
- Detailed error messages with troubleshooting hints
- Preserves partial scan results

**Database Resilience**

- Automatic corruption detection
- Backup and recovery system
- Read-only mode graceful degradation
- Foreign key integrity enforcement
- Transaction rollback on errors
- Concurrent scan support (tested 3+ simultaneous scans)

**Input Validation**

- Parameter validation before scan starts:
    - Rate limit must be positive (1-20 req/s)
    - Threads must be positive (1-20 workers)
    - Timeout must be positive (5-300 seconds)
    - Target URL must be valid HTTP/HTTPS
- Early failure prevents wasted resources

**Standardized Exit Codes**

- `0`: Scan completed successfully
- `1`: Technical error (connection, database, file I/O)
- `2`: Invalid target (malformed URL, DNS failure)
- `130`: User cancelled (Ctrl+C / SIGINT)

---

#### Developer Experience

**Rich CLI Interface**

- 25+ command-line flags
- Colored output with progress indicators
- ASCII art branding (forge/blacksmith theme)
- Comprehensive `--help` documentation
- Exit code documentation for automation

**Configuration Management**

- YAML configuration files (`config/defaults.yaml`)
- Environment variable overrides
- CLI flag priority system (CLI > ENV > YAML)
- Multi-environment support
- Template system for AI prompts

**Finding Code System**

```
HEPH-SRV-001: Server version disclosed
HEPH-SRV-004: Server disclosed in error page
HEPH-FILE-001: Environment file exposed
HEPH-FILE-002: Git repository exposed
HEPH-FILE-003: PHP information page exposed
HEPH-FILE-004: Apache server-status exposed
HEPH-HTTP-003: Unsafe HTTP method (TRACE)
HEPH-HTTP-008: TRACE method enabled
HEPH-HDR-001 to HEPH-HDR-006: Security headers
HEPH-CFG-001: Directory listing enabled
HEPH-TLS-000: TLS not enabled
HEPH-TLS-001: Weak TLS protocol
```

---

### Performance

**Scan Speed**

- Core checks: 21-22 seconds (safe mode, Docker labs)
- With AI analysis: +30-50 seconds
- Average requests per scan: 70-100

**AI Analysis Performance**
| Provider | Duration | Quality | Cost per Scan | Privacy |
|----------|----------|---------|---------------|---------|
| OpenAI GPT-4 | ~35s | ⭐⭐⭐⭐⭐ | $0.25 | Standard |
| Anthropic Claude | ~45s | ⭐⭐⭐⭐⭐ | $0.30 | Enhanced |
| Ollama (CPU) | ~28min | ⭐⭐⭐ | Free | 100% Offline |
| Ollama (GPU) | ~75s\* | ⭐⭐⭐ | Free | 100% Offline |

\*GPU time is estimated based on typical hardware

**Resource Usage**

- Memory: <300MB peak during scanning
- Database: 671KB for 80 scans and 1,159+ findings
- Report size:
    - JSON: 15-25KB
    - HTML: 50-70KB (without AI)
    - HTML: 200-250KB (with AI analysis)
- Concurrent scans: Tested up to 3 simultaneous without race conditions

**Validation Results**

- **55 Tests Passed** across 10 comprehensive phases
- **Apache Lab Accuracy**: 21/21 findings detected (100% precision, 100% recall)
- **Nginx Lab Accuracy**: 13/13 findings detected (100% precision, 100% recall)
- **F1-Score**: 1.0 (perfect balance)
- **False Positives**: 0
- **False Negatives**: 0

---

### Security

**Safe by Default**

- Non-intrusive checks unless explicitly authorized
- Consent enforcement for aggressive mode
- Automatic secret redaction in logs and outputs
- AI data sanitization (removes tokens, credentials, certificates, PII)

**Privacy Options**

- Ollama support for 100% offline operation
- No telemetry or tracking
- Local database storage only (`~/.argos/argos.db`)
- Shared database for cross-tool integration, not cloud sync

**Best Practices**

- Non-root Docker execution
- Schema validation for all JSON reports
- Foreign key constraints enforced in database
- No credential exposure in error messages
- Secure API key handling via environment variables

---

### Known Limitations

These limitations are documented and tracked for future versions:

**TLS/SSL Analysis**

- Basic protocol detection only (no cipher suite analysis)
- No certificate chain validation
- No OCSP/CRL checking
- No vulnerability checks (Heartbleed, POODLE, etc.)
- **Planned improvement**: HEPH-002 in v0.2.0 (SSLyze integration)

**Server Module Detection**

- Only detects base server (Apache, Nginx, IIS)
- No detection of modules (mod_security, mod_rewrite, ngx_http_gzip)
- No framework detection (Laravel, Django, Express.js)
- No reverse proxy identification (Cloudflare, CloudFront)
- **Planned improvement**: HEPH-003 in v0.2.0

**Configuration Analysis**

- No support for analyzing configuration files offline
- Requires live server for all checks
- **Planned improvement**: HEPH-005 in v0.2.0 (httpd.conf/nginx.conf parser)

**AI Features**

- Provider switching requires manual YAML editing
- No cost tracking or budget limits
- No streaming responses (long wait times)
- **Planned improvements**: HEPH-006, HEPH-007, HEPH-009 in v0.2.0-v0.3.0

**Ollama Performance**

- Extremely slow on CPU (~28 minutes vs 35 seconds for OpenAI)
- Recommended only for privacy-critical scenarios or when using GPU acceleration

**Database Management**

- Requires SQL knowledge for advanced queries
- No built-in export/import utilities
- **Planned improvement**: HEPH-011 in v0.3.0 (interactive CLI)

**Reporting**

- No CVE/CWE badges in HTML reports
- Security headers shown without configuration examples
- No finding grouping or filtering in HTML
- **Planned improvement**: HEPH-004 in v0.2.0

---

## Support & Contributing

**Found a bug?**  
Open an issue: https://github.com/rodhnin/hephaestus-server-forger/issues

**Feature request?**  
Start a discussion: https://github.com/rodhnin/hephaestus-server-forger/discussions

**Want to contribute?**  
See `CONTRIBUTING.md` for guidelines

**Need help?**  
Check documentation in `docs/` or ask in Discussions

---

## Roadmap

**v0.2.0** ✅ Released May 2026 — Enhanced Detection & AI

- Deep TLS/SSL analysis with SSLyze + SSL Labs grading
- Server module & framework detection (Laravel, Django, Rails, Node.js, ASP.NET, Spring)
- Enhanced HTML reporting — filter bar, CVE/CWE/OWASP badges, AI tabs, diff section
- Apache/Nginx config file parser (offline analysis via `--config-file`)
- AI cost tracking, budget limits, streaming, agent mode, compare mode
- Live CVE lookup (NVD API v2 + CIRCL fallback)
- Port scanner with banner grabbing and CVE enrichment
- Diff reports (`--diff last` / `--diff SCAN_ID`)

**v0.3.0** (Q3 2026) - Enterprise Features

- Interactive config management (Metasploit-style CLI)
- Database CLI interface (no SQL required)
- Multi-site scanning (batch processing)
- Interactive AI chat (conversational hardening)
- CI/CD integration templates
- REST API server (FastAPI)

**v0.4.0** (Q1 2027) - Intelligence & Automation

- Automated remediation (Ansible playbooks)
- ML-based detection (anomaly detection)
- Advanced AI agents (autonomous scanning)
- Distributed scanning (worker nodes)

See `ROADMAP.md` for complete feature list

---

## License

This project is licensed under the MIT License. See `LICENSE` file for details.

---

## Acknowledgments

- Apache & Nginx communities for documentation and hardening guides
- OWASP for security standards (Top 10, Testing Guide, Secure Headers Project)
- CIS Benchmarks for server hardening best practices
- LangChain team for AI framework
- OpenAI, Anthropic, and Ollama for AI models
- Python community for amazing libraries (requests, Jinja2, PyYAML)
- All contributors and testers who helped validate this release

---

## Disclaimer

**IMPORTANT:** This tool is for **authorized security testing only**.

- Only scan systems you own or have explicit written permission to test
- Unauthorized access is illegal (CFAA, Computer Misuse Act, etc.)
- The authors assume no liability for misuse
- Always practice responsible disclosure

See `docs/ETHICS.md` for complete ethical guidelines.

---

**Generated:** May 2026
**Version:** 0.2.0
**Status:** Production Release
**Author:** Rodney Dhavid Jimenez Chacin (rodhnin)

[0.2.0]: https://github.com/rodhnin/hephaestus-server-forger/releases/tag/v0.2.0
[0.1.0]: https://github.com/rodhnin/hephaestus-server-forger/releases/tag/v0.1.0
