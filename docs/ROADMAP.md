# Hephaestus Development Roadmap

## Current Version: v0.2.0 ✅ RELEASED

**Release Date:** April 2026
**Status:** ✅ **PRODUCTION READY**

---

## v0.1.0 ✅ RELEASED

**Release Date:** January 2026
**Status:** ✅ **PRODUCTION READY** (superseded by v0.2.0)

### Features Included

#### Core Scanning

- ✅ **Server Fingerprinting**: Multi-method detection (Apache, Nginx, IIS) via headers, error pages, and behavior analysis
- ✅ **Sensitive File Detection**: 70+ critical paths including:
    - Environment files (`.env`, `.env.local`, `.env.production`)
    - Configuration backups (`httpd.conf.bak`, `nginx.conf.old`, `.htaccess~`)
    - Version control (`.git/`, `.svn/`, `.hg/`)
    - Database credentials (`database.yml`, `config.php`)
    - Server status pages (`server-status`, `server-info`, `nginx_status`)
    - PHP information (`phpinfo.php`, `info.php`)
    - Development artifacts (`composer.json`, `package.json`, `.idea/`)
- ✅ **HTTP Methods Testing**: Detection of unsafe methods (PUT, DELETE, TRACE, OPTIONS) and XST vulnerability
- ✅ **Security Headers Analysis**: Comprehensive evaluation of 6 critical headers:
    - HSTS (HTTP Strict Transport Security)
    - CSP (Content Security Policy)
    - X-Frame-Options (Clickjacking protection)
    - X-Content-Type-Options (MIME sniffing prevention)
    - Referrer-Policy (Referrer leakage control)
    - Permissions-Policy (Feature policy enforcement)
- ✅ **TLS/SSL Configuration**: Protocol versions, cipher suites, certificate validity checks
- ✅ **Directory Listing Detection**: Apache `Indexes` and Nginx `autoindex` misconfiguration identification

#### Performance & Control

- ✅ **Rate Limiting**: Configurable request throttling (1-10 req/s) with thread-safe implementation
- ✅ **Thread Pool Management**: Concurrent scanning with 1-20 worker threads
- ✅ **Intelligent Retry Logic**: Exponential backoff on transient failures
- ✅ **Graceful Degradation**: Continues scanning even if modules fail

#### Infrastructure

- ✅ **Consent Token System**: Ethical scanning with HTTP/.well-known or DNS TXT verification
- ✅ **Shared SQLite Database**: `~/.argos/argos.db` for cross-tool integration (Argus, Pythia, future tools)
- ✅ **Dual Reporting**: JSON (machine-readable) and HTML (human-readable) formats
- ✅ **Professional HTML Reports**: Forge-themed (⚒️ blacksmith aesthetic), responsive, self-contained
- ✅ **Automatic Secret Redaction**: Logging system prevents credential leaks
- ✅ **Multi-Source Configuration**: YAML defaults + environment variables + CLI overrides
- ✅ **Docker Support**: Production-ready containerized scanning + vulnerable test labs

#### AI-Powered Analysis (3 Providers)

- ✅ **OpenAI GPT-4 Turbo**: Premium quality analysis (~35s, $0.25/scan)
- ✅ **Anthropic Claude**: Privacy-focused alternative (~45s, $0.30/scan)
- ✅ **Ollama (Local Models)**: 100% offline analysis (free, 28min CPU / 75s GPU)
- ✅ **Technical Hardening Guides**: Apache/Nginx config snippets, CLI commands, step-by-step instructions
- ✅ **Executive Risk Summaries**: Business-friendly language for stakeholders
- ✅ **Dual-Tone Mode**: Both technical and executive analysis in single report
- ✅ **Automatic Sanitization**: Zero secrets leaked to AI providers (consent tokens, API keys, certificates removed)

#### Resilience & Error Handling

- ✅ **Connection Error Recovery**: Handles timeouts, DNS failures, refused connections
- ✅ **Database Corruption Recovery**: Automatic backup and recreation
- ✅ **Permission Handling**: Graceful degradation for read-only directories
- ✅ **Partial Scan Support**: Preserves results even if target goes offline mid-scan
- ✅ **Standardized Exit Codes**: 0=success, 1=error, 2=invalid-target, 130=cancelled

#### Developer Experience

- ✅ **Rich CLI Interface**: Colored output, progress tracking, ASCII art branding (forge/blacksmith theme)
- ✅ **Verbosity Levels**: `-v` (INFO), `-vv` (DEBUG), `-vvv` (TRACE) for troubleshooting
- ✅ **Comprehensive Help**: Built-in documentation with examples
- ✅ **Flexible Deployment**: Native Python, Docker, or containerized scanning
- ✅ **Safe Testing Labs**: Docker Compose environments for Apache & Nginx with 34 planted vulnerabilities

### Performance Benchmarks (v0.1.0)

- **Scan Duration**: 21-22 seconds (safe mode, local Docker lab, 6 phases)
- **Database Efficiency**: 671 KB for 80 scans and 1,159+ findings
- **Query Performance**: 5-50ms for complex aggregations
- **Concurrent Scanning**: 3+ simultaneous scans without race conditions
- **Scalability**: Tested up to 80+ scans with linear performance

### Validation & Testing

- ✅ **55 Validation Tests**: 10 comprehensive phases covering all functionality
- ✅ **Empirical Accuracy**: 100% precision (zero false positives), 100% recall (zero false negatives)
- ✅ **Controlled Labs**: Apache lab (21 findings), Nginx lab (13 findings) for reproducible testing (v0.1.0 baseline)
- ✅ **F1-Score**: 1.0 (perfect balance between precision and recall)

---

## v0.2.0 ✅ RELEASED — Enhanced Detection & AI Features

**Theme:** Deep Server Analysis + Advanced AI Capabilities
**Release Date:** April 2026
**Status:** ✅ **PRODUCTION READY**
**Focus:** Detection accuracy, AI enhancements, reporting improvements

---

### ✅ 🔍 Deep TLS/SSL Analysis

**Ticket:** IMPROV-002
**Priority:** High
**Status:** ✅ DONE

#### Current Limitations

Basic TLS checks only verify:

- Protocol availability (TLS enabled/disabled)
- Basic protocol version (SSLv3, TLS 1.0 = weak)
- No cipher suite analysis
- No certificate chain validation
- No OCSP/CRL checking

#### Planned Enhancements

**1. SSLyze Integration**

```bash
# Install dependency
pip install sslyze>=6.0.0

# Enhanced TLS scan
python -m heph --target https://example.com --check-tls
```

**Detection Features:**

```python
# Cipher suite analysis
- Identify weak ciphers (RC4, 3DES, CBC mode)
- Detect export-grade ciphers
- Check forward secrecy (ECDHE, DHE)
- Validate cipher order (server preference)

# Protocol version testing
- SSLv2/SSLv3 (critical: POODLE, DROWN)
- TLS 1.0/1.1 (high: deprecated in 2020)
- TLS 1.2 (medium: acceptable but aging)
- TLS 1.3 (info: modern and secure)

# Certificate validation
- Expiration date (warn 30 days before)
- Self-signed detection
- Hostname mismatch
- Chain trust validation
- Weak signature algorithms (SHA-1, MD5)

# Vulnerability checks
- Heartbleed (CVE-2014-0160)
- ROBOT (Return Of Bleichenbacher's Oracle Threat)
- BEAST, CRIME, BREACH
- POODLE (SSLv3 padding oracle)
- DROWN (SSLv2 cross-protocol attack)
```

**2. Enhanced Findings**

```json
{
    "finding_code": "HEPH-TLS-002",
    "title": "Weak TLS cipher suite enabled",
    "severity": "high",
    "description": "Server accepts TLS_RSA_WITH_3DES_EDE_CBC_SHA (weak)",
    "evidence": {
        "protocol": "TLS 1.2",
        "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "key_size": 168,
        "forward_secrecy": false
    },
    "cve": "CVE-2016-2183 (Sweet32 Attack)",
    "cvss": 7.5,
    "recommendation": "Disable 3DES cipher in Apache/Nginx:\n\nApache:\nSSLCipherSuite HIGH:!aNULL:!MD5:!3DES\n\nNginx:\nssl_ciphers 'HIGH:!aNULL:!MD5:!3DES';"
}
```

**3. HTML Report Enhancement**

```html
<h3>🔐 TLS/SSL Configuration</h3>

<table class="tls-table">
    <tr>
        <th>Protocol</th>
        <th>Status</th>
        <th>Ciphers</th>
        <th>Score</th>
    </tr>
    <tr>
        <td>TLS 1.3</td>
        <td><span class="badge badge-success">✓ Supported</span></td>
        <td>5 modern ciphers</td>
        <td>A+</td>
    </tr>
    <tr>
        <td>TLS 1.2</td>
        <td><span class="badge badge-warning">⚠️ Supported</span></td>
        <td>12 ciphers (2 weak)</td>
        <td>B</td>
    </tr>
    <tr>
        <td>TLS 1.0</td>
        <td><span class="badge badge-critical">❌ Enabled</span></td>
        <td>8 legacy ciphers</td>
        <td>F</td>
    </tr>
</table>

<h4>Certificate Information</h4>
<ul>
    <li>Common Name: example.com</li>
    <li>Issuer: Let's Encrypt</li>
    <li>Valid Until: 2025-04-15 (87 days remaining)</li>
    <li>Signature Algorithm: SHA-256 with RSA ✓</li>
    <li>Key Size: 2048 bits ✓</li>
</ul>
```

**Benefits:**

- SSL Labs-grade scoring (A+, A, B, C, D, F)
- CVE correlation for TLS vulnerabilities
- Actionable remediation (specific cipher strings)
- Certificate lifecycle management

---

### ✅ 🌐 Server Module & Framework Detection

**Ticket:** IMPROV-003
**Priority:** High
**Status:** ✅ DONE

#### Current Limitations

Only detects base server (Apache, Nginx, IIS). No detection of:

- Server modules (mod_security, mod_rewrite, ngx_http_gzip)
- Web frameworks (Laravel, Django, Express.js, Rails)
- Application servers (Tomcat, Gunicorn, uWSGI)
- Reverse proxy configurations

#### Detection Methods

**1. Apache Modules**

```bash
# server-info page
GET /server-info

Loaded Modules:
  mod_rewrite.c
  mod_ssl.c
  mod_security2.c  # WAF detected!
  mod_deflate.c
  mod_headers.c

# HTTP headers
X-Powered-By: PHP/7.4.3
X-Mod-Pagespeed: 1.13.35.2  # Google PageSpeed module
```

**2. Nginx Modules**

```bash
# Headers revealing modules
Server: nginx/1.18.0
X-Nginx-Cache: HIT  # Proxy cache enabled
X-Content-Type-Options: nosniff  # Headers module

# Common module indicators
- ngx_http_gzip_module (Vary: Accept-Encoding header)
- ngx_http_realip_module (X-Real-IP header handling)
- ngx_http_ssl_module (HTTPS support)
```

**3. Framework Detection**

```python
# Laravel (PHP)
/public/index.php → Laravel routing
/storage/logs/ → Laravel directory structure
X-Powered-By: Laravel

# Django (Python)
/admin/login/ → Django admin panel
csrftoken cookie → Django CSRF protection
X-Frame-Options: DENY → Django default

# Express.js (Node.js)
X-Powered-By: Express
/node_modules/ exposed → NPM packages

# Ruby on Rails
/rails/info/properties → Rails info page
_session_id cookie → Rails session management
```

**4. Application Server Detection**

```bash
# Tomcat (Java)
/manager/html → Tomcat manager
Server: Apache-Coyote/1.1

# Gunicorn (Python)
Server: gunicorn/20.1.0

# uWSGI (Python)
Server: uWSGI

# Passenger (Ruby/Node.js)
X-Powered-By: Phusion Passenger
```

**5. Reverse Proxy Detection**

```bash
# Cloudflare
CF-Ray: 7d1234567890-MIA
CF-Cache-Status: HIT
Server: cloudflare

# AWS CloudFront
Via: 1.1 a1b2c3d4e5f6.cloudfront.net (CloudFront)
X-Amz-Cf-Id: xyz

# Nginx Proxy
X-Proxy-Cache: HIT
X-Cache-Status: MISS
```

#### Enhanced Output

**Before:**

```json
{
    "title": "Apache server version disclosed",
    "server": "Apache/2.4.54"
}
```

**After:**

```json
{
    "title": "Apache server with mod_security detected",
    "server": "Apache/2.4.54 (Ubuntu)",
    "modules": [
        {
            "name": "mod_security2",
            "version": "2.9.3",
            "type": "WAF",
            "severity": "info",
            "description": "ModSecurity Web Application Firewall detected"
        },
        {
            "name": "mod_ssl",
            "version": "2.4.54",
            "type": "security",
            "severity": "info"
        },
        {
            "name": "mod_rewrite",
            "severity": "low",
            "recommendation": "Ensure mod_rewrite rules don't expose sensitive paths"
        }
    ],
    "framework": {
        "name": "Laravel",
        "version": "9.x",
        "language": "PHP",
        "confidence": 0.95
    },
    "reverse_proxy": {
        "provider": "Cloudflare",
        "detected_via": "CF-Ray header"
    }
}
```

**Benefits:**

- Context-aware recommendations (framework-specific hardening)
- WAF detection (ModSecurity, Cloudflare WAF)
- Reverse proxy identification (attack surface mapping)
- Technology stack profiling

---

### ✅ 📊 Enhanced HTML Reporting

**Ticket:** IMPROV-004
**Priority:** High
**Status:** ✅ DONE

#### Current Limitations

- No CVE/CWE badges for findings
- Security headers shown without configuration examples
- No finding grouping or filtering
- References lack metadata
- No interactive elements (collapsible sections)

#### Planned Improvements

**1. CVE/CWE Badges**

```html
<tr>
    <td class="finding-title">
        TLS 1.0 enabled
        <span class="badge badge-critical">CVE-2011-3389</span>
        <span class="badge">CWE-327</span>
    </td>
    <td>
        <span class="severity-badge critical">CRITICAL</span>
    </td>
    <td>
        <a href="https://nvd.nist.gov/vuln/detail/CVE-2011-3389" target="_blank">NVD</a>
    </td>
</tr>
```

**2. Configuration Snippets**

```html
<div class="finding">
    <h4>❌ Missing: HTTP Strict Transport Security (HSTS)</h4>
    <p>Protect against SSL stripping and cookie hijacking</p>

    <div class="config-tabs">
        <button class="tab active" data-tab="apache">Apache</button>
        <button class="tab" data-tab="nginx">Nginx</button>
        <button class="tab" data-tab="iis">IIS</button>
    </div>

    <div class="config-content apache active">
        <pre><code># In httpd.conf or .htaccess
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"</code></pre>
    </div>

    <div class="config-content nginx">
        <pre><code># In nginx.conf server block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;</code></pre>
    </div>

    <div class="config-content iis">
        <pre><code><!-- In web.config -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="Strict-Transport-Security" value="max-age=31536000" />
    </customHeaders>
  </httpProtocol>
</system.webServer></code></pre>
    </div>
</div>
```

**3. Finding Grouping & Filtering**

```html
<div class="filters">
    <button class="filter-btn active" data-filter="all">All (34)</button>
    <button class="filter-btn" data-filter="critical">Critical (6)</button>
    <button class="filter-btn" data-filter="high">High (2)</button>
    <button class="filter-btn" data-filter="medium">Medium (8)</button>
    <button class="filter-btn" data-filter="low">Low (5)</button>
    <button class="filter-btn" data-filter="info">Info (13)</button>
</div>

<div class="groups">
    <h3>📁 Sensitive Files (9)</h3>
    <ul class="findings-list">
        <li class="critical">.env exposed</li>
        <li class="critical">.git directory accessible</li>
        <!-- ... -->
    </ul>

    <h3>🔒 Security Headers (6)</h3>
    <ul class="findings-list">
        <li class="medium">Missing HSTS</li>
        <li class="medium">Missing CSP</li>
        <!-- ... -->
    </ul>

    <h3>⚙️ Configuration Issues (5)</h3>
    <ul class="findings-list">
        <li class="high">Directory listing enabled</li>
        <li class="medium">Server version disclosed</li>
        <!-- ... -->
    </ul>
</div>
```

**4. Reference Enrichment**

```json
{
    "references": [
        {
            "url": "https://httpd.apache.org/docs/2.4/mod/mod_headers.html",
            "title": "Apache Module mod_headers",
            "domain": "httpd.apache.org",
            "type": "official_documentation",
            "year": 2024
        },
        {
            "url": "https://owasp.org/www-project-secure-headers/",
            "title": "OWASP Secure Headers Project",
            "domain": "owasp.org",
            "type": "security_best_practice",
            "year": 2024
        }
    ]
}
```

**5. Interactive Elements**

```html
<div class="finding collapsible">
    <button class="expand-btn">
        <span class="icon">▶</span>
        Show full evidence (245 lines)
    </button>
    <div class="evidence-content" style="display:none">
        <pre><code>HTTP/1.1 200 OK
Server: Apache/2.4.54 (Ubuntu)
Date: Mon, 21 Oct 2024 12:30:45 GMT
<!-- Full HTTP response -->
</code></pre>
    </div>
</div>
```

**Benefits:**

- Copy-paste ready configurations (reduce remediation time)
- Visual organization (easier to prioritize)
- Interactive filtering (focus on critical issues)
- Enhanced credibility (authoritative references)

---

### ✅ 🔧 Apache/Nginx Configuration File Parser

**Ticket:** IMPROV-005
**Priority:** Medium
**Status:** ✅ DONE

#### Vision

Analyze uploaded Apache (`httpd.conf`) or Nginx (`nginx.conf`) files for misconfigurations **without** requiring live server access.

#### Use Cases

1. Pre-deployment auditing (before server goes live)
2. Compliance checking (against CIS Benchmarks)
3. Migration planning (identify issues before cutover)
4. Offline security reviews (no consent token needed)

#### Configuration Analysis

**Apache httpd.conf**

```python
# Dangerous directives
<Directory />
    Options Indexes FollowSymLinks  # ❌ CRITICAL: Directory listing
    AllowOverride All               # ⚠️ HIGH: Unrestricted .htaccess
    Require all granted             # ❌ CRITICAL: World-readable root
</Directory>

ServerTokens Full                   # ⚠️ MEDIUM: Version disclosure
ServerSignature On                  # ⚠️ MEDIUM: Version in errors
TraceEnable On                      # ❌ HIGH: XST vulnerability

<IfModule mod_ssl.c>
    SSLProtocol all                 # ❌ HIGH: Includes SSLv2/SSLv3
    SSLCipherSuite ALL              # ❌ HIGH: Weak ciphers allowed
</IfModule>

# Missing directives
# ❌ MEDIUM: No security headers (mod_headers)
# ❌ MEDIUM: No request limiting (mod_ratelimit)
```

**Nginx nginx.conf**

```nginx
server {
    listen 80;
    server_name example.com;

    # ❌ CRITICAL: No HTTPS redirect

    location / {
        autoindex on;               # ❌ CRITICAL: Directory listing
        root /var/www/html;
    }

    location ~ \.php$ {
        # ❌ HIGH: Insecure PHP execution
        fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    }

    # Missing directives
    # ❌ MEDIUM: No security headers (add_header)
    # ❌ MEDIUM: No rate limiting (limit_req_zone)
    # ❌ HIGH: No client_max_body_size (DoS risk)
}

# ❌ HIGH: Missing TLS configuration
# ❌ MEDIUM: No gzip compression
# ❌ LOW: No access/error log rotation
```

#### CLI Usage

```bash
# Analyze configuration file
python -m heph --config-file /path/to/httpd.conf --server-type apache

# Offline mode (no network requests)
python -m heph --config-file nginx.conf --server-type nginx --offline

# Compare against CIS Benchmark
python -m heph --config-file httpd.conf --benchmark cis-apache-2.4
```

#### Output Format

```json
{
    "tool": "hephaestus",
    "mode": "config_analysis",
    "file": "/etc/httpd/httpd.conf",
    "server_type": "apache",
    "findings": [
        {
            "finding_code": "HEPH-CFG-010",
            "title": "Dangerous 'Options Indexes' directive",
            "severity": "critical",
            "line_number": 245,
            "directive": "Options Indexes FollowSymLinks",
            "context": "<Directory />\n  Options Indexes FollowSymLinks\n</Directory>",
            "recommendation": "Disable directory listing:\nOptions -Indexes",
            "cis_benchmark": "CIS Apache 2.4 Benchmark v1.5 - Section 2.4"
        }
    ]
}
```

**Benefits:**

- Pre-deployment security (catch issues before going live)
- No server access required (offline analysis)
- Compliance validation (CIS, NIST, OWASP)
- Educational tool (learn secure configurations)

---

### ✅ 💰 AI Cost Tracking & Budget Limits

**Ticket:** IMPROV-006
**Priority:** Medium
**Status:** ✅ DONE

#### Configuration

```yaml
# config/defaults.yaml
ai:
    budget:
        enabled: true
        max_cost_per_scan: 0.50 # USD
        max_tokens_per_request: 3000
        warn_threshold: 0.80 # Warn at 80%
        abort_on_exceed: true

    tracking:
        log_costs: true
        cost_report: ~/.hephaestus/costs.json
```

#### Runtime Output

```bash
python -m heph --target https://example.com --use-ai --ai-tone both

[Phase 6/6] AI Hardening Analysis...
  ├─ Executive Summary: 1,180 tokens → $0.11
  ├─ Technical Guide: 1,620 tokens → $0.17
  └─ Total AI Cost: $0.28 / $0.50 budget (56% used)

⚠️  WARNING: 80% budget threshold reached ($0.40 / $0.50)
```

#### Cost Report

```json
{
    "scans": [
        {
            "scan_id": 81,
            "target": "http://localhost:8080",
            "timestamp": "2025-10-21T19:01:56Z",
            "provider": "openai",
            "model": "gpt-4-turbo-preview",
            "executive_summary": {
                "tokens_input": 1450,
                "tokens_output": 1180,
                "cost": 0.11
            },
            "technical_guide": {
                "tokens_input": 1450,
                "tokens_output": 1620,
                "cost": 0.17
            },
            "total_cost": 0.28
        }
    ],
    "totals": {
        "total_scans": 81,
        "total_cost": 22.68,
        "avg_cost_per_scan": 0.28
    }
}
```

**Benefits:**

- Cost transparency
- Budget enforcement
- Enterprise compliance
- Monthly projections

---

### ✅ 🌊 AI Streaming Responses

**Ticket:** IMPROV-007
**Priority:** Low
**Status:** ✅ DONE

#### Current Behavior

```bash
[Phase 6/6] AI Hardening Analysis...
  ⏳ Generating insights... (30+ seconds)
  ✓ Analysis complete
```

#### Streaming Behavior

```bash
[Phase 6/6] AI Hardening Analysis...
  [Executive Summary] Analyzing security posture...
  [Executive Summary] ████████░░ 80% - Assessing risks...
  [Executive Summary] ✓ Complete (2,300 chars in 18s)

  [Technical Guide] Generating remediation steps...
  [Technical Guide] ████░░░░░░ 40% - Apache hardening...
  [Technical Guide] ████████░░ 80% - TLS configuration...
  [Technical Guide] ✓ Complete (4,800 chars in 31s)
```

**Benefits:**

- Improved UX (see progress)
- Reduced perceived latency
- Critical for Ollama (28 min → see output)
- Immediate error detection

---

### 📚 Additional v0.2.0 Features

#### ✅ CVE Database Integration

- Live NVD API v2 lookup for detected server/component versions
- Apache, Nginx, PHP, OpenSSL CVE correlation
- CIRCL.lu fallback when NVD rate-limits
- CVSS scoring enriched per finding (`cvss` field + `vulnerabilities` array)
- CPE vendor normalization (f5/nginx, oracle/mysql, redis/redis)

#### ✅ Port Scanner (NEW — not in original roadmap)

- 37 common ports with banner grabbing
- Web framework detection on open ports
- CVE enrichment for detected services

#### ✅ Multi-Component Server Header Parsing (NEW)

- PHP version + OpenSSL version extracted from Apache `Server:` header
- Separate findings HEPH-SRV-016 / HEPH-SRV-017 with CVE enrichment

**Breaking Changes:** None (fully backward compatible)

---

## v0.3.0 — Enterprise & Interactive Features

**Theme:** Scale, Automation, Conversational AI
**Target Release:** Q3 2026 (July-August)
**Focus:** Enterprise needs, multi-site scanning, interactive AI

---

### 🛠️ Interactive Config Management

**Ticket:** IMPROV-009  
**Priority:** Medium

#### Metasploit-Style Interface

```bash
# Show configuration
$ heph --show-options

╔═══════════════════════════════════════════════╗
║         HEPHAESTUS CONFIGURATION              ║
╠═══════════════════════════════════════════════╣
║ SCAN SETTINGS                                 ║
╠═══════════════════════════════════════════════╣
║ mode             safe          [safe|aggressive]
║ rate_limit       3.0           req/s          ║
║ threads          5             workers        ║
║ timeout          30            seconds        ║
╠═══════════════════════════════════════════════╣
║ AI SETTINGS                                   ║
╠═══════════════════════════════════════════════╣
║ ai.provider      openai        [openai|anthropic|ollama]
║ ai.model         gpt-4-turbo   string         ║
║ ai.temperature   0.3           0.0-1.0        ║
╚═══════════════════════════════════════════════╝

# Modify settings
$ heph --set rate_limit=5.0
✓ Updated: rate_limit = 5.0

$ heph --set ai.provider=anthropic
✓ Updated: ai.provider = anthropic
✓ Updated: ai.model = claude-3-5-sonnet

# Configuration profiles
$ heph --save-profile fast-scan
✓ Saved profile: fast-scan

$ heph --load-profile privacy-mode
✓ Loaded profile: privacy-mode (Ollama, 100% offline)
```

**Benefits:**

- No YAML editing required
- Real-time validation
- Reusable profiles
- Team collaboration

---

### 💾 Interactive Database CLI

**Ticket:** IMPROV-011  
**Priority:** Medium

#### Management Commands

```bash
# List scans
$ heph db scans list --limit 10
ID   Target              Mode        Status     Findings  Date
83   example.com         safe        failed     0         2025-10-21
82   localhost:9999      safe        failed     0         2025-10-21
81   localhost:8080      safe        completed  21        2025-10-21

# Show scan details
$ heph db scans show 81
╔═══════════════════════════════════════════════╗
║ SCAN #81: localhost:8080                      ║
╠═══════════════════════════════════════════════╣
║ Mode:          safe                           ║
║ Duration:      21 seconds                     ║
║ Findings:      21 total                       ║
║   Critical:    6                              ║
║   High:        2                              ║
║   Medium:      8                              ║
║   Low:         5                              ║
╚═══════════════════════════════════════════════╝

# Search findings
$ heph db findings search ".env"
ID    Scan  Severity   Title
1159  81    critical   Environment file exposed (.env)

# Export findings
$ heph db findings export --format csv --output findings.csv
✓ Exported 1,159 findings to findings.csv

# Database statistics
$ heph db stats
Total Scans:       80
Total Findings:    1,159
Verified Domains:  3
Database Size:     671 KB
```

**Benefits:**

- No SQL knowledge required
- Rapid auditing
- Automation-friendly
- Data integrity checks

---

### 💬 Interactive AI Chat

**Ticket:** IMPROV-012  
**Priority:** Medium

#### Conversational Hardening Assistant

```bash
$ heph chat --scan-id 81

Hephaestus AI Chat (Scan #81: localhost:8080)
Type 'exit' to quit, 'help' for commands

You: What's the most critical issue?
AI: Your .env file is publicly accessible at http://localhost:8080/.env
    This exposes database credentials and API keys. Fix immediately:

    1. Move .env outside document root
    2. Add to .gitignore
    3. Deny access in Apache/Nginx config

You: Show me the Apache config
AI: Add this to your .htaccess or httpd.conf:

    <FilesMatch "^\.env">
      Require all denied
    </FilesMatch>

    Or in nginx.conf:

    location ~ /\.env {
      deny all;
      return 404;
    }

You: Are there any CVEs for Apache 2.4.54?
AI: Searching CVE database... Found 3 vulnerabilities:
    1. CVE-2023-45802 (High) - HTTP/2 request smuggling
    2. CVE-2023-43622 (Medium) - mod_auth improper validation
    3. CVE-2023-31122 (Low) - mod_proxy resource exhaustion

    Update to Apache 2.4.58 to patch all three.
```

**Features:**

- Natural language queries
- Multi-turn dialogue with context
- Scan comparison and diff analysis
- CVE/ExploitDB integration
- Step-by-step remediation guidance

---

### 🌐 Multi-Site Scanning

**Ticket:** IMPROV-013  
**Priority:** High

#### Batch Scanning

```bash
# Create targets file
$ cat targets.txt
https://example.com
https://staging.example.com
http://localhost:8080
https://beta.example.org

# Batch scan
$ heph --targets-file targets.txt --html
[1/4] Scanning https://example.com...
  ✓ Complete (38 findings in 30s)
[2/4] Scanning https://staging.example.com...
  ✓ Complete (24 findings in 28s)
[3/4] Scanning http://localhost:8080...
  ✓ Complete (42 findings in 29s)
[4/4] Scanning https://beta.example.org...
  ⚠️  Failed (Connection refused)

Summary Report:
  Total Scans:    4
  Successful:     3
  Failed:         1
  Total Findings: 104
  Avg Duration:   29s
```

#### Aggregate Reporting

```bash
# Generate summary across multiple sites
$ heph db reports aggregate --scans 81,82,83 --output aggregate.html

Aggregate Report (3 sites):
  example.com:     38 findings
  staging.example: 24 findings
  localhost:8080:  42 findings

Common Issues (found in all 3):
  ❌ Missing HSTS header
  ❌ Server version disclosed
  ❌ Directory listing enabled
```

**Benefits:**

- Network-wide visibility
- Common vulnerability identification
- Parallel scanning
- Centralized reporting

---

### 🔗 CI/CD Integration

**Ticket:** IMPROV-014  
**Priority:** Medium

#### Templates & Examples

**GitHub Actions**

```yaml
# .github/workflows/security-scan.yml
name: Hephaestus Server Security Scan

on:
    push:
        branches: [main]
    pull_request:
    schedule:
        - cron: "0 2 * * 1" # Weekly Monday 2am

jobs:
    scan:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v3

            - name: Install Hephaestus
              run: |
                  python -m pip install hephaestus-scanner

            - name: Run Security Scan
              run: |
                  heph --target https://staging.example.com \
                    --html \
                    --fail-on critical,high
              env:
                  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

            - name: Upload Report
              uses: actions/upload-artifact@v3
              if: always()
              with:
                  name: security-report
                  path: ~/.hephaestus/reports/*.html
```

**GitLab CI**

```yaml
# .gitlab-ci.yml
security-scan:
    image: python:3.12
    stage: test
    script:
        - pip install hephaestus-scanner
        - heph --target https://staging.example.com --html
    artifacts:
        paths:
            - ~/.hephaestus/reports/
        expire_in: 1 week
    only:
        - merge_requests
        - main
```

**Jenkins Pipeline**

```groovy
pipeline {
  agent any
  stages {
    stage('Security Scan') {
      steps {
        sh '''
          pip install hephaestus-scanner
          heph --target https://staging.example.com \
            --html \
            --fail-on critical
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: '~/.hephaestus/reports/*.html'
    }
  }
}
```

#### Exit Codes for CI

```python
# Fail pipeline on severity threshold
--fail-on critical        # Exit 1 if any critical findings
--fail-on critical,high   # Exit 1 if critical or high
--fail-on all             # Exit 1 if any findings
```

**Benefits:**

- Shift-left security (catch issues in CI)
- Automated compliance checking
- Historical tracking via artifacts
- Block deployments on critical findings

---

### 📊 REST API Server

**Ticket:** IMPROV-015  
**Priority:** Medium

#### FastAPI Server

```bash
# Start API server
$ heph api serve --port 8000 --workers 4
Hephaestus API Server running on http://0.0.0.0:8000
Swagger UI: http://0.0.0.0:8000/docs
```

#### API Endpoints

```python
# Trigger scan
POST /api/v1/scans
{
  "target": "https://example.com",
  "mode": "safe",
  "use_ai": true
}

Response:
{
  "scan_id": 85,
  "status": "queued",
  "eta": "30s"
}

# Get scan status
GET /api/v1/scans/85
{
  "scan_id": 85,
  "status": "running",
  "progress": 65,
  "findings_so_far": 12
}

# Get scan results
GET /api/v1/scans/85/findings
{
  "scan_id": 85,
  "findings": [...],
  "summary": {...}
}

# Webhook notifications
POST /api/v1/webhooks
{
  "url": "https://example.com/webhook",
  "events": ["scan.completed", "finding.critical"]
}
```

**Features:**

- Async scan triggering
- Real-time progress updates
- Webhook notifications
- Multi-user authentication (JWT)
- Rate limiting per API key
- OpenAPI/Swagger docs

**Benefits:**

- Integration with SIEM/SOAR platforms
- Automated scanning workflows
- Custom dashboards
- Programmatic access

---

### 📚 Additional v0.3.0 Features

#### PDF Export (moved from v0.2.0)

- Customizable PDF reports with branding
- Executive-friendly formatting
- Charts and graphs for trends
- Professional deliverable for clients

#### Nmap Integration

- Port scanning before server checks
- Service version detection
- OS fingerprinting
- Combined vulnerability assessment

#### Advanced Crawling

- Spider mode with configurable depth
- JavaScript rendering (Playwright)
- Form discovery
- API endpoint enumeration

**Breaking Changes:** Database schema v2 (auto-migration provided)

---

## v0.4.0 - Intelligence & Automation

**Theme:** Smart Automation with ML and AI Agents  
**Target Release:** Q1 2027  
**Focus:** Automated remediation, ML detection, advanced AI

### Planned Features

#### Automated Remediation

- Ansible playbook generation for fixes
- Safe auto-patching with approval workflow
- Rollback capability
- Dry-run mode (simulate without applying)
- Chef/Puppet integration

#### ML-Based Detection

- Anomaly detection (unusual server configurations)
- False positive reduction (learn from user feedback)
- Behavioral analysis (detect suspicious patterns)
- Custom model training on historical data

#### Advanced AI Capabilities

- Agent autonomy (AI plans scan strategies)
- Exploit generation (PoC code for findings)
- Custom remediation scripts (AI-generated bash/PowerShell)
- Natural language queries ("What's most urgent?")

#### Performance Enhancements

- Distributed scanning (worker nodes)
- Redis cache for common checks
- Optimized request batching
- GPU acceleration for ML models

**Breaking Changes:** Configuration schema v2 (backward compatible)

---

## Pro Track (Commercial Product)

**Target Audience:** Security consultancies, MSPs, enterprises  
**Pricing Model:** Subscription-based (per-seat or per-scan)

**IN PROCESS**

---

## Community Requests

Vote on features at **[GitHub Discussions](https://github.com/rodhnin/hephaestus-server-forger/discussions)**

**Have an idea?** Open a discussion!

---

## Development Philosophy

Hephaestus development follows these principles:

1. **🔒 Security First**: Ethical safeguards and consent are non-negotiable
2. **🔐 Privacy by Design**: Data minimization, local-first, no telemetry
3. **✅ Quality Over Speed**: Stable releases > frequent releases
4. **👥 Community Driven**: Listen to users, prioritize common needs
5. **🆓 Open Core Model**: Core features free forever, optional Pro tier
6. **🧪 Testing First**: No release without validation (100% coverage goal)

### Commitments

- ✅ **Quarterly feature releases** with new capabilities
- ✅ **Open development** with public roadmap
- ✅ **Responsive support** on GitHub (48h response)

---

## Get Involved

**Questions about the roadmap?**  
Open a discussion: https://github.com/rodhnin/hephaestus-server-forger/discussions

**Want to contribute?**  
See CONTRIBUTING.md for developer guidelines

**Need a feature urgently?**  
Consider Pro Track or sponsor the project

_Last updated: May 2026_
_Roadmap version: 2.0 (v0.2.0)_
