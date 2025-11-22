# Changelog

All notable changes to Hephaestus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-01-21

**Initial Production Release** 🎉

Hephaestus v0.1.0 is a comprehensive server security auditor with ethical scanning practices, AI-powered hardening guides, and professional reporting. This release includes 6 security check modules covering 34+ vulnerability types, multi-provider AI integration, and robust error handling.

---

### Added

#### Core Security Scanner

**Server Fingerprinting**

-   Multi-method detection via HTTP headers, error pages, and behavior analysis
-   Accurate identification of Apache, Nginx, and IIS
-   Version disclosure detection in:
    -   Server headers
    -   Error pages (404, 403, 500)
    -   Default server pages
-   Zero false positives in controlled testing

**Sensitive File Detection**

-   70+ critical file paths monitored:
    -   **Environment files**: `.env`, `.env.local`, `.env.production`, `.env.development`
    -   **Configuration backups**: `httpd.conf.bak`, `nginx.conf.old`, `apache2.conf~`, `.htaccess.save`
    -   **Version control**: `.git/`, `.git/HEAD`, `.git/config`, `.svn/`, `.hg/`
    -   **Database credentials**: `database.yml`, `config.php`, `wp-config.php`
    -   **Server status pages**: `/server-status`, `/server-info`, `/nginx_status`
    -   **PHP information**: `phpinfo.php`, `info.php`, `test.php`
    -   **Development artifacts**: `composer.json`, `composer.lock`, `package.json`, `package-lock.json`, `.idea/`, `.vscode/`
    -   **Backup archives**: `backup.zip`, `backup.tar.gz`, `database.sql`, `dump.sql`
-   Evidence preservation with full HTTP responses

**HTTP Methods Testing**

-   Detection of unsafe HTTP methods:
    -   TRACE (XST vulnerability - CVE-2003-1567)
    -   PUT (arbitrary file upload)
    -   DELETE (file deletion)
    -   OPTIONS (method enumeration)
-   RFC 7231 compliance verification
-   Evidence collection via OPTIONS response

**Security Headers Analysis**

-   Comprehensive evaluation of 6 critical headers:
    -   **HSTS** (HTTP Strict Transport Security): SSL stripping protection
    -   **CSP** (Content Security Policy): XSS and data injection prevention
    -   **X-Frame-Options**: Clickjacking protection
    -   **X-Content-Type-Options**: MIME sniffing prevention
    -   **Referrer-Policy**: Referrer leakage control
    -   **Permissions-Policy**: Feature policy enforcement
-   OWASP Secure Headers Project compliance
-   Server-specific recommendations (Apache/Nginx/IIS)

**TLS/SSL Configuration**

-   Protocol version detection:
    -   TLS 1.3 (modern, secure)
    -   TLS 1.2 (acceptable)
    -   TLS 1.0/1.1 (deprecated, high severity)
    -   SSLv2/SSLv3 (critical vulnerability)
-   Certificate validation (when available)
-   Missing TLS detection (HTTP-only sites)

**Directory Listing Detection**

-   Apache `Options Indexes` misconfiguration
-   Nginx `autoindex on` misconfiguration
-   Evidence: HTML directory listing page content
-   CVSS 5.3 (Medium severity, CWE-548)

---

#### AI-Powered Hardening Guides

**Multi-Provider Support**

-   **OpenAI GPT-4 Turbo**: Premium quality, ~35 seconds per analysis, $0.25/scan
-   **Anthropic Claude**: Enhanced privacy, ~45 seconds, $0.30/scan
-   **Ollama (Local Models)**: 100% offline, ~28 minutes CPU / ~75 seconds GPU, free

**Analysis Modes**

-   **Technical Tone**:
    -   Apache/Nginx/IIS configuration snippets
    -   CLI commands and step-by-step instructions
    -   File paths and directory structures
    -   Restart procedures
-   **Non-Technical Tone**:
    -   Executive risk summaries
    -   Business impact assessments
    -   Plain-language recommendations
    -   Stakeholder-friendly explanations
-   **Both Modes**: Combined technical + executive analysis in single report

**Security & Privacy**

-   Automatic sanitization removes sensitive data before AI processing:
    -   Consent tokens
    -   API keys and credentials
    -   Private keys and certificates
    -   Internal IP addresses
    -   Database credentials
-   No PII sent to AI providers
-   Configurable via environment variables and YAML

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

-   **Consent Token System**: Verify server ownership before aggressive scanning
    -   HTTP verification (`.well-known/verify-{token}.txt`)
    -   DNS TXT record verification (`hephaestus-verify={token}`)
    -   48-hour token expiration
    -   Database tracking of verified domains
-   **Safe Mode** (default): Non-intrusive, no consent required, 3 req/s
-   **Aggressive Mode**: Deep probing, consent required, 8 req/s

**Dual Report Formats**

-   **JSON Reports**: Machine-readable with schema validation

    -   Complete scan metadata (tool, version, target, mode)
    -   Structured findings with evidence
    -   AI hardening guides (when enabled)
    -   Severity breakdown summary
    -   ~15-25KB per scan

-   **HTML Reports**: Professional, forge-themed (⚒️ blacksmith aesthetic)
    -   Responsive design with orange/red gradients
    -   Self-contained (inline CSS, no external dependencies)
    -   Severity-color-coded findings (critical=red, high=orange, etc.)
    -   Expandable evidence sections
    -   AI analysis beautifully formatted with syntax highlighting
    -   Mobile-friendly layout
    -   ~50-70KB per scan

**Shared Database Persistence**

-   SQLite database: `~/.argos/argos.db` (shared with Argus suite)
-   Tracks all scans across Hephaestus, Argus, Asterion, Pythia, and other tools
-   Schema includes:
    -   `scans` table: Scan history with metadata
    -   `findings` table: All discovered vulnerabilities
    -   `consent_tokens` table: Verified domain tracking
    -   Foreign key constraints enforced
    -   Indices for fast queries (5-50ms)
-   Automatic corruption recovery
-   Read-only mode support for locked databases
-   Cross-tool integration capabilities

**Advanced Logging**

-   Automatic secret redaction (API keys, tokens, credentials)
-   Multiple verbosity levels:
    -   Default: INFO + WARNING + ERROR
    -   `-v`: DEBUG messages
    -   `-vv`: HTTP request/response details
    -   `-vvv`: TRACE-level debugging
-   JSON and text format support
-   Timestamped with severity levels
-   Color-coded console output

---

#### Performance & Control

**Rate Limiting**

-   Configurable request throttling (1-10 req/s)
-   Thread-safe implementation with token bucket algorithm
-   Respects server load
-   Default: 3 req/s (safe) / 8 req/s (aggressive)

**Concurrent Scanning**

-   Thread pool management (1-20 workers)
-   Parallel checks for faster scans:
    -   Sensitive files checked concurrently
    -   Security headers analyzed in parallel
    -   HTTP methods tested simultaneously
-   Intelligent retry logic (exponential backoff)
-   Graceful degradation on individual check failures

**Scan Modes**

-   **Safe Mode** (default):
    -   Non-intrusive checks
    -   No consent required
    -   3 req/s rate limit
    -   5 worker threads
-   **Aggressive Mode**:
    -   Deep probing
    -   Requires verified consent token
    -   8 req/s rate limit
    -   10 worker threads
    -   Extended file checks

---

#### Docker Support

**Production-Ready Container**

-   Optimized multi-stage build
-   Non-root user execution (security best practice)
-   Volume mounts for reports and database
-   Environment variable configuration
-   Compatible with Docker Compose
-   ~150MB final image size

**Vulnerable Server Labs**

-   **Apache Lab** (port 8080):

    -   Apache 2.4.54 on Ubuntu
    -   9 sensitive files planted (.env, 2x.git, 2xphpinfo.php, server-status, backup files)
    -   Directory listing enabled
    -   Security headers missing
    -   TRACE method enabled
    -   Expected: 21 findings (6 critical, 2 high, 8 medium, 5 low)

-   **Nginx Lab** (port 8081):

    -   Nginx 1.18.0 on Alpine
    -   3 sensitive files planted (.env, 2x.git)
    -   Autoindex enabled
    -   Security headers missing
    -   Version disclosure in headers
    -   Expected: 13 findings (3 critical, 2 high, 5 medium, 3 low)

-   Docker Compose setup for easy deployment
-   Safe testing environment without targeting real servers

---

#### Error Handling & Resilience

**Connection Error Management**

-   Handles network failures gracefully:
    -   DNS resolution failures
    -   Connection refused (port closed/unreachable)
    -   Connection timeouts
    -   SSL/TLS handshake errors
    -   HTTP protocol errors
-   Detailed error messages with troubleshooting hints
-   Preserves partial scan results

**Database Resilience**

-   Automatic corruption detection
-   Backup and recovery system
-   Read-only mode graceful degradation
-   Foreign key integrity enforcement
-   Transaction rollback on errors
-   Concurrent scan support (tested 3+ simultaneous scans)

**Input Validation**

-   Parameter validation before scan starts:
    -   Rate limit must be positive (1-20 req/s)
    -   Threads must be positive (1-20 workers)
    -   Timeout must be positive (5-300 seconds)
    -   Target URL must be valid HTTP/HTTPS
-   Early failure prevents wasted resources

**Standardized Exit Codes**

-   `0`: Scan completed successfully
-   `1`: Technical error (connection, database, file I/O)
-   `2`: Invalid target (malformed URL, DNS failure)
-   `130`: User cancelled (Ctrl+C / SIGINT)

---

#### Developer Experience

**Rich CLI Interface**

-   25+ command-line flags
-   Colored output with progress indicators
-   ASCII art branding (forge/blacksmith theme)
-   Comprehensive `--help` documentation
-   Exit code documentation for automation

**Configuration Management**

-   YAML configuration files (`config/defaults.yaml`)
-   Environment variable overrides
-   CLI flag priority system (CLI > ENV > YAML)
-   Multi-environment support
-   Template system for AI prompts

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

-   Core checks: 21-22 seconds (safe mode, Docker labs)
-   With AI analysis: +30-50 seconds
-   Average requests per scan: 70-100

**AI Analysis Performance**
| Provider | Duration | Quality | Cost per Scan | Privacy |
|----------|----------|---------|---------------|---------|
| OpenAI GPT-4 | ~35s | ⭐⭐⭐⭐⭐ | $0.25 | Standard |
| Anthropic Claude | ~45s | ⭐⭐⭐⭐⭐ | $0.30 | Enhanced |
| Ollama (CPU) | ~28min | ⭐⭐⭐ | Free | 100% Offline |
| Ollama (GPU) | ~75s\* | ⭐⭐⭐ | Free | 100% Offline |

\*GPU time is estimated based on typical hardware

**Resource Usage**

-   Memory: <300MB peak during scanning
-   Database: 671KB for 80 scans and 1,159+ findings
-   Report size:
    -   JSON: 15-25KB
    -   HTML: 50-70KB (without AI)
    -   HTML: 200-250KB (with AI analysis)
-   Concurrent scans: Tested up to 3 simultaneous without race conditions

**Validation Results**

-   **55 Tests Passed** across 10 comprehensive phases
-   **Apache Lab Accuracy**: 21/21 findings detected (100% precision, 100% recall)
-   **Nginx Lab Accuracy**: 13/13 findings detected (100% precision, 100% recall)
-   **F1-Score**: 1.0 (perfect balance)
-   **False Positives**: 0
-   **False Negatives**: 0

---

### Security

**Safe by Default**

-   Non-intrusive checks unless explicitly authorized
-   Consent enforcement for aggressive mode
-   Automatic secret redaction in logs and outputs
-   AI data sanitization (removes tokens, credentials, certificates, PII)

**Privacy Options**

-   Ollama support for 100% offline operation
-   No telemetry or tracking
-   Local database storage only (`~/.argos/argos.db`)
-   Shared database for cross-tool integration, not cloud sync

**Best Practices**

-   Non-root Docker execution
-   Schema validation for all JSON reports
-   Foreign key constraints enforced in database
-   No credential exposure in error messages
-   Secure API key handling via environment variables

---

### Known Limitations

These limitations are documented and tracked for future versions:

**TLS/SSL Analysis**

-   Basic protocol detection only (no cipher suite analysis)
-   No certificate chain validation
-   No OCSP/CRL checking
-   No vulnerability checks (Heartbleed, POODLE, etc.)
-   **Planned improvement**: HEPH-002 in v0.2.0 (SSLyze integration)

**Server Module Detection**

-   Only detects base server (Apache, Nginx, IIS)
-   No detection of modules (mod_security, mod_rewrite, ngx_http_gzip)
-   No framework detection (Laravel, Django, Express.js)
-   No reverse proxy identification (Cloudflare, CloudFront)
-   **Planned improvement**: HEPH-003 in v0.2.0

**Configuration Analysis**

-   No support for analyzing configuration files offline
-   Requires live server for all checks
-   **Planned improvement**: HEPH-005 in v0.2.0 (httpd.conf/nginx.conf parser)

**AI Features**

-   Provider switching requires manual YAML editing
-   No cost tracking or budget limits
-   No streaming responses (long wait times)
-   **Planned improvements**: HEPH-006, HEPH-007, HEPH-009 in v0.2.0-v0.3.0

**Ollama Performance**

-   Extremely slow on CPU (~28 minutes vs 35 seconds for OpenAI)
-   Recommended only for privacy-critical scenarios or when using GPU acceleration

**Database Management**

-   Requires SQL knowledge for advanced queries
-   No built-in export/import utilities
-   **Planned improvement**: HEPH-011 in v0.3.0 (interactive CLI)

**Reporting**

-   No CVE/CWE badges in HTML reports
-   Security headers shown without configuration examples
-   No finding grouping or filtering in HTML
-   **Planned improvement**: HEPH-004 in v0.2.0

---

## Installation

### Requirements

-   Python 3.11+ (3.12 recommended)
-   pip (Python package manager)
-   Docker (optional, for containerized scanning and vulnerable labs)

### Quick Start

**1. Clone the repository**

```bash
git clone https://github.com/rodhnin/hephaestus-server-forger.git
cd hephaestus-server-forger
```

**2. (Optional) Install `venv` if not already available**

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y python3-venv

# Fedora/RHEL
sudo dnf install python3-virtualenv

# macOS (via Homebrew)
brew install python@3.11
```

**3. Create and activate virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
# You should see (.venv) in your terminal prompt
```

**4. Upgrade pip**

```bash
python -m pip install --upgrade pip
```

**5. Install dependencies**

```bash
python -m pip install -r requirements.txt
```

**6. (Optional) Install AI providers**

```bash
# For OpenAI GPT-4
python -m pip install langchain-openai==1.0.0

# For Anthropic Claude
python -m pip install langchain-anthropic==1.0.0

# For Ollama (local)
python -m pip install "langchain-ollama>=0.3.0,<0.4.0"
```

**7. Configure API keys (if using cloud AI)**

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

**8. Verify installation**

```bash
python -m heph --version
# Output: heph 0.1.0
```

**9. Run first scan**

```bash
# Basic scan (no AI)
python -m heph --target http://localhost:8080

# With AI hardening guide
python -m heph --target http://localhost:8080 --use-ai --html
```

---

## Usage Examples

### Basic Scanning

```bash
# Safe mode scan (default)
python -m heph --target https://example.com

# Generate HTML report
python -m heph --target https://example.com --html

# Verbose output for troubleshooting
python -m heph --target https://example.com -vv
```

### AI-Powered Hardening Guides

```bash
# Technical guide (for sysadmins)
python -m heph --target https://example.com \
  --use-ai \
  --ai-tone technical \
  --html

# Executive summary (for stakeholders)
python -m heph --target https://example.com \
  --use-ai \
  --ai-tone non_technical \
  --html

# Both analyses in one report
python -m heph --target https://example.com \
  --use-ai \
  --ai-tone both \
  --html
```

### Aggressive Mode (Requires Consent)

```bash
# 1. Generate consent token
python -m heph --gen-consent example.com
# Output: Token: verify-a3f9b2c1d8e4...

# 2. Place token on your server
# Create: https://example.com/.well-known/verify-a3f9b2c1d8e4.txt
# Content: verify-a3f9b2c1d8e4

# 3. Verify consent
python -m heph --verify-consent http \
  --domain example.com \
  --token verify-a3f9b2c1d8e4

# 4. Run aggressive scan
python -m heph --target https://example.com --aggressive
```

### Advanced Options

```bash
# Control scan speed
python -m heph --target https://example.com --rate 5 --threads 8

# Custom timeout for slow servers
python -m heph --target https://example.com --timeout 60

# Custom output directory
python -m heph --target https://example.com --report-dir ./my-reports

# Disable SSL verification (testing only)
python -m heph --target https://self-signed.badssl.com --no-verify-ssl
```

### Docker Deployment

```bash
# Build image
docker build -f docker/Dockerfile -t hephaestus:0.1.0 .

# Run scan
docker run --rm \
  --network host \
  -v $(pwd)/reports:/reports \
  -v $(pwd)/data:/data \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  hephaestus:0.1.0 \
  --target https://example.com \
  --report-dir /reports \
  --db /data/argos.db \
  --use-ai \
  --html
```

### Safe Testing with Docker Labs

```bash
# Navigate to docker directory
cd docker

# Option 1: Interactive script (recommended)
cd docker && ./deploy.sh
# Select option 2 (Testing Lab)

# Option 2: Manual Docker Compose
docker compose -f docker/compose.testing.yml up -d

# Wait for services to be ready
sleep 15

# Scan Apache lab
python -m heph --target http://localhost:8080 --html

# Scan Nginx lab
python -m heph --target http://localhost:8081 --html

# Stop labs
docker compose -f docker/compose.testing.yml down -v
# OR use cd docker && ./deploy.sh (option 5 for complete removal)
```

---

## Configuration

### AI Provider Selection

Edit `config/defaults.yaml`:

```yaml
ai:
    langchain:
        provider: "openai" # Options: openai, anthropic, ollama
        model: "gpt-4-turbo-preview"
        temperature: 0.3
        max_tokens: 3000
```

Or use environment variables:

```bash
export LANGCHAIN_PROVIDER="anthropic"
export LANGCHAIN_MODEL="claude-3-5-sonnet"
```

**Note:** Dynamic provider switching via CLI will be available in v0.3.0 (HEPH-009)

### Rate Limiting

```bash
# Slow scan (1 req/s)
python -m heph --target example.com --rate 1

# Fast scan (10 req/s, requires consent for aggressive)
python -m heph --target example.com --rate 10 --aggressive
```

### Thread Control

```bash
# Single-threaded (slowest but safest)
python -m heph --target example.com --threads 1

# Multi-threaded (faster)
python -m heph --target example.com --threads 10
```

---

## Database Management

### Shared Database Location

Hephaestus uses a **shared database** with other Argos suite tools:

-   Path: `~/.argos/argos.db`
-   Shared with: Argus (WordPress scanner), Pythia (SQL), Asteropm (Network) and other tools
-   Cross-tool integration for unified vulnerability tracking

### Query Examples

**View recent Hephaestus scans:**

```sql
sqlite3 ~/.argos/argos.db \
  "SELECT scan_id, target, mode, status, started_at
   FROM scans
   WHERE tool = 'hephaestus'
   ORDER BY scan_id DESC
   LIMIT 10;"
```

**Find critical server findings:**

```sql
sqlite3 ~/.argos/argos.db \
  "SELECT f.finding_id, f.title, f.severity, s.target
   FROM findings f
   JOIN scans s ON f.scan_id = s.scan_id
   WHERE s.tool = 'hephaestus'
     AND f.severity = 'critical';"
```

**Check verified domains:**

```sql
sqlite3 ~/.argos/argos.db \
  "SELECT domain, method, verified_at, expires_at
   FROM consent_tokens
   WHERE tool = 'hephaestus';"
```

**Aggregate statistics:**

```sql
sqlite3 ~/.argos/argos.db \
  "SELECT
     COUNT(*) as total_scans,
     SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
     SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
   FROM scans
   WHERE tool = 'hephaestus';"
```

For complete database reference, see `docs/DATABASE_GUIDE.md`

**Note:** Interactive database CLI will be available in v0.3.0 (HEPH-011)

---

## Migration Notes

### Upgrading from Pre-Release

This is the first production release. No migration required.

### Future Upgrades

**v0.2.0** (Q2 2026):

-   Fully backward compatible
-   New features: SSLyze integration, AI cost tracking, enhanced HTML reports
-   No database migration required

**v0.3.0** (Q3 2026):

-   Database schema v2 (automatic migration provided via `heph db migrate`)
-   Breaking change: Configuration file format (migration tool included)
-   New features: Interactive config, database CLI, AI chat, multi-site scanning

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

**v0.2.0** (Q2 2026) - Enhanced Detection & AI

-   Deep TLS/SSL analysis with SSLyze
-   Server module & framework detection
-   Enhanced HTML reporting with CVE/CWE badges
-   Apache/Nginx config file parser (offline analysis)
-   AI cost tracking & budget limits
-   AI streaming responses

**v0.3.0** (Q3 2026) - Enterprise Features

-   Interactive config management (Metasploit-style CLI)
-   Database CLI interface (no SQL required)
-   Multi-site scanning (batch processing)
-   Interactive AI chat (conversational hardening)
-   CI/CD integration templates
-   REST API server (FastAPI)

**v0.4.0** (Q1 2027) - Intelligence & Automation

-   Automated remediation (Ansible playbooks)
-   ML-based detection (anomaly detection)
-   Advanced AI agents (autonomous scanning)
-   Distributed scanning (worker nodes)

See `ROADMAP.md` for complete feature list

---

## License

This project is licensed under the MIT License. See `LICENSE` file for details.

---

## Acknowledgments

-   Apache & Nginx communities for documentation and hardening guides
-   OWASP for security standards (Top 10, Testing Guide, Secure Headers Project)
-   CIS Benchmarks for server hardening best practices
-   LangChain team for AI framework
-   OpenAI, Anthropic, and Ollama for AI models
-   Python community for amazing libraries (requests, Jinja2, PyYAML)
-   All contributors and testers who helped validate this release

---

## Disclaimer

**IMPORTANT:** This tool is for **authorized security testing only**.

-   Only scan systems you own or have explicit written permission to test
-   Unauthorized access is illegal (CFAA, Computer Misuse Act, etc.)
-   The authors assume no liability for misuse
-   Always practice responsible disclosure

See `docs/ETHICS.md` for complete ethical guidelines.

---

**Generated:** November 22, 2025  
**Version:** 0.1.0  
**Status:** Production Release  
**Author:** Rodney Dhavid Jimenez Chacin (rodhnin)

[0.1.0]: https://github.com/rodhnin/hephaestus-server-forger/releases/tag/v0.1.0
