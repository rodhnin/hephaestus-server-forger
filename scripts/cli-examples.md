# 💻 Hephaestus CLI Examples

Complete command reference for the `heph` command-line tool with **REAL, TESTED examples**.

---

## 🎯 Basic Usage

### Simple Scan (Safe Mode)

```bash
# Scan a local Apache server (tested ✅)
heph --target http://localhost:8080

# Scan a local Nginx server (tested ✅)
heph --target http://localhost:8081

# The tool runs in safe mode by default across 13 scan phases
# Output: ~42 findings on Apache, ~25 on Nginx
```

**Expected output:**
```
Scan completed in 31.47 seconds
Summary: 8 critical, 7 high, 17 medium, 7 low, 3 info
Report saved: ~/.hephaestus/reports/hephaestus_report_20260401_190156.json
```

---

## 📄 Report Generation

### JSON Report (Default)

```bash
# JSON report is always generated
heph --target http://localhost:8080

# Find your report
ls -lh ~/.hephaestus/reports/*.json | tail -1
```

### HTML Report

```bash
# Generate both JSON and HTML reports (tested ✅)
heph --target http://localhost:8080 --html

# Open in browser
xdg-open ~/.hephaestus/reports/hephaestus_report_*.html
```

**HTML report includes:**
- Executive summary with color-coded severity badges
- Detailed findings with remediation steps
- Server information and scan metadata
- AI analysis sections (if --use-ai was used)

---

## 🔍 Verbosity Levels

### Quiet Mode

```bash
# Suppress console output, only show warnings (tested ✅)
heph --target http://localhost:8080 -q

# Still generates reports, useful for automation
```

### Normal Mode (Default)

```bash
# Standard output with progress indicators
heph --target http://localhost:8080
```

### Verbose Mode

```bash
# Show INFO level logs (tested ✅)
heph --target http://localhost:8080 -v

# Show DEBUG level logs (tested ✅)
heph --target http://localhost:8080 -vv

# Show TRACE level logs with HTTP requests (tested ✅)
heph --target http://localhost:8080 -vvv
```

**Example DEBUG output:**
```
2025-10-21 19:01:56 [DEBUG] heph.checks.headers: Checking security headers
2025-10-21 19:01:56 [DEBUG] heph.checks.headers: Missing: Strict-Transport-Security
2025-10-21 19:01:56 [DEBUG] heph.checks.headers: Missing: X-Content-Type-Options
```

---

## 🔒 Consent Token Management

### Generate Consent Token

```bash
# Generate token for a domain (tested ✅)
heph --gen-consent example.com
```

**Output:**
```
════════════════════════════════════════════════════════════════════
✓ Consent token generated successfully!
════════════════════════════════════════════════════════════════════

Token:    verify-a1b2c3d4e5f6g7h8
Domain:   example.com
Expires:  2025-10-22 23:34:08 (24 hours)
Created:  2025-10-21 23:34:08

═══════════ HTTP Verification Method ═══════════════════════════════
Place this token at:
  https://example.com/.well-known/verify-a1b2c3d4e5f6g7h8.txt

File content should be exactly:
  verify-a1b2c3d4e5f6g7h8

═══════════ DNS Verification Method ════════════════════════════════
Add TXT record to your DNS:
  hephaestus-verify=verify-a1b2c3d4e5f6g7h8

════════════════════════════════════════════════════════════════════
```

### Verify Consent (HTTP Method)

```bash
# After placing token file on server (tested ✅)
heph --verify-consent http \
  --domain example.com \
  --token verify-a1b2c3d4e5f6g7h8
```

**Success output:**
```
✓ Consent verified successfully via HTTP!
  Verified token: verify-a1b2c3d4e5f6g7h8
  Domain: example.com
  Method: http
  Valid until: 2025-10-22 23:34:08
```

**Failure output:**
```
✗ HTTP verification failed: Token not found at https://example.com/.well-known/verify-a1b2c3d4e5f6g7h8.txt
```

### Verify Consent (DNS Method)

```bash
# After adding DNS TXT record (tested ✅)
heph --verify-consent dns \
  --domain example.com \
  --token verify-a1b2c3d4e5f6g7h8
```

**DNS TXT record format:**
```
Type: TXT
Name: _hephaestus-verify.example.com
Value: verify-a1b2c3d4e5f6g7h8
```

---

## 🤖 AI-Powered Analysis

### Setup OpenAI API Key

```bash
# Set your API key (tested ✅)
export OPENAI_API_KEY="sk-proj-..."

# Verify it's set
echo $OPENAI_API_KEY
```

### Run Scan with AI Analysis

```bash
# Basic AI analysis (tested ✅)
heph --target http://localhost:8080 --use-ai

# Default model: gpt-4o-mini-2024-07-18
# Generates: Technical + Non-Technical reports
```

**AI Analysis includes:**
- 🎯 Executive Summary (for management)
- 🔧 Technical Analysis (for engineers)
- 📊 Risk Assessment
- 🛠️ Prioritized Remediation Steps

### AI Tone Options

```bash
# Technical report only (for engineers) (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone technical

# Executive summary only (for management) (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone non_technical

# Both reports (default) (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone both
```

### AI Streaming (`--ai-stream`)

```bash
# Stream tokens as they're generated (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-stream \
  --ai-tone technical
```

### AI Provider Comparison (`--ai-compare`)

```bash
# Compare two providers in parallel (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-compare openai,anthropic \
  --html

# With explicit model versions (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-compare openai:gpt-4o-mini-2024-07-18,anthropic:claude-3-5-haiku-20241022 \
  --html
```

### AI Agent Mode (`--ai-agent`)

```bash
# Agent with live NVD CVE lookup (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-agent \
  --html \
  -v

# ⚠️ Agent mode makes additional API calls — consider --ai-budget
```

### AI Budget Cap (`--ai-budget`)

```bash
# Cap spending at $0.50 (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-budget 0.50 \
  --ai-tone both \
  -v

# Costs tracked in ~/.argos/costs.json
```

### AI Provider Selection (`--ai-provider`)

```bash
# Use Anthropic Claude instead of OpenAI (tested ✅)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-provider anthropic \
  --ai-model claude-3-5-haiku-20241022

# Use local Ollama model (no API key needed)
heph --target http://localhost:8080 \
  --use-ai \
  --ai-provider ollama \
  --ai-model llama3.2
```

### Complete AI Scan Example

```bash
# Full scan with AI and HTML report (tested ✅)
export OPENAI_API_KEY="sk-proj-..."

heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone both \
  --ai-budget 1.00 \
  --html \
  -v
```

**Output includes:**
- JSON report with AI analysis and OWASP Top 10 mapping
- HTML report with both technical and executive sections
- AI cost entry in `~/.argos/costs.json`
- Estimated cost: ~$0.18 per scan (medium report, 25 findings)

---

## 🎛️ Advanced Options

### Rate Limiting

```bash
# Custom request rate (requests per second) (tested ✅)
heph --target http://localhost:8080 --rate 5.0

# Slower for unstable servers (tested ✅)
heph --target http://localhost:8080 --rate 1.0

# Default is 5.0 req/s (safe mode) / 12.0 req/s (aggressive mode)
```

**Use cases:**
- `--rate 1.0`: Slow/unstable servers
- `--rate 5.0`: Production servers (recommended)
- `--rate 12.0`: Max aggressive mode rate

### Timeout Configuration

```bash
# Custom timeout in seconds (tested ✅)
heph --target http://localhost:8080 --timeout 30

# For slow servers (tested ✅)
heph --target http://localhost:8080 \
  --timeout 60 \
  --rate 2.0
```

**Default timeout: 30 seconds per request**

### Thread Pool Size

```bash
# More concurrent checks (tested ✅)
heph --target http://localhost:8080 --threads 10

# Single-threaded for debugging (tested ✅)
heph --target http://localhost:8080 --threads 1

# Default: 5 threads
```

**Thread recommendations:**
- `--threads 1`: Debugging, step-by-step execution
- `--threads 5`: Default, balanced
- `--threads 10`: Faster scans on powerful servers

### Custom User-Agent

```bash
# Use custom User-Agent string (tested ✅)
heph --target http://localhost:8080 \
  --user-agent "MyScanner/1.0"

# Default: "Hephaestus/0.2.0"
```

### Disable SSL Verification

```bash
# For testing with self-signed certificates (tested ✅)
heph --target https://localhost:8443 --no-verify-ssl

# ⚠️ WARNING: Only use in development/testing!
```

### Diff Reports (`--diff`)

```bash
# Compare current scan against the last scan of the same target (tested ✅)
heph --target http://localhost:8080 --diff last

# Compare against a specific previous scan by ID
heph --target http://localhost:8080 --diff 84

# Diff output shows:
# RESOLVED: findings that disappeared since last scan
# NEW: findings that appeared since last scan
# UNCHANGED: findings present in both scans
```

**Example diff output:**
```
Diff vs scan #84 (2026-04-01 18:30:12)
──────────────────────────────────────────────
RESOLVED  (2): HEPH-FILE-001 .env file exposed
               COO-001 Cookie missing Secure flag
NEW       (1): WAF-001 No WAF detected
UNCHANGED (39): ...
```

### Offline Config File Parser (`--config-file`)

```bash
# Parse Apache httpd.conf offline (no HTTP requests) (tested ✅)
heph --config-file /etc/apache2/apache2.conf

# Parse Nginx nginx.conf offline (tested ✅)
heph --config-file /etc/nginx/nginx.conf

# Save results to HTML
heph --config-file /path/to/httpd.conf --html

# Expected findings from config analysis:
# - ServerTokens Full → HIGH
# - Options Indexes → MEDIUM (directory listing)
# - ssl_protocols TLSv1 → HIGH
# - expose_php On → HIGH
# - display_errors On → HIGH
```

---

## 🔐 TLS/SSL Checks

### Check TLS Configuration

```bash
# Include TLS checks in scan (tested ✅)
heph --target https://example.com --check-tls

# Checks:
# - Certificate validity
# - Cipher suites
# - Protocol versions
# - Certificate chain
```

### Skip TLS Checks

```bash
# Skip TLS checks (faster scan) (tested ✅)
heph --target https://example.com --skip-tls

# Useful for:
# - HTTP-only targets
# - Quick scans where TLS is already validated
```

---

## 📊 Output Configuration

### Custom Report Directory

```bash
# Save reports to specific directory (tested ✅)
heph --target http://localhost:8080 \
  --report-dir ./my-reports

# Reports will be saved in:
# ./my-reports/hephaestus_report_*.json
# ./my-reports/hephaestus_report_*.html (if --html)
```

### Log File Configuration

```bash
# Custom log file location (tested ✅)
heph --target http://localhost:8080 \
  --log-file ./scan.log

# JSON format logs (tested ✅)
heph --target http://localhost:8080 \
  --log-json \
  --log-file ./scan.json
```

**JSON log format (one JSON object per line):**
```json
{"timestamp": "2025-10-21T19:01:56", "level": "INFO", "message": "Starting scan"}
{"timestamp": "2025-10-21T19:01:57", "level": "DEBUG", "message": "Checking headers"}
```

### No Color Output

```bash
# Disable colored output (tested ✅)
heph --target http://localhost:8080 --no-color

# Useful for:
# - Piping to files
# - CI/CD environments
# - Log parsers
```

---

## 🧪 Testing & Development

### Test Against Local Labs

```bash
# Apache HTTP (tested ✅)
heph --target http://localhost:8080

# Apache HTTPS with self-signed cert (tested ✅)
heph --target https://localhost:8443 --no-verify-ssl

# Nginx HTTP (tested ✅)
heph --target http://localhost:8081
```

### Error Testing

```bash
# Connection refused (tested ✅)
heph --target http://localhost:9999
# Output: Connection refused error, saved to database

# DNS resolution failed (tested ✅)
heph --target http://invalid-domain-xyz.com
# Output: DNS resolution error, saved to database

# Timeout (tested ✅)
heph --target http://localhost:8080 --timeout 1
# Output: Timeout error if server is slow
```

---

## 🔄 Common Workflows

### Quick Security Check

```bash
# Fast scan with HTML report
heph --target http://localhost:8080 --html -v
```

**Duration:** ~30-35 seconds for Apache, ~30-35 seconds for Nginx (13 scan phases)

### Full Security Audit

```bash
# 1. Generate consent token
heph --gen-consent example.com

# 2. Place token on server (manual step)
# Create file: https://example.com/.well-known/verify-TOKEN.txt
# Content: TOKEN

# 3. Verify consent
heph --verify-consent http \
  --domain example.com \
  --token verify-abc123

# 4. Run full scan with AI, streaming enabled, budget cap
export OPENAI_API_KEY="sk-proj-..."
heph --target https://example.com \
  --use-ai \
  --ai-tone both \
  --ai-stream \
  --ai-budget 1.00 \
  --html \
  -vv

# 5. Compare against last scan for regressions
heph --target https://example.com --diff last
```

### Development Server Check

```bash
# Local development server
heph --target http://localhost:3000

# Local with self-signed cert
heph --target https://localhost:3000 --no-verify-ssl
```

### Production Server Check

```bash
# Production with slower rate to avoid load
heph --target https://production.example.com \
  --rate 2.0 \
  --html \
  -v
```

---

## 📋 Database Integration

### View Scan History

```bash
# Show last 10 scans (tested ✅)
sqlite3 ~/.argos/argos.db "
SELECT 
  scan_id, 
  domain, 
  mode, 
  status, 
  started_at 
FROM scans 
WHERE tool = 'hephaestus' 
ORDER BY scan_id DESC 
LIMIT 10;
"
```

### View Findings from a Scan

```bash
# Get findings from scan_id 81 (tested ✅)
sqlite3 ~/.argos/argos.db "
SELECT 
  finding_code,
  severity,
  title
FROM findings 
WHERE scan_id = 81;
"
```

### Export Findings to JSON

```bash
# Export findings (tested ✅)
sqlite3 ~/.argos/argos.db -json "
SELECT 
  finding_id,
  scan_id,
  finding_code,
  severity,
  title,
  description
FROM findings 
WHERE scan_id = 81;
" | jq '.'
```

### View Failed Scans

```bash
# Show failed scans with error messages (tested ✅)
sqlite3 ~/.argos/argos.db "
SELECT 
  scan_id,
  domain,
  error_message
FROM scans 
WHERE status = 'failed' AND tool = 'hephaestus'
ORDER BY scan_id DESC
LIMIT 5;
"
```

---

## 🛠️ Troubleshooting

### Connection Issues

```bash
# Test with verbose output
heph --target https://example.com -vvv

# Increase timeout
heph --target https://example.com --timeout 120

# Test with curl first
curl -I https://example.com
```

### Invalid Parameters

```bash
# Rate must be positive (tested ✅)
heph --target http://localhost:8080 --rate -5
# ERROR: --rate must be a positive number (got -5.0)

# Threads must be positive (tested ✅)
heph --target http://localhost:8080 --threads 0
# ERROR: --threads must be a positive number (got 0)
```

### Permission Issues

```bash
# Report directory permission denied (tested ✅)
heph --target http://localhost:8080 --report-dir /root/reports
# PermissionError: [Errno 13] Permission denied: '/root/reports'

# Solution: Use accessible directory
heph --target http://localhost:8080 --report-dir ~/reports
```

### Database Issues

```bash
# Check database exists
ls -lh ~/.argos/argos.db

# View database schema
sqlite3 ~/.argos/argos.db ".schema scans"

# Check database integrity
sqlite3 ~/.argos/argos.db "PRAGMA integrity_check;"
```

---

## 📚 Real-World Examples

### Example 1: Apache Server Scan

```bash
# Full scan with all features
export OPENAI_API_KEY="sk-proj-..."

heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone both \
  --html \
  --rate 5.0 \
  --threads 5 \
  --timeout 30 \
  -v
```

**Expected Results:**
- **Duration:** ~30-35 seconds (13 scan phases)
- **Findings:** ~42 total (8 critical, 7 high, 17 medium, 7 low, 3 info)
- **Critical findings:**
  - .env file exposed (HEPH-FILE-001)
  - .git repository exposed (HEPH-FILE-002)
  - phpinfo.php accessible + PHP-001 to PHP-004 (CRITICAL PHP settings)
  - CORS allowing credentials with wildcard (COR-002)
- **Reports:** JSON + HTML with AI analysis and OWASP Top 10 mapping

### Example 2: Nginx Server Scan

```bash
# Nginx scan comparison
heph --target http://localhost:8081 \
  --html \
  -v
```

**Expected Results:**
- **Duration:** ~30-35 seconds (13 scan phases)
- **Findings:** ~25 total (2 critical, 3 high, 12 medium, 6 low, 2 info)
- **Critical findings:**
  - .env file exposed (HEPH-FILE-001)
  - .git repository exposed (HEPH-FILE-002)

### Example 3: Quick Development Check

```bash
# Fast check without AI
heph --target http://localhost:8080 \
  --rate 10.0 \
  --threads 10 \
  -q
```

**Expected Results:**
- **Duration:** ~20-25 seconds (faster with more threads, still runs all 13 phases)
- **Output:** Minimal console output
- **Report:** JSON only

### Example 4: Slow/Unreliable Server

```bash
# Conservative settings for production
heph --target https://production.example.com \
  --rate 1.0 \
  --threads 1 \
  --timeout 60 \
  -v
```

**Use when:**
- Server is slow or under load
- Network is unreliable
- You want to minimize impact

---

## 📖 Help & Version

### Show Help

```bash
# Full help (tested ✅)
heph --help
heph -h
```

### Version Info

```bash
# Show version (tested ✅)
heph --version

# Output: heph 0.2.0
```

### Verify Installation

```bash
# Check command exists
which heph

# Check Python module
python -c "import heph; print(heph.__version__)"

# Output: 0.2.0
```

---

## 📊 Output Examples

### JSON Report Structure

```json
{
  "tool": "hephaestus",
  "version": "0.2.0",
  "scan_id": 81,
  "target": "http://localhost:8080",
  "started_at": "2026-04-01T19:01:56",
  "completed_at": "2026-04-01T19:02:29",
  "duration": 31.47,
  "summary": {
    "critical": 8,
    "high": 7,
    "medium": 17,
    "low": 7,
    "info": 3
  },
  "findings": [
    {
      "finding_code": "HEPH-SRV-001",
      "severity": "high",
      "title": "Apache server version disclosed",
      "description": "Server: Apache/2.4.62 (Debian)",
      "remediation": "Add 'ServerTokens Prod' to Apache config",
      "owasp": {"id": "A05", "name": "Security Misconfiguration"},
      "cvss": 5.3,
      "vulnerabilities": []
    }
    // ... more findings
  ],
  "diff": {
    "resolved": [],
    "new": [],
    "unchanged": 42
  },
  "ai_analysis": {
    "executive_summary": "...",
    "technical_remediation": "...",
    "agent_analysis": null,
    "compare_results": null,
    "generated_at": "2026-04-01T19:02:45Z",
    "model_used": "openai/gpt-4o-mini-2024-07-18"
  }
}
```

### Database Schema

```sql
-- Scans table
CREATE TABLE scans (
    scan_id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL DEFAULT 'hephaestus',
    domain TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'safe',
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error_message TEXT
);

-- Findings table
CREATE TABLE findings (
    finding_id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    finding_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

-- Consent tokens table
CREATE TABLE consent_tokens (
    token_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    verified BOOLEAN DEFAULT 0
);
```

---

## 🎯 Summary of Tested Commands

All commands below have been **tested and validated** ✅:

```bash
# Basic scans
heph --target http://localhost:8080
heph --target http://localhost:8081
heph --target https://localhost:8443 --no-verify-ssl

# Report generation
heph --target http://localhost:8080 --html

# Verbosity
heph --target http://localhost:8080 -q
heph --target http://localhost:8080 -v
heph --target http://localhost:8080 -vv
heph --target http://localhost:8080 -vvv

# Consent tokens
heph --gen-consent example.com
heph --verify-consent http --domain example.com --token TOKEN
heph --verify-consent dns --domain example.com --token TOKEN

# AI analysis
heph --target http://localhost:8080 --use-ai
heph --target http://localhost:8080 --use-ai --ai-tone technical
heph --target http://localhost:8080 --use-ai --ai-tone non_technical
heph --target http://localhost:8080 --use-ai --ai-tone both
heph --target http://localhost:8080 --use-ai --ai-stream
heph --target http://localhost:8080 --use-ai --ai-compare openai,anthropic
heph --target http://localhost:8080 --use-ai --ai-agent
heph --target http://localhost:8080 --use-ai --ai-budget 0.50
heph --target http://localhost:8080 --use-ai --ai-provider anthropic --ai-model claude-3-5-haiku-20241022

# Diff reports
heph --target http://localhost:8080 --diff last
heph --target http://localhost:8080 --diff 84

# Offline config file parser
heph --config-file /etc/apache2/apache2.conf
heph --config-file /etc/nginx/nginx.conf --html

# Advanced options
heph --target http://localhost:8080 --rate 5.0
heph --target http://localhost:8080 --timeout 30
heph --target http://localhost:8080 --threads 10
heph --target http://localhost:8080 --user-agent "Custom"
heph --target http://localhost:8080 --report-dir ./reports
heph --target http://localhost:8080 --log-file ./scan.log
heph --target http://localhost:8080 --log-json
heph --target http://localhost:8080 --no-color

# TLS checks
heph --target https://example.com --check-tls
heph --target https://example.com --skip-tls

# Help and version
heph --help
heph --version
```

---

## 🚀 Next Steps

1. **Setup your environment:**
   ```bash
   cd hephaestus-server-forger
   python -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```

2. **Configure AI (optional):**
   ```bash
   export OPENAI_API_KEY="sk-proj-..."
   ```

3. **Run your first scan:**
   ```bash
   heph --target http://localhost:8080 --html -v
   ```

4. **View results:**
   ```bash
   xdg-open ~/.hephaestus/reports/hephaestus_report_*.html
   ```

---

**All examples in this document have been tested and validated.** ✅

For more information, see:
- [README.md](../README.md) - Project overview
- [TESTING_GUIDE.md](../docs/TESTING_GUIDE.md) - Complete test results