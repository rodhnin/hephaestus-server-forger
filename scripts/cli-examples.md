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

# The tool runs in safe mode by default
# Output: 21 findings on Apache, 13 on Nginx
```

**Expected output:**
```
Scan completed in 21.34 seconds
Summary: 6 critical, 2 high, 8 medium, 5 low, 0 info
Report saved: ~/.hephaestus/reports/hephaestus_report_20241021_190156.json
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

# This uses GPT-4 Turbo by default
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

### Complete AI Scan Example

```bash
# Full scan with AI and HTML report (tested ✅)
export OPENAI_API_KEY="sk-proj-..."

heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone both \
  --html \
  -v
```

**Output includes:**
- JSON report with AI analysis
- HTML report with both technical and executive sections
- Estimated cost: ~$0.05 per scan

---

## 🎛️ Advanced Options

### Rate Limiting

```bash
# Custom request rate (requests per second) (tested ✅)
heph --target http://localhost:8080 --rate 5.0

# Slower for unstable servers (tested ✅)
heph --target http://localhost:8080 --rate 1.0

# Default is 10.0 req/s
```

**Use cases:**
- `--rate 1.0`: Slow/unstable servers
- `--rate 5.0`: Production servers (recommended)
- `--rate 10.0`: Default, safe for most cases

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

# Default: "Hephaestus/0.1.0"
```

### Disable SSL Verification

```bash
# For testing with self-signed certificates (tested ✅)
heph --target https://localhost:8443 --no-verify-ssl

# ⚠️ WARNING: Only use in development/testing!
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

**Duration:** ~21 seconds for Apache, ~22 seconds for Nginx

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

# 4. Run full scan with AI
export OPENAI_API_KEY="sk-proj-..."
heph --target https://example.com \
  --use-ai \
  --ai-tone both \
  --html \
  -vv
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
- **Duration:** ~21 seconds
- **Findings:** 21 total (6 critical, 2 high, 8 medium, 5 low)
- **Critical findings:**
  - Server version disclosure (HEPH-SRV-001)
  - Directory listing enabled (HEPH-DIR-001)
  - Missing security headers (HEPH-HDR-001-006)
- **Reports:** JSON + HTML with AI analysis

### Example 2: Nginx Server Scan

```bash
# Nginx scan comparison
heph --target http://localhost:8081 \
  --html \
  -v
```

**Expected Results:**
- **Duration:** ~22 seconds
- **Findings:** 13 total (3 critical, 2 high, 5 medium, 3 low)
- **Critical findings:**
  - Server version disclosure (HEPH-SRV-001)
  - Missing security headers (HEPH-HDR-001-003)

### Example 3: Quick Development Check

```bash
# Fast check without AI
heph --target http://localhost:8080 \
  --rate 10.0 \
  --threads 10 \
  -q
```

**Expected Results:**
- **Duration:** ~15-18 seconds (faster with more threads)
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

# Output: heph 0.1.0
```

### Verify Installation

```bash
# Check command exists
which heph

# Check Python module
python -c "import heph; print(heph.__version__)"

# Output: 0.1.0
```

---

## 📊 Output Examples

### JSON Report Structure

```json
{
  "tool": "hephaestus",
  "version": "0.1.0",
  "scan_id": 81,
  "target": "http://localhost:8080",
  "started_at": "2025-10-21T19:01:56",
  "completed_at": "2025-10-21T19:02:17",
  "duration": 21.34,
  "summary": {
    "critical": 6,
    "high": 2,
    "medium": 8,
    "low": 5,
    "info": 0
  },
  "findings": [
    {
      "code": "HEPH-SRV-001",
      "severity": "high",
      "title": "Apache server version disclosed",
      "description": "Server: Apache/2.4.62 (Debian)",
      "remediation": "Add 'ServerTokens Prod' to Apache config"
    }
    // ... more findings
  ],
  "ai_analysis": {
    "technical": "...",
    "non_technical": "..."
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