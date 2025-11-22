# 🧪 Safe Testing Guide for Hephaestus

This guide explains how to safely test Hephaestus without scanning unauthorized systems.

---

## ⚠️ Testing Ethics

**CRITICAL RULES:**

1. ✅ **ONLY** test against systems you own or have explicit permission
2. ✅ Use the provided Docker lab environment (Apache & Nginx)
3. ✅ Use isolated VMs with snapshots
4. ❌ **NEVER** scan production servers without authorization
5. ❌ **NEVER** scan third-party servers "for practice"

Unauthorized scanning is **illegal** in most jurisdictions (CFAA, Computer Misuse Act, etc.).

---

## 🐳 Method 1: Docker Lab (Recommended)

The safest and fastest way to test Hephaestus features. **Fully automated setup** - no manual file creation required!

### Quick Start (15 Seconds to Full Lab)

**Option 1: Using Interactive Script (Recommended)**
```bash
# Run from project root
cd docker && ./deploy.sh

# Select option 2 (Testing Lab)
```

**Option 2: Manual Docker Compose**
```bash
# Start vulnerable lab (Apache + Nginx)
docker compose -f docker/compose.testing.yml up -d

# Wait for initialization (15 seconds)
sleep 15

# Verify services are running
docker compose -f docker/compose.testing.yml ps
```

**Expected output:**

```
NAME                            STATUS    PORTS
hephaestus-vulnerable-apache    Up        0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp
hephaestus-vulnerable-nginx     Up        0.0.0.0:8081->80/tcp, 0.0.0.0:8444->443/tcp
```

✅ **That's it!** No manual file creation, no configuration needed. Everything is auto-generated.

### What Gets Auto-Generated

When containers start, `docker-entrypoint.sh` scripts automatically create:

#### Apache Lab (`http://localhost:8080`)

-   ✅ `.env` file with exposed secrets (CRITICAL)
-   ✅ `.git/` repository with config files (CRITICAL)
-   ✅ `phpinfo.php` with full PHP configuration (CRITICAL)
-   ✅ `test.php`, `info.php` files (MEDIUM)
-   ✅ `/uploads/` directory with files and listing enabled (MEDIUM)
-   ✅ `/server-status` endpoint publicly accessible (MEDIUM)
-   ✅ Self-signed SSL certificate with weak ciphers (HIGH)
-   ✅ Full server version disclosure (`ServerTokens Full`) (HIGH)
-   ✅ TRACE method enabled (MEDIUM)
-   ✅ All security headers removed (MEDIUM/LOW)

#### Nginx Lab (`http://localhost:8081`)

-   ✅ `.env` file with credentials (CRITICAL)
-   ✅ `.git/` repository (CRITICAL)
-   ✅ `/uploads/` directory with autoindex enabled (MEDIUM)
-   ✅ Self-signed SSL certificate (HIGH)
-   ✅ Server version disclosure (`server_tokens on`) (HIGH)
-   ✅ All security headers missing (MEDIUM/LOW)

### Verifying the Lab

Run these quick tests to confirm everything is working:

```bash
# Test 1: Apache version disclosure
curl -I http://localhost:8080
# Expected: Server: Apache/2.4.54 (Debian) PHP/7.4.33 OpenSSL/1.1.1n

# Test 2: .env exposed on Apache
curl http://localhost:8080/.env
# Expected: APP_NAME=VulnerableApp
#          DB_PASSWORD=SuperSecretPassword123!

# Test 3: phpinfo.php leak
curl -s http://localhost:8080/phpinfo.php | grep "PHP Version"
# Expected: PHP Version 7.4.33

# Test 4: .git exposed
curl http://localhost:8080/.git/HEAD
# Expected: ref: refs/heads/master

# Test 5: Directory listing
curl http://localhost:8080/uploads/ | grep "Index of"
# Expected: <title>Index of /uploads</title>

# Test 6: Nginx version disclosure
curl -I http://localhost:8081
# Expected: Server: nginx/1.18.0

# Test 7: .env on Nginx
curl http://localhost:8081/.env
# Expected: DB_PASSWORD=NginxSecretPass456!

# Test 8: Weak TLS on Apache
curl -k -I https://localhost:8443
# Expected: 200 OK (weak ciphers accepted)
```

✅ If all tests pass, the lab is fully operational!

---

## 🎯 Running Test Scans

### Prerequisites

```bash
# 1. Navigate to project root
cd ~/Argos/hephaestus-server-forger

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Verify installation
python -m heph --version
# Output: heph 0.1.0
```

### Test 1: Basic Scan (Apache)

```bash
python -m heph --target http://localhost:8080

# Expected findings:
# - HEPH-SRV-001: Apache version disclosed (HIGH)
# - HEPH-SRV-002: PHP version disclosed (HIGH)
# - HEPH-FILE-001: .env file exposed (CRITICAL)
# - HEPH-FILE-002: .git repository exposed (CRITICAL)
# - HEPH-FILE-004: phpinfo.php accessible (CRITICAL)
# - HEPH-CFG-001: Directory listing enabled (MEDIUM)
# - HEPH-HTTP-003: TRACE method enabled (MEDIUM)
# - HEPH-HDR-001 to HEPH-HDR-006: Missing security headers (MEDIUM/LOW)
# Total: ~21 findings
```

### Test 2: Basic Scan (Nginx)

```bash
python -m heph --target http://localhost:8081

# Expected findings:
# - HEPH-SRV-001: Nginx version disclosed (HIGH)
# - HEPH-FILE-001: .env file exposed (CRITICAL)
# - HEPH-FILE-002: .git repository exposed (CRITICAL)
# - HEPH-CFG-001: Directory listing enabled (MEDIUM)
# - HEPH-HDR-001 to HEPH-HDR-006: Missing headers (MEDIUM/LOW)
# Total: ~13 findings
```

### Test 3: Verbose Output

```bash
# See detailed scan progress
python -m heph --target http://localhost:8080 -vv

# Expected:
# [DEBUG] Checking server information...
# [DEBUG] Found: Apache/2.4.54
# [DEBUG] Checking sensitive files...
# [DEBUG] Found: .env (200 OK)
# [DEBUG] Found: .git/HEAD (200 OK)
# ...
```

### Test 4: HTML Report Generation

```bash
# Generate beautiful HTML report
python -m heph --target http://localhost:8080 --html

# Check output
ls -lh ~/.hephaestus/reports/
# Expected: hephaestus_report_localhost_*.html (50-100 KB)

# Open in browser
xdg-open ~/.hephaestus/reports/hephaestus_report_localhost_*.html
# (macOS: open, Windows: start)
```

### Test 5: TLS/SSL Scanning

```bash
# Scan HTTPS endpoints (weak TLS)
python -m heph --target https://localhost:8443 --no-verify-ssl

# Expected additional findings:
# - HEPH-TLS-001: Weak TLS protocols enabled (TLS 1.0/1.1) (HIGH)
# - HEPH-HDR-001: Missing HSTS header (MEDIUM)
```

### Test 6: Custom Options

```bash
# Slower rate for testing rate limiting
python -m heph --target http://localhost:8080 --rate 1.0 -v

# More threads for faster scanning
python -m heph --target http://localhost:8080 --threads 10

# Custom timeout
python -m heph --target http://localhost:8080 --timeout 60
```

### Test 7: Database Persistence

```bash
# Run multiple scans
python -m heph --target http://localhost:8080
python -m heph --target http://localhost:8081

# Check database (shared with Argos)
sqlite3 ~/.argos/argos.db "SELECT scan_id, domain, mode, status, started_at FROM scans WHERE tool='hephaestus' ORDER BY scan_id DESC LIMIT 5;"

# Expected:
# 85|localhost:8081|safe|completed|2025-10-21 19:30:45
# 84|localhost:8080|safe|completed|2025-10-21 19:29:12
```

### Test 8: JSON Report Schema

```bash
# Generate JSON report
python -m heph --target http://localhost:8080

# Validate schema
LAST_REPORT=$(ls -t ~/.hephaestus/reports/*.json | head -1)
jq '{tool, version, target, summary, findings: (.findings | length)}' "$LAST_REPORT"

# Expected:
# {
#   "tool": "hephaestus",
#   "version": "0.1.0",
#   "target": "http://localhost:8080",
#   "summary": {
#     "critical": 6,
#     "high": 2,
#     "medium": 8,
#     "low": 5,
#     "info": 0
#   },
#   "findings": 21
# }
```

---

## 🔐 Testing Consent Token System

Aggressive mode and AI analysis require ownership verification.

### Test 9: Consent Token Generation

```bash
python -m heph --gen-consent localhost:8080

# Expected output:
# ======================================================================
# DOMAIN OWNERSHIP VERIFICATION REQUIRED
# ======================================================================
# Domain: localhost:8080
# Token: verify-a3f9b2c1d8e4f5a6
# Expires: 48 hours from now
#
# Place at: http://localhost:8080/.well-known/verify-a3f9b2c1d8e4f5a6.txt
# Content: verify-a3f9b2c1d8e4f5a6
```

### Test 10: Place Token in Lab

```bash
# Extract token from previous command (example)
TOKEN="verify-a3f9b2c1d8e4f5a6"

# Place token in Apache container
docker exec hephaestus-vulnerable-apache bash -c \
  "mkdir -p /var/www/html/.well-known && \
   echo '$TOKEN' > /var/www/html/.well-known/$TOKEN.txt"

# Verify token is accessible
curl http://localhost:8080/.well-known/$TOKEN.txt
# Expected: verify-a3f9b2c1d8e4f5a6
```

### Test 11: Verify Consent (HTTP)

```bash
python -m heph --verify-consent http \
  --domain localhost:8080 \
  --token verify-a3f9b2c1d8e4f5a6

# Expected output:
# ✓ CONSENT VERIFICATION SUCCESSFUL
# Token verified via HTTP method
# Domain: localhost:8080
# Expires: 2025-10-23 19:45:30 UTC
```

### Test 12: Aggressive Mode (With Consent)

```bash
# Now that consent is verified, test aggressive mode
python -m heph --target http://localhost:8080 --aggressive -v

# Expected:
# - Higher rate limit (8 req/s instead of 3)
# - More detailed checks
# - Same findings (lab already exposes everything)
```

### Test 13: Consent Enforcement

```bash
# Try aggressive mode WITHOUT consent on different domain
python -m heph --target http://localhost:8081 --aggressive

# Expected error:
# ERROR: Aggressive mode requires consent verification
# Run: python -m heph --gen-consent localhost:8081
```

---

## 🤖 Testing AI Features (Optional)

⚠️ **Requires API key** (costs ~$0.25/scan)

### Test 14: AI Analysis (Technical)

```bash
# Set API key
export OPENAI_API_KEY="sk-..."

# Run AI-powered scan (technical report)
python -m heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone technical \
  --html \
  -v

# Expected:
# [INFO] Generating AI analysis (technical)...
# [INFO] AI analysis complete (35 seconds)
#
# Check HTML report for:
# - Technical Hardening Guide section
# - Apache config snippets
# - Step-by-step remediation
```

### Test 15: AI Analysis (Executive)

```bash
# Executive summary for management
python -m heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone non_technical \
  --html

# Expected in HTML:
# - Executive Risk Summary section
# - Plain-language risk description
# - Business impact analysis
```

### Test 16: AI Analysis (Both)

```bash
# Both technical and executive in one report
python -m heph --target http://localhost:8080 \
  --use-ai \
  --ai-tone both \
  --html

# Expected in HTML:
# - Executive Risk Summary (top)
# - Technical Hardening Guide (bottom)
```

### Test 17: AI with Ollama (Local, Free)

```bash
# Install Ollama first: https://ollama.ai
ollama pull llama3.2

# Edit config to use Ollama
nano ~/.hephaestus/config.yaml
# Change:
# ai:
#   langchain:
#     provider: "ollama"
#     model: "llama3.2"

# Run scan (no API key needed, but slower)
python -m heph --target http://localhost:8080 --use-ai --html
# Expected: 28 minutes on CPU, 75 seconds on GPU
```

---

## 🧪 Test Cases & Expected Results

### Comprehensive Test Matrix

| Test Case                      | Target                              | Severity     | Finding ID    | Auto-Generated |
| ------------------------------ | ----------------------------------- | ------------ | ------------- | -------------- |
| **Apache Core**                |
| Version disclosure             | http://localhost:8080               | HIGH         | HEPH-SRV-001  | ✅             |
| PHP version leak               | http://localhost:8080               | HIGH         | HEPH-SRV-002  | ✅             |
| Apache in error page           | http://localhost:8080/404           | MEDIUM       | HEPH-SRV-004  | ✅             |
| **Sensitive Files**            |
| .env exposed                   | http://localhost:8080/.env          | **CRITICAL** | HEPH-FILE-001 | ✅             |
| .git/HEAD                      | http://localhost:8080/.git/HEAD     | **CRITICAL** | HEPH-FILE-002 | ✅             |
| .git/config                    | http://localhost:8080/.git/config   | **CRITICAL** | HEPH-FILE-002 | ✅             |
| phpinfo.php                    | http://localhost:8080/phpinfo.php   | **CRITICAL** | HEPH-FILE-004 | ✅             |
| /server-status                 | http://localhost:8080/server-status | MEDIUM       | HEPH-INFO-002 | ✅             |
| **HTTP Methods**               |
| TRACE enabled                  | http://localhost:8080               | MEDIUM       | HEPH-HTTP-003 | ✅             |
| OPTIONS discloses methods      | http://localhost:8080               | LOW          | HEPH-HTTP-008 | ✅             |
| **Security Headers**           |
| Missing HSTS                   | http://localhost:8080               | MEDIUM       | HEPH-HDR-001  | ✅             |
| Missing CSP                    | http://localhost:8080               | MEDIUM       | HEPH-HDR-002  | ✅             |
| Missing X-Frame-Options        | http://localhost:8080               | MEDIUM       | HEPH-HDR-003  | ✅             |
| Missing X-Content-Type-Options | http://localhost:8080               | LOW          | HEPH-HDR-004  | ✅             |
| Missing Referrer-Policy        | http://localhost:8080               | LOW          | HEPH-HDR-005  | ✅             |
| Missing Permissions-Policy     | http://localhost:8080               | LOW          | HEPH-HDR-006  | ✅             |
| **TLS/SSL**                    |
| Weak TLS protocols             | https://localhost:8443              | HIGH         | HEPH-TLS-001  | ✅             |
| Self-signed cert               | https://localhost:8443              | INFO         | HEPH-TLS-002  | ✅             |
| **Configuration**              |
| Directory listing              | http://localhost:8080/uploads/      | MEDIUM       | HEPH-CFG-001  | ✅             |
| **Nginx Specific**             |
| Nginx version                  | http://localhost:8081               | HIGH         | HEPH-SRV-001  | ✅             |
| Nginx .env                     | http://localhost:8081/.env          | **CRITICAL** | HEPH-FILE-001 | ✅             |

### Expected Finding Counts

#### Apache Lab (localhost:8080)

-   **CRITICAL**: 3-6 findings (.env, .git/HEAD, .git/config, phpinfo.php, server-status)
-   **HIGH**: 2-3 findings (version disclosure, weak TLS)
-   **MEDIUM**: 7-9 findings (headers, TRACE, directory listing, error page)
-   **LOW**: 3-5 findings (headers, HTTP methods)
-   **INFO**: 0-2 findings
-   **TOTAL**: 15-25 findings

#### Nginx Lab (localhost:8081)

-   **CRITICAL**: 2-3 findings (.env, .git files)
-   **HIGH**: 2 findings (version, TLS)
-   **MEDIUM**: 4-6 findings (headers, directory listing)
-   **LOW**: 3-4 findings (headers)
-   **INFO**: 0-1 findings
-   **TOTAL**: 11-16 findings

---

## 📊 Acceptance Criteria

### ✅ Pass Conditions

-   [ ] All expected CRITICAL findings detected (.env, .git, phpinfo)
-   [ ] Server versions correctly identified (Apache 2.4.54, Nginx 1.18.0)
-   [ ] Severity levels match expectations
-   [ ] No false positives on clean/secure servers
-   [ ] JSON validates against schema (`schema/report.schema.json`)
-   [ ] HTML renders correctly in modern browsers
-   [ ] Database persistence works (scans stored in `~/.argos/argos.db`)
-   [ ] Consent system blocks aggressive mode without verification
-   [ ] AI analysis completes without errors (if API key provided)
-   [ ] Rate limiting works (3 req/s safe, 8 req/s aggressive)

### ❌ Fail Conditions

-   [ ] CRITICAL findings missed (e.g., .env file not detected)
-   [ ] False positives on secure configurations
-   [ ] JSON schema validation fails
-   [ ] Crash or unhandled exceptions
-   [ ] Consent bypass possible
-   [ ] Database foreign key violations
-   [ ] Memory leaks or resource exhaustion

---

## 📋 Regression Testing

Before each release, run the complete test suite:

### Automated Test Script

```bash
#!/bin/bash
# tests/run_integration_tests.sh

set -e

echo "🧪 Hephaestus Integration Test Suite"
echo "===================================="

# 1. Reset lab
echo "1. Resetting Docker lab..."
cd docker
docker compose -f compose.testing.yml down -v
docker compose -f compose.testing.yml up -d
sleep 15

# 2. Basic scans
echo "2. Running basic scans..."
cd ..
python -m heph --target http://localhost:8080 --html -v
python -m heph --target http://localhost:8081 --html -v

# 3. Verify findings count
echo "3. Verifying findings..."
APACHE_FINDINGS=$(jq '.findings | length' ~/.hephaestus/reports/hephaestus_report_localhost_8080_*.json | tail -1)
NGINX_FINDINGS=$(jq '.findings | length' ~/.hephaestus/reports/hephaestus_report_localhost_8081_*.json | tail -1)

if [ "$APACHE_FINDINGS" -lt 15 ]; then
    echo "❌ FAIL: Apache findings too low ($APACHE_FINDINGS < 15)"
    exit 1
fi

if [ "$NGINX_FINDINGS" -lt 10 ]; then
    echo "❌ FAIL: Nginx findings too low ($NGINX_FINDINGS < 10)"
    exit 1
fi

# 4. Test consent system
echo "4. Testing consent system..."
python -m heph --gen-consent localhost:8080 > /tmp/token.txt
TOKEN=$(grep "Token:" /tmp/token.txt | awk '{print $2}')

docker exec hephaestus-vulnerable-apache bash -c \
  "mkdir -p /var/www/html/.well-known && echo '$TOKEN' > /var/www/html/.well-known/$TOKEN.txt"

python -m heph --verify-consent http --domain localhost:8080 --token "$TOKEN"

# 5. Test aggressive mode
echo "5. Testing aggressive mode..."
python -m heph --target http://localhost:8080 --aggressive

# 6. Database checks
echo "6. Checking database..."
SCAN_COUNT=$(sqlite3 ~/.argos/argos.db "SELECT COUNT(*) FROM scans WHERE tool='hephaestus'")
if [ "$SCAN_COUNT" -lt 3 ]; then
    echo "❌ FAIL: Not enough scans in database ($SCAN_COUNT < 3)"
    exit 1
fi

echo "✅ ALL TESTS PASSED"
echo "===================================="
echo "Apache findings: $APACHE_FINDINGS"
echo "Nginx findings: $NGINX_FINDINGS"
echo "Database scans: $SCAN_COUNT"
```

### Run Tests

```bash
chmod +x tests/run_integration_tests.sh
./tests/run_integration_tests.sh
```

---

## 🐛 Troubleshooting

### Lab Not Starting

```bash
# Check Docker status
docker compose -f docker/compose.testing.yml ps

# View logs
docker compose -f docker/compose.testing.yml logs vulnerable-apache
docker compose -f docker/compose.testing.yml logs vulnerable-nginx

# Common issues:
# - Port conflicts: Change ports in compose.yml
# - Permission issues: Run with sudo (not recommended) or fix Docker permissions
# - Script errors: Check docker-entrypoint.sh syntax
```

### No Findings Detected

```bash
# Verify vulnerable conditions exist
curl http://localhost:8080/.env
curl http://localhost:8080/.git/HEAD
curl http://localhost:8080/phpinfo.php

# If 404, check container logs
docker compose -f docker/compose.testing.yml logs vulnerable-apache

# Restart containers if needed
docker compose -f docker/compose.testing.yml restart
```

### Database Errors

```bash
# Check database exists
ls -lh ~/.argos/argos.db

# Check schema
sqlite3 ~/.argos/argos.db ".tables"

# If corrupted, delete and recreate
rm ~/.argos/argos.db
python -m heph --target http://localhost:8080
```

### Consent Verification Fails

```bash
# Check token file exists
docker exec hephaestus-vulnerable-apache \
  cat /var/www/html/.well-known/verify-*.txt

# Check token format
# Must be: verify-[16 hex characters]

# Check token is accessible
curl http://localhost:8080/.well-known/verify-abc123.txt

# Regenerate if expired (48h)
python -m heph --gen-consent localhost:8080
```

### AI Analysis Fails

```bash
# Check API key is set
echo $OPENAI_API_KEY

# Test API key
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Check config
cat ~/.hephaestus/config.yaml

# Try with verbose output
python -m heph --target http://localhost:8080 --use-ai -vv
```

---

## 📝 Testing Checklist

Before deploying Hephaestus or reporting issues:

**Lab Setup:**

-   [ ] Docker lab starts successfully (`docker compose -f docker/compose.testing.yml up -d` or `cd docker && ./deploy.sh`)
-   [ ] Apache accessible at http://localhost:8080
-   [ ] Nginx accessible at http://localhost:8081
-   [ ] HTTPS endpoints work (8443, 8444)
-   [ ] Vulnerable files auto-generated (.env, .git, phpinfo.php)

**Basic Functionality:**

-   [ ] Safe scan detects all CRITICAL issues
-   [ ] Server fingerprinting works (Apache/Nginx versions)
-   [ ] Sensitive file detection finds .env, .git, phpinfo
-   [ ] HTTP methods testing detects TRACE
-   [ ] Security headers analysis reports missing headers
-   [ ] Directory listing detection works

**Reporting:**

-   [ ] JSON report generates successfully
-   [ ] JSON validates against schema
-   [ ] HTML report renders correctly
-   [ ] Severity badges show correct colors
-   [ ] Evidence sections are expandable

**Database:**

-   [ ] Scans stored in `~/.argos/argos.db`
-   [ ] Findings linked to scans correctly
-   [ ] No foreign key violations
-   [ ] Query scans from database works

**Consent System:**

-   [ ] Token generation works
-   [ ] HTTP verification succeeds
-   [ ] Aggressive mode blocked without consent
-   [ ] Aggressive mode works with consent

**AI Features (Optional):**

-   [ ] AI analysis completes (OpenAI/Anthropic/Ollama)
-   [ ] Technical report generated
-   [ ] Executive summary generated
-   [ ] AI sections in HTML report

**Error Handling:**

-   [ ] Graceful handling of connection refused
-   [ ] Timeout handling works
-   [ ] DNS resolution failures handled
-   [ ] Invalid parameters rejected

**Cleanup:**

-   [ ] `docker compose -f docker/compose.testing.yml down` stops services
-   [ ] `docker compose -f docker/compose.testing.yml down -v` removes data
-   [ ] `cd docker && ./deploy.sh` (option 4/5) works correctly
-   [ ] Logs can be deleted safely

---

## 🔒 Security Reminders

1. **Docker lab ports are localhost-only** (127.0.0.1:8080/8081)
2. **Never expose vulnerable lab to network**
3. **Use VM snapshots for testing** (easy rollback)
4. **Don't reuse lab credentials** in production
5. **Delete lab after testing** (`docker compose -f docker/compose.testing.yml down -v` or `cd docker && ./deploy.sh` option 5)
6. **Lab is for TESTING ONLY** - never deploy vulnerable configs

---

## 📚 Further Reading

-   [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
-   [CIS Apache Benchmark](https://www.cisecurity.org/benchmark/apache_http_server)
-   [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
-   [Apache Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
-   [Nginx Security Controls](https://docs.nginx.com/nginx/admin-guide/security-controls/)

---

## 🎓 Learning Exercises

1. **Scan → Fix → Verify Cycle**

    - Run scan against lab
    - Pick one vulnerability (e.g., directory listing)
    - Modify `docker-entrypoint.sh` to fix it
    - Rebuild container and verify fix

2. **Compare Servers**

    - Why does Apache have more findings than Nginx?
    - What's PHP-specific to Apache?
    - Which server is "more secure" by default?

3. **Create New Vulnerabilities**

    - Add `backup.tar.gz` with source code
    - Expose `/admin` endpoint
    - Add `.htpasswd` file in webroot
    - Test if Hephaestus detects them

4. **Bypass Testing**
    - Try accessing `.ENV` (uppercase)
    - Try `//.git//HEAD` (double slashes)
    - Try different HTTP methods (POST to .env)
    - Document bypass techniques

---

**Happy (Safe) Testing!** 🛡️

If you find any issues with this testing guide or lab setup, please report them at:  
https://github.com/rodhnin/hephaestus-server-forger/issues
