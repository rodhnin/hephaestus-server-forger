# Hephaestus Database Guide

**Database:** SQLite 3.x
**Location:** `~/.argos/argos.db` (shared with Argos ecosystem)
**Schema Version:** 2.0
**Last Updated:** May 2026

---

## Overview

Hephaestus uses the **shared Argos SQLite database** for persistent storage of:

- Server configuration scan history
- Security findings (misconfigurations, exposed files, missing headers)
- Consent verification tokens (aggressive mode)
- Client/project information

**Key Difference from Argus:**

- Hephaestus scans have `tool = 'hephaestus'` in the `scans` table
- Findings use `HEPH-*` codes instead of `ARGUS-*` codes
- Focus on **server-level security** rather than WordPress-specific issues

**Note:** This guide provides SQL query examples. An interactive CLI is planned for v0.3.0.

---

## Database Schema

### Tables

#### 1. `clients`

Stores information about clients or projects (shared across all Argos tools).

```sql
CREATE TABLE clients (
    client_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT UNIQUE NOT NULL,
    contact_email TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);
CREATE INDEX idx_clients_domain ON clients(domain);
```

---

#### 2. `consent_tokens`

Tracks ownership verification tokens for aggressive mode scans.

```sql
CREATE TABLE consent_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    token TEXT NOT NULL,
    method TEXT NOT NULL CHECK(method IN ('http', 'dns')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    expires_at TEXT NOT NULL,
    verified_at TEXT,
    proof_path TEXT
);
CREATE INDEX idx_consent_domain ON consent_tokens(domain);
CREATE INDEX idx_consent_verified ON consent_tokens(verified_at);
```

**Hephaestus Usage:**

- Aggressive mode (`--aggressive`) requires consent verification
- Tokens generated with format: `verify-XXXX`
- HTTP method: Place token file at `/.well-known/hephaestus-verify.txt`
- DNS method: Add TXT record `_hephaestus-verify.domain.com`

---

#### 3. `scans`

Stores scan execution history across all Argos tools.

```sql
CREATE TABLE scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL CHECK(tool IN ('argus', 'hephaestus', 'pythia', 'asterion')),
    client_id INTEGER DEFAULT NULL,
    domain TEXT NOT NULL,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('safe', 'aggressive')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    finished_at TEXT DEFAULT NULL,
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running', 'completed', 'failed', 'aborted')),
    report_json_path TEXT,
    report_html_path TEXT,
    summary TEXT,  -- JSON: {"critical": 6, "high": 2, "medium": 8, "low": 5, "info": 0}
    error_message TEXT DEFAULT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE SET NULL
);
CREATE INDEX idx_scans_tool ON scans(tool);
CREATE INDEX idx_scans_domain ON scans(domain);
CREATE INDEX idx_scans_started ON scans(started_at);
CREATE INDEX idx_scans_status ON scans(status);
```

**Hephaestus-Specific Values:**

- `tool`: Always `'hephaestus'`
- `mode`: `'safe'` (default) or `'aggressive'` (requires consent)
- `status`:
    - `'running'`: Scan in progress
    - `'completed'`: Scan finished successfully (42 findings for Apache, 25 for Nginx in v0.2.0)
    - `'failed'`: Connection error (port closed, DNS failure, timeout)
    - `'aborted'`: User cancelled

**Typical Durations:**

- Apache (localhost:8080): ~30-35s (13 scan phases, 42 findings)
- Nginx (localhost:8081): ~30-35s (13 scan phases, 25 findings)

---

#### 4. `findings`

Stores individual security findings from scans.

```sql
CREATE TABLE findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_code TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence TEXT NOT NULL CHECK(confidence IN ('high', 'medium', 'low')),
    evidence_type TEXT,
    evidence_value TEXT,
    recommendation TEXT NOT NULL,
    "references" TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_code ON findings(finding_code);
```

**Hephaestus Finding Codes (70+ total):**

| Code Prefix   | Category         | Examples                                         |
| ------------- | ---------------- | ------------------------------------------------ |
| `HEPH-SRV-*`  | Server Info      | Version disclosure, error page leaks             |
| `HEPH-FILE-*` | Sensitive Files  | .env, .git, phpinfo.php, server-status           |
| `HEPH-HTTP-*` | HTTP Methods     | TRACE enabled, unsafe methods                    |
| `HEPH-HDR-*`  | Security Headers | HSTS, CSP, X-Frame-Options missing               |
| `HEPH-CFG-*`  | Configuration    | Directory listing, config file misconfigurations |
| `HEPH-TLS-*`  | TLS/SSL          | TLS not enabled, weak ciphers, CVE-correlated    |
| `COR-*`       | CORS             | Wildcard, null-origin, reflected origin          |
| `ROB-*`       | Robots.txt       | Disallowed paths, accessible sensitive paths     |
| `WAF-*`       | WAF Detection    | Cloudflare, Sucuri, ModSecurity, AWS WAF         |
| `API-*`       | API Discovery    | Swagger, GraphQL, unauthenticated endpoints      |
| `COO-*`       | Cookie Security  | Missing HttpOnly, Secure, SameSite flags         |
| `PHP-*`       | phpinfo Analysis | display_errors, allow_url_include, open_basedir  |

**Evidence Types:**

- `header`: HTTP response header
- `body`: Response body content
- `url`: Accessible URL
- `other`: Custom evidence

---

---

#### 5. `ai_costs`

Tracks per-scan AI token usage and costs (added in v0.2.0, shared with Argus).

```sql
CREATE TABLE IF NOT EXISTS ai_costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    tool TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    analysis_type TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_usd REAL,
    duration_s REAL,
    created_at TEXT DEFAULT (datetime('now', 'utc')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE SET NULL
);
```

**Hephaestus Usage:**

- Populated when `--use-ai` is used with `--ai-budget` or globally enabled
- `tool` field is always `'hephaestus'`
- `analysis_type`: `'executive_summary'`, `'technical_guide'`, `'agent'`, `'compare'`
- Costs file also written to `~/.argos/costs.json` (shared with Argus)

---

## Common Query Examples

### Hephaestus-Specific Queries

#### List All Hephaestus Scans (Recent First)

```sql
SELECT
    scan_id,
    domain,
    mode,
    status,
    started_at,
    finished_at,
    ROUND((julianday(finished_at) - julianday(started_at)) * 86400, 2) AS duration_sec,
    summary
FROM scans
WHERE tool = 'hephaestus'
ORDER BY started_at DESC
LIMIT 10;
```

**Expected Output:**

```
scan_id | domain         | mode | status    | started_at          | duration_sec | summary
--------|----------------|------|-----------|---------------------|--------------|--------
83      | example.com    | safe | failed    | 2025-10-21 19:07:57 | NULL         | NULL
82      | localhost:9999 | safe | failed    | 2025-10-21 19:06:24 | NULL         | NULL
81      | localhost:8080 | safe | completed | 2026-04-01 10:01:56 | 32.15        | {"critical": 8, ...}
```

---

#### Get Scan Summary with Finding Counts

```sql
SELECT
    s.scan_id,
    s.domain,
    s.mode,
    s.status,
    s.started_at,
    COUNT(f.finding_id) AS total_findings,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high,
    SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium,
    SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low
FROM scans s
LEFT JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'hephaestus' AND s.scan_id = 81
GROUP BY s.scan_id;
```

**Expected Output:**

```
scan_id | domain         | total_findings | critical | high | medium | low
--------|----------------|----------------|----------|------|--------|----
81      | localhost:8080 | 42             | 8        | 4    | 18     | 12
```

---

#### List Failed Scans with Error Messages

```sql
SELECT
    scan_id,
    domain,
    started_at,
    error_message
FROM scans
WHERE tool = 'hephaestus' AND status = 'failed'
ORDER BY started_at DESC;
```

**Expected Output:**

```
scan_id | domain          | error_message
--------|-----------------|----------------------------------------------------------
83      | example.com     | DNS resolution failed: ...Temporary failure...
82      | localhost:9999  | Connection refused: ...port=9999...Connection refused
```

---

### Finding Queries

#### Get All Findings for a Scan (Ordered by Severity)

```sql
SELECT
    finding_code,
    title,
    severity,
    confidence,
    evidence_type,
    evidence_value
FROM findings
WHERE scan_id = 81
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END,
    finding_id;
```

**Expected Output (first 5 findings):**

```
finding_code   | title                            | severity | confidence | evidence_type | evidence_value
---------------|----------------------------------|----------|------------|---------------|------------------
HEPH-FILE-001  | Environment file exposed (.env)  | critical | high       | url           | http://localhost:8080/.env
HEPH-FILE-002  | Git repository exposed           | critical | high       | url           | http://localhost:8080/.git/HEAD
HEPH-FILE-002  | Git repository exposed           | critical | high       | url           | http://localhost:8080/.git/config
HEPH-FILE-003  | PHP information page exposed     | critical | high       | url           | http://localhost:8080/phpinfo.php
HEPH-FILE-003  | PHP information page exposed     | critical | high       | url           | http://localhost:8080/info.php
```

---

#### Count Findings by Category (Code Prefix)

```sql
SELECT
    SUBSTR(finding_code, 1, 9) AS category,
    COUNT(*) AS count,
    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.scan_id = 81
GROUP BY SUBSTR(finding_code, 1, 9)
ORDER BY count DESC;
```

**Expected Output:**

```
category  | count | critical | high
----------|-------|----------|-----
HEPH-HDR- | 6     | 0        | 0     (Security headers missing)
HEPH-FILE | 9     | 6        | 0     (Sensitive files exposed)
HEPH-HTTP | 2     | 0        | 0     (HTTP methods)
HEPH-SRV- | 2     | 0        | 2     (Server info disclosure)
HEPH-CFG- | 1     | 0        | 0     (Directory listing)
HEPH-TLS- | 1     | 0        | 1     (TLS not enabled)
```

---

#### Find Specific Vulnerability Across All Scans

```sql
SELECT
    s.scan_id,
    s.domain,
    s.started_at,
    f.finding_code,
    f.title,
    f.evidence_value
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.finding_code = 'HEPH-FILE-001'  -- .env exposure
  AND s.tool = 'hephaestus'
ORDER BY s.started_at DESC;
```

---

#### Get Critical Findings (All Hephaestus Scans)

```sql
SELECT
    s.domain,
    s.started_at,
    f.finding_code,
    f.title,
    f.evidence_value
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'hephaestus'
  AND f.severity = 'critical'
ORDER BY s.started_at DESC, f.finding_code
LIMIT 20;
```

---

#### Missing Security Headers Report

```sql
SELECT
    s.domain,
    s.started_at,
    f.finding_code,
    f.title
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'hephaestus'
  AND f.finding_code LIKE 'HEPH-HDR-%'
  AND s.scan_id = 81
ORDER BY f.finding_code;
```

**Expected Output:**

```
domain         | finding_code  | title
---------------|---------------|-------------------------------
localhost:8080 | HEPH-HDR-001  | Missing security header: HSTS
localhost:8080 | HEPH-HDR-002  | Missing security header: CSP
localhost:8080 | HEPH-HDR-003  | Missing security header: X-Frame-Options
localhost:8080 | HEPH-HDR-004  | Missing security header: X-Content-Type-Options
localhost:8080 | HEPH-HDR-005  | Missing security header: Referrer-Policy
localhost:8080 | HEPH-HDR-006  | Missing security header: Permissions-Policy
```

---

### Consent Token Management

#### Check Domain Verification Status

```sql
SELECT
    domain,
    token,
    method,
    verified_at,
    expires_at,
    CASE
        WHEN verified_at IS NOT NULL AND datetime('now', 'utc') < expires_at
        THEN 'verified'
        WHEN verified_at IS NOT NULL AND datetime('now', 'utc') >= expires_at
        THEN 'expired'
        ELSE 'pending'
    END AS status
FROM consent_tokens
WHERE domain IN ('localhost:8080', '127.0.0.1:8081')
ORDER BY created_at DESC;
```

**Expected Output:**

```
domain          | token                     | method | verified_at              | status
----------------|---------------------------|--------|--------------------------|----------
127.0.0.1:8081  | verify-59b7db3b4564ebbf   | http   | 2025-10-20T21:52:28...   | verified
localhost:8080  | verify-d521979c2751baf5   | http   | 2025-10-20T21:52:21...   | verified
```

---

#### List All Verified Domains for Hephaestus

```sql
SELECT
    ct.domain,
    ct.method,
    ct.verified_at,
    COUNT(s.scan_id) AS scan_count,
    MAX(s.started_at) AS last_scan
FROM consent_tokens ct
LEFT JOIN scans s ON ct.domain = s.domain AND s.tool = 'hephaestus'
WHERE ct.verified_at IS NOT NULL
GROUP BY ct.domain, ct.method, ct.verified_at
ORDER BY last_scan DESC;
```

---

### Statistics & Reports

#### Hephaestus Scan Statistics

```sql
SELECT
    status,
    COUNT(*) AS count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM scans WHERE tool = 'hephaestus'), 2) AS percentage,
    ROUND(AVG((julianday(finished_at) - julianday(started_at)) * 86400), 2) AS avg_duration_sec
FROM scans
WHERE tool = 'hephaestus'
GROUP BY status
ORDER BY count DESC;
```

**Expected Output:**

```
status    | count | percentage | avg_duration_sec
----------|-------|------------|------------------
completed | 75    | 85.23      | 21.53
failed    | 10    | 11.36      | NULL
running   | 3     | 3.41       | NULL
```

---

#### Top Vulnerable Domains (By Critical Findings)

```sql
SELECT
    s.domain,
    COUNT(DISTINCT s.scan_id) AS total_scans,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
    MAX(s.started_at) AS last_scan
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'hephaestus' AND s.status = 'completed'
GROUP BY s.domain
HAVING critical_count > 0
ORDER BY critical_count DESC, last_scan DESC
LIMIT 10;
```

---

#### Findings Distribution (All Hephaestus Scans)

```sql
SELECT
    f.severity,
    COUNT(*) AS total,
    COUNT(DISTINCT s.domain) AS affected_domains,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM findings WHERE scan_id IN (SELECT scan_id FROM scans WHERE tool = 'hephaestus')), 2) AS percentage
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'hephaestus'
GROUP BY f.severity
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;
```

---

#### Compare Apache vs Nginx Findings

```sql
SELECT
    CASE
        WHEN s.domain LIKE '%8080%' THEN 'Apache'
        WHEN s.domain LIKE '%8081%' THEN 'Nginx'
        ELSE 'Other'
    END AS server_type,
    COUNT(DISTINCT s.scan_id) AS scans,
    COUNT(f.finding_id) AS total_findings,
    ROUND(AVG(COUNT(f.finding_id)) OVER (PARTITION BY s.scan_id), 2) AS avg_findings_per_scan,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical
FROM scans s
LEFT JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'hephaestus' AND s.status = 'completed'
  AND s.domain IN ('localhost:8080', 'localhost:8081')
GROUP BY server_type;
```

**Expected Output:**

```
server_type | scans | total_findings | avg_findings_per_scan | critical
------------|-------|----------------|----------------------|----------
Apache      | 45    | 1890           | 42.00                | 540
Nginx       | 30    | 750            | 25.00                | 180
```

---

### Maintenance Queries

#### Database Size and Statistics

```sql
SELECT
    'Hephaestus Scans' AS category,
    COUNT(*) AS count
FROM scans WHERE tool = 'hephaestus'
UNION ALL
SELECT
    'Hephaestus Findings',
    COUNT(*)
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE s.tool = 'hephaestus'
UNION ALL
SELECT
    'Verified Domains',
    COUNT(*)
FROM consent_tokens
WHERE verified_at IS NOT NULL;
```

---

#### Check for Orphaned Findings (Should be 0)

```sql
SELECT COUNT(*) AS orphaned_findings
FROM findings f
LEFT JOIN scans s ON f.scan_id = s.scan_id
WHERE s.scan_id IS NULL;
```

**Expected:** `0`

---

#### Delete Old Hephaestus Scans (Older than 90 Days)

```sql
DELETE FROM scans
WHERE tool = 'hephaestus'
  AND started_at < datetime('now', '-90 days');
-- Findings will auto-delete (CASCADE)
```

---

#### Vacuum (Optimize Database)

```sql
VACUUM;
```

---

## Database Access from Python

### Using heph.core.db Module

```python
from heph.core.db import get_db

# Get database instance
db = get_db()

# Start scan
scan_id = db.start_scan(
    tool='hephaestus',
    domain='example.com',
    target_url='http://example.com',
    mode='safe'
)

# Save findings
findings = [
    {
        'finding_code': 'HEPH-FILE-001',
        'title': 'Environment file exposed (.env)',
        'severity': 'critical',
        'confidence': 'high',
        'evidence_type': 'url',
        'evidence_value': 'http://example.com/.env',
        'recommendation': 'Remove .env file from web root',
        'references': ['https://owasp.org/...']
    }
]
db.save_findings(scan_id, findings)

# Finish scan
db.finish_scan(scan_id, status='completed')

# Get scan details
scan = db.get_scan(scan_id)
print(f"Scan status: {scan['status']}")

# Get findings
findings = db.get_findings(scan_id)
print(f"Total findings: {len(findings)}")
```

---

### Direct SQL Access

```python
import sqlite3
from pathlib import Path

# Connect to shared Argos database
db_path = Path.home() / ".argos" / "argos.db"
conn = sqlite3.connect(str(db_path))
conn.row_factory = sqlite3.Row

# Get recent Hephaestus scans
cursor = conn.execute("""
    SELECT scan_id, domain, status, started_at
    FROM scans
    WHERE tool = 'hephaestus'
    ORDER BY started_at DESC
    LIMIT 10
""")

for row in cursor.fetchall():
    print(f"Scan {row['scan_id']}: {row['domain']} - {row['status']}")

conn.close()
```

---

## Typical Scan Results

### Apache Server (localhost:8080)

**Scan Characteristics (v0.2.0):**

- Duration: ~30-35 seconds (13 scan phases)
- Rate limit: 5 req/s (default)
- Total findings: **42**

**Finding Distribution:**

```json
{
    "critical": 6,
    "high": 4,
    "medium": 18,
    "low": 10,
    "info": 4
}
```

---

### Nginx Server (localhost:8081)

**Scan Characteristics (v0.2.0):**

- Duration: ~30-35 seconds (13 scan phases)
- Rate limit: 5 req/s (default)
- Total findings: **25**

**Finding Distribution:**

```json
{
    "critical": 3,
    "high": 3,
    "medium": 12,
    "low": 6,
    "info": 1
}
```

---

## Error Handling

### Failed Scan Examples

#### Connection Refused (Port Closed)

```sql
SELECT scan_id, domain, error_message
FROM scans
WHERE scan_id = 82;
```

**Output:**

```
scan_id: 82
domain: localhost:9999
error_message: Connection refused: HTTPConnectionPool(host='localhost', port=9999):
Max retries exceeded with url: / (Caused by NewConnectionError(...Connection refused'))
```

---

#### DNS Resolution Failed

```sql
SELECT scan_id, domain, error_message
FROM scans
WHERE scan_id = 83;
```

**Output:**

```
scan_id: 83
domain: example.com
error_message: DNS resolution failed: HTTPSConnectionPool(host='example.com', port=443):
Max retries exceeded with url: / (Caused by NameResolutionError(...Temporary failure in name resolution))
```

---

## Troubleshooting

### No Findings Recorded

```sql
SELECT s.scan_id, s.status, s.error_message, COUNT(f.finding_id) AS findings
FROM scans s
LEFT JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'hephaestus' AND s.status = 'completed'
GROUP BY s.scan_id
HAVING findings = 0;
```

**Possible Causes:**

- Scan failed early (check error_message)
- Target is too secure (unlikely)
- Database write error

---

### Database Locked

```bash
# Find process using database
lsof ~/.argos/argos.db

# Kill if needed
kill <PID>
```

---

### Backup Database

```bash
# Create backup
sqlite3 ~/.argos/argos.db ".backup /tmp/argos-backup-$(date +%Y%m%d).db"

# Restore from backup
cp /tmp/argos-backup-20251021.db ~/.argos/argos.db
```

---

## Schema Version History

| Version | Date     | Changes                                         |
| ------- | -------- | ----------------------------------------------- |
| **1.0** | Jan 2026 | Initial schema (Phase 10 validated)             |
| **2.0** | May 2026 | Added `ai_costs` table; 13 phases; 70+ findings |

---

**Last Updated:** May 2026
**Schema Version:** 2.0
**Tool Version:** Hephaestus v0.2.0
