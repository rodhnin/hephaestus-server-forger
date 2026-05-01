# Hephaestus Report Format Documentation

## Overview

Hephaestus generates structured security reports in **JSON** (machine-readable) and **HTML** (human-readable) formats. All reports conform to a strict JSON Schema for consistency and validation across the Argos ecosystem.

---

## 📋 JSON Schema

### Location

Reports follow the shared Argos schema at `schema/report.schema.json` (JSON Schema Draft 2020-12)

### Validation

Reports are automatically validated before saving:

```python
from heph.core.report import ReportGenerator

generator = ReportGenerator()
report = {...}
is_valid = generator.validate_report(report)  # True/False
```

### Top-Level Structure

```json
{
  "tool": "hephaestus",
  "version": "0.2.0",
  "target": "http://localhost:8080",
  "date": "2026-04-01T19:01:56Z",
  "mode": "safe",
  "summary": {...},
  "findings": [...],
  "notes": {...},
  "consent": {...},
  "ai_analysis": {...},
  "diff": {...}
}
```

---

## 🔍 Field Definitions

### Required Fields

#### `tool` (string)

- **Value**: `"hephaestus"`
- **Purpose**: Identifies the security auditor
- **Example**: `"hephaestus"`

#### `version` (string)

- **Format**: Semantic versioning (X.Y.Z)
- **Purpose**: Tool version for compatibility tracking
- **Example**: `"0.2.0"`

#### `target` (string)

- **Format**: Full URL or IP:port
- **Purpose**: Scanned server identifier
- **Examples**:
    - `"http://localhost:8080"`
    - `"https://example.com:443"`
    - `"http://192.168.1.100:80"`

#### `date` (string)

- **Format**: ISO 8601 (UTC with Z suffix)
- **Purpose**: Scan completion timestamp
- **Example**: `"2025-10-21T19:01:56Z"`

#### `mode` (string)

- **Values**: `"safe"`, `"aggressive"`, or `"offline"`
- **Purpose**: Scan depth indicator
- **Example**: `"safe"`

#### `summary` (object)

- **Purpose**: Quick overview of findings by severity
- **Required keys**: `critical`, `high`, `medium`, `low`, `info`
- **All values**: Non-negative integers

```json
"summary": {
  "critical": 6,
  "high": 2,
  "medium": 8,
  "low": 5,
  "info": 0
}
```

#### `findings` (array)

- **Purpose**: Detailed list of server security issues
- **Items**: Finding objects (see below)

---

## 🔍 Finding Categories

Hephaestus organizes findings into specific categories (70+ codes total):

### Server Configuration (SRV)

Server identification, version disclosure, error pages, module/framework detection

### Security Headers (HDR)

Missing or misconfigured HTTP security headers

### Sensitive Files (FILE)

Exposed configuration files, backups, credentials (70+ paths)

### HTTP Methods (METH)

Dangerous HTTP methods enabled (TRACE, TRACK)

### TLS/SSL (TLS)

Certificate issues, weak ciphers, outdated protocols, CVE-correlated findings

### Directory Listing (DIR)

Exposed directory indexes

### Authentication (AUTH)

Missing or weak authentication mechanisms

### CORS (COR)

Cross-Origin Resource Sharing misconfigurations (COR-001 to COR-006)

### Robots.txt Intelligence (ROB)

Disallowed path analysis and accessibility probes (ROB-001/002/003)

### WAF Detection (WAF)

Web Application Firewall signatures: Cloudflare, Sucuri, ModSecurity, AWS WAF, Imperva (WAF-001/002)

### API Discovery (API)

Swagger/OpenAPI spec exposure, GraphQL introspection, unauthenticated endpoints (API-001 to API-005)

### Cookie Security (COO)

Per-cookie HttpOnly/Secure/SameSite analysis (COO-001 to COO-005)

### PHP Configuration (PHP)

phpinfo() dangerous setting detection (PHP-001 to PHP-009)

---

## 📝 Finding Object Structure

Each finding in the `findings` array:

```json
{
    "id": "HEPH-SRV-001",
    "title": "Apache server version disclosed",
    "description": "The web server reveals its version through HTTP headers...",
    "severity": "high",
    "confidence": "high",
    "evidence": {
        "type": "header",
        "value": "Server: Apache/2.4.41 (Ubuntu)",
        "context": "HTTP response from http://localhost:8080/"
    },
    "recommendation": "Configure ServerTokens Prod in Apache configuration...",
    "references": ["https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"],
    "cve": [],
    "affected_component": "Apache HTTP Server 2.4.41",
    "owasp": { "id": "A05", "name": "Security Misconfiguration" },
    "vulnerabilities": [
        {
            "cve_id": "CVE-2023-45802",
            "title": "HTTP/2 request smuggling",
            "description": "...",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-45802",
            "cvss_score": 7.5,
            "cwe_id": "CWE-444",
            "cwe_name": "Inconsistent Interpretation of HTTP Requests"
        }
    ],
    "cvss": 7.5
}
```

#### Finding Fields

| Field                | Required | Type   | Description                                         |
| -------------------- | -------- | ------ | --------------------------------------------------- |
| `id`                 | ✅ Yes   | string | Unique finding identifier (e.g., `HEPH-SRV-001`)    |
| `title`              | ✅ Yes   | string | Short, descriptive title (max 200 chars)            |
| `description`        | ❌ No    | string | Detailed vulnerability explanation                  |
| `severity`           | ✅ Yes   | enum   | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `confidence`         | ✅ Yes   | enum   | `high` \| `medium` \| `low`                         |
| `evidence`           | ❌ No    | object | Proof of misconfiguration/vulnerability             |
| `recommendation`     | ✅ Yes   | string | Actionable remediation guidance                     |
| `references`         | ❌ No    | array  | External links (CVE, vendor docs, best practices)   |
| `cve`                | ❌ No    | array  | CVE identifiers (format: `CVE-YYYY-NNNNN`)          |
| `affected_component` | ❌ No    | string | Server component (Apache, Nginx, OpenSSL)           |
| `owasp`              | ❌ No    | object | OWASP Top 10 2021 mapping (`id`, `name`)            |
| `vulnerabilities`    | ❌ No    | array  | Live CVE findings from NVD API v2                   |
| `cvss`               | ❌ No    | float  | CVSS score (from NVD or manual assignment)          |

---

## 🎯 Severity Levels for Server Issues

| Level        | Use When                                  | Examples                                                                    |
| ------------ | ----------------------------------------- | --------------------------------------------------------------------------- |
| **Critical** | Immediate compromise possible             | Exposed .git directory with source code, backup files with credentials      |
| **High**     | Known vulnerable version with exploit     | Outdated server version with RCE exploit, version disclosure aiding attacks |
| **Medium**   | Information disclosure, misconfigurations | Server signature disclosure, missing security headers, directory listing    |
| **Low**      | Minor security improvements               | HTTP methods enabled but restricted, informational headers                  |
| **Info**     | Informational only                        | Server type detected, supported TLS versions                                |

### Confidence Levels

| Level      | Meaning             | Example                                                         |
| ---------- | ------------------- | --------------------------------------------------------------- |
| **High**   | Confirmed issue     | Direct evidence in headers/response, file successfully accessed |
| **Medium** | Strong indicators   | Behavior suggests misconfiguration, indirect evidence           |
| **Low**    | Heuristic detection | Pattern matching, assumptions based on responses                |

---

## 📋 Finding ID Scheme

### Format

`HEPH-{CATEGORY}-{NUMBER}`

### Category Ranges

| ID Range            | Category         | Description                             |
| ------------------- | ---------------- | --------------------------------------- |
| `HEPH-SRV-000-019`  | Server Detection | Server type, version, framework leaks   |
| `HEPH-HDR-001-019`  | Security Headers | Missing or weak headers, cookie flags   |
| `HEPH-FILE-001-039` | Sensitive Files  | Exposed configs, backups, credentials   |
| `HEPH-HTTP-001-009` | HTTP Methods     | Dangerous methods enabled               |
| `HEPH-TLS-001-029`  | TLS/SSL          | Certificate, cipher, protocol issues    |
| `HEPH-CFG-001-009`  | Configuration    | Directory listing, server config issues |
| `HEPH-COR-001-006`  | CORS             | Cross-Origin Resource Sharing issues    |
| `HEPH-ROB-001-003`  | Robots.txt       | Sensitive paths in robots.txt           |
| `HEPH-WAF-001-002`  | WAF Detection    | Web Application Firewall fingerprint    |
| `HEPH-API-001-005`  | API Discovery    | Exposed API docs, endpoints             |
| `HEPH-COO-001-005`  | Cookie Security  | Missing Secure/HttpOnly/SameSite flags  |
| `HEPH-PHP-001-009`  | phpinfo Analysis | Dangerous PHP settings exposed          |

### Examples

| ID              | Meaning                            |
| --------------- | ---------------------------------- |
| `HEPH-SRV-000`  | Apache/Nginx server detected       |
| `HEPH-SRV-001`  | Apache version disclosed in header |
| `HEPH-SRV-002`  | Nginx version disclosed in header  |
| `HEPH-SRV-004`  | Server disclosed in error page     |
| `HEPH-HDR-001`  | Missing X-Frame-Options header     |
| `HEPH-HDR-002`  | Missing X-Content-Type-Options     |
| `HEPH-HDR-003`  | Missing Strict-Transport-Security  |
| `HEPH-FILE-001` | .git directory exposed             |
| `HEPH-FILE-002` | .env file accessible               |
| `HEPH-FILE-003` | phpinfo.php exposed                |
| `HEPH-METH-001` | HTTP TRACE method enabled          |
| `HEPH-TLS-001`  | Weak TLS cipher suites             |
| `HEPH-DIR-001`  | Directory listing enabled          |

---

## 🛡️ Evidence Types for Server Scans

### Evidence Object Structure

```json
"evidence": {
  "type": "header|body|url|path|other",
  "value": "Evidence value",
  "context": "Additional context"
}
```

### Common Evidence Types

#### Header Evidence

```json
"evidence": {
  "type": "header",
  "value": "Server: Apache/2.4.41 (Ubuntu)",
  "context": "HTTP response from GET /"
}
```

#### Body Evidence

```json
"evidence": {
  "type": "body",
  "value": "<title>Index of /backup</title>",
  "context": "HTTP 200, directory listing detected"
}
```

#### URL Evidence

```json
"evidence": {
  "type": "url",
  "value": "http://localhost:8080/.git/config",
  "context": "HTTP 200, 289 bytes, Git repository exposed"
}
```

#### Path Evidence

```json
"evidence": {
  "type": "path",
  "value": "/.env",
  "context": "HTTP 200, environment variables file accessible"
}
```

---

## 📊 Complete Example Reports

### Diff Section (v0.2.0)

When `--diff last` or `--diff SCAN_ID` is used, the report includes a `diff` top-level section:

```json
{
    "diff": {
        "compared_to_scan_id": 81,
        "compared_to_date": "2026-03-15T10:00:00Z",
        "new_findings": ["HEPH-TLS-002", "COR-001"],
        "fixed_findings": ["HEPH-FILE-005"],
        "persisting_findings": ["HEPH-FILE-001", "HEPH-HDR-001"],
        "summary": {
            "new": 2,
            "fixed": 1,
            "persisting": 12
        }
    }
}
```

---

### Apache Server - Safe Mode

```json
{
    "tool": "hephaestus",
    "version": "0.2.0",
    "target": "http://localhost:8080",
    "date": "2026-04-01T19:01:56Z",
    "mode": "safe",
    "summary": {
        "critical": 6,
        "high": 4,
        "medium": 18,
        "low": 10,
        "info": 4
    },
    "findings": [
        {
            "id": "HEPH-SRV-000",
            "title": "Apache HTTP Server detected",
            "description": "Apache web server identified through HTTP headers",
            "severity": "info",
            "confidence": "high",
            "evidence": {
                "type": "header",
                "value": "Server: Apache/2.4.41 (Ubuntu)",
                "context": "HTTP response from GET /"
            },
            "recommendation": "Server detected. Review all security findings.",
            "references": ["https://httpd.apache.org/docs/2.4/"],
            "affected_component": "Apache HTTP Server 2.4.41"
        },
        {
            "id": "HEPH-SRV-001",
            "title": "Apache server version disclosed",
            "description": "The Server header reveals specific version information...",
            "severity": "high",
            "confidence": "high",
            "evidence": {
                "type": "header",
                "value": "Server: Apache/2.4.41 (Ubuntu)",
                "context": "HTTP response from GET /"
            },
            "recommendation": "Add 'ServerTokens Prod' and 'ServerSignature Off' to Apache config",
            "references": ["https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"],
            "affected_component": "Apache HTTP Server 2.4.41"
        },
        {
            "id": "HEPH-HDR-001",
            "title": "Missing X-Frame-Options header",
            "description": "The X-Frame-Options header is not set, allowing potential clickjacking...",
            "severity": "medium",
            "confidence": "high",
            "evidence": {
                "type": "header",
                "value": null,
                "context": "Header not present in HTTP response"
            },
            "recommendation": "Add 'Header always set X-Frame-Options \"DENY\"' to Apache config",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
            "affected_component": "Apache HTTP Server"
        },
        {
            "id": "HEPH-FILE-001",
            "title": "Exposed .git directory",
            "description": "Git repository metadata is publicly accessible...",
            "severity": "critical",
            "confidence": "high",
            "evidence": {
                "type": "url",
                "value": "http://localhost:8080/.git/config",
                "context": "HTTP 200, 289 bytes, Git config accessible"
            },
            "recommendation": "Block access to .git directory:\n<Directory ~ \"\\.git\">\n    Require all denied\n</Directory>",
            "references": ["https://git-scm.com/docs/git-config"],
            "affected_component": "Git Repository"
        },
        {
            "id": "HEPH-METH-001",
            "title": "HTTP TRACE method enabled",
            "description": "The TRACE method is enabled, potentially allowing XST attacks...",
            "severity": "medium",
            "confidence": "high",
            "evidence": {
                "type": "other",
                "value": "TRACE",
                "context": "HTTP 200 response to TRACE request"
            },
            "recommendation": "Disable TRACE method: TraceEnable off",
            "references": ["https://httpd.apache.org/docs/current/mod/core.html#traceenable"],
            "affected_component": "Apache HTTP Server"
        }
    ],
    "notes": {
        "scan_duration_seconds": 31.24,
        "requests_sent": 142,
        "rate_limit_applied": false,
        "scope_limitations": "Safe mode: non-intrusive checks only",
        "false_positive_disclaimer": "Manual verification recommended for all findings."
    }
}
```

### Nginx Server with AI Analysis

```json
{
    "tool": "hephaestus",
    "version": "0.2.0",
    "target": "https://example.com",
    "date": "2026-04-01T20:15:30Z",
    "mode": "aggressive",
    "summary": {
        "critical": 3,
        "high": 3,
        "medium": 12,
        "low": 6,
        "info": 1
    },
    "findings": [
        {
            "id": "HEPH-SRV-002",
            "title": "Nginx version disclosed",
            "severity": "high",
            "confidence": "high",
            "evidence": {
                "type": "header",
                "value": "Server: nginx/1.18.0",
                "context": "HTTP response from GET /"
            },
            "recommendation": "Add 'server_tokens off;' to nginx.conf",
            "references": ["https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"],
            "affected_component": "Nginx 1.18.0"
        }
    ],
    "notes": {
        "scan_duration_seconds": 45.8,
        "requests_sent": 287,
        "rate_limit_applied": true,
        "scope_limitations": "Aggressive mode with consent verification",
        "false_positive_disclaimer": "Manual verification recommended for all findings."
    },
    "consent": {
        "method": "http",
        "token": "verify-heph-a3f9b2c1d8e4f5a6",
        "verified_at": "2025-10-21T20:10:15Z"
    },
    "ai_analysis": {
        "executive_summary": "Your server has 3 critical security issues...",
        "technical_remediation": "## Critical Actions\n\n1. **Remove .git directory**...",
        "generated_at": "2026-04-01T20:15:35Z",
        "model_used": "gpt-4o-mini-2024-07-18",
        "agent_analysis": "## CVE Analysis\n\nApache 2.4.54 is affected by CVE-2022-31813...",
        "compare_results": {
            "openai": "## OpenAI Analysis\n\nCritical: .git directory exposed...",
            "anthropic": "## Anthropic Analysis\n\nThe most urgent finding is..."
        }
    }
}
```

---

## 🌐 HTML Report

### Template Location

`heph/templates/report.html.j2` (Jinja2)

### Sections

1. **Header**
    - Tool name and version
    - Target server URL
    - Scan date and mode
    - Summary badges (severity counts with icons)

2. **Executive Summary** (if `--use-ai` enabled)
    - Non-technical business impact summary
    - Priority recommendations
    - Risk assessment

3. **Technical Remediation** (if `--use-ai` enabled)
    - Step-by-step configuration fixes
    - Apache/Nginx config snippets
    - Command examples

4. **Findings Table**
    - Sortable by ID, Severity, Category
    - Color-coded severity indicators
    - Expandable evidence details
    - Copy-paste recommendations

5. **Server Information**
    - Detected server type and version
    - Supported HTTP methods
    - Security headers present/missing
    - TLS/SSL configuration summary

6. **Scan Metadata**
    - Duration and request count
    - Rate limiting status
    - Scope limitations
    - False positive disclaimer

7. **Consent Verification** (if aggressive/AI mode)
    - Verification method
    - Token used
    - Timestamp

8. **Footer**
    - Hephaestus attribution
    - GitHub repository link
    - Contact and support information

### Styling Features

- **Server-themed design**: Industrial/forge aesthetic
- **Responsive layout**: Mobile, tablet, desktop optimized
- **Print-ready**: Clean PDF export with page breaks
- **Syntax highlighting**: Config snippets with Prism.js
- **Accessibility**: WCAG 2.1 AA compliant, keyboard navigation
- **Dark mode support**: Automatic theme detection

### Example HTML Structure

```html
<div class="container">
    <header class="heph-header">
        <div class="forge-logo">🔥 Hephaestus</div>
        <h1>Server Security Audit Report</h1>
        <div class="target-info">
            <span class="label">Target:</span>
            <code>http://localhost:8080</code>
        </div>
        <div class="summary-badges">
            <span class="badge badge-critical">⚠️ Critical: 6</span>
            <span class="badge badge-high">🔴 High: 2</span>
            <span class="badge badge-medium">🟠 Medium: 8</span>
            <span class="badge badge-low">🟡 Low: 5</span>
        </div>
    </header>

    <section id="findings">
        <h2>Security Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <tr class="finding-row severity-high">
                    <td><code>HEPH-SRV-001</code></td>
                    <td><strong>Apache server version disclosed</strong></td>
                    <td><span class="severity-badge severity-high">HIGH</span></td>
                    <td><span class="confidence-badge confidence-high">HIGH</span></td>
                    <td><button class="btn-expand">Details</button></td>
                </tr>
                <tr class="finding-details">
                    <td colspan="5">
                        <div class="evidence">
                            <h4>Evidence</h4>
                            <pre><code>Server: Apache/2.4.41 (Ubuntu)</code></pre>
                        </div>
                        <div class="recommendation">
                            <h4>Recommendation</h4>
                            <pre><code>ServerTokens Prod
ServerSignature Off</code></pre>
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
    </section>
</div>
```

---

## 🔧 Programmatic Usage

### Generating Reports

```python
from heph.core.report import ReportGenerator
from heph.core.scanner import ServerScanner

# Perform scan
scanner = ServerScanner(target='http://localhost:8080')
findings = scanner.scan()

# Generate report
generator = ReportGenerator()
report = generator.create_report(
    tool='hephaestus',
    version='0.2.0',
    target='http://localhost:8080',
    mode='safe',
    findings=findings,
    scan_duration=31.45,
    requests_sent=142
)

# Validate
if generator.validate_report(report):
    # Save JSON
    json_path = generator.save_json(report, '~/.hephaestus/reports')
    print(f"JSON report: {json_path}")

    # Generate HTML
    html_path = generator.generate_html(report, '~/.hephaestus/reports')
    print(f"HTML report: {html_path}")
```

### Creating Custom Findings

```python
# Server version disclosure finding
finding = {
    'id': 'HEPH-SRV-001',
    'title': 'Apache server version disclosed',
    'severity': 'high',
    'confidence': 'high',
    'evidence': {
        'type': 'header',
        'value': 'Server: Apache/2.4.41 (Ubuntu)',
        'context': 'HTTP response from GET /'
    },
    'recommendation': 'Configure ServerTokens Prod in Apache configuration',
    'references': [
        'https://httpd.apache.org/docs/2.4/mod/core.html#servertokens'
    ],
    'affected_component': 'Apache HTTP Server 2.4.41'
}

# Sensitive file finding
finding = {
    'id': 'HEPH-FILE-001',
    'title': 'Exposed .git directory',
    'severity': 'critical',
    'confidence': 'high',
    'evidence': {
        'type': 'url',
        'value': 'http://localhost:8080/.git/config',
        'context': 'HTTP 200, 289 bytes'
    },
    'recommendation': 'Block access to .git directory in web server config',
    'references': ['https://git-scm.com/docs/git-config'],
    'affected_component': 'Git Repository'
}
```

---

## 📈 Report Analysis

### SQLite Queries for Hephaestus

```sql
-- Most common server vulnerabilities
SELECT
    finding_code,
    title,
    COUNT(*) as occurrence_count
FROM findings
WHERE tool = 'hephaestus'
    AND severity IN ('critical', 'high')
GROUP BY finding_code, title
ORDER BY occurrence_count DESC
LIMIT 10;

-- Server types scanned
SELECT
    CASE
        WHEN target LIKE '%:8080%' THEN 'Apache'
        WHEN target LIKE '%:8081%' THEN 'Nginx'
        ELSE 'Unknown'
    END as server_type,
    COUNT(DISTINCT scan_id) as scan_count,
    AVG(JSON_EXTRACT(summary, '$.critical')) as avg_critical,
    AVG(JSON_EXTRACT(summary, '$.high')) as avg_high
FROM scans
WHERE tool = 'hephaestus'
    AND status = 'completed'
GROUP BY server_type;

-- Security header compliance over time
SELECT
    DATE(started_at) as scan_date,
    COUNT(*) as total_scans,
    SUM(CASE WHEN finding_code LIKE 'HEPH-HDR-%' THEN 1 ELSE 0 END) as header_issues
FROM scans s
JOIN findings f ON s.scan_id = f.scan_id
WHERE s.tool = 'hephaestus'
GROUP BY DATE(started_at)
ORDER BY scan_date DESC;

-- Version disclosure trends
SELECT
    finding_code,
    COUNT(*) as found_count,
    COUNT(DISTINCT scan_id) as affected_scans
FROM findings
WHERE tool = 'hephaestus'
    AND finding_code IN ('HEPH-SRV-001', 'HEPH-SRV-002')
GROUP BY finding_code;
```

### Python Analysis Examples

```python
import sqlite3
import json
from collections import Counter

db = sqlite3.connect('~/.argos/argos.db')

# Analyze severity distribution
cursor = db.execute("""
    SELECT summary
    FROM scans
    WHERE tool = 'hephaestus'
        AND status = 'completed'
    ORDER BY started_at DESC
    LIMIT 50
""")

severity_counts = Counter()
for (summary_json,) in cursor:
    summary = json.loads(summary_json)
    severity_counts['critical'] += summary['critical']
    severity_counts['high'] += summary['high']
    severity_counts['medium'] += summary['medium']

print(f"Total critical issues: {severity_counts['critical']}")
print(f"Total high issues: {severity_counts['high']}")

# Find most vulnerable servers
cursor = db.execute("""
    SELECT
        domain,
        COUNT(f.finding_id) as total_findings,
        SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) as critical_count
    FROM scans s
    JOIN findings f ON s.scan_id = f.scan_id
    WHERE s.tool = 'hephaestus'
    GROUP BY domain
    HAVING critical_count > 0
    ORDER BY critical_count DESC, total_findings DESC
""")

for domain, total, critical in cursor:
    print(f"{domain}: {critical} critical, {total} total")
```

---

## ✅ Best Practices for Hephaestus Reports

### 1. Evidence Collection

```python
# Good: Specific header value
evidence = {
    'type': 'header',
    'value': 'Server: Apache/2.4.41 (Ubuntu)',
    'context': 'HTTP response from GET /'
}

# Bad: Vague evidence
evidence = {
    'type': 'other',
    'value': 'Server header present'
}
```

### 2. Recommendations

```python
# Good: Actionable Apache config
recommendation = """Add to Apache configuration:

ServerTokens Prod
ServerSignature Off

Then reload:
sudo systemctl reload apache2"""

# Bad: Generic advice
recommendation = "Hide server version"
```

### 3. Severity Assignment

**Critical**: Direct credential/code exposure

- Exposed .git, .env, database backups
- Source code disclosure
- Default credentials accessible

**High**: Version disclosure aiding exploitation

- Server/Framework version in headers
- Detailed error messages with versions
- Debug mode enabled

**Medium**: Security best practice violations

- Missing security headers
- Directory listing enabled
- Unnecessary HTTP methods

**Low**: Minor informational leaks

- Informational headers present
- Default pages accessible

**Info**: Detection only

- Server type identified
- Framework detected

### 4. Report Storage

```python
# Save with timestamp in filename
timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
report_dir = Path.home() / '.hephaestus' / 'reports'
json_file = report_dir / f"hephaestus_{timestamp}_{scan_id}.json"
html_file = report_dir / f"hephaestus_{timestamp}_{scan_id}.html"
```

### 5. Sensitive Data Handling

```python
# Sanitize evidence before storing
def sanitize_evidence(value: str) -> str:
    # Remove potential credentials
    value = re.sub(r'password["\s:=]+\w+', 'password=REDACTED', value, flags=re.I)
    value = re.sub(r'api[_-]?key["\s:=]+\w+', 'api_key=REDACTED', value, flags=re.I)
    # Truncate long values
    if len(value) > 500:
        value = value[:497] + '...'
    return value
```

### 6. Reference Links

Always include official documentation:

- Apache: `https://httpd.apache.org/docs/2.4/`
- Nginx: `https://nginx.org/en/docs/`
- Security Headers: `https://securityheaders.com/`
- OWASP: `https://owasp.org/www-project-secure-headers/`

---

## 🎨 Customization

### Custom Finding Types

Add custom checks by extending the scanner:

```python
from heph.checks.base import BaseCheck

class CustomCheck(BaseCheck):
    def run(self) -> list[dict]:
        findings = []

        # Your custom check logic
        response = self.http_get('/custom-endpoint')

        if self.detect_issue(response):
            findings.append({
                'id': 'HEPH-CUSTOM-001',
                'title': 'Custom security issue detected',
                'severity': 'medium',
                'confidence': 'high',
                'evidence': {
                    'type': 'body',
                    'value': response.text[:200],
                    'context': f'HTTP {response.status_code}'
                },
                'recommendation': 'Fix the custom issue...',
                'references': ['https://example.com/docs'],
                'affected_component': 'Custom Component'
            })

        return findings
```

### Custom HTML Template

Override the default template:

```python
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# Use custom template
template_dir = Path('/path/to/custom/templates')
env = Environment(loader=FileSystemLoader(template_dir))
template = env.get_template('custom_hephaestus_report.html.j2')

html_output = template.render(
    report=report,
    custom_branding='Your Company'
)
```

---

## 📊 Report Metrics

### Key Performance Indicators

Track these metrics from reports:

```python
# Scan efficiency
scan_duration = report['notes']['scan_duration_seconds']
requests_sent = report['notes']['requests_sent']
requests_per_second = requests_sent / scan_duration

# Security posture
critical_count = report['summary']['critical']
high_count = report['summary']['high']
risk_score = (critical_count * 10) + (high_count * 5)

# Detection coverage
total_checks = 50  # Approximate total checks
findings_count = len(report['findings'])
coverage_rate = (findings_count / total_checks) * 100
```

### Trending Analysis

```python
import pandas as pd

# Load recent scans
scans_df = pd.read_sql("""
    SELECT
        scan_id,
        started_at,
        JSON_EXTRACT(summary, '$.critical') as critical,
        JSON_EXTRACT(summary, '$.high') as high
    FROM scans
    WHERE tool = 'hephaestus'
        AND started_at > datetime('now', '-30 days')
    ORDER BY started_at
""", db)

# Calculate 7-day moving average
scans_df['risk_score'] = scans_df['critical']*10 + scans_df['high']*5
scans_df['ma_7d'] = scans_df['risk_score'].rolling(window=7).mean()

print(scans_df[['started_at', 'risk_score', 'ma_7d']])
```

---

## 🔐 Security Considerations

### Report Encryption (for sensitive environments)

```python
from cryptography.fernet import Fernet
import json

# Generate key (store securely!)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt report
report_json = json.dumps(report)
encrypted = cipher.encrypt(report_json.encode())

# Save encrypted
with open('report.json.encrypted', 'wb') as f:
    f.write(encrypted)

# Decrypt later
with open('report.json.encrypted', 'rb') as f:
    encrypted = f.read()
decrypted = cipher.decrypt(encrypted)
report = json.loads(decrypted.decode())
```

### Access Control

```python
import os
from pathlib import Path

# Set restrictive permissions
report_file = Path('~/.hephaestus/reports/sensitive_scan.json')
os.chmod(report_file, 0o600)  # Owner read/write only
```

---

## 📚 Additional Resources

### Documentation

- **Hephaestus GitHub**: https://github.com/rodhnin/hephaestus-server-forger
- **Apache Security**: https://httpd.apache.org/docs/2.4/misc/security_tips.html
- **Nginx Security**: https://nginx.org/en/docs/http/ngx_http_ssl_module.html
- **OWASP Secure Headers**: https://owasp.org/www-project-secure-headers/

### Support

- **Issues**: https://github.com/rodhnin/hephaestus-server-forger/issues
- **Discussions**: https://github.com/rodhnin/hephaestus-server-forger/discussions

_Last Updated: May 2026_
_Version: 2.0_
_Tool: Hephaestus v0.2.0_
