# Security Policy

## Overview

Security is at the core of **Hephaestus Server Security Auditor**. We are committed to maintaining the highest security standards for our codebase and responsibly handling any vulnerabilities discovered in the project.

This document outlines our security policies, vulnerability reporting process, and responsible disclosure guidelines.

---

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Status                    |
| ------- | ------------------ | ------------------------- |
| 0.1.x   | :white_check_mark: | Current stable release    |
| < 0.1.0 | :x:                | Pre-release (unsupported) |

**Recommendation**: Always use the latest stable release to ensure you have the most recent security patches.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Hephaestus, we appreciate your help in disclosing it to us responsibly.

### Where to Report

**DO NOT** create a public GitHub issue for security vulnerabilities. Instead, use one of these secure channels:

1. **GitHub Security Advisories** (Preferred):

    - Go to: https://github.com/rodhnin/hephaestus-server-forger/security/advisories/new
    - Click "Report a vulnerability"
    - Fill out the private advisory form

2. **Direct Contact**:
    - Visit: https://rodhnin.com (contact form available)
    - Include `[SECURITY] Hephaestus Vulnerability` in the subject line

### What to Include

Please provide the following information to help us understand and reproduce the issue:

````
**Vulnerability Type**: [e.g., SQL Injection, Command Injection, XSS]

**Affected Component**: [e.g., heph/checks/ssl.py, heph/db/manager.py]

**Affected Versions**: [e.g., 0.1.0, all versions]

**Description**:
[Clear description of the vulnerability]

**Steps to Reproduce**:
1. Step one
2. Step two
3. ...

**Proof of Concept** (if applicable):
```python
# Code demonstrating the vulnerability
````

**Impact Assessment**:

-   Confidentiality: [None/Low/Medium/High/Critical]
-   Integrity: [None/Low/Medium/High/Critical]
-   Availability: [None/Low/Medium/High/Critical]

**Suggested Fix** (optional):
[Your recommendations for fixing the issue]

````

### Our Commitment

When you report a vulnerability, you can expect:

- **Acknowledgment**: Within **24-48 hours** of your report
- **Initial Assessment**: Within **5 business days**
- **Status Updates**: Weekly updates on our progress
- **Fix Timeline**: Target **30-90 days** depending on severity
- **Credit**: Public acknowledgment in release notes (unless you prefer anonymity)

---

## Responsible Disclosure Policy

We follow a **coordinated disclosure** approach:

### Timeline

1. **Day 0**: Vulnerability reported via secure channel
2. **Day 1-2**: Acknowledgment sent to reporter
3. **Day 3-7**: Initial triage and severity assessment
4. **Day 7-30**: Fix development and testing
5. **Day 30-60**: Coordinated patch release
6. **Day 90**: Public disclosure (if fix is not yet available)

### Severity Levels

We use the **CVSS v3.1** scoring system:

| Severity | CVSS Score | Response Time | Fix Target |
| -------- | ---------- | ------------- | ---------- |
| Critical | 9.0-10.0   | 24 hours      | 7 days     |
| High     | 7.0-8.9    | 48 hours      | 30 days    |
| Medium   | 4.0-6.9    | 5 days        | 60 days    |
| Low      | 0.1-3.9    | 10 days       | 90 days    |

### Public Disclosure

- **Coordinated Release**: We will work with you to agree on a public disclosure date
- **Credit Attribution**: We will publicly credit you (unless you request anonymity)
- **CVE Assignment**: For critical/high vulnerabilities, we will request a CVE identifier
- **Release Notes**: Security fixes will be documented in CHANGELOG.md

---

## Security Best Practices

### For Users

When using Hephaestus, follow these security best practices:

1. **Keep Updated**: Always use the latest stable version
   ```bash
   git pull origin main
   pip install --upgrade -r requirements.txt
````

2. **Consent Tokens**: ALWAYS obtain proper authorization before scanning

    ```bash
    python -m heph --gen-consent example.com
    ```

3. **API Key Security**: Never commit API keys to version control

    ```bash
    # Use environment variables
    export OPENAI_API_KEY="sk-..."
    # Or use .env files (add to .gitignore)
    echo "OPENAI_API_KEY=sk-..." > .env
    ```

4. **Database Permissions**: Ensure proper file permissions on `~/.argos/argos.db`

    ```bash
    chmod 600 ~/.argos/argos.db
    ```

5. **Docker Security**: Use non-root user (already configured in Dockerfile)
    ```yaml
    user: "1000:1000" # Run as non-root
    ```

### For Contributors

When contributing code, ensure:

1. **Input Validation**: Sanitize all user inputs

    ```python
    # Bad: Direct string interpolation
    url = f"https://{user_input}"

    # Good: Validate and sanitize
    from urllib.parse import urlparse
    parsed = urlparse(user_input)
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid URL scheme")
    ```

2. **SQL Injection Prevention**: Use parameterized queries

    ```python
    # Bad: String concatenation
    cursor.execute(f"SELECT * FROM scans WHERE domain='{domain}'")

    # Good: Parameterized query
    cursor.execute("SELECT * FROM scans WHERE domain=?", (domain,))
    ```

3. **Command Injection Prevention**: Avoid shell=True

    ```python
    # Bad: Shell injection risk
    subprocess.run(f"curl {url}", shell=True)

    # Good: Use array syntax
    subprocess.run(["curl", url], shell=False)
    ```

4. **Path Traversal Prevention**: Validate file paths

    ```python
    # Bad: Direct path concatenation
    file_path = f"/reports/{filename}"

    # Good: Validate and resolve
    from pathlib import Path
    base_dir = Path("/reports").resolve()
    file_path = (base_dir / filename).resolve()
    if not file_path.is_relative_to(base_dir):
        raise ValueError("Invalid file path")
    ```

5. **Secrets Management**: Never log sensitive data

    ```python
    # Bad: Logging API keys
    logger.debug(f"Using API key: {api_key}")

    # Good: Redact sensitive data
    logger.debug(f"Using API key: {api_key[:8]}...")
    ```

---

## Known Security Considerations

### Rate Limiting

Hephaestus implements rate limiting to prevent abuse:

-   **Safe Mode**: 5 requests/second (default)
-   **Aggressive Mode**: 12 requests/second (requires consent token)

**Recommendation**: Never disable rate limiting against third-party servers.

### Consent Token System

Hephaestus requires consent tokens for:

-   Aggressive scanning mode (`--aggressive`)
-   AI-powered analysis (`--use-ai`)

**How it works**:

1. Generate token: `python -m heph --gen-consent example.com`
2. Place token on server: `.well-known/verify-{token}.txt`
3. Verify: `python -m heph --verify-consent http --domain example.com --token {token}`

### Database Security

The shared Argos database (`~/.argos/argos.db`) stores:

-   Scan history and findings
-   Consent tokens with expiration dates
-   No passwords or API keys

**Permissions**: Ensure database file is only readable by the user:

```bash
chmod 600 ~/.argos/argos.db
```

### AI Provider Security

When using AI features, be aware:

-   **OpenAI/Anthropic**: Data sent to third-party APIs (check their privacy policies)
-   **Ollama (Local)**: 100% offline, no data leaves your machine
-   **Recommendations**:
    -   Use Ollama for sensitive/confidential scans
    -   Never send PII or credentials to AI providers
    -   Review generated recommendations before applying

---

## Security Audit History

| Date       | Auditor         | Scope                       | Findings           | Status      |
| ---------- | --------------- | --------------------------- | ------------------ | ----------- |
| 2025-10-XX | Internal Review | Full codebase (v0.1.0)      | 0 critical, 0 high | ✅ Resolved |
| TBD        | External Audit  | Third-party security review | Pending            | 🔜 Planned  |

---

## Security-Related Configuration

### Recommended Production Settings

```yaml
# config/defaults.yaml (security-focused)
scan:
    timeout: 10 # Prevent hanging requests
    rate_limit: 5 # Respectful scanning
    verify_ssl: true # Validate SSL certificates
    follow_redirects: false # Prevent redirect loops

ai:
    provider: "ollama" # Use local AI for privacy
    timeout: 300 # 5-minute timeout for AI requests
```

### Environment Variables

```bash
# Production environment
export HEPHAESTUS_REPORT_DIR="/secure/reports"
export HEPHAESTUS_DATABASE="/secure/data/argos.db"
export HEPHAESTUS_IN_CONTAINER="true"
export HEPHAESTUS_LOG_LEVEL="info"  # Avoid debug logs in production
```

---

## Hall of Fame

We appreciate the following individuals for responsibly disclosing vulnerabilities:

| Reporter | Vulnerability | Severity | Disclosure Date |
| -------- | ------------- | -------- | --------------- |
| TBD      | TBD           | TBD      | TBD             |

_Be the first to help secure Hephaestus!_

---

## Security Resources

-   **OWASP Top 10**: https://owasp.org/www-project-top-ten/
-   **CWE Top 25**: https://cwe.mitre.org/top25/
-   **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
-   **Python Security Best Practices**: https://python.readthedocs.io/en/latest/library/security_warnings.html

---

## Contact

-   **Security Team**: https://rodhnin.com (contact form)
-   **GitHub Security Advisories**: https://github.com/rodhnin/hephaestus-server-forger/security/advisories
-   **Project Maintainer**: Rodney Dhavid Jimenez Chacin (rodhnin)

For non-security issues, please use [GitHub Issues](https://github.com/rodhnin/hephaestus-server-forger/issues).

---

**Last Updated**: November 2025

Thank you for helping keep Hephaestus and our users safe!
