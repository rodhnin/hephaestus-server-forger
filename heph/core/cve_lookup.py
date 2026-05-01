"""
CVE Lookup Module — NVD API v2 + CIRCL Fallback (v0.2.0)

Queries NIST NVD API for real CVEs affecting detected server software versions.
Zero hardcoded CVE data — everything comes from live APIs.

Strategy:
  1. NVD API v2  (primary)  — virtualMatchString with exact CPE, sorted by CVSS desc
  2. CIRCL CVE Search (fallback) — when NVD is rate-limited or CPE is unknown
  3. In-memory cache — avoids duplicate API calls within the same scan

Rate limits:
  NVD without key: 5 req / 30s  → sleep 7s between calls
  NVD with key:   50 req / 30s  → sleep 0.6s between calls

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import time
import threading
import requests
from typing import Any, Dict, List, Optional, Tuple

from .logging import get_logger

logger = get_logger(__name__)

# ─── NVD API ──────────────────────────────────────────────────────────────────
NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_BASE = "https://cve.circl.lu/api"

# ─── CPE vendor / product mapping ────────────────────────────────────────────
# Format: normalized_software_key → (nvd_vendor, nvd_product)
CPE_MAP: Dict[str, Tuple[str, str]] = {
    # Web servers
    "apache":               ("apache", "http_server"),
    "httpd":                ("apache", "http_server"),
    "nginx":                ("f5",     "nginx"),
    "iis":                  ("microsoft", "internet_information_services"),
    "lighttpd":             ("lighttpd", "lighttpd"),
    "tomcat":               ("apache", "tomcat"),
    "caddy":                ("caddyserver", "caddy"),
    "haproxy":              ("haproxy", "haproxy"),
    "varnish":              ("varnish-cache", "varnish"),
    # Languages / runtimes
    "php":                  ("php", "php"),
    "nodejs":               ("nodejs", "node.js"),
    "node":                 ("nodejs", "node.js"),
    "python":               ("python", "python"),
    "ruby":                 ("ruby-lang", "ruby"),
    "java":                 ("oracle", "jdk"),
    "openjdk":              ("oracle", "openjdk"),
    # Cryptography
    "openssl":              ("openssl", "openssl"),
    # Databases
    "mysql":                ("oracle",    "mysql"),         # NVD uses oracle/mysql
    "mariadb":              ("mariadb",   "mariadb"),
    "postgresql":           ("postgresql","postgresql"),
    "postgres":             ("postgresql","postgresql"),
    "mongodb":              ("mongodb",   "mongodb"),
    "redis":                ("redis",     "redis"),          # NVD uses redis/redis (not redislabs)
    "memcached":            ("memcached", "memcached"),
    "elasticsearch":        ("elastic",   "elasticsearch"),
    "cassandra":            ("apache", "cassandra"),
    "couchdb":              ("apache", "couchdb"),
    "influxdb":             ("influxdata", "influxdb"),
    "mssql":                ("microsoft", "sql_server"),
    "sqlserver":            ("microsoft", "sql_server"),
    # Frameworks
    "django":               ("djangoproject", "django"),
    "rails":                ("rubyonrails", "ruby_on_rails"),
    "laravel":              ("laravel", "laravel"),
    "spring":               ("vmware", "spring_framework"),
    "springboot":           ("vmware", "spring_boot"),
    "flask":                ("palletsprojects", "flask"),
    "express":              ("expressjs", "express"),
    "fastapi":              ("tiangolo", "fastapi"),
    "wordpress":            ("wordpress", "wordpress"),
    "drupal":               ("drupal", "drupal"),
    "joomla":               ("joomla", "joomla"),
    # Message queues
    "rabbitmq":             ("rabbitmq", "rabbitmq"),
    "kafka":                ("apache", "kafka"),
    # Other
    "openssh":              ("openbsd", "openssh"),
    "postfix":              ("postfix", "postfix"),
    "exim":                 ("exim", "exim"),
    "proftpd":              ("proftpd", "proftpd"),
    "vsftpd":               ("vsftpd_project", "vsftpd"),
}

# ─── In-memory cache (thread-safe) ───────────────────────────────────────────
_CACHE: Dict[Tuple[str, str, str], List[Dict]] = {}
_CACHE_LOCK = threading.Lock()

# ─── Common CWE names (offline lookup, avoids extra API call) ────────────────
_CWE_NAMES: Dict[str, str] = {
    "CWE-20":  "Improper Input Validation",
    "CWE-22":  "Path Traversal",
    "CWE-77":  "Command Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Copy without Size Check",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Sensitive Information Exposure",
    "CWE-264": "Permissions / Privilege Issues",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-310": "Cryptographic Issues",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken/Risky Cryptographic Algorithm",
    "CWE-330": "Insufficient Random Values",
    "CWE-352": "CSRF",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Memory Leak",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-444": "HTTP Request Smuggling",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-755": "Improper Exception Handling",
    "CWE-787": "Out-of-bounds Write",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def lookup_cves(
    software: str,
    version: str,
    max_results: int = 10,
    api_key: Optional[str] = None,
    timeout: int = 12,
) -> List[Dict[str, Any]]:
    """
    Look up CVEs for a specific software+version from NVD API.

    Args:
        software: Software name key (e.g. 'apache', 'nginx', 'php', 'mysql')
        version:  Version string (e.g. '2.4.41', '1.18.0', '8.0.28')
        max_results: Max CVEs to return (highest CVSS first)
        api_key:  Optional NVD API key for higher rate limits
        timeout:  HTTP request timeout in seconds

    Returns:
        List of dicts with: cve_id, title, description, link,
        cvss_score, cvss_severity, cwe_id, cwe_name, published
    """
    # Guard: empty or unknown version produces meaningless CPE queries
    if not version or not version.strip() or version.strip().lower() in ("unknown", "n/a", "-"):
        logger.debug(f"Skipping CVE lookup for '{software}': no valid version provided")
        return []

    key = software.lower().replace("-", "").replace(" ", "").replace("_", "")

    cpe_entry = CPE_MAP.get(key)
    if not cpe_entry:
        logger.debug(f"No CPE mapping for '{software}' — trying CIRCL fallback")
        return _circl_fallback(software, version, max_results, timeout)

    vendor, product = cpe_entry
    cache_key = (vendor, product, version)

    with _CACHE_LOCK:
        if cache_key in _CACHE:
            logger.debug(f"CVE cache hit: {vendor}/{product} {version}")
            return _CACHE[cache_key][:max_results]

    results = _query_nvd(vendor, product, version, api_key, timeout)

    with _CACHE_LOCK:
        _CACHE[cache_key] = results

    return results[:max_results]


def _query_nvd(
    vendor: str,
    product: str,
    version: str,
    api_key: Optional[str],
    timeout: int,
) -> List[Dict[str, Any]]:
    """Query NVD API v2 using virtualMatchString CPE lookup."""
    cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}"
    params = {
        "virtualMatchString": cpe_string,
        "resultsPerPage": 2000,
    }
    headers = {"apiKey": api_key} if api_key else {}

    try:
        logger.debug(f"NVD query: {cpe_string}")
        resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code == 403:
            logger.warning("NVD rate limited — sleeping 30s then retrying")
            time.sleep(30)
            resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=timeout)

        if resp.status_code in (404, 204):
            logger.debug(f"NVD: no results for {cpe_string}")
            return []

        resp.raise_for_status()
        data = resp.json()
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        logger.info(f"NVD: {total} CVE(s) for {vendor}/{product} {version}")

        results = [r for r in (_parse_nvd(v) for v in vulns) if r]
        results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
        return results

    except requests.exceptions.Timeout:
        logger.warning(f"NVD timeout for {vendor}/{product} {version} — trying CIRCL")
        return _circl_fallback(f"{vendor} {product}", version, 10, timeout)

    except requests.exceptions.RequestException as e:
        logger.warning(f"NVD request error: {e}")
        return []

    except Exception as e:
        logger.error(f"Unexpected NVD error: {e}")
        return []


def _parse_nvd(vuln: Dict) -> Optional[Dict[str, Any]]:
    """Parse one NVD vulnerability entry into our schema format."""
    try:
        cve      = vuln["cve"]
        cve_id   = cve["id"]
        desc_en  = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "",
        )

        # CVSS: prefer v3.1 → v3.0 → v2.0
        metrics      = cve.get("metrics", {})
        cvss_score   = None
        cvss_severity = None

        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                d = entries[0]["cvssData"]
                cvss_score    = d.get("baseScore")
                cvss_severity = d.get("baseSeverity")
                break

        if cvss_score is None:
            entries = metrics.get("cvssMetricV2", [])
            if entries:
                cvss_score    = entries[0]["cvssData"].get("baseScore")
                cvss_severity = entries[0].get("baseSeverity", "")

        # CWE
        cwe_ids = [
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")
        ]
        cwe_id = cwe_ids[0] if cwe_ids else None

        record: Dict[str, Any] = {
            "cve_id":        cve_id,
            "title":         desc_en[:120] or cve_id,
            "description":   desc_en,
            "link":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cvss_score":    cvss_score,
            "cvss_severity": cvss_severity,
            "published":     cve.get("published", "")[:10],
        }
        # Only include CWE fields when they have a value (schema requires strings, not null)
        if cwe_id:
            record["cwe_id"]   = cwe_id
            record["cwe_name"] = _CWE_NAMES.get(cwe_id, "")
        return record
    except Exception as e:
        logger.debug(f"CVE parse error: {e}")
        return None


def _circl_fallback(
    software: str,
    version: str,
    max_results: int,
    timeout: int,
) -> List[Dict[str, Any]]:
    """CIRCL CVE Search API fallback — returns most recent CVEs for a product."""
    # Derive vendor/product guess from software string
    parts = software.lower().replace("-", "_").split()
    vendor  = parts[0] if parts else software.lower()
    product = "_".join(parts) if parts else software.lower()

    url = f"{CIRCL_BASE}/search/{vendor}/{product}"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return []

        data = resp.json()
        results = []
        items = data if isinstance(data, list) else data.get("data", [])

        for item in items:
            cve_id  = item.get("id", "")
            summary = item.get("summary", "")
            cvss    = item.get("cvss")
            cwe     = item.get("cwe", "")

            try:
                cvss_f = float(cvss) if cvss else None
            except (TypeError, ValueError):
                cvss_f = None

            cve_record: Dict[str, Any] = {
                "cve_id":        cve_id,
                "title":         summary[:120] or cve_id,
                "description":   summary,
                "link":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cvss_score":    cvss_f,
                "cvss_severity": _score_to_severity(cvss_f),
                "published":     item.get("Published", "")[:10],
            }
            # Only include CWE fields when they have a value
            if isinstance(cwe, str) and cwe.startswith("CWE-"):
                cve_record["cwe_id"]   = cwe
                cve_record["cwe_name"] = _CWE_NAMES.get(cwe, "")
            results.append(cve_record)

        results.sort(key=lambda x: x.get("cvss_score") or 0.0, reverse=True)
        return results[:max_results]

    except Exception as e:
        logger.debug(f"CIRCL fallback error: {e}")
        return []


def _score_to_severity(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def enrich_finding_with_cves(
    finding: Dict[str, Any],
    software: str,
    version: str,
    max_cves: int = 8,
    api_key: Optional[str] = None,
) -> None:
    """
    Enrich a finding dict in-place with CVE data from NVD.

    Adds / updates:
      - finding['vulnerabilities'] : list of CVE records
      - finding['cve']             : list of CVE IDs
      - finding['cvss']            : highest CVSS score found
    """
    if not version or version in ("unknown", ""):
        return

    cves = lookup_cves(software, version, max_results=max_cves, api_key=api_key)
    if not cves:
        return

    finding["vulnerabilities"] = cves
    finding["cve"] = [c["cve_id"] for c in cves if c.get("cve_id")]

    scores = [c["cvss_score"] for c in cves if c.get("cvss_score") is not None]
    if scores:
        finding["cvss"] = max(scores)

    logger.debug(
        f"Enriched finding {finding.get('id')} with {len(cves)} CVEs "
        f"for {software} {version} (top CVSS: {finding.get('cvss')})"
    )


def clear_cache() -> None:
    """Clear in-memory CVE cache (useful between test runs)."""
    with _CACHE_LOCK:
        _CACHE.clear()
    logger.debug("CVE cache cleared")
