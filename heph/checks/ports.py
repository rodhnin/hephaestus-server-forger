"""
Port Scanner & Service Banner Grabber (v0.2.0)

Scans common backend service ports to detect:
- Exposed database services (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch)
- Exposed infrastructure (SSH, FTP, SMTP, RabbitMQ, Memcached)
- Service version disclosure via banners
- Unauthenticated access to dangerous services (Redis, Memcached, Elasticsearch)
- CVE enrichment via NVD API for detected software versions

Strategy:
  1. Parallel TCP connect scan (ThreadPoolExecutor)
  2. Banner grabbing for each open port
  3. Service-specific probes for auth testing (Redis PING, Elasticsearch GET /, etc.)
  4. Version extraction via regex per service
  5. CVE enrichment via cve_lookup module (NVD API + CIRCL fallback)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..core.logging import get_logger
from ..core.config import get_config
from ..core.cve_lookup import enrich_finding_with_cves

logger = get_logger(__name__)

# ─── Port → Service metadata ─────────────────────────────────────────────────
# Format: port → (service_name, cve_software_key, default_severity, description)
PORT_SERVICES: Dict[int, Tuple[str, Optional[str], str, str]] = {
    21:    ("FTP",                   "vsftpd",         "medium",   "File Transfer Protocol server"),
    22:    ("SSH",                   "openssh",        "info",     "Secure Shell daemon"),
    25:    ("SMTP",                  "postfix",        "low",      "Simple Mail Transfer Protocol"),
    110:   ("POP3",                  "postfix",        "low",      "Post Office Protocol"),
    143:   ("IMAP",                  "postfix",        "low",      "Internet Message Access Protocol"),
    465:   ("SMTPS",                 "postfix",        "low",      "SMTP over SSL"),
    587:   ("SMTP Submission",       "postfix",        "low",      "SMTP submission port"),
    # ─── Relational databases ──────────────────────────────────────────────────
    1433:  ("Microsoft SQL Server",  "mssql",          "high",     "Microsoft SQL Server database"),
    1521:  ("Oracle Database",       None,             "high",     "Oracle Database listener"),
    3306:  ("MySQL/MariaDB",         "mysql",          "high",     "MySQL/MariaDB database server"),
    5432:  ("PostgreSQL",            "postgresql",     "high",     "PostgreSQL database server"),
    # ─── NoSQL / caches ────────────────────────────────────────────────────────
    5984:  ("CouchDB",               "couchdb",        "high",     "Apache CouchDB REST API"),
    6379:  ("Redis",                 "redis",          "critical", "Redis in-memory data store"),
    11211: ("Memcached",             "memcached",      "critical", "Memcached distributed cache"),
    27017: ("MongoDB",               "mongodb",        "high",     "MongoDB document database"),
    27018: ("MongoDB",               "mongodb",        "high",     "MongoDB document database (alt)"),
    # ─── Search / time-series / analytics ─────────────────────────────────────
    9200:  ("Elasticsearch HTTP",    "elasticsearch",  "high",     "Elasticsearch REST API"),
    9300:  ("Elasticsearch TCP",     "elasticsearch",  "medium",   "Elasticsearch transport layer"),
    8086:  ("InfluxDB",              "influxdb",       "medium",   "InfluxDB time-series database"),
    # ─── Message queues ────────────────────────────────────────────────────────
    5672:  ("RabbitMQ AMQP",         "rabbitmq",       "medium",   "RabbitMQ AMQP message broker"),
    15672: ("RabbitMQ Management",   "rabbitmq",       "high",     "RabbitMQ management HTTP API"),
    # ─── Development / app servers (likely not meant to be public) ────────────
    3000:  ("Dev Server :3000",      None,             "medium",   "Common Node.js/React/Next.js dev port"),
    4000:  ("Dev Server :4000",      None,             "medium",   "Common dev/API server port"),
    4200:  ("Angular Dev Server",    None,             "medium",   "Angular CLI development server"),
    5000:  ("Dev Server :5000",      None,             "medium",   "Common Flask/dev server port"),
    8000:  ("Dev Server :8000",      None,             "medium",   "Common Python/Django dev port"),
    8080:  ("HTTP Alt :8080",        None,             "low",      "HTTP alternative port"),
    8443:  ("HTTPS Alt :8443",       None,             "low",      "HTTPS alternative port"),
    8888:  ("Jupyter Notebook",      None,             "high",     "Jupyter Notebook (often no auth)"),
    9000:  ("Dev Server :9000",      None,             "medium",   "Common PHP-FPM/dev server port"),
    # ─── Admin / monitoring interfaces ────────────────────────────────────────
    2181:  ("Zookeeper",             None,             "high",     "Apache Zookeeper client port"),
    4848:  ("GlassFish Admin",       None,             "high",     "GlassFish application server admin"),
    7001:  ("WebLogic",              None,             "high",     "Oracle WebLogic admin port"),
    8161:  ("ActiveMQ Web Console",  None,             "high",     "Apache ActiveMQ management UI"),
    9090:  ("Prometheus",            None,             "medium",   "Prometheus metrics server"),
    3001:  ("Grafana",               None,             "medium",   "Grafana dashboard (default :3001)"),
    # ─── Big data ──────────────────────────────────────────────────────────────
    50070: ("Hadoop NameNode",       None,             "high",     "Apache Hadoop NameNode HTTP UI"),
}

# ─── Default ports to scan ────────────────────────────────────────────────────
DEFAULT_SCAN_PORTS = sorted(PORT_SERVICES.keys())

# ─── Version extraction regexes per software key ──────────────────────────────
VERSION_PATTERNS: Dict[str, re.Pattern] = {
    "openssh":       re.compile(r'SSH-\d+\.\d+-OpenSSH[_\s]([0-9a-z.p]+)', re.I),
    "vsftpd":        re.compile(r'vsftpd\s+([0-9.]+)', re.I),
    "proftpd":       re.compile(r'ProFTPD\s+([0-9.]+)', re.I),
    "postfix":       re.compile(r'Postfix\s+(?:ESMTP\s+)?(?:Mail\s+)?([0-9.]+)', re.I),
    "redis":         re.compile(r'redis_version:([0-9.]+)', re.I),
    "memcached":     re.compile(r'VERSION\s+([0-9.]+)', re.I),
    "mysql":         re.compile(r'([5-9]\.[0-9]+\.[0-9]+)', re.I),
    "mssql":         re.compile(r'([0-9]+\.[0-9]+\.[0-9]+)', re.I),
    "mongodb":       re.compile(r'"version"\s*:\s*"([0-9.]+)"', re.I),
    "elasticsearch": re.compile(r'"number"\s*:\s*"([0-9.]+)"', re.I),
    "couchdb":       re.compile(r'"version"\s*:\s*"([0-9.]+)"', re.I),
    "influxdb":      re.compile(r'"version"\s*:\s*"([0-9.]+)"', re.I),
    "rabbitmq":      re.compile(r'(?:RabbitMQ|rabbitmq_version)["\s:]+([0-9.]+)', re.I),
    "postgresql":    re.compile(r'PostgreSQL\s+([0-9.]+)', re.I),
}

# ─── Service-specific probes (to elicit banner/version) ──────────────────────
SERVICE_PROBES: Dict[int, bytes] = {
    # Protocol-specific probes
    6379:  b"PING\r\n",
    11211: b"version\r\n",
    # HTTP-based service probes
    9200:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    5984:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8086:  b"GET /ping HTTP/1.0\r\nHost: localhost\r\n\r\n",
    15672: b"GET /api/overview HTTP/1.0\r\nHost: localhost\r\nAccept: application/json\r\n\r\n",
    50070: b"GET /jmx HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8888:  b"GET /api/kernels HTTP/1.0\r\nHost: localhost\r\n\r\n",  # Jupyter
    9090:  b"GET /-/healthy HTTP/1.0\r\nHost: localhost\r\n\r\n",    # Prometheus
    3001:  b"GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n",   # Grafana
    4848:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",             # GlassFish
    8161:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",             # ActiveMQ
    # Generic HTTP probe for dev ports — detect framework from response
    3000:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    4000:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    4200:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    5000:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8000:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    9000:  b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
}

# ─── Unauthenticated access: (response_indicator, human-readable explanation) ─
UNAUTH_INDICATORS: Dict[int, Tuple[bytes, str]] = {
    6379:  (b"+PONG",              "Redis accepted PING without authentication"),
    11211: (b"VERSION ",           "Memcached returned version without authentication"),
    9200:  (b'"cluster_name"',     "Elasticsearch returned cluster info without authentication"),
    5984:  (b'"couchdb"',          "CouchDB returned server info without authentication"),
    8086:  (b"204 No Content",     "InfluxDB /ping responded without authentication"),
    15672: (b'"rabbitmq_version"', "RabbitMQ Management API is unauthenticated"),
    8888:  (b'"kernels"',          "Jupyter Notebook API accessible without token"),
    9090:  (b"Prometheus",         "Prometheus metrics endpoint is publicly accessible"),
    3001:  (b'"grafanaVersion"',   "Grafana API accessible without authentication"),
    8161:  (b"ActiveMQ",           "ActiveMQ web console is publicly accessible"),
    4848:  (b"GlassFish",          "GlassFish admin console is publicly accessible"),
    50070: (b"NameNode",           "Hadoop NameNode UI is publicly accessible"),
}

# ─── Web framework fingerprints (for dev/HTTP ports) ─────────────────────────
# Patterns to detect what's running on HTTP-responding dev ports
WEB_FINGERPRINTS = [
    # (indicator_bytes, framework_name, cve_key_or_None)
    (b"X-Powered-By: Express",        "Node.js/Express",  None),
    (b"X-Powered-By: PHP",            "PHP",              "php"),
    (b'"powered_by":"Flask"',         "Flask",            "flask"),
    (b"django",                       "Django",           "django"),
    (b"X-Rails",                      "Ruby on Rails",    "rails"),
    (b"Spring",                       "Spring Boot",      "springboot"),
    (b"Werkzeug",                      "Flask/Werkzeug",   "flask"),
    (b"Tornado",                      "Tornado (Python)", None),
    (b"Gunicorn",                     "Gunicorn (Python)",None),
    (b"uvicorn",                      "FastAPI/Uvicorn",  "fastapi"),
    (b"Jetty",                        "Jetty",            None),
    (b"Tomcat",                       "Apache Tomcat",    "tomcat"),
    (b"WebLogic",                     "Oracle WebLogic",  None),
    (b"GlassFish",                    "GlassFish",        None),
    (b"laravel",                      "Laravel",          "laravel"),
    (b"Jupyter",                      "Jupyter Notebook", None),
    (b"Prometheus",                   "Prometheus",       None),
    (b'"grafanaVersion"',             "Grafana",          None),
    (b"ActiveMQ",                     "Apache ActiveMQ",  "kafka"),
]

# ─── OWASP mapping for port exposure findings ────────────────────────────────
PORT_OWASP = {
    "critical": {"id": "A05", "name": "Security Misconfiguration"},
    "high":     {"id": "A05", "name": "Security Misconfiguration"},
    "medium":   {"id": "A05", "name": "Security Misconfiguration"},
    "low":      {"id": "A05", "name": "Security Misconfiguration"},
    "info":     None,
}


class PortScanner:
    """
    Scans backend service ports on the target host.
    Detects exposed databases, caches, and infrastructure services
    with banner-based version disclosure and CVE enrichment.
    """

    def __init__(self, config=None):
        self.config = config or get_config()
        self.connect_timeout = getattr(self.config, 'port_scan_timeout', 3)
        self.scan_ports = getattr(self.config, 'port_scan_ports', DEFAULT_SCAN_PORTS)
        self.cve_enabled = getattr(self.config, 'port_scan_cve_enabled', True)
        self.max_workers = getattr(self.config, 'port_scan_workers', 20)

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Run port scan against the target host.

        Args:
            target: Target URL (e.g., http://example.com or https://example.com)

        Returns:
            List of findings for each detected open port/service
        """
        parsed = urlparse(target)
        host = parsed.hostname or parsed.netloc
        if not host:
            logger.warning(f"Cannot extract hostname from target: {target}")
            return []

        # Determine the target's own port to avoid redundant findings
        target_port = parsed.port
        if target_port is None:
            target_port = 443 if parsed.scheme == 'https' else 80

        logger.info(f"Port scanning {host} ({len(self.scan_ports)} ports)...")

        # Parallel TCP connect scan
        open_ports = self._scan_ports_parallel(host)

        if not open_ports:
            logger.info(f"No open backend service ports found on {host}")
            return []

        logger.info(f"Open ports on {host}: {sorted(open_ports)}")

        # Build findings for each open port (sequential IDs for schema compliance)
        # Skip the target's own port — already being scanned as the web target
        findings = []
        seq = 0
        for port, banner_bytes in sorted(open_ports.items()):
            if port == target_port:
                logger.debug(f"Skipping port {port} (same as target port)")
                continue
            seq += 1
            finding = self._build_finding(host, port, banner_bytes, target, seq)
            if finding:
                findings.append(finding)

        return findings

    # ─── Private: parallel TCP connect scan ───────────────────────────────────

    def _scan_ports_parallel(self, host: str) -> Dict[int, Optional[bytes]]:
        """
        Probe all configured ports in parallel.
        Returns dict of {port: banner_bytes} for open ports only.
        """
        open_ports: Dict[int, Optional[bytes]] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._probe_port, host, port): port
                for port in self.scan_ports
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result is not None:
                        open_ports[port] = result
                except Exception as e:
                    logger.debug(f"Port probe error {host}:{port} — {e}")

        return open_ports

    def _probe_port(self, host: str, port: int) -> Optional[bytes]:
        """
        Attempt TCP connect + banner grab on a single port.
        Returns raw response bytes if port is open, None if closed/filtered.
        """
        try:
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                sock.settimeout(self.connect_timeout)

                # Try reading initial banner (most services send immediately)
                banner = self._read_banner(sock)

                # If no banner and we have a service-specific probe, send it
                if not banner and port in SERVICE_PROBES:
                    try:
                        sock.sendall(SERVICE_PROBES[port])
                        time.sleep(0.3)
                        banner = self._read_banner(sock)
                    except (socket.error, OSError):
                        pass

                # Port is open even if no banner was grabbed
                return banner or b""

        except (ConnectionRefusedError, socket.timeout, OSError):
            return None  # Port closed or filtered

    def _read_banner(self, sock: socket.socket) -> Optional[bytes]:
        """Read up to 4096 bytes from an open socket (with timeout)."""
        try:
            data = sock.recv(4096)
            return data if data else None
        except socket.timeout:
            return None
        except OSError:
            return None

    # ─── Private: build finding per port ─────────────────────────────────────

    def _build_finding(
        self,
        host: str,
        port: int,
        banner_bytes: Optional[bytes],
        target: str,
        seq: int = 1,
    ) -> Optional[Dict[str, Any]]:
        """
        Construct a finding dict for an open port.
        Includes banner evidence, version extraction, and CVE enrichment.
        """
        service_info = PORT_SERVICES.get(port)
        if not service_info:
            # Unknown port — create a generic finding
            service_name = f"Unknown service"
            cve_key = None
            severity = "low"
            description = "Unknown service"
        else:
            service_name, cve_key, severity, description = service_info

        banner_text = ""
        if banner_bytes:
            banner_text = banner_bytes.decode("utf-8", errors="replace").strip()[:500]

        # ── Check for unauthenticated access ──────────────────────────────────
        unauth_detected = False
        unauth_msg = None
        if port in UNAUTH_INDICATORS and banner_bytes:
            indicator, msg = UNAUTH_INDICATORS[port]
            if indicator in banner_bytes:
                unauth_detected = True
                unauth_msg = msg
                # Elevate severity for unauthenticated critical services
                if severity in ("critical", "high"):
                    severity = "critical"
                elif severity in ("medium", "low"):
                    severity = "high"

        # ── Detect web framework for HTTP-responding ports ────────────────────
        web_framework = None
        if banner_bytes and port in SERVICE_PROBES and port not in (6379, 11211):
            for indicator, fw_name, fw_cve in WEB_FINGERPRINTS:
                if indicator.lower() in banner_bytes.lower():
                    web_framework = fw_name
                    if fw_cve and not cve_key:
                        cve_key = fw_cve
                        service_name = fw_name
                    break

        # ── Extract software version from banner ──────────────────────────────
        version = None
        detected_software = cve_key
        if banner_text and cve_key and cve_key in VERSION_PATTERNS:
            match = VERSION_PATTERNS[cve_key].search(banner_text)
            if match:
                version = match.group(1)

        # Fallback: try SSH-specific, FTP-specific version extraction
        if not version and banner_text:
            version = self._generic_version_extract(banner_text, port)

        version_str = f" {version}" if version else ""

        # ── Build evidence ────────────────────────────────────────────────────
        evidence_lines = [f"Port {port}/TCP open on {host}"]
        if banner_text:
            evidence_lines.append(f"Banner: {banner_text[:200]}")
        if unauth_detected:
            evidence_lines.append(f"Auth check: {unauth_msg}")

        # ── Build description ─────────────────────────────────────────────────
        framework_str = f" [{web_framework}]" if web_framework and web_framework != service_name else ""

        if unauth_detected:
            full_desc = (
                f"{service_name}{framework_str} (port {port}) is accessible on {host} without authentication. "
                f"{unauth_msg}. This service should be restricted to authorized networks only "
                "and protected with strong authentication. Exposure of backend services to the "
                "internet is a critical security misconfiguration."
            )
        else:
            full_desc = (
                f"{service_name}{version_str}{framework_str} (port {port}) is accessible on {host}. "
                f"{description}. "
                "Backend service ports should not be exposed to the internet without "
                "strict access controls and network-level restrictions."
            )

        # ── Build recommendation ──────────────────────────────────────────────
        rec = self._build_recommendation(service_name, port, cve_key, unauth_detected)

        # ── Base finding dict ─────────────────────────────────────────────────
        finding = {
            "id": f"HEPH-NET-{seq:03d}",
            "title": self._build_title(service_name, port, version, unauth_detected, web_framework),
            "severity": severity,
            "confidence": "high" if unauth_detected else "medium",
            "description": full_desc,
            "evidence": {
                "type": "other",
                "value": "\n".join(evidence_lines),
                "context": f"TCP port scan of {host}:{port}",
            },
            "recommendation": rec,
            "references": self._get_references(port, cve_key),
            "affected_component": f"{service_name}{version_str} ({host}:{port})",
            "owasp": PORT_OWASP.get(severity),
        }

        finding["port"] = port
        finding["service"] = service_name

        if version:
            finding["detected_version"] = version
            finding["detected_software"] = cve_key or service_name

        # ── CVE Enrichment via NVD ────────────────────────────────────────────
        if self.cve_enabled and version and cve_key:
            try:
                enrich_finding_with_cves(finding, cve_key, version, max_cves=5)
                if finding.get("vulnerabilities"):
                    logger.info(
                        f"CVE enriched: {cve_key} {version} — "
                        f"{len(finding['vulnerabilities'])} CVEs (top CVSS: {finding.get('cvss')})"
                    )
                    # Elevate severity if high CVSS found
                    top_cvss = finding.get("cvss", 0) or 0
                    if top_cvss >= 9.0 and severity not in ("critical",):
                        finding["severity"] = "critical"
                    elif top_cvss >= 7.0 and severity not in ("critical", "high"):
                        finding["severity"] = "high"
            except Exception as e:
                logger.debug(f"CVE enrichment failed for {cve_key} {version}: {e}")

        return finding

    # ─── Private: helpers ─────────────────────────────────────────────────────

    def _generic_version_extract(self, banner: str, port: int) -> Optional[str]:
        """
        Fallback generic version extraction from banner string.
        Looks for common version patterns in any banner.
        """
        # SSH banner: SSH-2.0-OpenSSH_8.9p1
        ssh_match = re.search(r'SSH-\d+\.\d+-\S+_([0-9.p]+)', banner)
        if ssh_match:
            return ssh_match.group(1)

        # FTP: 220 (vsFTPd 3.0.3)
        ftp_match = re.search(r'220.*?([0-9]+\.[0-9]+\.[0-9]+)', banner)
        if ftp_match and port == 21:
            return ftp_match.group(1)

        # Generic version string after software name
        generic_match = re.search(r'(?:ver(?:sion)?|v)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', banner, re.I)
        if generic_match:
            return generic_match.group(1)

        return None

    def _build_title(
        self,
        service_name: str,
        port: int,
        version: Optional[str],
        unauth: bool,
        web_framework: Optional[str] = None,
    ) -> str:
        version_str = f" {version}" if version else ""
        fw_str = f" [{web_framework}]" if web_framework and web_framework != service_name else ""
        if unauth:
            return f"Unauthenticated {service_name}{version_str}{fw_str} exposed on port {port}"
        return f"{service_name}{version_str}{fw_str} exposed on port {port}"

    def _build_recommendation(
        self,
        service_name: str,
        port: int,
        cve_key: Optional[str],
        unauth: bool,
    ) -> str:
        lines = [
            f"Restrict port {port} ({service_name}) from public internet access:",
            "1. Use firewall rules to allow only trusted IPs (iptables/ufw/security groups)",
            "2. Bind the service to localhost (127.0.0.1) instead of 0.0.0.0 if only local access needed",
        ]
        if unauth:
            lines.append("3. Enable authentication immediately — this service is publicly accessible without credentials")
        if cve_key in ("redis",):
            lines.extend([
                "4. Redis: set 'requirepass <strong-password>' in redis.conf",
                "5. Redis: set 'bind 127.0.0.1' to prevent external access",
                "6. Redis: enable protected-mode (default on Redis 3.2+)",
            ])
        elif cve_key in ("memcached",):
            lines.extend([
                "4. Memcached: use '-l 127.0.0.1' to bind to localhost only",
                "5. Memcached: use SASL authentication if external access is required",
            ])
        elif cve_key in ("elasticsearch",):
            lines.extend([
                "4. Elasticsearch: enable X-Pack security (free tier) for authentication",
                "5. Elasticsearch: set network.host to a private interface, not 0.0.0.0",
            ])
        elif cve_key in ("mongodb",):
            lines.extend([
                "4. MongoDB: enable authentication with --auth flag",
                "5. MongoDB: bind to 127.0.0.1 or private network interface",
            ])
        elif cve_key in ("mysql", "postgresql"):
            lines.extend([
                "4. Grant DB access only to application server IPs via GRANT statements",
                "5. Disable remote root login for the database",
            ])
        lines.append(
            f"\nReference: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        )
        return "\n".join(lines)

    def _get_references(self, port: int, cve_key: Optional[str]) -> List[str]:
        refs = [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://www.cisecurity.org/controls/network-monitoring-and-defense",
        ]
        docs = {
            "redis":         "https://redis.io/docs/management/security/",
            "memcached":     "https://github.com/memcached/memcached/wiki/SecurityRecommendations",
            "elasticsearch": "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
            "mongodb":       "https://www.mongodb.com/docs/manual/administration/security-checklist/",
            "mysql":         "https://dev.mysql.com/doc/refman/8.0/en/security.html",
            "postgresql":    "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
            "openssh":       "https://www.openssh.com/security.html",
            "rabbitmq":      "https://www.rabbitmq.com/access-control.html",
        }
        if cve_key and cve_key in docs:
            refs.append(docs[cve_key])
        return refs
