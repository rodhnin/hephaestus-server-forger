"""
Sensitive Files Exposure Check

Enhanced detection based on validation lab analysis.
Added detection for:
- diagnostic.php, system-check.php
- /admin/diagnostics, /nginx_status
- SQL backups with date patterns
- Config backups (.old, .save, .bak)
- Rotated log files

Detects publicly accessible sensitive files that should not be exposed.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class SensitiveFilesChecker:
    """
    Detects sensitive files exposed on web server.
    """
    
    # Severity mapping for file types
    SEVERITY_MAP = {
        '.env': 'critical',
        '.git': 'critical',
        'phpinfo': 'critical',
        'diagnostic.php': 'critical',
        'system-check.php': 'critical',
        'debug.php': 'critical',
        'server-status': 'critical',
        'nginx_status': 'critical',
        'admin/diagnostics': 'critical',
        '.sql': 'critical',
        '_backup_': 'critical',
        '_dump_': 'critical',
        'postgres_dump': 'critical',
        'mysql_dump': 'critical',
        '.bak': 'high',
        '.old': 'high',
        '.save': 'high',
        '.zip': 'high',
        '.log': 'medium',
        'access.log.old': 'medium',
        '.htaccess': 'medium',
        '.htpasswd': 'critical',
        'composer.json': 'low',
        'package.json': 'low',
    }
    
    # Patterns to sanitize from evidence (passwords, keys)
    SANITIZE_PATTERNS = [
        (re.compile(r'(DB_PASSWORD\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(DATABASE_URL\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(PASSWORD\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(API_KEY\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(SECRET\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(TOKEN\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(AWS_ACCESS_KEY\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(AWS_SECRET\s*=\s*)[^\n]+', re.IGNORECASE), r'\1[REDACTED]'),
    ]
    
    def __init__(self, config=None, http_client=None, target=None):
        self.config = config or get_config()
        self.http_client = http_client
        self.target = target
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan target for sensitive file exposure.
        
        Args:
            target: Target URL (e.g., https://example.com)
        
        Returns:
            List of findings
        
        Raises:
            requests.exceptions.RequestException: If connection fails critically
        """
        findings = []
        
        logger.info(f"Checking sensitive files exposure: {target}")
        
        # Get file list from config
        file_paths = self.config.server_common_paths
        
        # Track connection errors to detect if target is unreachable
        connection_errors = []
        successful_requests = 0
        total_requests = 0
        
        # Use thread pool for concurrent checking (like Argus)
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(self._check_file, target, path): path
                for path in file_paths
            }
            
            for future in as_completed(futures):
                path = futures[future]
                total_requests += 1
                
                try:
                    result = future.result()
                    successful_requests += 1
                    
                    if result:
                        findings.append(result)
                
                except requests.exceptions.ConnectionError as e:
                    connection_errors.append((path, e))
                    logger.debug(f"Connection error checking {path}: {e}")
                
                except requests.exceptions.Timeout as e:
                    connection_errors.append((path, e))
                    logger.debug(f"Timeout checking {path}: {e}")
                
                except requests.exceptions.RequestException as e:
                    connection_errors.append((path, e))
                    logger.debug(f"Request error checking {path}: {e}")
                
                except Exception as e:
                    logger.debug(f"Error checking {path}: {e}")
        
        # CRITICAL: If ALL requests failed due to connection errors, propagate
        if connection_errors and successful_requests == 0:
            first_error = connection_errors[0][1]
            logger.error(f"All file checks failed due to connection errors ({len(connection_errors)}/{total_requests})")
            raise first_error
        
        # If MOST requests failed (>80%) but not all, still warn
        elif connection_errors and (len(connection_errors) / total_requests) > 0.8:
            logger.warning(
                f"Most file checks failed ({len(connection_errors)}/{total_requests}) - "
                f"possible connection issues, but continuing with {successful_requests} successful checks"
            )
        
        logger.info(f"Found {len(findings)} sensitive files exposed")
        return findings
    
    def _check_file(self, target: str, path: str) -> Optional[Dict[str, Any]]:
        """
        Check if a specific file is accessible.
        
        Args:
            target: Base target URL
            path: File path to check (e.g., /.env)
        
        Returns:
            Finding dict if file is accessible, None otherwise
        
        Raises:
            requests.exceptions.RequestException: For connection issues
        """
        url = urljoin(target, path)
        
        # Let exceptions propagate - they'll be caught by the executor
        response = self.http_client.get(
            url,
            timeout=(self.config.timeout_connect, self.config.timeout_read),
            allow_redirects=False
        )
        
        # File is accessible
        if response.status_code == 200:
            return self._create_finding_for_file(path, url, response)
        
        # File exists but forbidden (still a finding, lower severity)
        elif response.status_code == 403:
            return self._create_forbidden_finding(path, url)
        
        # Other status codes (404, etc.) - file not accessible
        return None
    
    def _create_finding_for_file(
        self,
        path: str,
        url: str,
        response: requests.Response
    ) -> Dict[str, Any]:
        """Create detailed finding for accessible file."""
        
        # Determine file type and severity
        severity = self._get_severity(path)
        file_size = len(response.content)
        
        # Sanitize evidence (remove passwords, keys)
        evidence_preview = response.text[:500] if response.text else "[binary content]"
        evidence_preview = self._sanitize_evidence(evidence_preview)
        
        # ═══════════════════════════════════════════════════════════════
        # ENVIRONMENT FILES
        # ═══════════════════════════════════════════════════════════════
        if '.env' in path:
            # Check if .env.example has real secrets (common mistake)
            has_real_secrets = False
            if '.env.example' in path:
                secret_patterns = ['password', 'api_key', 'secret', 'token', 'aws_']
                has_real_secrets = any(pattern in response.text.lower() for pattern in secret_patterns)
            
            return {
                'id': 'HEPH-FILE-001',
                'title': 'Environment file exposed (.env)',
                'severity': 'critical' if not '.example' in path or has_real_secrets else 'high',
                'confidence': 'high',
                'description': (
                    f"Environment configuration file accessible at {url}. "
                    f"This file commonly contains: database passwords, API keys, "
                    f"secret tokens, AWS credentials, and other sensitive data. "
                    f"{'NOTE: .env.example files often contain real secrets used as examples!' if '.example' in path else ''}"
                ),
                'evidence': {
                    'type': 'content_preview',
                    'value': evidence_preview,
                    'context': f"HTTP 200, Size: {file_size} bytes"
                },
                'recommendation': (
                    "CRITICAL - Immediate action required:\n"
                    "1. Delete .env file from web root: sudo rm /var/www/html/.env\n"
                    "2. Block .env files via web server config:\n"
                    "   Apache: <FilesMatch \"\\.env\"> Require all denied </FilesMatch>\n"
                    "   Nginx: location ~ /\\.env { deny all; }\n"
                    "3. Rotate ALL credentials found in the file\n"
                    "4. Review git history for .env files (git filter-branch if found)\n"
                    "5. Add .env to .gitignore"
                ),
                'references': [
                    'https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
                ],
                'affected_component': path
            }
        
        # ═══════════════════════════════════════════════════════════════
        # GIT REPOSITORY
        # ═══════════════════════════════════════════════════════════════
        elif '.git' in path:
            return {
                'id': 'HEPH-FILE-002',
                'title': 'Git repository exposed',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    f"Git repository directory is accessible at {url}. "
                    f"Attackers can download the entire source code, commit history, "
                    f"and potentially find credentials in git history."
                ),
                'evidence': {
                    'type': 'url',
                    'value': url,
                    'context': f"HTTP 200, Git repository accessible"
                },
                'recommendation': (
                    "CRITICAL - Immediate action required:\n"
                    "1. Remove .git directory from web root: sudo rm -rf /var/www/html/.git\n"
                    "2. Block .git via web server config:\n"
                    "   Apache: <DirectoryMatch \"\\.git\"> Require all denied </DirectoryMatch>\n"
                    "   Nginx: location ~ /\\.git { deny all; }\n"
                    "3. Review git history for leaked credentials\n"
                    "4. Rotate any credentials found in git history"
                ),
                'references': [
                    'https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/about-coordinated-disclosure-of-security-vulnerabilities',
                ],
                'affected_component': '.git/'
            }
        
        # ═══════════════════════════════════════════════════════════════
        # PHP INFO FILES
        # ═══════════════════════════════════════════════════════════════
        elif any(php_file in path.lower() for php_file in [
            'phpinfo', 'info.php', 'diagnostic.php', 'system-check.php', 'debug.php'
        ]):
            return {
                'id': 'HEPH-FILE-003',
                'title': 'PHP information page exposed',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    f"PHP information disclosure page accessible at {url}. "
                    f"phpinfo() reveals extensive server configuration including: "
                    f"PHP version, loaded extensions, file paths, environment variables, "
                    f"and potentially database credentials. "
                    f"File: {path}"
                ),
                'evidence': {
                    'type': 'url',
                    'value': url,
                    'context': f"HTTP 200, phpinfo() output detected in {path}"
                },
                'recommendation': (
                    "CRITICAL - Immediate action:\n"
                    f"1. Delete file immediately: sudo rm /var/www/html{path}\n"
                    "2. Search for ALL phpinfo files:\n"
                    "   find /var/www -name \"*info.php\" -o -name \"*diagnostic*.php\" -o -name \"*check*.php\" -o -name \"*debug*.php\"\n"
                    "3. Remove all test/debug files from production\n"
                    "4. Review access logs to see if file was accessed:\n"
                    f"   grep \"{path}\" /var/log/apache2/access.log"
                ),
                'references': [
                    'https://www.php.net/manual/en/function.phpinfo.php',
                    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework',
                ],
                'affected_component': path
            }
        
        # ═══════════════════════════════════════════════════════════════
        # SERVER STATUS PAGES
        # ═══════════════════════════════════════════════════════════════
        elif any(status_path in path for status_path in [
            'server-status', 'server-info', '/status', 
            'admin/diagnostics', 'nginx_status', 'nginx-status'
        ]):
            server_type = "Nginx" if "nginx" in path.lower() else "Apache"
            
            return {
                'id': 'HEPH-FILE-004',
                'title': f'{server_type} server status page exposed',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    f"{server_type} server status page is publicly accessible at {url}. "
                    f"This reveals active connections, virtual hosts, request details, "
                    f"server metrics, and potentially sensitive URLs with query parameters. "
                    f"{'NOTE: This endpoint is obfuscated but still accessible!' if 'admin/diagnostics' in path else ''}"
                ),
                'evidence': {
                    'type': 'url',
                    'value': url,
                    'context': f"HTTP 200, {server_type} status page accessible"
                },
                'recommendation': (
                    "CRITICAL - Restrict access immediately:\n"
                    f"Apache:\n"
                    f"  Edit /etc/apache2/mods-available/status.conf:\n"
                    f"  <Location \"{path}\">\n"
                    f"    SetHandler server-status\n"
                    f"    Require ip 127.0.0.1\n"
                    f"  </Location>\n"
                    f"\n"
                    f"Nginx:\n"
                    f"  Edit nginx.conf:\n"
                    f"  location {path} {{\n"
                    f"    stub_status on;\n"
                    f"    allow 127.0.0.1;\n"
                    f"    deny all;\n"
                    f"  }}\n"
                    f"\n"
                    f"Restart web server: sudo systemctl restart {server_type.lower()}"
                ),
                'references': [
                    'https://httpd.apache.org/docs/2.4/mod/mod_status.html',
                    'https://nginx.org/en/docs/http/ngx_http_stub_status_module.html',
                ],
                'affected_component': path
            }
        
        # ═══════════════════════════════════════════════════════════════
        # SQL BACKUP FILES
        # ═══════════════════════════════════════════════════════════════
        elif '.sql' in path or self._is_sql_backup(path):
            # Check if it's a dated backup
            is_dated_backup = bool(re.search(r'(_backup_|_dump_)\d{4}(_\d{2}){2,3}', path))
            
            return {
                'id': 'HEPH-FILE-005',
                'title': 'Database backup exposed',
                'severity': 'critical',
                'confidence': 'high',
                'description': (
                    f"Database backup file accessible at {url}. "
                    f"This file likely contains complete database dumps with all data. "
                    f"{'NOTE: Dated backup detected - systematic backup process exposed!' if is_dated_backup else ''}"
                ),
                'evidence': {
                    'type': 'url',
                    'value': url,
                    'context': f"HTTP 200, Size: {file_size} bytes, File: {path}"
                },
                'recommendation': (
                    "CRITICAL - Remove immediately:\n"
                    f"1. Delete SQL file: sudo rm /var/www/html{path}\n"
                    "2. Find ALL SQL backups in web root:\n"
                    "   find /var/www/html -name \"*.sql\" -type f\n"
                    "3. Store backups outside web root (e.g., /var/backups/)\n"
                    "4. Encrypt backups with GPG:\n"
                    "   gpg --symmetric --cipher-algo AES256 backup.sql\n"
                    "5. Review access logs for downloads:\n"
                    f"   grep \"{path}\" /var/log/*/access.log"
                ),
                'references': [
                    'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html',
                ],
                'affected_component': path
            }
        
        # ═══════════════════════════════════════════════════════════════
        # CONFIG BACKUP FILES
        # ═══════════════════════════════════════════════════════════════
        elif self._is_config_backup(path):
            return {
                'id': 'HEPH-FILE-006',
                'title': 'Configuration backup file exposed',
                'severity': 'high',
                'confidence': 'high',
                'description': (
                    f"Configuration backup file accessible at {url}. "
                    f"Backup files with extensions like .old, .save, .bak often contain "
                    f"sensitive configuration data including database credentials, API keys, "
                    f"and system paths. These are commonly left behind during deployments."
                ),
                'evidence': {
                    'type': 'content_preview',
                    'value': evidence_preview,
                    'context': f"HTTP 200, Size: {file_size} bytes"
                },
                'recommendation': (
                    "HIGH PRIORITY - Remove backup files:\n"
                    f"1. Delete backup file: sudo rm /var/www/html{path}\n"
                    "2. Find ALL config backups:\n"
                    "   find /var/www/html -name \"*.old\" -o -name \"*.save\" -o -name \"*.bak\"\n"
                    "3. Configure deployment to exclude backup files:\n"
                    "   rsync --exclude='*.old' --exclude='*.bak' --exclude='*.save'\n"
                    "4. Add to .gitignore: *.old, *.bak, *.save\n"
                    "5. Review file content for exposed credentials and rotate them"
                ),
                'references': [
                    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
                ],
                'affected_component': path
            }
        
        # ═══════════════════════════════════════════════════════════════
        # LOG FILES
        # ═══════════════════════════════════════════════════════════════
        elif '.log' in path or path.endswith(('.log.old', '.log.1', '.log.2')):
            return {
                'id': 'HEPH-FILE-007',
                'title': 'Log file exposed',
                'severity': 'medium',
                'confidence': 'high',
                'description': (
                    f"Log file accessible at {url}. "
                    f"Log files may contain sensitive information such as: "
                    f"session IDs, user authentication attempts, API keys in URLs, "
                    f"internal IP addresses, file paths, and error messages revealing "
                    f"system configuration."
                ),
                'evidence': {
                    'type': 'content_preview',
                    'value': evidence_preview[:200],  # Shorter preview for logs
                    'context': f"HTTP 200, Size: {file_size} bytes"
                },
                'recommendation': (
                    "MEDIUM PRIORITY - Restrict log access:\n"
                    f"1. Move log files outside web root: sudo mv /var/www/html{path} /var/log/\n"
                    "2. Block all .log files via web server config:\n"
                    "   Apache: <FilesMatch \"\\.log$\"> Require all denied </FilesMatch>\n"
                    "   Nginx: location ~ \\.log$ { deny all; }\n"
                    "3. Review log content for sensitive data\n"
                    "4. Configure log rotation properly (logrotate)\n"
                    "5. Ensure logs don't contain sensitive data (passwords, tokens)"
                ),
                'references': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
                ],
                'affected_component': path
            }
        
        # ═══════════════════════════════════════════════════════════════
        # GENERIC SENSITIVE FILE
        # ═══════════════════════════════════════════════════════════════
        else:
            return {
                'id': 'HEPH-FILE-999',
                'title': f'Sensitive file exposed: {path}',
                'severity': severity,
                'confidence': 'high',
                'description': (
                    f"File '{path}' is publicly accessible at {url}. "
                    f"This file should not be accessible from the web."
                ),
                'evidence': {
                    'type': 'url',
                    'value': url,
                    'context': f"HTTP 200, Size: {file_size} bytes"
                },
                'recommendation': (
                    f"Remove or restrict access to {path}:\n"
                    f"1. Delete if not needed\n"
                    f"2. Move outside web root\n"
                    f"3. Block via .htaccess or Nginx config"
                ),
                'affected_component': path
            }
    
    def _create_forbidden_finding(self, path: str, url: str) -> Dict[str, Any]:
        """Create finding for 403 Forbidden (file exists but blocked)."""
        return {
            'id': 'HEPH-FILE-403',
            'title': f'Sensitive file exists but access denied: {path}',
            'severity': 'low',
            'confidence': 'medium',
            'description': (
                f"File '{path}' exists (HTTP 403) but is currently blocked. "
                f"This is good, but the file should be removed entirely."
            ),
            'evidence': {
                'type': 'url',
                'value': url,
                'context': "HTTP 403 Forbidden"
            },
            'recommendation': (
                f"Consider removing {path} entirely if not needed:\n"
                f"- Files blocked by web server could still be accessible via other means\n"
                f"- Best practice: delete sensitive files from web root"
            ),
            'affected_component': path
        }
    
    def _get_severity(self, path: str) -> str:
        """Determine severity based on file type."""
        for pattern, severity in self.SEVERITY_MAP.items():
            if pattern in path:
                return severity
        return 'medium'  # Default
    
    def _sanitize_evidence(self, text: str) -> str:
        """Remove sensitive data from evidence."""
        for pattern, replacement in self.SANITIZE_PATTERNS:
            text = pattern.sub(replacement, text)
        return text
    
    def _is_sql_backup(self, path: str) -> bool:
        """Check if file matches SQL backup patterns."""
        sql_patterns = [
            r'.*backup.*\.sql$',
            r'.*dump.*\.sql$',
            r'.*_backup_\d{4}_\d{2}_\d{2}\.sql$',  # YYYY_MM_DD
            r'.*_dump_\d{8}\.sql$',                # YYYYMMDD
            r'postgres_dump.*\.sql$',
            r'mysql_dump.*\.sql$',
        ]
        return any(re.match(pattern, path, re.IGNORECASE) for pattern in sql_patterns)
    
    def _is_config_backup(self, path: str) -> bool:
        """Check if file is a configuration backup (.old, .save, .bak)."""
        config_patterns = [
            r'config\.(php|yml|json|xml)\.(old|save|bak|backup)$',
            r'settings\.(php|yml|json|xml)\.(old|save|bak|backup)$',
            r'database\.(php|yml|json|xml)\.(old|save|bak|backup)$',
            r'app\.config\.json\.bak$',
        ]
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in config_patterns)


if __name__ == "__main__":
    # Test the checker
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    config.expand_paths()
    
    http_client = create_http_client(mode='safe', config=config)
    checker = SensitiveFilesChecker(config, http_client, target="https://example.com")
    
    findings = checker.scan("https://example.com")
    
    print(f"Found {len(findings)} sensitive files:")
    for finding in findings:
        print(f"  [{finding['severity'].upper()}] {finding['title']}")