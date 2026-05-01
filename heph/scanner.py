"""
Hephaestus Scanner with Phase Parallelization

Main orchestrator that coordinates all server security checks.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import time
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests  # For exception handling

from .core.logging import get_logger
from .core.config import get_config
from .core.db import get_db
from .core.report import ReportGenerator
from .core.ai import analyze_report
from .core.diff import compute_diff
from .core.http_client import create_http_client

from .checks.server_info import ServerInfoChecker
from .checks.files import SensitiveFilesChecker
from .checks.http_methods import HTTPMethodsChecker
from .checks.headers import SecurityHeadersChecker
from .checks.config import ConfigChecker
from .checks.tls import TLSChecker
from .checks.ports import PortScanner
from .checks.phpinfo import PhpinfoChecker
from .checks.cookies import CookieSecurityChecker
from .checks.cors import CORSChecker
from .checks.robots import RobotsChecker
from .checks.waf import WAFDetector
from .checks.api_discovery import APIDiscoveryChecker

logger = get_logger(__name__)


class ServerScanner:
    """
    Main server security scanner with phase parallelization.
    Coordinates all check modules and generates reports.
    """
    
    def __init__(self, config=None):
        self.config = config or get_config()
        self.db = get_db()
        self.report_gen = ReportGenerator(self.config)
        
        logger.info("Hephaestus scanner initialized (with phase parallelization)")
    
    def scan(
        self,
        target: str,
        mode: str = 'safe',
        use_ai: bool = False,
        ai_tone: str = 'both',
        ai_compare: Optional[list] = None,
        ai_agent: bool = False,
        diff_ref: Optional[str] = None,
    ) -> Dict:
        """
        Execute full server security scan with parallelized phases.
        
        Args:
            target: Target URL or domain
            mode: 'safe' (non-intrusive) or 'aggressive' (requires consent)
            use_ai: Enable AI analysis
            ai_tone: 'technical', 'non_technical', or 'both'
            ai_compare: List of {provider, model} dicts for multi-LLM compare (IMPROV-007)
            ai_agent: Use agent mode with external tools (IMPROV-008)
            diff_ref: Scan ID or 'last' for diff comparison (IMPROV-004)

        Returns:
            Scan results dictionary with report path
        """
        start_time = time.time()
        
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        domain = urlparse(target).netloc or target
        
        logger.info(f"=" * 70)
        logger.info(f"Starting Hephaestus scan: {target}")
        logger.info(f"Mode: {mode.upper()}")
        logger.info(f"AI Analysis: {'Enabled' if use_ai else 'Disabled'}")
        if ai_compare:
            providers_str = [f"{p['provider']}/{p['model']}" for p in ai_compare]
            logger.info(f"AI Compare Mode: {providers_str}")
        if ai_agent:
            logger.info("AI Agent Mode: Enabled (NVD + server vuln lookup)")
        if diff_ref:
            logger.info(f"Diff comparison: vs {diff_ref}")
        logger.info(f"=" * 70)
        
        # Create HTTP client with rate limiting
        http_client = create_http_client(mode=mode, config=self.config)
        
        # Initialize check modules with HTTP client
        self.server_info = ServerInfoChecker(self.config, http_client)
        self.files = SensitiveFilesChecker(self.config, http_client)
        self.http_methods = HTTPMethodsChecker(self.config, http_client)
        self.headers = SecurityHeadersChecker(self.config, http_client)
        self.directory_listing = ConfigChecker(self.config, http_client)
        self.tls = TLSChecker(self.config, http_client)
        self.ports = PortScanner(self.config)
        # Bloque 2 checkers
        self.phpinfo = PhpinfoChecker(self.config, http_client, mode)
        self.cookies = CookieSecurityChecker(self.config, http_client, mode)
        self.cors = CORSChecker(self.config, http_client, mode)
        self.robots = RobotsChecker(self.config, http_client, mode)
        self.waf = WAFDetector(self.config, http_client, mode)
        self.api = APIDiscoveryChecker(self.config, http_client, mode)
        
        # Verify consent for aggressive/AI modes
        if mode == 'aggressive' or use_ai:
            if not self.db.is_domain_verified(domain):
                logger.error(f"Domain {domain} not verified for {mode} mode")
                raise PermissionError(
                    f"Domain {domain} requires consent verification. "
                    f"Run: heph --gen-consent {domain}"
                )
        
        # Get or create client
        client = self.db.get_client_by_domain(domain)
        client_id = client['client_id'] if client else None
        
        # Start scan record
        scan_id = self.db.start_scan(
            tool='hephaestus',
            domain=domain,
            target_url=target,
            mode=mode,
            client_id=client_id
        )
        
        logger.info(f"Scan ID: {scan_id}")
        
        # Collect all findings
        all_findings = []
        requests_count = 0
        
        try:
            # ============================================================
            # Phase 1: Server Information (MUST RUN FIRST - Connectivity Check)
            # ============================================================
            logger.info("\n[Phase 1/13] Server Information Gathering...")
            
            try:
                server_findings = self.server_info.scan(target)
                all_findings.extend(server_findings)
                requests_count += 3  # Typically 3 requests (GET, HEAD, error page)
            
            except requests.exceptions.RequestException as e:
                # Connection error (timeout, DNS, refused, etc.)
                return self._handle_connection_error(
                    e, target, domain, scan_id, start_time
                )
            
            # ============================================================
            # Phases 2-13: Run in PARALLEL using ThreadPoolExecutor
            # ============================================================
            logger.info("\n[Phases 2-13] Running parallel security checks...")
            logger.info("(Files, Methods, Headers, Config, TLS, Ports, CORS, Robots, WAF, API, Cookies, phpinfo)")
            
            # Run phases in parallel
            parallel_results = self._run_phases_parallel(target)
            
            # Process results
            for phase_name, findings, phase_requests in parallel_results:
                all_findings.extend(findings)
                requests_count += phase_requests
                logger.info(f"✓ {phase_name}: {len(findings)} findings, {phase_requests} requests")
            
            # Finalize scan
            result = self._finalize_scan(
                scan_id, all_findings, start_time, requests_count,
                status='completed', target=target, mode=mode,
                use_ai=use_ai, ai_tone=ai_tone,
                ai_compare=ai_compare, ai_agent=ai_agent,
                diff_ref=diff_ref, domain=domain
            )
            
            logger.info("\n" + "=" * 70)
            logger.info("Scan completed successfully!")
            logger.info(f"Total findings: {result['findings_count']}")
            logger.info(f"Duration: {result['duration']:.2f}s")
            logger.info(f"Report: {result['report_json']}")
            if result.get('report_html'):
                logger.info(f"HTML: {result['report_html']}")
            logger.info("=" * 70 + "\n")
            
            return result
        
        except KeyboardInterrupt:
            # ================================================================
            # Handle Ctrl+C gracefully - Update DB before exit
            # ================================================================
            logger.warning("Scan interrupted by user (KeyboardInterrupt)")
            duration = time.time() - start_time
            
            # Update database: mark scan as 'aborted'
            self.db.finish_scan(
                scan_id,
                status='aborted',
                error_message='Scan interrupted by user (Ctrl+C)'
            )
            
            logger.info(f"Scan {scan_id} marked as 'aborted' in database")
            
            # Note: ThreadPoolExecutor cleanup is handled by 'with' statement
            # The context manager will call executor.shutdown(wait=True)
            # which waits for currently executing tasks to complete
            
            # Re-raise to let cli.py handle exit code 130
            raise
        
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            
            # Mark scan as failed
            self.db.finish_scan(
                scan_id,
                status='failed',
                error_message=str(e)
            )
            
            raise
    
    def _run_phases_parallel(self, target: str) -> List[Tuple[str, List[Dict], int]]:
        """
        Run phases 2-13 in parallel using ThreadPoolExecutor.
        
        Args:
            target: Target URL
        
        Returns:
            List of (phase_name, findings, request_count) tuples
        """
        # Define phases to run in parallel
        phases = [
            ('Phase 2: Files', self._run_files_phase, target),
            ('Phase 3: Methods', self._run_methods_phase, target),
            ('Phase 4: Headers', self._run_headers_phase, target),
            ('Phase 5: Config', self._run_config_phase, target),
            ('Phase 6: TLS', self._run_tls_phase, target),
            ('Phase 8: CORS', self._run_cors_phase, target),
            ('Phase 9: Robots', self._run_robots_phase, target),
            ('Phase 10: WAF', self._run_waf_phase, target),
            ('Phase 11: API', self._run_api_phase, target),
            ('Phase 12: Cookies', self._run_cookies_phase, target),
            ('Phase 13: phpinfo', self._run_phpinfo_phase, target),
        ]

        # Add port scan phase if enabled
        if getattr(self.config, 'port_scan_enabled', True):
            phases.append(('Phase 7: Ports', self._run_ports_phase, target))

        results = []

        # Use ThreadPoolExecutor to run phases in parallel
        # Max workers = min(number of phases, config.max_workers)
        max_workers = min(len(phases), self.config.max_workers)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all phases
            future_to_phase = {
                executor.submit(phase_func, target_url): (phase_name, phase_func)
                for phase_name, phase_func, target_url in phases
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_phase):
                phase_name, phase_func = future_to_phase[future]
                
                try:
                    phase_findings, phase_requests = future.result()
                    results.append((phase_name, phase_findings, phase_requests))
                    
                except Exception as e:
                    logger.error(f"{phase_name} failed: {e}")
                    # Don't fail entire scan if one phase fails
                    results.append((phase_name, [], 0))
        
        return results
    
    def _run_files_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 2: Sensitive Files Detection"""
        logger.debug("Running files phase...")
        findings = self.files.scan(target)
        requests = len(self.config.server_common_paths)
        return findings, requests
    
    def _run_methods_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 3: HTTP Methods Testing"""
        logger.debug("Running methods phase...")
        findings = self.http_methods.scan(target)
        requests = len(self.config.http_methods_to_test)
        return findings, requests
    
    def _run_headers_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 4: Security Headers Analysis"""
        logger.debug("Running headers phase...")
        findings = self.headers.scan(target)
        requests = 2  # GET + HEAD
        return findings, requests
    
    def _run_config_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 5: Directory Listing Check"""
        logger.debug("Running config phase...")
        findings = self.directory_listing.scan(target)
        requests = min(
            len(self.config.directory_paths_to_check),
            self.config.max_directory_checks
        )
        return findings, requests
    
    def _run_ports_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 7: Port Scanning & Backend Service Detection"""
        logger.debug("Running port scan phase...")
        findings = self.ports.scan(target)
        return findings, len(getattr(self.config, 'port_scan_ports', []))

    def _run_tls_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 6: TLS/SSL Configuration"""
        logger.debug("Running TLS phase...")
        
        if target.startswith('https://'):
            findings = self.tls.scan(target)
            requests = 1  # SSL handshake
        else:
            logger.debug("Skipping TLS checks (target is HTTP)")
            findings = [{
                'id': 'HEPH-TLS-000',
                'title': 'TLS not enabled',
                'severity': 'high',
                'confidence': 'high',
                'description': 'Target is using unencrypted HTTP protocol. All traffic is transmitted in plaintext.',
                'evidence': {
                    'type': 'url',
                    'value': target,
                    'context': 'HTTP protocol detected'
                },
                'recommendation': 'Enable HTTPS with valid TLS certificate. Use Let\'s Encrypt for free certificates.',
                'references': [
                    'https://letsencrypt.org/',
                    'https://www.ssllabs.com/ssltest/'
                ]
            }]
            requests = 0
        
        return findings, requests
    
    def _run_cors_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 8: CORS Misconfiguration"""
        logger.debug("Running CORS phase...")
        findings = self.cors.scan(target)
        return findings, 4

    def _run_robots_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 9: Robots.txt Analysis"""
        logger.debug("Running robots phase...")
        findings = self.robots.scan(target)
        return findings, 1

    def _run_waf_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 10: WAF Detection"""
        logger.debug("Running WAF detection phase...")
        findings = self.waf.scan(target)
        return findings, 2

    def _run_api_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 11: API Discovery"""
        logger.debug("Running API discovery phase...")
        findings = self.api.scan(target)
        return findings, len(findings) + 5

    def _run_cookies_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 12: Cookie Security (multi-endpoint)"""
        logger.debug("Running cookie security phase...")
        findings = self.cookies.scan(target)
        return findings, 7

    def _run_phpinfo_phase(self, target: str) -> Tuple[List[Dict], int]:
        """Phase 13: phpinfo() Deep Analysis"""
        logger.debug("Running phpinfo phase...")
        findings = self.phpinfo.scan(target)
        return findings, 4

    def _handle_connection_error(
        self,
        error: requests.exceptions.RequestException,
        target: str,
        domain: str,
        scan_id: int,
        start_time: float
    ) -> Dict:
        """
        Handle connection errors in Phase 1 (fail-fast).
        
        Args:
            error: The exception that occurred
            target: Target URL
            domain: Target domain
            scan_id: Scan ID
            start_time: Scan start time
        
        Returns:
            Failure result dictionary
        """
        error_msg = str(error)
        logger.error(f"Connection failed: {error_msg}")
        
        # Determine error type for user-friendly message
        if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
            error_type = "Connection timeout"
            user_msg = f"Target {target} did not respond within timeout period"
        elif "name resolution" in error_msg.lower() or "nameresolutionerror" in error_msg.lower():
            error_type = "DNS resolution failed"
            user_msg = f"Could not resolve domain name: {domain}"
        elif "connection refused" in error_msg.lower():
            error_type = "Connection refused"
            user_msg = f"Target {target} refused connection (port may be closed)"
        elif "no route to host" in error_msg.lower():
            error_type = "Network unreachable"
            user_msg = f"Cannot reach {target} (network issue)"
        else:
            error_type = "Connection error"
            user_msg = f"Failed to connect to {target}"
        
        # Mark scan as failed in database
        self.db.finish_scan(
            scan_id,
            status='failed',
            error_message=f"{error_type}: {error_msg}"
        )
        
        # Print clear error message
        print("\n" + "=" * 70)
        print(f"✖ SCAN FAILED: {error_type}")
        print("=" * 70)
        print(f"Target: {target}")
        print(f"Error: {user_msg}")
        print(f"\nDetails: {error_msg}")
        print("\nPossible causes:")
        if error_type == "Connection timeout":
            print("  - Server is slow or unresponsive")
            print("  - Firewall blocking requests")
            print("  - Try increasing timeout: --timeout 60")
        elif error_type == "DNS resolution failed":
            print("  - Domain does not exist")
            print("  - DNS server issue")
            print("  - Check domain spelling")
        elif error_type == "Connection refused":
            print("  - Web server not running on target port")
            print("  - Firewall blocking connections")
            print("  - Wrong port number")
        elif error_type == "Network unreachable":
            print("  - Target IP address unreachable")
            print("  - Network connectivity issue")
            print("  - VPN or routing problem")
        else:
            print("  - Check network connectivity")
            print("  - Verify target URL is correct")
            print("  - Check firewall settings")
        print("=" * 70 + "\n")
        
        # Return failure result
        duration = time.time() - start_time
        return {
            'scan_id': scan_id,
            'status': 'failed',
            'error': error_type,
            'error_message': error_msg,
            'duration': duration
        }
    
    def _finalize_scan(
        self,
        scan_id: int,
        findings: List[Dict],
        start_time: float,
        requests_count: int,
        status: str,
        target: str,
        mode: str,
        use_ai: bool = False,
        ai_tone: Optional[str] = None,
        ai_compare: Optional[list] = None,
        ai_agent: bool = False,
        diff_ref: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> Dict:
        """
        Generate reports, save to DB, and optionally run AI analysis.
        
        Args:
            scan_id: Database scan ID
            findings: List of all findings
            start_time: Scan start timestamp
            requests_count: Total HTTP requests made
            status: 'completed' or 'failed'
            target: Target URL
            mode: Scan mode
            use_ai: Whether to run AI analysis
            ai_tone: AI tone (technical/non_technical/both)
            ai_compare: Multi-LLM compare providers list
            ai_agent: Use agent mode
            diff_ref: Diff reference scan ID or 'last'
            domain: Target domain (pre-parsed)

        Returns:
            Result summary dictionary
        """
        duration = time.time() - start_time

        # Get consent info if available
        if not domain:
            domain = urlparse(target).netloc
        consent_info = None
        
        if mode == 'aggressive' or use_ai:
            verified_tokens = self.db.get_verified_tokens(domain)
            if verified_tokens:
                latest = verified_tokens[0]
                consent_info = {
                    'method': latest['method'],
                    'token': latest['token'],
                    'verified_at': latest['verified_at']
                }
        
        # Create report (diff and ai_analysis will be added after)
        report = self.report_gen.create_report(
            tool='hephaestus',
            target=target,
            mode=mode,
            findings=findings,
            scan_duration=duration,
            requests_sent=requests_count,
            consent=consent_info
        )

        # Save findings to database FIRST — required before compute_diff() queries them
        for finding in findings:
            self.db.add_finding(
                scan_id=scan_id,
                finding_code=finding['id'],
                title=finding['title'],
                severity=finding['severity'],
                confidence=finding['confidence'],
                recommendation=finding['recommendation'],
                evidence_type=finding.get('evidence', {}).get('type'),
                evidence_value=finding.get('evidence', {}).get('value'),
                references=finding.get('references')
            )

        # Compute diff if requested (findings already in DB at this point)
        if diff_ref:
            logger.info(f"\n[Diff] Comparing vs {diff_ref}...")
            try:
                diff_result = compute_diff(self.db, scan_id, diff_ref, domain)
                if diff_result:
                    report['diff'] = diff_result
                    logger.info(
                        f"✓ Diff computed: {len(diff_result.get('new', []))} new, "
                        f"{len(diff_result.get('fixed', []))} fixed, "
                        f"{len(diff_result.get('persisting', []))} persisting"
                    )
                else:
                    logger.warning("Diff skipped (no reference scan found)")
            except Exception as e:
                logger.error(f"Diff computation failed: {e}")

        # Run AI analysis if enabled (BEFORE saving reports)
        if use_ai:
            logger.info("\n[AI Analysis] Generating insights...")
            try:
                ai_analysis = analyze_report(
                    report,
                    tone=ai_tone,
                    config=self.config,
                    scan_id=scan_id,
                    compare_providers=ai_compare,
                    use_agent=ai_agent,
                )

                if ai_analysis:
                    report['ai_analysis'] = ai_analysis
                    logger.info("✓ AI analysis completed")

            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
        
        # Save JSON report ONCE (with or without AI)
        json_path = self.report_gen.save_json(report)
        
        # Generate HTML ONCE (with or without AI)
        html_path = None
        if self.config.generate_html:
            try:
                html_path = self.report_gen.generate_html(report, json_path)
            except Exception as e:
                logger.warning(f"HTML generation failed: {e}")
        
        # Get summary from report
        summary = report['summary']
        
        # Finish scan in database
        self.db.finish_scan(
            scan_id,
            status=status,
            report_json_path=str(json_path),
            report_html_path=str(html_path) if html_path else None,
            summary=summary
        )
        
        return {
            'scan_id': scan_id,
            'status': status,
            'findings_count': len(findings),
            'summary': summary,
            'duration': duration,
            'requests_sent': requests_count,
            'report_json': str(json_path),
            'report_html': str(html_path) if html_path else None,
            'ai_analysis': bool(report.get('ai_analysis'))
        }


if __name__ == "__main__":
    # Test scanner
    from .core.config import Config
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m heph.scanner <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    config = Config.load()
    config.expand_paths()
    config.ensure_directories()
    
    scanner = ServerScanner(config)
    
    try:
        result = scanner.scan(target, mode='safe', use_ai=False)
        print(f"\nScan completed: {result['report_json']}")
    
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)