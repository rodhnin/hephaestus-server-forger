"""
Hephaestus Configuration Checker

Detects directory listing and configuration issues:
- Apache/Nginx directory indexing enabled
- Publicly accessible configuration directories
- File permissions issues (where detectable)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import re
from typing import List, Dict, Any
from urllib.parse import urljoin
import requests

from ..core.logging import get_logger
from ..core.config import get_config

logger = get_logger(__name__)


class ConfigChecker:
    """
    Checks for configuration issues and directory listing.
    """
    
    def __init__(self, config=None, http_client=None):
        self.config = config or get_config()
        self.http_client = http_client
        
        # Patterns to detect directory listing
        self.listing_patterns = [
            # Apache
            r'<title>Index of /',
            r'<h1>Index of /',
            r'Parent Directory',
            r'<a href="\.\."',
            
            # Nginx
            r'<title>Index of ',
            r'<h1>Directory listing for ',
            r'nginx/',
            
            # Generic
            r'<pre>',  # Common in basic directory listings
            r'\[To Parent Directory\]',
        ]
        
        # Compile patterns
        self.listing_regex = [re.compile(p, re.IGNORECASE) for p in self.listing_patterns]
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Execute configuration checks.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        
        Raises:
            requests.exceptions.RequestException: If connection fails critically
        """
        findings = []
        
        # Check directory listing
        findings.extend(self._check_directory_listing(target))
        
        return findings
    
    def _check_directory_listing(self, target: str) -> List[Dict[str, Any]]:
        """
        Check for directory listing on common paths.
        
        Args:
            target: Target URL
        
        Returns:
            List of findings
        
        Raises:
            requests.exceptions.RequestException: If first request fails with connection error
        """
        findings = []
        
        paths_to_check = self.config.directory_paths_to_check[:self.config.max_directory_checks]
        
        logger.info(f"Checking {len(paths_to_check)} directories for listing...")
        
        # Track connection errors to detect if target is unreachable
        connection_errors = 0
        successful_requests = 0
        first_request = True
        
        for path in paths_to_check:
            try:
                url = urljoin(target, path)
                
                # GET request with timeout
                response = self.http_client.get(
                    url,
                    allow_redirects=True,
                    timeout=(self.config.timeout_connect, self.config.timeout_read)
                )
                
                # Mark successful request
                successful_requests += 1
                first_request = False
                
                # Only interested in 200 OK responses
                if response.status_code != 200:
                    logger.debug(f"Directory {path}: HTTP {response.status_code}")
                    continue
                
                # Check if response looks like directory listing
                html = response.text
                
                # Check for directory listing patterns
                is_listing = any(pattern.search(html) for pattern in self.listing_regex)
                
                if not is_listing:
                    # Additional heuristic: check for multiple <a href="..."> links
                    # that don't look like navigation (suggest file listing)
                    link_pattern = re.compile(r'<a\s+href="([^"]+)"', re.IGNORECASE)
                    links = link_pattern.findall(html)
                    
                    # Filter out navigation links (parent dir, etc.)
                    file_links = [
                        link for link in links 
                        if not link.startswith(('http://', 'https://', '#', 'javascript:', '..'))
                        and not link in ('/', '/index.html', '/index.php')
                    ]
                    
                    # If we have 3+ file-like links and <pre> tag, likely a listing
                    if len(file_links) >= 3 and '<pre>' in html.lower():
                        is_listing = True
                
                if is_listing:
                    # Count items if possible
                    item_count = self._count_directory_items(html)
                    
                    context = f"HTTP 200, directory listing detected"
                    if item_count > 0:
                        context += f", {item_count} items listed"
                    
                    finding = {
                        'id': 'HEPH-CFG-001',
                        'title': f'Directory listing enabled: {path}',
                        'severity': 'medium',
                        'confidence': 'high',
                        'description': (
                            f"Directory listing is enabled for {path}, allowing attackers to "
                            f"browse and download files. This exposes file structure and may reveal "
                            f"sensitive files, backup files, or configuration files."
                        ),
                        'evidence': {
                            'type': 'url',
                            'value': url,
                            'context': context
                        },
                        'recommendation': (
                            f"Disable directory listing for {path}:\n"
                            f"Apache: Add 'Options -Indexes' to .htaccess or <Directory> directive\n"
                            f"Nginx: Set 'autoindex off;' in location block\n"
                            f"Alternative: Add blank index.html files to directories"
                        ),
                        'references': [
                            'https://httpd.apache.org/docs/2.4/mod/core.html#options',
                            'https://nginx.org/en/docs/http/ngx_http_autoindex_module.html',
                        ],
                        'affected_component': path
                    }
                    
                    findings.append(finding)
                    logger.warning(f"Directory listing found: {url}")
                
                else:
                    logger.debug(f"Directory {path}: No listing detected")
            
            except requests.exceptions.ConnectionError as e:
                connection_errors += 1
                
                # If this is the FIRST request and it fails, propagate immediately
                if first_request:
                    logger.error(f"First directory check failed with connection error: {e}")
                    raise  # Propagate to scanner for fail-fast
                
                # Otherwise, log and continue (might be 404 or specific path issue)
                logger.debug(f"Directory {path}: Connection error - {e}")
                continue
            
            except requests.exceptions.Timeout as e:
                connection_errors += 1
                
                # If this is the FIRST request and it fails, propagate immediately
                if first_request:
                    logger.error(f"First directory check timed out: {e}")
                    raise  # Propagate to scanner for fail-fast
                
                logger.debug(f"Directory {path}: Timeout")
                continue
            
            except requests.exceptions.RequestException as e:
                connection_errors += 1
                
                # If this is the FIRST request and it fails, propagate immediately
                if first_request:
                    logger.error(f"First directory check failed: {e}")
                    raise  # Propagate to scanner for fail-fast
                
                logger.debug(f"Directory {path}: Request failed - {e}")
                continue
            
            except Exception as e:
                # Unexpected errors - log but continue
                logger.error(f"Unexpected error checking {path}: {e}")
                continue
        
        # If ALL requests failed (and we got past the first request check), warn
        if successful_requests == 0 and connection_errors > 0:
            logger.warning(
                f"All directory checks failed ({connection_errors}/{len(paths_to_check)}) - "
                f"possible connection issues"
            )
        
        if not findings:
            logger.info("No directory listing issues found")
        else:
            logger.info(f"Found {len(findings)} directory listing issue(s)")
        
        return findings
    
    def _count_directory_items(self, html: str) -> int:
        """
        Attempt to count items in directory listing.
        
        Args:
            html: HTML response
        
        Returns:
            Number of items (0 if unable to count)
        """
        try:
            # Look for <a href="..."> links that look like files/directories
            link_pattern = re.compile(r'<a\s+href="([^"]+)"', re.IGNORECASE)
            links = link_pattern.findall(html)
            
            # Filter out parent directory and navigation
            file_links = [
                link for link in links 
                if not link.startswith(('http://', 'https://', '#', 'javascript:'))
                and link not in ('/', '..')
            ]
            
            return len(file_links)
        
        except Exception as e:
            logger.debug(f"Failed to count directory items: {e}")
            return 0


if __name__ == "__main__":
    # Test config checker
    from ..core.config import Config
    from ..core.http_client import create_http_client
    
    config = Config.load()
    config.expand_paths()
    
    http_client = create_http_client(mode='safe', config=config)
    checker = ConfigChecker(config, http_client)
    
    # Test against a target
    target = "https://example.com"
    findings = checker.scan(target)
    
    print(f"\nConfig Check Results for {target}:")
    print(f"Found {len(findings)} issue(s)\n")
    
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['title']}")
        print(f"  Evidence: {finding['evidence']['value']}")
        print(f"  Context: {finding['evidence']['context']}")
        print()