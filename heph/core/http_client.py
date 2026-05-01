"""
HTTP Client with Rate Limiting using Token Bucket Algorithm

Provides a shared HTTP session with automatic rate limiting
to prevent overwhelming target servers during security audits.

Used by Hephaestus for all server security checks.

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import time
import threading
from typing import Optional
import requests
from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class TokenBucket:
    """
    Token Bucket algorithm for rate limiting.
    
    Allows bursts of requests while maintaining average rate limit.
    Thread-safe implementation using minimal lock time.
    """
    
    def __init__(self, rate: float, burst_size: Optional[int] = None):
        """
        Initialize token bucket.
        
        Args:
            rate: Tokens per second (e.g., 3.0 = 3 requests/second)
            burst_size: Maximum tokens in bucket (default: max(rate * 2, 5))
        """
        self.rate = max(0.1, rate)  # Minimum 0.1 req/s
        
        # Better burst size calculation
        if burst_size is None:
            # At least 5 tokens for burst, or 2x rate
            burst_size = max(5, int(rate * 2))
        
        self.burst_size = burst_size
        
        # Initialize bucket as full (allows immediate burst)
        self.tokens = float(self.burst_size)
        self.last_refill = time.time()
        
        # Lock ONLY for token operations (not for sleeping!)
        self._lock = threading.Lock()
        
        # Logging control (reduce spam)
        self._check_count = 0
        self._log_every = 10  # Log every 10 checks instead of every check
        
        logger.info(
            f"Token bucket initialized: rate={self.rate:.2f} req/s, "
            f"burst={self.burst_size} tokens, "
            f"min_interval={1.0/self.rate:.3f}s"
        )
    
    def _refill_tokens(self):
        """
        Refill tokens based on elapsed time.
        MUST be called while holding lock.
        """
        now = time.time()
        elapsed = now - self.last_refill
        
        # Calculate new tokens based on elapsed time
        new_tokens = elapsed * self.rate
        
        # Add new tokens, capped at burst_size
        self.tokens = min(self.burst_size, self.tokens + new_tokens)
        
        # Update last refill time
        self.last_refill = now
        
        # Reduced logging - only every 10th check
        self._check_count += 1
        if self._check_count % self._log_every == 0:
            logger.debug(
                f"Token bucket state: {self.tokens:.1f}/{self.burst_size} tokens "
                f"(rate: {self.rate:.1f} req/s)"
            )
    
    def take_token(self, timeout: Optional[float] = None) -> bool:
        """
        Take a token from the bucket (blocking until available).
        
        Args:
            timeout: Maximum time to wait for token (None = wait forever)
        
        Returns:
            True if token acquired, False if timeout
        """
        start_time = time.time()
        attempts = 0
        
        while True:
            attempts += 1
            
            with self._lock:
                self._refill_tokens()
                
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    
                    if attempts == 1 or attempts % 50 == 0:
                        logger.debug(f"Token acquired after {attempts} attempts, {self.tokens:.1f} remaining")
                    
                    return True
                
                time_until_token = (1.0 - self.tokens) / self.rate
            
            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    logger.warning(f"Token acquisition timeout after {elapsed:.2f}s ({attempts} attempts)")
                    return False
            
            # Sleep for minimum time or until next token
            sleep_time = min(0.1, time_until_token)
            time.sleep(sleep_time)
    
    def peek_tokens(self) -> float:
        """
        Check current token count (for debugging).
        
        Returns:
            Current number of tokens in bucket
        """
        with self._lock:
            self._refill_tokens()
            return self.tokens


class RateLimitedSession:
    """
    HTTP session with automatic rate limiting using Token Bucket.
    
    Enforces a maximum requests-per-second rate across all threads.
    Thread-safe with minimal lock contention.
    """
    
    def __init__(self, rate_limit: float, config=None):
        """
        Initialize rate-limited session.
        
        Args:
            rate_limit: Maximum requests per second (e.g., 3.0 = 3 req/s)
            config: Config instance (optional)
        """
        self.config = config or get_config()
        self.rate_limit = max(0.1, rate_limit)  # Minimum 0.1 req/s
        
        # Create token bucket for rate limiting
        # Better burst size calculation
        burst_size = max(5, int(rate_limit * 2))
        self.bucket = TokenBucket(rate=rate_limit, burst_size=burst_size)
        
        # Create requests session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.config.user_agent})
        
        # Custom headers from config
        if self.config.custom_headers:
            self.session.headers.update(self.config.custom_headers)
        
        # Proxy settings
        if self.config.proxy_http or self.config.proxy_https:
            proxies = {}
            if self.config.proxy_http:
                proxies['http'] = self.config.proxy_http
            if self.config.proxy_https:
                proxies['https'] = self.config.proxy_https
            self.session.proxies.update(proxies)
        
        logger.info(
            f"HTTP client initialized: rate={self.rate_limit:.2f} req/s, "
            f"burst={burst_size} tokens, threads={self.config.max_workers}"
        )
    
    def _acquire_token(self):
        """
        Acquire a token before making request.
        Blocks until token is available (respects rate limit).
        """
        self.bucket.take_token(timeout=None)
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        HTTP GET with automatic rate limiting.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments for requests.get()
        
        Returns:
            Response object
        """
        self._acquire_token()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        if 'allow_redirects' not in kwargs:
            kwargs['allow_redirects'] = self.config.follow_redirects
        
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """HTTP POST with rate limiting."""
        self._acquire_token()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        return self.session.post(url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """HTTP HEAD with rate limiting."""
        self._acquire_token()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        return self.session.head(url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        """HTTP OPTIONS with rate limiting (for HTTP methods check)."""
        self._acquire_token()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        return self.session.options(url, **kwargs)
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Generic HTTP request with rate limiting.
        Useful for testing unsafe methods (PUT, DELETE, TRACE).
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            **kwargs: Additional arguments for requests.request()
        
        Returns:
            Response object
        """
        self._acquire_token()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (self.config.timeout_connect, self.config.timeout_read)
        
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
        return self.session.request(method, url, **kwargs)


def create_http_client(mode: str = 'safe', config=None) -> RateLimitedSession:
    """
    Create HTTP client with appropriate rate limit for scan mode.
    
    Args:
        mode: 'safe' or 'aggressive'
        config: Config instance (optional)
    
    Returns:
        RateLimitedSession instance with Token Bucket rate limiting
    """
    config = config or get_config()
    
    if mode == 'aggressive':
        rate_limit = config.rate_limit_aggressive
    else:
        rate_limit = config.rate_limit_safe
    
    logger.info(f"Creating HTTP client: mode={mode}, rate={rate_limit:.2f} req/s")
    logger.info(f"Using Token Bucket v2 with reduced logging")
    
    return RateLimitedSession(rate_limit, config)