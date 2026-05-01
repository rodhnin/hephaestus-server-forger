"""
Hephaestus Configuration Loader

Handles configuration from multiple sources with priority:
1. Command-line arguments (highest priority)
2. Environment variables
3. User config file (~/.hephaestus/config.yaml)
4. Default config (config/defaults.yaml)

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Config:
    """
    Configuration container for Hephaestus.
    
    All settings are accessible as attributes with dot notation.
    """
    
    # ========================================================================
    # CLASS-LEVEL DEFAULTS (for mutable types)
    # ========================================================================
    
    DEFAULT_SERVER_PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/HEAD", "/.git/config", "/phpinfo.php", "/info.php",
        "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
        "/composer.json", "/package.json", "/backup.zip", "/backup.sql"
    ]
    
    DEFAULT_HTTP_METHODS = ["OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    
    DEFAULT_DIRECTORY_PATHS = [
        "/uploads/", "/images/", "/files/", "/public/", "/assets/",
        "/static/", "/media/", "/download/", "/tmp/", "/temp/"
    ]

    DEFAULT_SCAN_PORTS = [
        # Infrastructure
        21, 22, 25, 110, 143, 465, 587,
        # Relational databases
        1433, 1521, 3306, 5432,
        # NoSQL / caches
        5984, 6379, 11211, 27017, 27018,
        # Search / time-series
        9200, 9300, 8086,
        # Message queues
        5672, 15672,
        # Dev / app servers
        3000, 4000, 4200, 5000, 8000, 8080, 8443, 8888, 9000,
        # Admin / monitoring
        2181, 4848, 7001, 8161, 9090, 3001,
        # Big data
        50070,
    ]
    
    DEFAULT_CUSTOM_HEADERS = {}
    DEFAULT_RETRY_ON_CODES = [429, 500, 502, 503, 504]
    DEFAULT_RETRY_SKIP_CODES = [400, 401, 403, 404]
    
    # ========================================================================
    # INSTANCE ATTRIBUTES
    # ========================================================================
    
    # General
    version: str = "0.2.0"
    author: str = "Rodney Dhavid Jimenez Chacin (rodhnin)"
    github: str = "https://github.com/rodhnin/hephaestus-server-forger"
    contact: str = "https://rodhnin.com"
    
    # Paths
    report_dir: Path = Path.home() / ".hephaestus" / "reports"
    database: Path = Path.home() / ".argos" / "argos.db" 
    log_file: Optional[Path] = Path.home() / ".hephaestus" / "hephaestus.log"
    consent_proofs_dir: Path = Path.home() / ".hephaestus" / "consent-proofs"
    
    # Scan behavior
    default_mode: str = "safe"
    rate_limit_safe: float = 5.0
    rate_limit_aggressive: float = 12.0
    timeout_connect: int = 15
    timeout_read: int = 45
    user_agent: str = "Hephaestus/0.2.0 (Server Security Auditor; +https://github.com/rodhnin/hephaestus)"
    follow_redirects: bool = True
    max_redirects: int = 3
    verify_ssl: bool = True
    
    # Server settings (NEW for Hephaestus)
    server_common_paths: list = field(default_factory=lambda: Config.DEFAULT_SERVER_PATHS.copy())
    http_methods_to_test: list = field(default_factory=lambda: Config.DEFAULT_HTTP_METHODS.copy())
    directory_paths_to_check: list = field(default_factory=lambda: Config.DEFAULT_DIRECTORY_PATHS.copy())
    max_directory_checks: int = 10
    check_server_header: bool = True
    check_x_powered_by: bool = True
    probe_unsafe_methods: bool = True
    
    # Port scanning (v0.2.0)
    port_scan_enabled: bool = True
    port_scan_timeout: int = 3
    port_scan_workers: int = 20
    port_scan_cve_enabled: bool = True
    port_scan_ports: list = field(default_factory=lambda: Config.DEFAULT_SCAN_PORTS.copy())

    # TLS/SSL settings (NEW for Hephaestus)
    tls_verify_certificate: bool = True
    tls_check_expiration: bool = True
    tls_check_hostname_match: bool = True
    tls_check_self_signed: bool = True
    tls_check_sslv3: bool = True
    tls_check_tls10: bool = True
    tls_check_tls11: bool = True
    tls_check_tls12: bool = True
    tls_check_tls13: bool = True
    tls_advanced_enabled: bool = False  # Requires sslyze
    
    # Consent token
    token_expiry_hours: int = 24  # Shorter than Argus (48h)
    token_hex_length: int = 16
    http_verification_path: str = "/.well-known/"
    dns_txt_prefix: str = "hephaestus-verify="
    verification_retries: int = 3
    verification_retry_delay: int = 2
    
    # Reporting
    generate_json: bool = True
    generate_html: bool = False
    json_indent: int = 2
    html_include_evidence: bool = True
    html_css_inline: bool = True
    html_theme: str = "forge"
    
    # Logging
    log_level: str = "INFO"
    log_json_format: bool = False
    log_colors: bool = True
    log_redact_secrets: bool = True
    
    # AI integration (same as Argus v0.2.0)
    ai_enabled: bool = False
    ai_provider: str = "openai"
    ai_model: str = "gpt-4o-mini-2024-07-18"  # v0.2.0: cheaper default (was gpt-4-turbo-preview)
    ai_temperature: float = 0.3
    ai_max_tokens: int = 2000
    ai_agent_type: str = "zero-shot-react-description"
    ai_memory_enabled: bool = True
    ai_memory_type: str = "buffer"
    ai_memory_max_history: int = 10
    ai_api_key_env: str = "OPENAI_API_KEY"
    ai_prompts_dir: Path = Path("config/prompts")
    ai_remove_urls: bool = False
    ai_remove_tokens: bool = True
    ai_remove_credentials: bool = True
    ai_remove_private_keys: bool = True
    ai_remove_certificates: bool = True
    ai_max_evidence_length: int = 500
    # v0.2.0: Streaming (IMPROV-006)
    ai_streaming: bool = False
    # v0.2.0: Budget tracking (IMPROV-005)
    ai_budget_enabled: bool = False
    ai_max_cost_per_scan: float = 1.0
    ai_warn_threshold: float = 0.8
    ai_abort_on_exceed: bool = False
    # v0.2.0: Agent (IMPROV-008)
    ai_agent_max_iterations: int = 10
    # v0.2.0: Ollama base URL
    ai_ollama_base_url: str = "http://localhost:11434"
    
    # Advanced
    max_workers: int = 5
    cache_responses: bool = False
    cache_ttl_seconds: int = 3600
    custom_headers: Dict[str, str] = field(default_factory=lambda: Config.DEFAULT_CUSTOM_HEADERS.copy())
    proxy_http: Optional[str] = None
    proxy_https: Optional[str] = None
    
    # Retry policy
    retry_retries: int = 3
    retry_backoff: str = "exponential"
    retry_backoff_factor: int = 2
    retry_on_codes: list = field(default_factory=lambda: Config.DEFAULT_RETRY_ON_CODES.copy())
    retry_skip_codes: list = field(default_factory=lambda: Config.DEFAULT_RETRY_SKIP_CODES.copy())
    
    # Docker
    in_container: bool = False
    container_report_dir: Path = Path("/reports")
    container_db_path: Path = Path("/data/argos.db")
    
    @classmethod
    def load(
        cls,
        config_file: Optional[Path] = None,
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> "Config":
        """
        Load configuration from multiple sources.
        
        Args:
            config_file: Path to user config file (default: ~/.hephaestus/config.yaml)
            cli_overrides: Dictionary of CLI argument overrides
        
        Returns:
            Configured Config instance
        """
        # Start with defaults
        config_dict = cls._load_defaults()
        
        # Merge user config file if exists
        if config_file is None:
            config_file = Path.home() / ".hephaestus" / "config.yaml"
        
        if config_file.exists():
            user_config = cls._load_yaml(config_file)
            config_dict = cls._deep_merge(config_dict, user_config)
        
        # Apply environment variables
        env_config = cls._load_env_vars()
        config_dict = cls._deep_merge(config_dict, env_config)
        
        # Apply CLI overrides
        if cli_overrides:
            config_dict = cls._deep_merge(config_dict, cli_overrides)
        
        # Flatten nested dict to Config attributes
        return cls._dict_to_config(config_dict)
    
    @staticmethod
    def _load_defaults() -> Dict[str, Any]:
        """Load default configuration from config/defaults.yaml."""
        defaults_path = Path(__file__).parent.parent.parent / "config" / "defaults.yaml"
        
        if not defaults_path.exists():
            # Return minimal defaults if file not found
            return {
                "general": {"version": "0.2.0"},
                "paths": {},
                "scan": {},
                "server": {},
                "tls": {},
                "consent": {},
                "reporting": {},
                "logging": {},
                "ai": {},
                "advanced": {},
                "docker": {}
            }
        
        return Config._load_yaml(defaults_path)
    
    @staticmethod
    def _load_yaml(path: Path) -> Dict[str, Any]:
        """Load YAML file safely."""
        try:
            with path.open('r') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {path}: {e}")
    
    @staticmethod
    def _load_env_vars() -> Dict[str, Any]:
        """
        Load configuration from environment variables.

        Env vars format: HEPHAESTUS_SECTION_KEY (e.g., HEPHAESTUS_PATHS_REPORT_DIR)

        Special handling for Docker:
        - HEPHAESTUS_DOCKER_IN_CONTAINER maps to docker.in_container
        """
        env_config = {}
        prefix = "HEPHAESTUS_"

        for key, value in os.environ.items():
            if key.startswith(prefix):
                # Special case for Docker variables with underscores in key names
                if key == "HEPHAESTUS_DOCKER_IN_CONTAINER":
                    env_config.setdefault('docker', {})['in_container'] = Config._parse_env_value(value)
                    continue
                if key == "HEPHAESTUS_DOCKER_CONTAINER_REPORT_DIR":
                    env_config.setdefault('docker', {})['container_report_dir'] = value
                    continue
                if key == "HEPHAESTUS_DOCKER_CONTAINER_DB_PATH":
                    env_config.setdefault('docker', {})['container_db_path'] = value
                    continue

                # Remove prefix and split by underscore
                parts = key[len(prefix):].lower().split('_')

                # Build nested dict
                current = env_config
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]

                # Set value (try to parse as int/float/bool)
                last_key = parts[-1]
                current[last_key] = Config._parse_env_value(value)

        return env_config
    
    @staticmethod
    def _parse_env_value(value: str) -> Any:
        """Parse environment variable value to appropriate type."""
        # Boolean
        if value.lower() in ('true', 'yes', '1'):
            return True
        if value.lower() in ('false', 'no', '0'):
            return False
        
        # Integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float
        try:
            return float(value)
        except ValueError:
            pass
        
        # String
        return value
    
    @staticmethod
    def _deep_merge(base: Dict, update: Dict) -> Dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    @classmethod
    def _dict_to_config(cls, config_dict: Dict[str, Any]) -> "Config":
        """Convert nested dict to flat Config instance."""
        # Flatten nested structure
        flat = {}
        
        # General
        if 'general' in config_dict:
            gen = config_dict['general']
            flat['version'] = gen.get('version', cls.version)
            flat['author'] = gen.get('author', cls.author)
            flat['github'] = gen.get('github', cls.github)
            flat['contact'] = gen.get('contact', cls.contact)
        
        # Paths
        if 'paths' in config_dict:
            paths = config_dict['paths']
            flat['report_dir'] = Path(paths.get('report_dir', cls.report_dir))
            flat['database'] = Path(paths.get('database', cls.database))
            log_file = paths.get('log_file')
            flat['log_file'] = Path(log_file) if log_file else None
            flat['consent_proofs_dir'] = Path(paths.get('consent_proofs_dir', cls.consent_proofs_dir))
        
        # Scan
        if 'scan' in config_dict:
            scan = config_dict['scan']
            flat['default_mode'] = scan.get('default_mode', cls.default_mode)
            if 'rate_limit' in scan:
                flat['rate_limit_safe'] = scan['rate_limit'].get('safe_mode', cls.rate_limit_safe)
                flat['rate_limit_aggressive'] = scan['rate_limit'].get('aggressive_mode', cls.rate_limit_aggressive)
            if 'timeout' in scan:
                flat['timeout_connect'] = scan['timeout'].get('connect', cls.timeout_connect)
                flat['timeout_read'] = scan['timeout'].get('read', cls.timeout_read)
            flat['user_agent'] = scan.get('user_agent', cls.user_agent)
            flat['follow_redirects'] = scan.get('follow_redirects', cls.follow_redirects)
            flat['max_redirects'] = scan.get('max_redirects', cls.max_redirects)
            flat['verify_ssl'] = scan.get('verify_ssl', cls.verify_ssl)
        
        # Server
        if 'server' in config_dict:
            server = config_dict['server']
            flat['server_common_paths'] = server.get('common_paths', cls.DEFAULT_SERVER_PATHS.copy())
            
            if 'http_methods' in server:
                http = server['http_methods']
                flat['http_methods_to_test'] = http.get('methods_to_test', cls.DEFAULT_HTTP_METHODS.copy())
                flat['probe_unsafe_methods'] = http.get('probe_unsafe', cls.probe_unsafe_methods)
            
            if 'directory_listing' in server:
                dirs = server['directory_listing']
                flat['directory_paths_to_check'] = dirs.get('paths_to_check', cls.DEFAULT_DIRECTORY_PATHS.copy())
                flat['max_directory_checks'] = dirs.get('max_paths_to_check', cls.max_directory_checks)
            
            if 'server_detection' in server:
                detect = server['server_detection']
                flat['check_server_header'] = detect.get('check_server_header', cls.check_server_header)
                flat['check_x_powered_by'] = detect.get('check_x_powered_by', cls.check_x_powered_by)
        
        # Port scan
        if 'port_scan' in config_dict:
            ps = config_dict['port_scan']
            flat['port_scan_enabled'] = ps.get('enabled', cls.port_scan_enabled)
            flat['port_scan_timeout'] = ps.get('timeout', cls.port_scan_timeout)
            flat['port_scan_workers'] = ps.get('max_workers', cls.port_scan_workers)
            flat['port_scan_cve_enabled'] = ps.get('cve_enrichment', cls.port_scan_cve_enabled)
            flat['port_scan_ports'] = ps.get('ports', cls.DEFAULT_SCAN_PORTS.copy())

        # TLS
        if 'tls' in config_dict:
            tls = config_dict['tls']
            if 'basic_checks' in tls:
                basic = tls['basic_checks']
                flat['tls_verify_certificate'] = basic.get('verify_certificate', cls.tls_verify_certificate)
                flat['tls_check_expiration'] = basic.get('check_expiration', cls.tls_check_expiration)
                flat['tls_check_hostname_match'] = basic.get('check_hostname_match', cls.tls_check_hostname_match)
                flat['tls_check_self_signed'] = basic.get('check_self_signed', cls.tls_check_self_signed)
            
            if 'protocols' in tls:
                protos = tls['protocols']
                flat['tls_check_sslv3'] = protos.get('check_sslv3', cls.tls_check_sslv3)
                flat['tls_check_tls10'] = protos.get('check_tls10', cls.tls_check_tls10)
                flat['tls_check_tls11'] = protos.get('check_tls11', cls.tls_check_tls11)
                flat['tls_check_tls12'] = protos.get('check_tls12', cls.tls_check_tls12)
                flat['tls_check_tls13'] = protos.get('check_tls13', cls.tls_check_tls13)
            
            if 'advanced' in tls:
                adv = tls['advanced']
                flat['tls_advanced_enabled'] = adv.get('enabled', cls.tls_advanced_enabled)
        
        # Consent
        if 'consent' in config_dict:
            consent = config_dict['consent']
            flat['token_expiry_hours'] = consent.get('token_expiry_hours', cls.token_expiry_hours)
            flat['token_hex_length'] = consent.get('token_hex_length', cls.token_hex_length)
            flat['http_verification_path'] = consent.get('http_verification_path', cls.http_verification_path)
            flat['dns_txt_prefix'] = consent.get('dns_txt_prefix', cls.dns_txt_prefix)
            flat['verification_retries'] = consent.get('verification_retries', cls.verification_retries)
            flat['verification_retry_delay'] = consent.get('verification_retry_delay', cls.verification_retry_delay)
        
        # Reporting
        if 'reporting' in config_dict:
            reporting = config_dict['reporting']
            if 'format' in reporting:
                flat['generate_json'] = reporting['format'].get('json', cls.generate_json)
                flat['generate_html'] = reporting['format'].get('html', cls.generate_html)
            flat['json_indent'] = reporting.get('json_indent', cls.json_indent)
            if 'html' in reporting:
                flat['html_include_evidence'] = reporting['html'].get('include_evidence', cls.html_include_evidence)
                flat['html_css_inline'] = reporting['html'].get('css_inline', cls.html_css_inline)
                flat['html_theme'] = reporting['html'].get('theme', cls.html_theme)
        
        # Logging
        if 'logging' in config_dict:
            logging_cfg = config_dict['logging']
            flat['log_level'] = logging_cfg.get('level', cls.log_level)
            flat['log_json_format'] = logging_cfg.get('json_format', cls.log_json_format)
            flat['log_colors'] = logging_cfg.get('colors', cls.log_colors)
            if 'redact' in logging_cfg:
                flat['log_redact_secrets'] = logging_cfg['redact'].get('enabled', cls.log_redact_secrets)
        
        # AI
        if 'ai' in config_dict:
            ai = config_dict['ai']
            flat['ai_enabled'] = ai.get('enabled', cls.ai_enabled)
            if 'langchain' in ai:
                lc = ai['langchain']
                flat['ai_provider'] = lc.get('provider', cls.ai_provider)
                flat['ai_model'] = lc.get('model', cls.ai_model)
                flat['ai_temperature'] = lc.get('temperature', cls.ai_temperature)
                flat['ai_max_tokens'] = lc.get('max_tokens', cls.ai_max_tokens)
                flat['ai_agent_type'] = lc.get('agent_type', cls.ai_agent_type)
                if 'memory' in lc:
                    flat['ai_memory_enabled'] = lc['memory'].get('enabled', cls.ai_memory_enabled)
                    flat['ai_memory_type'] = lc['memory'].get('type', cls.ai_memory_type)
                    flat['ai_memory_max_history'] = lc['memory'].get('max_history', cls.ai_memory_max_history)
            flat['ai_api_key_env'] = ai.get('api_key_env', cls.ai_api_key_env)
            prompts_dir = ai.get('prompts_dir', cls.ai_prompts_dir)
            flat['ai_prompts_dir'] = Path(prompts_dir) if prompts_dir else cls.ai_prompts_dir
            if 'sanitization' in ai:
                san = ai['sanitization']
                flat['ai_remove_urls'] = san.get('remove_urls', cls.ai_remove_urls)
                flat['ai_remove_tokens'] = san.get('remove_tokens', cls.ai_remove_tokens)
                flat['ai_remove_credentials'] = san.get('remove_credentials', cls.ai_remove_credentials)
                flat['ai_remove_private_keys'] = san.get('remove_private_keys', cls.ai_remove_private_keys)
                flat['ai_remove_certificates'] = san.get('remove_certificates', cls.ai_remove_certificates)
                flat['ai_max_evidence_length'] = san.get('max_evidence_length', cls.ai_max_evidence_length)
            # v0.2.0: streaming, budget, agent
            flat['ai_streaming'] = ai.get('streaming', cls.ai_streaming)
            flat['ai_agent_max_iterations'] = ai.get('agent_max_iterations', cls.ai_agent_max_iterations)
            flat['ai_ollama_base_url'] = ai.get('ollama_base_url', cls.ai_ollama_base_url)
            if 'budget' in ai:
                budget = ai['budget']
                flat['ai_budget_enabled'] = budget.get('enabled', cls.ai_budget_enabled)
                flat['ai_max_cost_per_scan'] = budget.get('max_cost_per_scan', cls.ai_max_cost_per_scan)
                flat['ai_warn_threshold'] = budget.get('warn_threshold', cls.ai_warn_threshold)
                flat['ai_abort_on_exceed'] = budget.get('abort_on_exceed', cls.ai_abort_on_exceed)
        
        # Advanced
        if 'advanced' in config_dict:
            adv = config_dict['advanced']
            flat['max_workers'] = adv.get('max_workers', cls.max_workers)
            flat['cache_responses'] = adv.get('cache_responses', cls.cache_responses)
            flat['cache_ttl_seconds'] = adv.get('cache_ttl_seconds', cls.cache_ttl_seconds)
            flat['custom_headers'] = adv.get('custom_headers', cls.DEFAULT_CUSTOM_HEADERS.copy())
            if 'proxy' in adv:
                flat['proxy_http'] = adv['proxy'].get('http', cls.proxy_http)
                flat['proxy_https'] = adv['proxy'].get('https', cls.proxy_https)
            if 'retry' in adv:
                retry = adv['retry']
                flat['retry_retries'] = retry.get('retries', cls.retry_retries)
                flat['retry_backoff'] = retry.get('backoff', cls.retry_backoff)
                flat['retry_backoff_factor'] = retry.get('backoff_factor', cls.retry_backoff_factor)
                flat['retry_on_codes'] = retry.get('retry_on', cls.DEFAULT_RETRY_ON_CODES.copy())
                flat['retry_skip_codes'] = retry.get('no_retry_on', cls.DEFAULT_RETRY_SKIP_CODES.copy())
        
        # Docker
        if 'docker' in config_dict:
            docker = config_dict['docker']
            flat['in_container'] = docker.get('in_container', cls.in_container)
            flat['container_report_dir'] = Path(docker.get('container_report_dir', cls.container_report_dir))
            flat['container_db_path'] = Path(docker.get('container_db_path', cls.container_db_path))
        
        return cls(**flat)
    
    def expand_paths(self):
        """Expand ~ and environment variables in paths."""
        # If running in container, use container paths automatically
        # (unless user explicitly specified custom paths)
        if self.in_container:
            default_report = Path.home() / ".hephaestus" / "reports"
            default_db = Path.home() / ".argos" / "argos.db"

            if self.report_dir == default_report:
                self.report_dir = self.container_report_dir
            else:
                self.report_dir = self.report_dir.expanduser()

            if self.database == default_db:
                self.database = self.container_db_path
            else:
                self.database = self.database.expanduser()
        else:
            self.report_dir = self.report_dir.expanduser()
            self.database = self.database.expanduser()

        if self.log_file:
            self.log_file = self.log_file.expanduser()
        self.consent_proofs_dir = self.consent_proofs_dir.expanduser()
    
    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            print(f"\n{'='*70}")
            print("✖ ERROR: Permission denied")
            print(f"{'='*70}")
            print(f"Cannot create report directory: {self.report_dir}")
            print(f"\nPossible solutions:")
            print(f"  1. Use a different directory:")
            print(f"     heph --target <url> --report-dir ~/my-reports")
            print(f"  2. Fix permissions:")
            print(f"     sudo chmod 755 {self.report_dir.parent}")
            print(f"  3. Use default location: ~/.hephaestus/reports")
            print(f"{'='*70}\n")
            raise SystemExit(1)
        
        try:
            self.database.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            print(f"\n{'='*70}")
            print("✖ ERROR: Permission denied")
            print(f"{'='*70}")
            print(f"Cannot create database directory: {self.database.parent}")
            print(f"\nThe shared Argos database requires write access.")
            print(f"Default location: ~/.argos/argos.db")
            print(f"{'='*70}\n")
            raise SystemExit(1)
        
        if self.log_file:
            try:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                # Log file is optional, just warn
                print(f"Warning: Cannot create log directory {self.log_file.parent}, logging to console only")
                self.log_file = None
        
        try:
            self.consent_proofs_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            print(f"\n{'='*70}")
            print("✖ ERROR: Permission denied")
            print(f"{'='*70}")
            print(f"Cannot create consent proofs directory: {self.consent_proofs_dir}")
            print(f"\nConsent verification requires write access to store proofs.")
            print(f"Default location: ~/.hephaestus/consent-proofs")
            print(f"{'='*70}\n")
            raise SystemExit(1)


# Global config instance
_global_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = Config.load()
        _global_config.expand_paths()
    return _global_config


def set_config(config: Config):
    """Set the global configuration instance."""
    global _global_config
    _global_config = config


if __name__ == "__main__":
    # Test configuration loading
    config = Config.load()
    config.expand_paths()
    
    print(f"Version: {config.version}")
    print(f"Report Dir: {config.report_dir}")
    print(f"Database: {config.database}")
    print(f"Rate Limit (safe): {config.rate_limit_safe} req/s")
    print(f"Server Common Paths: {len(config.server_common_paths)} paths")
    print(f"TLS Checks Enabled: {config.tls_verify_certificate}")
    print(f"AI Enabled: {config.ai_enabled}")
    print(f"AI Model: {config.ai_model}")