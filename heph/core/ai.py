"""
Hephaestus AI Integration with LangChain v1.0.0

Provides AI-powered analysis using modern LangChain LCEL:
- Executive summaries for stakeholders
- Technical remediation guides for engineers
- Automatic sanitization of sensitive data

Supports: OpenAI, Anthropic Claude, Ollama (local models)
Compatible with: langchain-core==1.0.0, langchain-community==0.4

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

try:
    # Core components (always needed)
    from langchain_core.prompts import PromptTemplate, ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LANGCHAIN_CORE = True
except ImportError:
    HAS_LANGCHAIN_CORE = False

# OpenAI support (optional)
try:
    from langchain_openai import ChatOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# Anthropic support (optional)
try:
    from langchain_anthropic import ChatAnthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

# Ollama support via dedicated package (optional)
try:
    from langchain_ollama import ChatOllama, OllamaLLM
    HAS_OLLAMA = True
except ImportError:
    # Fallback to community package if new package not installed
    try:
        from langchain_community.chat_models import ChatOllama
        from langchain_community.llms import Ollama as OllamaLLM
        HAS_OLLAMA = True
    except ImportError:
        HAS_OLLAMA = False

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


class AIAnalyzer:
    """
    Modern LangChain v1.0.0 AI analyzer for security reports.
    Uses LCEL (LangChain Expression Language) exclusively.
    No deprecated components (agents, memory).
    
    Supports:
    - OpenAI GPT models
    - Anthropic Claude models  
    - Ollama local models (privacy-focused)
    """
    
    def __init__(self, config=None):
        """Initialize AI analyzer with selected provider."""
        if not HAS_LANGCHAIN_CORE:
            error_msg = (
                "LangChain Core required for AI features. Install with:\n"
                "  pip install langchain-core==1.0.0\n"
                "  pip install langchain-openai==1.0.0  # For OpenAI\n"
                "  pip install langchain-anthropic==1.0.0  # For Anthropic\n"
                "  pip install langchain-ollama>=0.3.0,<0.4.0  # For Ollama\n"
            )
            raise ImportError(error_msg)
        
        self.config = config or get_config()
        
        # Sync custom env var with standard ones if needed
        self._sync_api_keys()
        
        # Initialize LLM based on provider
        self.llm = self._init_llm()
        
        # Initialize output parser (compatible with all providers)
        self.output_parser = StrOutputParser()
        
        # Load prompt templates
        self.technical_prompt = self._load_prompt('technical.txt')
        self.non_technical_prompt = self._load_prompt('non_technical.txt')
        
        # Store provider info for logging
        self.provider = self.config.ai_provider.lower()
        self.model = self.config.ai_model
        
        logger.info(f"AI analyzer initialized: {self.provider}/{self.model}")
    
    def _sync_api_keys(self):
        """
        Sync custom API key env var with standard ones.
        LangChain v1.0.0 reads from standard env vars by default.
        """
        custom_key_var = self.config.ai_api_key_env
        provider = self.config.ai_provider.lower()
        
        if provider == 'openai':
            # Check custom var first, then standard
            key = os.getenv(custom_key_var) or os.getenv('OPENAI_API_KEY')
            if key and custom_key_var != 'OPENAI_API_KEY':
                # Sync to standard var for LangChain
                os.environ['OPENAI_API_KEY'] = key
                logger.debug(f"Synced {custom_key_var} -> OPENAI_API_KEY")
        
        elif provider == 'anthropic':
            # Check custom var first, then standard
            key = os.getenv(custom_key_var) or os.getenv('ANTHROPIC_API_KEY')
            if key and custom_key_var != 'ANTHROPIC_API_KEY':
                # Sync to standard var for LangChain
                os.environ['ANTHROPIC_API_KEY'] = key
                logger.debug(f"Synced {custom_key_var} -> ANTHROPIC_API_KEY")
    
    def _init_llm(self):
        """
        Initialize language model based on config.
        LangChain v1.0.0 compatible initialization.
        """
        provider = self.config.ai_provider.lower()
        
        if provider == 'openai':
            if not HAS_OPENAI:
                raise ImportError(
                    "OpenAI support not installed. Run:\n"
                    "pip install langchain-openai==1.0.0"
                )
            
            # Verify API key is available (reads from env automatically)
            if not os.getenv('OPENAI_API_KEY'):
                raise ValueError(
                    f"OpenAI API key not found. Set OPENAI_API_KEY or {self.config.ai_api_key_env}"
                )
            
            logger.info(f"Initializing OpenAI: {self.config.ai_model}")
            
            return ChatOpenAI(
                model=self.config.ai_model,
                temperature=self.config.ai_temperature,
                max_tokens=self.config.ai_max_tokens,
                # Optional: add streaming, callbacks, etc.
                streaming=False,
                verbose=False
            )
        
        elif provider == 'anthropic':
            if not HAS_ANTHROPIC:
                raise ImportError(
                    "Anthropic support not installed. Run:\n"
                    "pip install langchain-anthropic==1.0.0 anthropic==0.71.0"
                )
            
            # Verify API key is available
            if not os.getenv('ANTHROPIC_API_KEY'):
                raise ValueError(
                    f"Anthropic API key not found. Set ANTHROPIC_API_KEY or {self.config.ai_api_key_env}"
                )
            
            logger.info(f"Initializing Anthropic: {self.config.ai_model}")
            
            return ChatAnthropic(
                model=self.config.ai_model,
                temperature=self.config.ai_temperature,
                max_tokens=self.config.ai_max_tokens,
                # Anthropic-specific options
                timeout=60,  # Longer timeout for Claude
                max_retries=2
            )
        
        elif provider == 'ollama':
            if not HAS_OLLAMA:
                raise ImportError(
                    "Ollama support not installed. Run:\n"
                    "pip install langchain-ollama>=0.3.0,<0.4.0\n"
                    "Or fallback: pip install langchain-community==0.4"
                )
            
            # Get Ollama base URL from config or use default
            base_url = getattr(self.config, 'ai_ollama_base_url', 'http://localhost:11434')
            
            # Verify Ollama server is running
            try:
                import requests
                resp = requests.get(f"{base_url}/api/tags", timeout=5)
                if resp.status_code != 200:
                    raise ConnectionError(f"Ollama server not responding at {base_url}")
                
                # Check if model exists
                models = resp.json().get('models', [])
                model_names = [m['name'] for m in models]
                if self.config.ai_model not in model_names:
                    available = ', '.join(model_names) if model_names else 'none'
                    raise ValueError(
                        f"Model '{self.config.ai_model}' not found in Ollama.\n"
                        f"Available models: {available}\n"
                        f"Pull it with: ollama pull {self.config.ai_model}"
                    )
                    
            except requests.exceptions.RequestException as e:
                raise ConnectionError(
                    f"Cannot connect to Ollama at {base_url}.\n"
                    f"Start Ollama with: ollama serve\n"
                    f"Error: {e}"
                )
            
            logger.info(f"Initializing Ollama: {self.config.ai_model} at {base_url}")
            
            # Use ChatOllama for better chat-like interactions
            try:
                return ChatOllama(
                    model=self.config.ai_model,
                    base_url=base_url,
                    temperature=self.config.ai_temperature,
                    num_predict=self.config.ai_max_tokens,
                    num_ctx=8192,
                    repeat_penalty=1.1,
                    top_k=40,
                    top_p=0.9,
                    timeout=120,
                    verbose=False
                )
            except Exception as e:
                logger.warning(f"ChatOllama initialization failed: {e}")
                logger.info("Falling back to base Ollama LLM")
                
                # Fallback to base Ollama (less optimal but works)
                return OllamaLLM(
                    model=self.config.ai_model,
                    base_url=base_url,
                    temperature=self.config.ai_temperature,
                    num_predict=self.config.ai_max_tokens,
                    num_ctx=8192,
                    repeat_penalty=1.1,
                    verbose=False
                )
        
        else:
            supported = "openai, anthropic, ollama"
            raise ValueError(
                f"Unsupported AI provider: '{provider}'.\n"
                f"Supported providers: {supported}\n"
                f"Update config/defaults.yaml -> ai.langchain.provider"
            )
    
    def _load_prompt(self, filename: str) -> str:
        """Load prompt template from file."""
        prompt_path = Path(__file__).parent.parent.parent / self.config.ai_prompts_dir / filename
        
        if not prompt_path.exists():
            logger.error(f"Prompt file not found: {prompt_path}")
            raise FileNotFoundError(f"Prompt template missing: {prompt_path}")
        
        with prompt_path.open('r', encoding='utf-8') as f:
            content = f.read()
            logger.debug(f"Loaded prompt from {filename} ({len(content)} chars)")
            return content
    
    def sanitize_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize report before sending to AI.
        Critical for privacy and security.
        
        Removes:
        - Tokens and API keys
        - Credentials and passwords  
        - Long evidence snippets
        - Personal identifiable information
        - Private keys and certificates (NEW for Hephaestus)
        
        Args:
            report: Original report dictionary
        
        Returns:
            Sanitized report safe for AI processing
        """
        import copy
        sanitized = copy.deepcopy(report)
        
        # Remove consent section (contains verification tokens)
        if 'consent' in sanitized:
            del sanitized['consent']
            logger.debug("Removed consent section from report")
        
        # Track sanitization stats
        tokens_removed = 0
        credentials_removed = 0
        private_keys_removed = 0
        certificates_removed = 0
        evidence_truncated = 0
        
        # Sanitize each finding
        for finding in sanitized.get('findings', []):
            if 'evidence' in finding:
                evidence = finding['evidence']
                
                # Remove tokens
                if self.config.ai_remove_tokens and 'value' in evidence:
                    original = evidence['value']
                    evidence['value'] = self._redact_tokens(evidence['value'])
                    if original != evidence['value']:
                        tokens_removed += 1
                
                # Remove credentials
                if self.config.ai_remove_credentials and 'value' in evidence:
                    original = evidence['value']
                    evidence['value'] = self._redact_credentials(evidence['value'])
                    if original != evidence['value']:
                        credentials_removed += 1
                
                # Remove private keys (NEW for Hephaestus)
                if self.config.ai_remove_private_keys and 'value' in evidence:
                    original = evidence['value']
                    evidence['value'] = self._redact_private_keys(evidence['value'])
                    if original != evidence['value']:
                        private_keys_removed += 1
                
                # Remove certificates (NEW for Hephaestus)
                if self.config.ai_remove_certificates and 'value' in evidence:
                    original = evidence['value']
                    evidence['value'] = self._redact_certificates(evidence['value'])
                    if original != evidence['value']:
                        certificates_removed += 1
                
                # Truncate long evidence
                if 'value' in evidence and len(evidence['value']) > self.config.ai_max_evidence_length:
                    evidence['value'] = evidence['value'][:self.config.ai_max_evidence_length] + "... [truncated]"
                    evidence_truncated += 1
                
                # Optionally sanitize URLs
                if self.config.ai_remove_urls and evidence.get('type') == 'url':
                    from urllib.parse import urlparse
                    parsed = urlparse(evidence['value'])
                    evidence['value'] = f"{parsed.scheme}://{parsed.netloc}/[path-redacted]"
        
        logger.info(
            f"Sanitization complete: {tokens_removed} tokens, "
            f"{credentials_removed} credentials, {private_keys_removed} private keys, "
            f"{certificates_removed} certificates, {evidence_truncated} truncated"
        )
        
        return sanitized
    
    def _redact_tokens(self, text: str) -> str:
        """Redact tokens and API keys from text."""
        if not text:
            return text
            
        patterns = [
            r'verify-[a-f0-9]{16}',
            r'Bearer\s+[A-Za-z0-9\-_\.]+',
            r'sk-[A-Za-z0-9]{48}',
            r'sk-ant-[A-Za-z0-9\-]+',
            r'[A-Za-z0-9]{32,}',
        ]
        
        for pattern in patterns:
            text = re.sub(pattern, '[REDACTED-TOKEN]', text, flags=re.IGNORECASE)
        
        return text
    
    def _redact_credentials(self, text: str) -> str:
        """Redact passwords and credentials from text."""
        if not text:
            return text
            
        patterns = [
            (r'(password["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
            (r'(passwd["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
            (r'(pwd["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
            (r'(apikey["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
            (r'(api_key["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
            (r'(secret["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
            (r'(db_password["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        ]
        
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        
        return text
    
    def _redact_private_keys(self, text: str) -> str:
        """Redact private keys from text (NEW for Hephaestus)."""
        if not text:
            return text
        
        # RSA/SSH private keys
        patterns = [
            (r'(-----BEGIN.*PRIVATE KEY-----)(.+?)(-----END.*PRIVATE KEY-----)', r'\1\n[REDACTED]\n\3'),
            (r'(-----BEGIN RSA PRIVATE KEY-----)(.+?)(-----END RSA PRIVATE KEY-----)', r'\1\n[REDACTED]\n\3'),
            (r'(-----BEGIN OPENSSH PRIVATE KEY-----)(.+?)(-----END OPENSSH PRIVATE KEY-----)', r'\1\n[REDACTED]\n\3'),
        ]
        
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.DOTALL | re.IGNORECASE)
        
        return text
    
    def _redact_certificates(self, text: str) -> str:
        """Redact certificate content from text (NEW for Hephaestus)."""
        if not text:
            return text
        
        # X.509 certificates
        patterns = [
            (r'(-----BEGIN CERTIFICATE-----)(.+?)(-----END CERTIFICATE-----)', r'\1\n[REDACTED]\n\3'),
            (r'(-----BEGIN TRUSTED CERTIFICATE-----)(.+?)(-----END TRUSTED CERTIFICATE-----)', r'\1\n[REDACTED]\n\3'),
        ]
        
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.DOTALL | re.IGNORECASE)
        
        return text
    
    def analyze_technical(self, report: Dict[str, Any]) -> str:
        """
        Generate technical remediation guide using LCEL.
        
        Modern LangChain v1.0.0 approach with proper error handling.
        
        Args:
            report: Scan report (will be sanitized)
        
        Returns:
            Technical analysis markdown text
        """
        logger.info(f"Generating technical remediation with {self.provider}")
        
        # Sanitize report for privacy
        sanitized = self.sanitize_report(report)
        
        # Create prompt template (works with all providers)
        prompt_template = PromptTemplate(
            input_variables=["report_json"],
            template=self.technical_prompt
        )
        
        # Build LCEL chain (LangChain Expression Language)
        chain = prompt_template | self.llm | self.output_parser
        
        # Generate analysis with error handling
        try:
            start_time = datetime.now(timezone.utc)
            
            # Invoke chain
            result = chain.invoke({
                "report_json": json.dumps(sanitized, indent=2)
            })
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(
                f"Technical analysis completed in {duration:.1f}s "
                f"({len(result)} chars)"
            )
            
            return result.strip()
        
        except Exception as e:
            logger.error(f"AI analysis failed ({self.provider}): {e}")
            
            # Provider-specific error messages
            if self.provider == 'ollama':
                return (
                    f"Ollama analysis failed: {e}\n\n"
                    "Troubleshooting:\n"
                    "1. Check Ollama is running: ollama serve\n"
                    "2. Verify model exists: ollama list\n"
                    f"3. Pull model if needed: ollama pull {self.model}"
                )
            elif self.provider == 'anthropic':
                return (
                    f"Anthropic analysis failed: {e}\n\n"
                    "Check your ANTHROPIC_API_KEY is valid."
                )
            else:
                return f"AI analysis unavailable ({self.provider}): {e}"
    
    def analyze_non_technical(self, report: Dict[str, Any]) -> str:
        """
        Generate executive summary for non-technical stakeholders.
        
        Uses same LCEL approach as technical analysis.
        
        Args:
            report: Scan report (will be sanitized)
        
        Returns:
            Executive summary text
        """
        logger.info(f"Generating executive summary with {self.provider}")
        
        # Sanitize report
        sanitized = self.sanitize_report(report)
        
        # Create prompt template
        prompt_template = PromptTemplate(
            input_variables=["report_json"],
            template=self.non_technical_prompt
        )
        
        # Build LCEL chain
        chain = prompt_template | self.llm | self.output_parser
        
        # Generate analysis
        try:
            start_time = datetime.now(timezone.utc)
            
            result = chain.invoke({
                "report_json": json.dumps(sanitized, indent=2)
            })
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.info(
                f"Executive summary completed in {duration:.1f}s "
                f"({len(result)} chars)"
            )
            
            return result.strip()
        
        except Exception as e:
            logger.error(f"Executive summary failed ({self.provider}): {e}")
            return f"Executive summary unavailable: {e}"
    
    def analyze_both(self, report: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate both technical and non-technical analyses.
        
        Args:
            report: Scan report
        
        Returns:
            Dictionary with both analyses
        """
        logger.info(f"Generating both analyses with {self.provider}")
        
        return {
            'executive_summary': self.analyze_non_technical(report),
            'technical_remediation': self.analyze_technical(report),
            'generated_at': report['date'],
            'model_used': f"{self.provider}/{self.model}"
        }


def analyze_report(
    report: Dict[str, Any],
    tone: str = 'both',
    config=None
) -> Optional[Dict[str, str]]:
    """
    Convenience function to analyze a report with AI.
    
    Entry point for scanner.py to use AI analysis.
    
    Args:
        report: Scan report dictionary
        tone: 'technical', 'non_technical', or 'both'
        config: Optional config override
    
    Returns:
        AI analysis dict or None if failed
    """
    try:
        analyzer = AIAnalyzer(config)
        
        if tone == 'technical':
            return {
                'technical_remediation': analyzer.analyze_technical(report),
                'generated_at': report['date'],
                'model_used': f"{analyzer.provider}/{analyzer.model}"
            }
        
        elif tone == 'non_technical':
            return {
                'executive_summary': analyzer.analyze_non_technical(report),
                'generated_at': report['date'],
                'model_used': f"{analyzer.provider}/{analyzer.model}"
            }
        
        else:  # both
            return analyzer.analyze_both(report)
    
    except Exception as e:
        logger.error(f"AI analysis initialization failed: {e}")
        return None


# =============================================================================
# TEST MODULE
# =============================================================================

if __name__ == "__main__":
    # Standalone test module for different AI providers
    from .config import Config
    import sys
    
    # Parse command line
    provider = sys.argv[1] if len(sys.argv) > 1 else 'openai'
    
    print(f"\n{'='*60}")
    print(f"HEPHAESTUS AI MODULE TEST - {provider.upper()}")
    print(f"{'='*60}\n")
    
    # Load config
    config = Config.load()
    config.ai_enabled = True
    config.ai_provider = provider
    
    # Configure based on provider
    if provider == 'openai':
        if not os.getenv('OPENAI_API_KEY'):
            print("❌ OPENAI_API_KEY not set")
            print("   Export it: export OPENAI_API_KEY='sk-...'")
            exit(1)
        config.ai_model = 'gpt-4-turbo-preview'
        print(f"✓ Using OpenAI {config.ai_model}")
    
    elif provider == 'anthropic':
        if not os.getenv('ANTHROPIC_API_KEY'):
            print("❌ ANTHROPIC_API_KEY not set")
            print("   Export it: export ANTHROPIC_API_KEY='sk-ant-...'")
            exit(1)
        config.ai_model = 'claude-3-5-sonnet-20241022'
        config.ai_api_key_env = 'ANTHROPIC_API_KEY'
        print(f"✓ Using Anthropic {config.ai_model}")
    
    elif provider == 'ollama':
        # Check Ollama server
        import requests
        try:
            resp = requests.get('http://localhost:11434/api/tags', timeout=5)
            models = resp.json().get('models', [])
            if not models:
                print("❌ No models found in Ollama")
                print("   Pull a model: ollama pull llama3.2")
                exit(1)
            
            # Use first available model or llama3.2 if present
            available_models = [m['name'] for m in models]
            if 'llama3.2' in available_models:
                config.ai_model = 'llama3.2'
            else:
                config.ai_model = available_models[0]
            
            config.ai_ollama_base_url = 'http://localhost:11434'
            print(f"✓ Using Ollama {config.ai_model}")
            print(f"  Available models: {', '.join(available_models)}")
            
        except Exception as e:
            print(f"❌ Ollama not running: {e}")
            print("   Start it: ollama serve")
            exit(1)
    
    else:
        print(f"❌ Unknown provider: {provider}")
        print("   Usage: python -m heph.core.ai [openai|anthropic|ollama]")
        exit(1)
    
    # Test report with realistic SERVER findings (not WordPress)
    test_report = {
        "tool": "hephaestus",
        "version": "0.1.0",
        "target": "https://vulnerable-server.example.com",
        "date": datetime.now(timezone.utc).isoformat(),
        "mode": "aggressive",
        "summary": {
            "critical": 2,
            "high": 3,
            "medium": 5,
            "low": 4,
            "info": 8
        },
        "findings": [
            {
                "id": "HEPH-FILE-001",
                "title": ".env file exposed",
                "severity": "critical",
                "confidence": "high",
                "evidence": {
                    "type": "path",
                    "value": "/.env",
                    "context": "HTTP 200 OK, file size: 1247 bytes, contains DB credentials"
                },
                "recommendation": "Move .env outside document root and rotate all credentials"
            },
            {
                "id": "HEPH-FILE-002",
                "title": "Git repository exposed",
                "severity": "critical",
                "confidence": "high",
                "evidence": {
                    "type": "path",
                    "value": "/.git/HEAD",
                    "context": "HTTP 200 OK, entire git history accessible"
                },
                "recommendation": "Block .git directory via web server config"
            },
            {
                "id": "HEPH-SRV-001",
                "title": "Server version disclosed",
                "severity": "high",
                "confidence": "high",
                "evidence": {
                    "type": "header",
                    "value": "Server: Apache/2.4.29 (Ubuntu)",
                    "context": "Disclosed in HTTP response header"
                },
                "recommendation": "Set ServerTokens Prod and ServerSignature Off"
            },
            {
                "id": "HEPH-SRV-002",
                "title": "PHP version disclosed",
                "severity": "high",
                "confidence": "high",
                "evidence": {
                    "type": "header",
                    "value": "X-Powered-By: PHP/7.2.24",
                    "context": "PHP version exposed in header"
                },
                "recommendation": "Set expose_php = Off in php.ini"
            },
            {
                "id": "HEPH-TLS-001",
                "title": "Weak TLS protocol (TLS 1.0)",
                "severity": "high",
                "confidence": "high",
                "evidence": {
                    "type": "protocol",
                    "value": "TLS 1.0",
                    "context": "Legacy protocol enabled, vulnerable to attacks"
                },
                "recommendation": "Disable TLS 1.0/1.1, enable only TLS 1.2+"
            },
            {
                "id": "HEPH-HDR-001",
                "title": "Missing HSTS header",
                "severity": "medium",
                "confidence": "high",
                "evidence": {
                    "type": "header",
                    "value": "Strict-Transport-Security: [not set]",
                    "context": "HTTPS enforcing header not present"
                },
                "recommendation": "Add Strict-Transport-Security header with max-age=31536000"
            }
        ],
        "consent": {
            "token": "verify-a3f9b2c1d8e4f5a6",  # Will be removed by sanitization
            "method": "http",
            "verified_at": "2025-01-15T10:30:00Z"
        }
    }
    
    try:
        print("\n[1/4] Initializing AI Analyzer...")
        analyzer = AIAnalyzer(config)
        print(f"✓ Analyzer ready: {analyzer.provider}/{analyzer.model}")
        
        print("\n[2/4] Testing Report Sanitization...")
        sanitized = analyzer.sanitize_report(test_report)
        
        # Verify sanitization worked
        assert 'consent' not in sanitized, "Consent should be removed"
        assert 'verify-' not in json.dumps(sanitized), "Tokens should be removed"
        print("✓ Sanitization successful")
        print(f"  - Original findings: {len(test_report['findings'])}")
        print(f"  - Sanitized findings: {len(sanitized['findings'])}")
        
        print(f"\n[3/4] Generating Executive Summary with {provider.upper()}...")
        print("-" * 40)
        summary = analyzer.analyze_non_technical(test_report)
        
        if "unavailable" in summary.lower() or "failed" in summary.lower():
            print(f"❌ Executive summary generation failed")
            print(summary)
        else:
            # Show first 500 chars
            preview = summary[:500] + "..." if len(summary) > 500 else summary
            print(preview)
            print("-" * 40)
            print(f"✓ Executive summary: {len(summary)} chars")
        
        print(f"\n[4/4] Generating Technical Guide with {provider.upper()}...")
        print("-" * 40)
        technical = analyzer.analyze_technical(test_report)
        
        if "unavailable" in technical.lower() or "failed" in technical.lower():
            print(f"❌ Technical guide generation failed")
            print(technical)
        else:
            # Show first 500 chars
            preview = technical[:500] + "..." if len(technical) > 500 else technical
            print(preview)
            print("-" * 40)
            print(f"✓ Technical guide: {len(technical)} chars")
        
        print(f"\n{'='*60}")
        print(f"✅ {provider.upper()} PROVIDER TEST COMPLETED")
        print(f"{'='*60}")
        
    except ImportError as e:
        print(f"\n❌ Import Error: {e}")
        print("\nInstall required packages:")
        if provider == 'openai':
            print("  pip install langchain-openai==1.0.0")
        elif provider == 'anthropic':
            print("  pip install langchain-anthropic==1.0.0 anthropic==0.71.0")
        elif provider == 'ollama':
            print("  pip install langchain-ollama>=0.3.0,<0.4.0")
            print("  # Or fallback: pip install langchain-community==0.4")
        exit(1)
        
    except Exception as e:
        print(f"\n❌ Test Failed: {e}")
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
        exit(1)