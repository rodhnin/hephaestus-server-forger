"""
Hephaestus AI Integration with LangChain v1.0.0

Provides AI-powered analysis using modern LangChain LCEL:
- Executive summaries for stakeholders
- Technical remediation guides for engineers
- Automatic sanitization of sensitive data

v0.2.0 additions:
- IMPROV-005: Cost tracking and budget enforcement
- IMPROV-006: Streaming output
- IMPROV-007: Multi-LLM comparison mode
- IMPROV-008: Agent with external tools (NVD CVE lookup + server vuln APIs)

Supports: OpenAI, Anthropic Claude, Ollama (local models)
Compatible with: langchain-core==1.0.0, langchain-community==0.4

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

import copy
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from langchain_core.prompts import PromptTemplate, ChatPromptTemplate, MessagesPlaceholder
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LANGCHAIN_CORE = True
except ImportError:
    HAS_LANGCHAIN_CORE = False

try:
    from langchain_openai import ChatOpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

try:
    from langchain_anthropic import ChatAnthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    from langchain_ollama import ChatOllama, OllamaLLM
    HAS_OLLAMA = True
except ImportError:
    try:
        from langchain_community.chat_models import ChatOllama
        from langchain_community.llms import Ollama as OllamaLLM
        HAS_OLLAMA = True
    except ImportError:
        HAS_OLLAMA = False

from .logging import get_logger
from .config import get_config

logger = get_logger(__name__)


# =============================================================================
# IMPROV-005: Pricing Table (identical to Argus — shared Argos Suite)
# =============================================================================

PRICING_TABLE = {
    'openai': {
        'gpt-4o-mini-2024-07-18':    {'input': 0.15,  'output': 0.60},   # Default (cheap, fast)
        'gpt-4o-2024-11-20':         {'input': 2.50,  'output': 10.00},
        'gpt-4o-2024-08-06':         {'input': 2.50,  'output': 10.00},
        'gpt-4-turbo-preview':       {'input': 10.00, 'output': 30.00},
        'gpt-4-turbo':               {'input': 10.00, 'output': 30.00},
        'gpt-4':                     {'input': 30.00, 'output': 60.00},
        'gpt-3.5-turbo':             {'input': 0.50,  'output': 1.50},
    },
    'anthropic': {
        'claude-3-5-sonnet-20241022': {'input': 3.00,  'output': 15.00},
        'claude-3-5-haiku-20241022':  {'input': 0.80,  'output': 4.00},
        'claude-3-opus-20240229':     {'input': 15.00, 'output': 75.00},
        'claude-3-sonnet-20240229':   {'input': 3.00,  'output': 15.00},
        'claude-3-haiku-20240307':    {'input': 0.25,  'output': 1.25},
    },
    'ollama': {},  # Local models — no cost
}


# =============================================================================
# IMPROV-005: Cost Tracker (identical pattern to Argus)
# =============================================================================

class AICostTracker:
    """
    Tracks AI token usage and costs across a scan session.

    Calculates costs from PRICING_TABLE, enforces budget limits,
    and persists results to ~/.argos/costs.json and the database.
    """

    def __init__(self, config=None):
        self.config = config or get_config()
        self._breakdown: Dict[str, Dict] = {}
        self._total_cost: float = 0.0
        self._total_input: int = 0
        self._total_output: int = 0

    def calculate_cost(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int
    ) -> float:
        """Calculate USD cost for a given token usage. Returns 0.0 for unknown models."""
        pricing = PRICING_TABLE.get(provider, {}).get(model)
        if not pricing:
            if provider != 'ollama':
                logger.warning(
                    f"No pricing data for {provider}/{model} — "
                    f"cost will be recorded as $0.00"
                )
            return 0.0

        cost = (
            input_tokens  * pricing['input'] +
            output_tokens * pricing['output']
        ) / 1_000_000

        return round(cost, 6)

    def record(
        self,
        label: str,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        duration_s: float
    ) -> float:
        """Record a completed analysis call. Returns the cost for this call."""
        cost = self.calculate_cost(provider, model, input_tokens, output_tokens)

        self._breakdown[label] = {
            'input_tokens':  input_tokens,
            'output_tokens': output_tokens,
            'cost_usd':      cost,
            'duration_s':    round(duration_s, 2),
        }
        self._total_cost   += cost
        self._total_input  += input_tokens
        self._total_output += output_tokens

        return cost

    def check_budget(self) -> Tuple[bool, bool, bool]:
        """
        Check budget status after latest accumulation.

        Returns:
            (within_budget, at_warning_threshold, should_abort)
        """
        if not self.config.ai_budget_enabled:
            return True, False, False

        max_cost  = self.config.ai_max_cost_per_scan
        warn_at   = max_cost * self.config.ai_warn_threshold
        exceeded  = self._total_cost >= max_cost
        at_warn   = self._total_cost >= warn_at

        should_abort = exceeded and self.config.ai_abort_on_exceed
        return not exceeded, at_warn, should_abort

    def print_cost_summary(self, provider: str, model: str):
        """Print cost breakdown to stdout after analysis."""
        if not self._breakdown:
            return

        print("")
        print("  AI Cost Summary:")
        for label, info in self._breakdown.items():
            tokens_total = info['input_tokens'] + info['output_tokens']
            print(
                f"    {label}: {tokens_total:,} tokens "
                f"(in={info['input_tokens']:,} out={info['output_tokens']:,}) "
                f"-> ${info['cost_usd']:.4f}  [{info['duration_s']:.1f}s]"
            )

        total_tokens = self._total_input + self._total_output
        print(
            f"    Total: {total_tokens:,} tokens -> ${self._total_cost:.4f}"
        )

        if self.config.ai_budget_enabled:
            used_pct = (self._total_cost / self.config.ai_max_cost_per_scan) * 100
            print(
                f"    Budget: ${self._total_cost:.4f} / "
                f"${self.config.ai_max_cost_per_scan:.4f} "
                f"({used_pct:.0f}% used)"
            )

    def save_to_file(
        self,
        scan_id: Optional[int],
        provider: str,
        model: str,
        db_path: Path
    ):
        """
        Append cost record to ~/.argos/costs.json (shared with Argus).
        Creates the file if it does not exist.
        """
        costs_path = Path(db_path).expanduser().parent / 'costs.json'
        costs_path.parent.mkdir(parents=True, exist_ok=True)

        record = {
            'scan_id':        scan_id,
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'tool':           'hephaestus',
            'provider':       provider,
            'model':          model,
            'breakdown':      self._breakdown,
            'total_cost_usd': round(self._total_cost, 6),
            'total_tokens':   self._total_input + self._total_output,
            'duration_s':     sum(v.get('duration_s', 0) for v in self._breakdown.values()),
        }

        try:
            if costs_path.exists():
                with costs_path.open('r', encoding='utf-8') as fh:
                    data = json.load(fh)
            else:
                data = {'scans': [], 'totals': {}}

            data['scans'].append(record)

            # Recompute totals
            all_costs = [s['total_cost_usd'] for s in data['scans']]
            total_cost = sum(all_costs)
            n = len(data['scans'])
            data['totals'] = {
                'total_scans':        n,
                'total_cost_usd':     round(total_cost, 4),
                'avg_cost_per_scan':  round(total_cost / n, 6) if n else 0.0,
                'monthly_projection': round((total_cost / max(n, 1)) * 30, 4),
            }

            with costs_path.open('w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2)

            logger.debug(f"Cost record appended to {costs_path}")

        except Exception as e:
            logger.warning(f"Could not save cost record to {costs_path}: {e}")

    @property
    def total_cost(self) -> float:
        return self._total_cost

    @property
    def breakdown(self) -> Dict:
        return dict(self._breakdown)


# =============================================================================
# IMPROV-008: Agent Tools (server-specific)
# =============================================================================

def _make_nvd_tool():
    """Create a NVD CVE lookup tool."""
    try:
        from langchain_core.tools import tool
        import requests as _requests

        @tool
        def lookup_nvd_cve(cve_id: str) -> str:
            """
            Look up CVE details from the National Vulnerability Database (NVD).
            Input: a CVE identifier like CVE-2023-12345.
            Returns severity, CVSS score, and description.
            """
            try:
                url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                resp = _requests.get(
                    url,
                    params={'cveId': cve_id.strip()},
                    timeout=10,
                    headers={'User-Agent': 'Hephaestus-Security-Scanner/0.2.0'}
                )
                if resp.status_code != 200:
                    return f"NVD lookup failed (HTTP {resp.status_code})"

                data = resp.json()
                vulns = data.get('vulnerabilities', [])
                if not vulns:
                    return f"No NVD record found for {cve_id}"

                cve = vulns[0].get('cve', {})
                desc_list = cve.get('descriptions', [])
                desc = next((d['value'] for d in desc_list if d.get('lang') == 'en'), 'No description')

                metrics = cve.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                cvss_score = 'N/A'
                severity = 'N/A'
                if cvss_v3:
                    cvss_data = cvss_v3[0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 'N/A')
                    severity   = cvss_data.get('baseSeverity', 'N/A')

                published = cve.get('published', 'N/A')[:10]

                return (
                    f"CVE: {cve_id}\n"
                    f"Severity: {severity} (CVSS {cvss_score})\n"
                    f"Published: {published}\n"
                    f"Description: {desc[:500]}"
                )

            except Exception as e:
                return f"NVD lookup error for {cve_id}: {e}"

        return lookup_nvd_cve

    except ImportError:
        return None


def _make_server_vuln_tool():
    """
    Create a server vulnerability search tool using NVD product search.
    Searches for vulnerabilities in specific server software versions.
    """
    try:
        from langchain_core.tools import tool
        import requests as _requests

        @tool
        def search_server_vulns(server_software: str) -> str:
            """
            Search for known vulnerabilities in server software using NVD.
            Input: server software name and version (e.g. 'Apache 2.4.29', 'nginx 1.18.0', 'PHP 7.4.3').
            Returns recent CVEs, severity, and fix versions.
            """
            try:
                # Parse software name and version
                parts = server_software.strip().split()
                keyword = server_software.strip()

                resp = _requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={
                        'keywordSearch': keyword,
                        'resultsPerPage': 5,
                        'pubStartDate': '2020-01-01T00:00:00.000',
                    },
                    timeout=10,
                    headers={'User-Agent': 'Hephaestus-Security-Scanner/0.2.0'}
                )

                if resp.status_code != 200:
                    return f"NVD search failed (HTTP {resp.status_code})"

                data = resp.json()
                vulns = data.get('vulnerabilities', [])
                total = data.get('totalResults', 0)

                if not vulns:
                    return f"No NVD records found for '{server_software}'"

                lines = [f"NVD results for '{server_software}': {total} total vulnerabilities (showing top {len(vulns)})"]

                for item in vulns:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', 'N/A')
                    descs = cve.get('descriptions', [])
                    desc = next((d['value'] for d in descs if d.get('lang') == 'en'), 'No description')

                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                    cvss_score = 'N/A'
                    severity = 'N/A'
                    if cvss_v3:
                        cvss_data = cvss_v3[0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 'N/A')
                        severity   = cvss_data.get('baseSeverity', 'N/A')

                    published = cve.get('published', 'N/A')[:10]
                    lines.append(
                        f"  [{cve_id}] {severity} (CVSS {cvss_score}) [{published}]: {desc[:200]}"
                    )

                return '\n'.join(lines)

            except Exception as e:
                return f"Server vulnerability search error for '{server_software}': {e}"

        return search_server_vulns

    except ImportError:
        return None


# =============================================================================
# Main AI Analyzer
# =============================================================================

class AIAnalyzer:
    """
    LangChain v1.0.0 AI analyzer for server security reports.
    Uses LCEL (LangChain Expression Language) exclusively.

    Supports:
    - OpenAI GPT models
    - Anthropic Claude models
    - Ollama local models

    v0.2.0 features:
    - Cost tracking and budget enforcement (IMPROV-005)
    - Streaming output (IMPROV-006)
    - Multi-LLM comparison mode (IMPROV-007)
    - Agent with external tools: NVD + server vulns (IMPROV-008)
    """

    def __init__(self, config=None):
        if not HAS_LANGCHAIN_CORE:
            raise ImportError(
                "LangChain Core required for AI features.\n"
                "  pip install langchain-core==1.0.0\n"
                "  pip install langchain-openai==1.0.0\n"
                "  pip install langchain-anthropic==1.0.0\n"
                "  pip install langchain-ollama>=0.3.0,<0.4.0"
            )

        self.config = config or get_config()
        self._sync_api_keys()
        self.llm = self._init_llm()
        self.output_parser = StrOutputParser()
        self.technical_prompt     = self._load_prompt('technical.txt')
        self.non_technical_prompt = self._load_prompt('non_technical.txt')
        self.provider = self.config.ai_provider.lower()
        self.model    = self.config.ai_model
        self.cost_tracker = AICostTracker(self.config)

        logger.info(f"AI analyzer initialized: {self.provider}/{self.model}")

    # ------------------------------------------------------------------
    # Initialization helpers
    # ------------------------------------------------------------------

    def _sync_api_keys(self):
        """Sync custom API key env var with provider standard env var."""
        custom_var = self.config.ai_api_key_env
        provider   = self.config.ai_provider.lower()

        if provider == 'openai':
            key = os.getenv(custom_var) or os.getenv('OPENAI_API_KEY')
            if key and custom_var != 'OPENAI_API_KEY':
                os.environ['OPENAI_API_KEY'] = key
                logger.debug(f"Synced {custom_var} -> OPENAI_API_KEY")

        elif provider == 'anthropic':
            key = os.getenv(custom_var) or os.getenv('ANTHROPIC_API_KEY')
            if key and custom_var != 'ANTHROPIC_API_KEY':
                os.environ['ANTHROPIC_API_KEY'] = key
                logger.debug(f"Synced {custom_var} -> ANTHROPIC_API_KEY")

    def _init_llm(self):
        """Initialize language model based on provider config."""
        provider  = self.config.ai_provider.lower()
        streaming = getattr(self.config, 'ai_streaming', False)

        if provider == 'openai':
            if not HAS_OPENAI:
                raise ImportError(
                    "OpenAI support not installed.\n"
                    "pip install langchain-openai==1.0.0"
                )
            if not os.getenv('OPENAI_API_KEY'):
                raise ValueError(
                    f"OpenAI API key not found. "
                    f"Set OPENAI_API_KEY or {self.config.ai_api_key_env}"
                )
            logger.info(f"Initializing OpenAI: {self.config.ai_model}")
            return ChatOpenAI(
                model=self.config.ai_model,
                temperature=self.config.ai_temperature,
                max_tokens=self.config.ai_max_tokens,
                streaming=streaming,
                verbose=False,
            )

        elif provider == 'anthropic':
            if not HAS_ANTHROPIC:
                raise ImportError(
                    "Anthropic support not installed.\n"
                    "pip install langchain-anthropic==1.0.0 anthropic==0.71.0"
                )
            if not os.getenv('ANTHROPIC_API_KEY'):
                raise ValueError(
                    f"Anthropic API key not found. "
                    f"Set ANTHROPIC_API_KEY or {self.config.ai_api_key_env}"
                )
            logger.info(f"Initializing Anthropic: {self.config.ai_model}")
            return ChatAnthropic(
                model=self.config.ai_model,
                temperature=self.config.ai_temperature,
                max_tokens=self.config.ai_max_tokens,
                timeout=60,
                max_retries=2,
                streaming=streaming,
            )

        elif provider == 'ollama':
            if not HAS_OLLAMA:
                raise ImportError(
                    "Ollama support not installed.\n"
                    "pip install langchain-ollama>=0.3.0,<0.4.0"
                )
            base_url = getattr(self.config, 'ai_ollama_base_url', 'http://localhost:11434')
            try:
                import requests as _req
                resp = _req.get(f"{base_url}/api/tags", timeout=5)
                if resp.status_code != 200:
                    raise ConnectionError(f"Ollama server not responding at {base_url}")
                models     = resp.json().get('models', [])
                model_names = [m['name'] for m in models]
                if self.config.ai_model not in model_names:
                    available = ', '.join(model_names) if model_names else 'none'
                    raise ValueError(
                        f"Model '{self.config.ai_model}' not found in Ollama.\n"
                        f"Available: {available}\n"
                        f"Pull it: ollama pull {self.config.ai_model}"
                    )
            except Exception as e:
                if isinstance(e, (ValueError, ConnectionError)):
                    raise
                raise ConnectionError(
                    f"Cannot connect to Ollama at {base_url}.\n"
                    f"Start Ollama: ollama serve\n"
                    f"Error: {e}"
                )
            logger.info(f"Initializing Ollama: {self.config.ai_model} at {base_url}")
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
                    timeout=180,
                    verbose=False,
                )
            except Exception as e:
                logger.warning(f"ChatOllama init failed ({e}), falling back to OllamaLLM")
                return OllamaLLM(
                    model=self.config.ai_model,
                    base_url=base_url,
                    temperature=self.config.ai_temperature,
                    num_predict=self.config.ai_max_tokens,
                    num_ctx=8192,
                    verbose=False,
                )

        else:
            raise ValueError(
                f"Unsupported AI provider: '{provider}'.\n"
                f"Supported: openai, anthropic, ollama"
            )

    def _load_prompt(self, filename: str) -> str:
        """Load prompt template from config/prompts/."""
        prompt_path = (
            Path(__file__).parent.parent.parent
            / self.config.ai_prompts_dir
            / filename
        )
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt template missing: {prompt_path}")
        with prompt_path.open('r', encoding='utf-8') as fh:
            content = fh.read()
        logger.debug(f"Loaded prompt {filename} ({len(content)} chars)")
        return content

    # ------------------------------------------------------------------
    # Report sanitization
    # ------------------------------------------------------------------

    def sanitize_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize report before sending to AI provider.
        Removes consent tokens, private keys, certificates, credentials,
        and truncates long evidence.
        """
        sanitized = copy.deepcopy(report)

        # Remove consent section
        sanitized.pop('consent', None)

        tokens_removed      = 0
        credentials_removed = 0
        keys_removed        = 0
        certs_removed       = 0
        evidence_truncated  = 0

        for finding in sanitized.get('findings', []):
            evidence = finding.get('evidence', {})
            if not evidence:
                continue

            if self.config.ai_remove_tokens and 'value' in evidence:
                original = evidence['value']
                evidence['value'] = self._redact_tokens(evidence['value'])
                if original != evidence['value']:
                    tokens_removed += 1

            if self.config.ai_remove_credentials and 'value' in evidence:
                original = evidence['value']
                evidence['value'] = self._redact_credentials(evidence['value'])
                if original != evidence['value']:
                    credentials_removed += 1

            if self.config.ai_remove_private_keys and 'value' in evidence:
                original = evidence['value']
                evidence['value'] = self._redact_private_keys(evidence['value'])
                if original != evidence['value']:
                    keys_removed += 1

            if self.config.ai_remove_certificates and 'value' in evidence:
                original = evidence['value']
                evidence['value'] = self._redact_certificates(evidence['value'])
                if original != evidence['value']:
                    certs_removed += 1

            if 'value' in evidence and len(evidence['value']) > self.config.ai_max_evidence_length:
                evidence['value'] = (
                    evidence['value'][:self.config.ai_max_evidence_length] + '... [truncated]'
                )
                evidence_truncated += 1

            if self.config.ai_remove_urls and evidence.get('type') == 'url':
                from urllib.parse import urlparse
                parsed = urlparse(evidence['value'])
                evidence['value'] = f"{parsed.scheme}://{parsed.netloc}/[path-redacted]"

        # Inject computed total so the LLM doesn't have to calculate it
        if 'summary' in sanitized:
            total = sum(v for k, v in sanitized['summary'].items() if not k.startswith('_'))
            sanitized['summary']['_total_findings'] = total

        logger.info(
            f"Sanitization: {tokens_removed} tokens, {credentials_removed} credentials, "
            f"{keys_removed} private keys, {certs_removed} certificates, "
            f"{evidence_truncated} truncated"
        )
        return sanitized

    def _redact_tokens(self, text: str) -> str:
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
        if not text:
            return text
        patterns = [
            (r'(password["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
            (r'(passwd["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)',   r'\1[REDACTED]'),
            (r'(pwd["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)',      r'\1[REDACTED]'),
            (r'(apikey["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)',   r'\1[REDACTED]'),
            (r'(api_key["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)',  r'\1[REDACTED]'),
            (r'(secret["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)',   r'\1[REDACTED]'),
            (r'(db_password["\']?\s*[:=]\s*["\']?)([^"\'}\s]+)', r'\1[REDACTED]'),
        ]
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text

    def _redact_private_keys(self, text: str) -> str:
        if not text:
            return text
        patterns = [
            (r'(-----BEGIN.*PRIVATE KEY-----)(.+?)(-----END.*PRIVATE KEY-----)', r'\1\n[REDACTED]\n\3'),
            (r'(-----BEGIN RSA PRIVATE KEY-----)(.+?)(-----END RSA PRIVATE KEY-----)', r'\1\n[REDACTED]\n\3'),
            (r'(-----BEGIN OPENSSH PRIVATE KEY-----)(.+?)(-----END OPENSSH PRIVATE KEY-----)', r'\1\n[REDACTED]\n\3'),
        ]
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.DOTALL | re.IGNORECASE)
        return text

    def _redact_certificates(self, text: str) -> str:
        if not text:
            return text
        patterns = [
            (r'(-----BEGIN CERTIFICATE-----)(.+?)(-----END CERTIFICATE-----)', r'\1\n[REDACTED]\n\3'),
            (r'(-----BEGIN TRUSTED CERTIFICATE-----)(.+?)(-----END TRUSTED CERTIFICATE-----)', r'\1\n[REDACTED]\n\3'),
        ]
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.DOTALL | re.IGNORECASE)
        return text

    # ------------------------------------------------------------------
    # IMPROV-005/006: Core invoke with cost tracking + streaming
    # ------------------------------------------------------------------

    def _invoke_with_tracking(
        self,
        prompt_template,
        inputs: Dict,
        label: str
    ) -> str:
        """
        Invoke a prompt + LLM chain with token tracking.

        IMPROV-005: captures usage_metadata for cost calculation.
        IMPROV-006: streams output when config.ai_streaming is True.

        Returns the generated text.
        """
        # Check budget before this call
        within, at_warn, should_abort = self.cost_tracker.check_budget()
        if should_abort:
            raise RuntimeError(
                f"AI budget exceeded: "
                f"${self.cost_tracker.total_cost:.4f} >= "
                f"${self.config.ai_max_cost_per_scan:.4f}. "
                f"Aborting AI analysis."
            )
        if at_warn:
            print(
                f"  WARNING: AI cost at "
                f"${self.cost_tracker.total_cost:.4f} / "
                f"${self.config.ai_max_cost_per_scan:.4f} "
                f"({self.config.ai_warn_threshold * 100:.0f}% threshold reached)"
            )

        start = time.time()

        if getattr(self.config, 'ai_streaming', False):
            text = self._stream_output(prompt_template, inputs, label)
            duration = time.time() - start
            estimated_tokens = len(text) // 4
            self.cost_tracker.record(
                label, self.provider, self.model,
                input_tokens=0, output_tokens=estimated_tokens,
                duration_s=duration
            )
        else:
            text, input_tokens, output_tokens = self._invoke_and_capture(
                prompt_template, inputs
            )
            duration = time.time() - start
            self.cost_tracker.record(
                label, self.provider, self.model,
                input_tokens=input_tokens, output_tokens=output_tokens,
                duration_s=duration
            )
            logger.info(
                f"{label} completed in {duration:.1f}s "
                f"({input_tokens + output_tokens:,} tokens, "
                f"${self.cost_tracker.breakdown.get(label, {}).get('cost_usd', 0):.4f})"
            )

        return text

    def _invoke_and_capture(
        self,
        prompt_template,
        inputs: Dict
    ) -> Tuple[str, int, int]:
        """
        Standard invoke; extracts token usage from AIMessage metadata.
        Returns (text, input_tokens, output_tokens).
        """
        chain_to_llm = prompt_template | self.llm
        ai_message   = chain_to_llm.invoke(inputs)
        text = self.output_parser.invoke(ai_message)

        usage = getattr(ai_message, 'usage_metadata', None) or {}
        input_tokens  = usage.get('input_tokens',  0)
        output_tokens = usage.get('output_tokens', 0)

        if not input_tokens and not output_tokens:
            resp_meta = getattr(ai_message, 'response_metadata', {}) or {}
            usage2 = resp_meta.get('usage', resp_meta.get('token_usage', {}))
            input_tokens  = usage2.get('input_tokens',  usage2.get('prompt_tokens',     0))
            output_tokens = usage2.get('output_tokens', usage2.get('completion_tokens', 0))

        return text.strip(), input_tokens, output_tokens

    def _stream_output(
        self,
        prompt_template,
        inputs: Dict,
        label: str
    ) -> str:
        """
        Stream LLM output character by character to stdout.
        IMPROV-006: provides real-time feedback during generation.
        """
        print(f"  [{label}] generating...", flush=True)

        chain  = prompt_template | self.llm | self.output_parser
        chunks = []

        try:
            for chunk in chain.stream(inputs):
                if isinstance(chunk, str):
                    chunks.append(chunk)
                elif hasattr(chunk, 'content'):
                    chunks.append(chunk.content)
                else:
                    chunks.append(str(chunk))
                sys.stdout.write(chunks[-1])
                sys.stdout.flush()
        except Exception as e:
            logger.error(f"Streaming failed for {label}: {e}")
            print(f"\n  [streaming failed, retrying without streaming]")
            try:
                result = (prompt_template | self.llm | self.output_parser).invoke(inputs)
                return result.strip()
            except Exception as e2:
                raise RuntimeError(f"Both streaming and non-streaming failed: {e2}")

        sys.stdout.write('\n')
        sys.stdout.flush()

        return ''.join(chunks).strip()

    # ------------------------------------------------------------------
    # Analysis methods
    # ------------------------------------------------------------------

    def analyze_technical(self, report: Dict[str, Any]) -> str:
        """Generate technical remediation guide."""
        logger.info(f"Generating technical remediation with {self.provider}/{self.model}")
        sanitized = self.sanitize_report(report)
        prompt_template = PromptTemplate(
            input_variables=["report_json"],
            template=self.technical_prompt
        )
        try:
            return self._invoke_with_tracking(
                prompt_template,
                {"report_json": json.dumps(sanitized, indent=2)},
                label="technical"
            )
        except RuntimeError as e:
            logger.error(str(e))
            return f"Technical analysis aborted: {e}"
        except Exception as e:
            logger.error(f"Technical analysis failed ({self.provider}): {e}")
            return self._error_message('technical', e)

    def analyze_non_technical(self, report: Dict[str, Any]) -> str:
        """Generate executive summary for non-technical stakeholders."""
        logger.info(f"Generating executive summary with {self.provider}/{self.model}")
        sanitized = self.sanitize_report(report)
        prompt_template = PromptTemplate(
            input_variables=["report_json"],
            template=self.non_technical_prompt
        )
        try:
            return self._invoke_with_tracking(
                prompt_template,
                {"report_json": json.dumps(sanitized, indent=2)},
                label="non_technical"
            )
        except RuntimeError as e:
            logger.error(str(e))
            return f"Executive summary aborted: {e}"
        except Exception as e:
            logger.error(f"Executive summary failed ({self.provider}): {e}")
            return self._error_message('non_technical', e)

    def analyze_both(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate both technical and non-technical analyses."""
        logger.info(f"Generating both analyses with {self.provider}/{self.model}")
        return {
            'executive_summary':     self.analyze_non_technical(report),
            'technical_remediation': self.analyze_technical(report),
            'generated_at':          report.get('date', datetime.now(timezone.utc).isoformat()),
            'model_used':            f"{self.provider}/{self.model}",
        }

    def _error_message(self, analysis_type: str, error: Exception) -> str:
        if self.provider == 'ollama':
            return (
                f"Ollama {analysis_type} analysis failed: {error}\n\n"
                "Troubleshooting:\n"
                "  1. Confirm Ollama is running: ollama serve\n"
                "  2. Verify model exists: ollama list\n"
                f"  3. Pull model if needed: ollama pull {self.model}"
            )
        elif self.provider == 'anthropic':
            return (
                f"Anthropic {analysis_type} analysis failed: {error}\n"
                "Check your ANTHROPIC_API_KEY is valid."
            )
        return f"AI {analysis_type} analysis unavailable ({self.provider}): {error}"

    # ------------------------------------------------------------------
    # IMPROV-007: Multi-LLM comparison mode
    # ------------------------------------------------------------------

    def compare_providers(
        self,
        report: Dict[str, Any],
        providers_config: List[Dict[str, str]],
        tone: str = 'both'
    ) -> Dict[str, Any]:
        """
        Run analysis through multiple providers and return side-by-side results.
        IMPROV-007: Multi-LLM comparison mode.

        Args:
            report: Scan report dictionary
            providers_config: List of dicts with keys 'provider' and 'model'
            tone: 'technical', 'non_technical', or 'both'

        Returns:
            Dict with comparison_mode, providers_compared, results, cost info
        """
        results     = {}
        cost_totals = {}

        def _analyze_one(prov_cfg: Dict) -> Tuple[str, Dict]:
            prov_label = f"{prov_cfg['provider']}/{prov_cfg['model']}"
            try:
                temp_config            = copy.copy(self.config)
                temp_config.ai_provider = prov_cfg['provider']
                temp_config.ai_model    = prov_cfg['model']

                analyzer = AIAnalyzer(temp_config)

                if tone == 'technical':
                    result = {'technical_remediation': analyzer.analyze_technical(report)}
                elif tone == 'non_technical':
                    result = {'executive_summary': analyzer.analyze_non_technical(report)}
                else:
                    result = analyzer.analyze_both(report)

                cost_totals[prov_label] = analyzer.cost_tracker.total_cost
                return prov_label, result

            except Exception as e:
                logger.error(f"Compare mode: {prov_cfg['provider']} failed: {e}")
                return prov_label, {'error': str(e)}

        with ThreadPoolExecutor(max_workers=len(providers_config)) as executor:
            futures = [executor.submit(_analyze_one, pc) for pc in providers_config]
            for future in as_completed(futures):
                label, result = future.result()
                results[label] = result

        return {
            'comparison_mode':    True,
            'providers_compared': list(results.keys()),
            'results':            results,
            'cost_by_provider':   cost_totals,
            'generated_at':       datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # IMPROV-008: Agent with external tools (server-specific)
    # ------------------------------------------------------------------

    def analyze_with_agent(self, report: Dict[str, Any]) -> str:
        """
        Run AI agent with external tools for enhanced server security analysis.
        IMPROV-008: Manual tool-calling loop with NVD CVE lookup and server vuln search.

        Tools:
          - lookup_nvd_cve       : NVD CVE database
          - search_server_vulns  : NVD product vulnerability search

        Loop:
          1. LLM receives report + system prompt
          2. If LLM returns tool_calls -> execute each tool -> ToolMessage -> re-invoke
          3. When LLM returns no tool_calls -> final answer
        """
        from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

        # Build tool list
        tools = []

        nvd_tool = _make_nvd_tool()
        if nvd_tool:
            tools.append(nvd_tool)
            logger.debug("Agent tool registered: lookup_nvd_cve")

        server_vuln_tool = _make_server_vuln_tool()
        if server_vuln_tool:
            tools.append(server_vuln_tool)
            logger.debug("Agent tool registered: search_server_vulns (NVD product search)")

        sanitized   = self.sanitize_report(report)
        report_json = json.dumps(sanitized, indent=2)

        agent_system = (
            "You are a senior server security engineer analyzing a Hephaestus scan report. "
            "You have two tools available to enrich your analysis with live NVD data.\n\n"
            "STEP 1 - TOOL USE (required before writing):\n"
            "  a) For each critical/high finding that has a CVE ID in its 'cve' array, "
            "call lookup_nvd_cve with that CVE ID to get CVSS score and description.\n"
            "  b) For each server software version disclosed (e.g. 'Apache 2.4.29', 'PHP 7.4.3', "
            "'nginx 1.18.0'), call search_server_vulns with the software name and version to "
            "find known vulnerabilities.\n"
            "  c) Perform ALL tool calls before writing your final analysis.\n\n"
            "STEP 2 - WRITE ANALYSIS with these sections:\n"
            "  ### Executive Summary (2-3 sentences)\n"
            "  ### Critical & High Findings (enriched with NVD CVSS scores)\n"
            "  ### Server Software Vulnerabilities (CVEs found for disclosed versions)\n"
            "  ### TLS/SSL Issues (protocol and certificate problems)\n"
            "  ### Prioritized Remediation (numbered, most critical first)\n\n"
            "RULES:\n"
            "- Cover ALL critical and high findings from the report\n"
            "- Include real CVSS scores from NVD where available\n"
            "- Be specific: include server versions, CVE IDs, configuration directives\n"
            "- Provide Apache httpd.conf AND Nginx nginx.conf config snippets where applicable\n"
            "- Do not repeat the raw JSON data\n"
            "- Total findings = sum of all severity counts in summary field"
        )

        start = time.time()

        if tools:
            llm_with_tools = self.llm.bind_tools(tools)
        else:
            llm_with_tools = self.llm

        tools_by_name = {t.name: t for t in tools}

        messages = [
            SystemMessage(content=agent_system),
            HumanMessage(content=report_json),
        ]

        max_iterations = getattr(self.config, 'ai_agent_max_iterations', 10)
        iteration      = 0
        text           = ""

        try:
            while iteration < max_iterations:
                iteration += 1
                response = llm_with_tools.invoke(messages)
                messages.append(response)

                tool_calls = getattr(response, 'tool_calls', []) or []

                if not tool_calls:
                    text = getattr(response, 'content', '') or ''
                    break

                logger.debug(f"Agent iteration {iteration}: {len(tool_calls)} tool call(s)")
                for tc in tool_calls:
                    tool_name    = tc.get('name', '')
                    tool_args    = tc.get('args', {})
                    tool_call_id = tc.get('id', '')

                    if tool_name in tools_by_name:
                        try:
                            tool_output = str(tools_by_name[tool_name].invoke(tool_args))
                            logger.debug(f"Tool {tool_name}: {tool_output[:100]}")
                        except Exception as te:
                            tool_output = f"Tool error: {te}"
                    else:
                        tool_output = f"Unknown tool: {tool_name}"

                    messages.append(
                        ToolMessage(
                            content=tool_output,
                            tool_call_id=tool_call_id,
                        )
                    )

            else:
                messages.append(
                    HumanMessage(content="Please provide your final security analysis based on the information gathered.")
                )
                final = llm_with_tools.invoke(messages)
                text  = getattr(final, 'content', '') or ''

        except Exception as e:
            logger.error(f"Agent analysis failed: {e}")
            raise

        duration = time.time() - start
        estimated_input  = len(report_json) // 4
        estimated_output = len(text) // 4
        self.cost_tracker.record(
            'agent', self.provider, self.model,
            input_tokens=estimated_input,
            output_tokens=estimated_output,
            duration_s=duration
        )
        logger.info(f"Agent analysis completed in {duration:.1f}s")

        return text.strip()


# =============================================================================
# Convenience entry point for scanner.py
# =============================================================================

def _persist_costs(analyzer: AIAnalyzer, scan_id: Optional[int], config):
    """Persist cost data to DB and costs.json file."""
    if not analyzer.cost_tracker.breakdown:
        return
    try:
        db_path = getattr(config, 'database', Path.home() / '.argos' / 'argos.db')
        analyzer.cost_tracker.save_to_file(scan_id, analyzer.provider, analyzer.model, db_path)
    except Exception as e:
        logger.warning(f"Could not persist AI costs: {e}")


def analyze_report(
    report: Dict[str, Any],
    tone: str = 'both',
    config=None,
    scan_id: Optional[int] = None,
    compare_providers: Optional[List[Dict[str, str]]] = None,
    use_agent: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Convenience function to analyze a report with AI.
    Entry point for scanner.py.

    Args:
        report: Scan report dictionary
        tone: 'technical', 'non_technical', or 'both'
        config: Optional config override
        scan_id: Scan ID for cost DB record
        compare_providers: List of {provider, model} dicts for IMPROV-007
        use_agent: Use agent mode for IMPROV-008

    Returns:
        AI analysis dict or None if failed
    """
    try:
        analyzer = AIAnalyzer(config)

        if compare_providers:
            if use_agent:
                logger.warning(
                    "--ai-agent is not compatible with --ai-compare in this version. "
                    "Agent mode requires a single provider context and will be ignored. "
                    "To use agent mode, run without --ai-compare."
                )
            result = analyzer.compare_providers(report, compare_providers, tone=tone)

        elif use_agent:
            agent_text = analyzer.analyze_with_agent(report)
            result = {
                'agent_analysis': agent_text,
                'generated_at':   report.get('date', datetime.now(timezone.utc).isoformat()),
                'model_used':     f"{analyzer.provider}/{analyzer.model}",
            }

        elif tone == 'technical':
            result = {
                'technical_remediation': analyzer.analyze_technical(report),
                'generated_at':          report.get('date', datetime.now(timezone.utc).isoformat()),
                'model_used':            f"{analyzer.provider}/{analyzer.model}",
            }

        elif tone == 'non_technical':
            result = {
                'executive_summary': analyzer.analyze_non_technical(report),
                'generated_at':      report.get('date', datetime.now(timezone.utc).isoformat()),
                'model_used':        f"{analyzer.provider}/{analyzer.model}",
            }

        else:
            result = analyzer.analyze_both(report)

        # Print cost summary to stdout
        analyzer.cost_tracker.print_cost_summary(analyzer.provider, analyzer.model)

        # Persist costs
        _persist_costs(analyzer, scan_id, config)

        # Attach cost metadata to result
        if result:
            if compare_providers:
                compare_total = sum(result.get('cost_by_provider', {}).values())
                result['cost'] = {
                    'total_usd': compare_total,
                    'breakdown': result.get('cost_by_provider', {}),
                    'provider':  'compare',
                    'model':     ','.join(p.get('model', '') for p in compare_providers),
                }
            else:
                result['cost'] = {
                    'total_usd': analyzer.cost_tracker.total_cost,
                    'breakdown': analyzer.cost_tracker.breakdown,
                    'provider':  analyzer.provider,
                    'model':     analyzer.model,
                }

        return result

    except Exception as e:
        logger.error(f"AI analysis initialization failed: {e}")
        return None
