# AI Integration Guide - Hephaestus

Hephaestus uses **LangChain v1.0.0** to provide intelligent analysis of server security findings through Large Language Models (LLMs).

## Overview

The AI assistant generates two types of analysis from scan results:

1. **Executive Summary** (non-technical) - For business stakeholders, managers, C-suite
2. **Technical Hardening Guide** - For system administrators, DevOps engineers, security teams

Both are generated from the JSON scan report using carefully crafted prompts and sanitized input.

---

## 🧪 Testing AI Integration

### Standalone Test Module

Hephaestus includes a built-in test module to verify AI provider configuration before running full scans:

```bash
# Test OpenAI (default)
python -m heph.core.ai openai

# Test Anthropic Claude
python -m heph.core.ai anthropic

# Test Ollama (local)
python -m heph.core.ai ollama
```

This test will:

1. Initialize the AI provider
2. Verify API keys/connectivity
3. Test report sanitization
4. Generate sample executive summary
5. Generate sample technical hardening guide
6. Report success/failure with diagnostics

**Use this test to verify your AI setup is working before running production scans.**

---

## Prerequisites

### Required Dependencies

```bash
# Core LangChain v1.0.0
pip install langchain-core==1.0.0

# For OpenAI
pip install langchain-openai==1.0.0

# For Anthropic Claude
pip install langchain-anthropic==1.0.0 anthropic==0.71.0

# For Ollama (local models)
pip install "langchain-ollama>=0.3.0,<0.4.0"
```

### API Keys

Set your API key as an environment variable:

```bash
# OpenAI (default)
export OPENAI_API_KEY="sk-..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Ollama - No API key needed (local)
```

---

## Configuration

### ⚠️ IMPORTANT: Provider Switching (v0.1.0)

**Current Method:** Provider selection is configured in `config/defaults.yaml`.

**To switch providers, you must edit the YAML file directly:**

```yaml
ai:
    langchain:
        provider: "openai" # Change this to: openai, anthropic, or ollama
        model: "gpt-4-turbo-preview" # Update model based on provider
        temperature: 0.3
        max_tokens: 2000

        # For Ollama only - add this section:
        ollama_base_url: "http://localhost:11434"
```

### Provider-Specific Configuration

#### OpenAI (Default)

```yaml
ai:
    langchain:
        provider: "openai"
        model: "gpt-4-turbo-preview" # or gpt-4, gpt-3.5-turbo
    api_key_env: "OPENAI_API_KEY"
```

#### Anthropic Claude

```yaml
ai:
    langchain:
        provider: "anthropic"
        model: "claude-3-5-sonnet-20241022" # or claude-3-opus, claude-3-haiku
    api_key_env: "ANTHROPIC_API_KEY"
```

#### Ollama (Local)

```yaml
ai:
    langchain:
        provider: "ollama"
        model: "llama3.2" # or whatever model you have pulled
        ollama_base_url: "http://localhost:11434"
    # No API key needed for Ollama
```

### Future Enhancement (v0.3.0)

In version 0.3.0, we will implement an interactive configuration system:

-   Dynamic provider switching without editing YAML
-   Runtime model selection
-   Interactive configuration menu
-   Profile management for different scenarios

For now, manual YAML editing is required for provider switching.

---

## Usage

### Basic AI Analysis

```bash
# 1. Configure provider in config/defaults.yaml (see above)

# 2. Verify domain consent
python -m heph --gen-consent example.com
python -m heph --verify-consent http --domain example.com --token verify-abc123

# 3. Run scan with AI
python -m heph --target https://example.com --use-ai --html

# Different analysis tones
python -m heph --target https://example.com --use-ai --ai-tone technical
python -m heph --target https://example.com --use-ai --ai-tone non_technical
python -m heph --target https://example.com --use-ai --ai-tone both
```

### Aggressive Mode + AI

```bash
# Requires consent verification
python -m heph --target https://example.com --aggressive --use-ai --html
```

**Benefits:**

-   More findings detected (8 req/s rate)
-   Deeper analysis from AI
-   Comprehensive hardening guide

---

## Privacy & Security

### Data Sanitization

Before sending reports to AI, Hephaestus automatically removes sensitive information.

**What Gets Removed:**

-   ✅ Consent tokens (`verify-abc123...`)
-   ✅ Bearer tokens and API keys
-   ✅ Passwords and credentials
-   ✅ Private keys (RSA, SSH)
-   ✅ Certificates (X.509)
-   ✅ Cookie values and session IDs
-   ✅ Long evidence snippets (truncated to 500 chars)

**What Gets Sent (Sanitized):**

-   Finding IDs (HEPH-SRV-001, HEPH-FILE-002, etc.)
-   Finding titles and descriptions
-   Severity levels
-   Redacted/truncated evidence
-   Generic recommendations
-   External reference URLs

### Privacy Recommendations

| Concern Level        | Recommended Provider | Why                                             |
| -------------------- | -------------------- | ----------------------------------------------- |
| **High Privacy**     | Ollama (local)       | Data never leaves your machine                  |
| **Moderate Privacy** | Anthropic Claude     | Strong privacy policy, no training on user data |
| **Standard**         | OpenAI GPT-4         | Best analysis quality, standard privacy         |

⚠️ **Note on Ollama:** While 100% private, local models may generate less accurate analysis for complex server configurations. Best for sensitive environments where privacy is paramount.

---

## Providers Comparison

### OpenAI GPT-4 (Default)

**Pros:**

-   Best analysis quality
-   Extensive server configuration knowledge
-   Fast response (15-25s)
-   Handles complex reports well
-   Up-to-date security practices

**Cons:**

-   Requires internet
-   Costs money ($0.10-0.30/scan)
-   Data sent to OpenAI servers

**Best For:** Production reports, client deliverables, complex findings

### Anthropic Claude

**Pros:**

-   Strong technical reasoning
-   Excellent with configuration files
-   Privacy-focused company
-   Competitive pricing
-   Good code snippet generation

**Cons:**

-   Requires internet
-   Costs money ($0.15-0.45/scan)
-   Slightly slower than GPT-4

**Best For:** Technical deep-dives, configuration audits, EU clients (privacy)

### Ollama (Local Models)

**Pros:**

-   100% offline operation
-   Complete privacy (no data leaves machine)
-   Free (no API costs)
-   No internet required

**Cons:**

-   Lower quality analysis
-   Very slow without GPU (10-30 minutes)
-   May struggle with complex configurations
-   Requires local setup

**Best For:** Sensitive environments, air-gapped networks, learning/testing

### Performance Comparison

| Provider         | Executive Summary | Technical Guide | Total Time | Quality    |
| ---------------- | ----------------- | --------------- | ---------- | ---------- |
| OpenAI GPT-4     | ~10s              | ~15s            | ~25s       | ⭐⭐⭐⭐⭐ |
| Anthropic Claude | ~15s              | ~20s            | ~35s       | ⭐⭐⭐⭐⭐ |
| Ollama (CPU)     | ~12min            | ~15min          | ~27min     | ⭐⭐⭐     |
| Ollama (GPU)     | ~25s              | ~35s            | ~60s       | ⭐⭐⭐     |

---

## Ollama Setup Guide

For **offline operation** with local models:

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Start Ollama server
ollama serve &

# 3. Pull a model (llama3.2 recommended for balance)
ollama pull llama3.2

# 4. Verify it's working
ollama list
curl http://localhost:11434/api/tags

# 5. Update config/defaults.yaml
ai:
  langchain:
    provider: "ollama"
    model: "llama3.2:latest"
    ollama_base_url: "http://localhost:11434"

# 6. Test the integration
python -m heph.core.ai ollama

# 7. Run a scan
python -m heph --target http://localhost:8080 --use-ai --html
```

**Recommended Models:**

-   `llama3.2` - Best balance (3.9GB)
-   `mistral` - Good for configurations (4.1GB)
-   `codellama` - Technical focus (3.8GB)
-   `phi3` - Smallest/fastest (2.2GB)

---

## Custom Prompts

Prompts are stored in `heph/prompts/`:

### Technical Prompt (`technical.txt`)

-   Server-specific hardening steps
-   Apache/Nginx/PHP configurations
-   TLS/SSL hardening
-   Command examples with verification
-   Prioritized action plan
-   Prevention & monitoring recommendations

### Non-Technical Prompt (`non_technical.txt`)

-   Business impact assessment
-   Financial & regulatory risks
-   Executive-level actions
-   Industry context
-   Plain language (no jargon)
-   Quantified risks ($, %, time)

Edit these files to customize AI output for your needs or organizational standards.

---

## Troubleshooting

### Provider Not Working?

Run the standalone test:

```bash
python -m heph.core.ai [provider_name]
```

This will tell you exactly what's wrong.

### Common Issues

#### "API key not found"

-   Check environment variable is set
-   For OpenAI: `echo $OPENAI_API_KEY`
-   For Anthropic: `echo $ANTHROPIC_API_KEY`

#### "Ollama server not responding"

-   Start server: `ollama serve`
-   Check it's running: `ps aux | grep ollama`
-   Verify port: `curl http://localhost:11434/api/tags`

#### "Model not found" (Ollama)

-   Pull the model: `ollama pull llama3.2`
-   List models: `ollama list`
-   Update defaults.yaml with correct model name

#### "Rate limit exceeded"

-   Reduce max_tokens in config
-   Wait and retry
-   Use `--ai-tone technical` (smaller output)

#### "AI analysis failed"

1. Run standalone test: `python -m heph.core.ai [provider]`
2. Check provider configuration in defaults.yaml
3. Verify API keys/connectivity
4. Try with a simpler report (fewer findings)

#### "Input to PromptTemplate is missing variables"

-   This was a bug in v0.1.0 (fixed in templates)
-   Update your prompts with escaped curly braces: `{{` and `}}`
-   See `heph/prompts/technical.txt` for corrected version

---

## Cost Management

### Token Usage Estimates

| Report Size          | Input Tokens | Output Tokens | OpenAI Cost | Anthropic Cost |
| -------------------- | ------------ | ------------- | ----------- | -------------- |
| Small (10 findings)  | ~2,000       | ~1,500        | ~$0.08      | ~$0.12         |
| Medium (25 findings) | ~4,000       | ~2,500        | ~$0.18      | ~$0.25         |
| Large (50+ findings) | ~6,000       | ~3,500        | ~$0.30      | ~$0.40         |

**Cost Reduction Tips:**

-   Use `--ai-tone technical` OR `non_technical` (not both)
-   Enable max_evidence_length truncation
-   Use GPT-3.5-turbo for quick analysis
-   Use Ollama for testing/development

---

## Best Practices

### 1. Choose Right Provider for Context

| Scenario           | Recommended Provider | Reason             |
| ------------------ | -------------------- | ------------------ |
| Client reports     | OpenAI GPT-4         | Best quality       |
| Internal testing   | Ollama               | Free, private      |
| Quick analysis     | GPT-3.5-turbo        | Fast & cheap       |
| Sensitive servers  | Ollama               | 100% offline       |
| EU/GDPR compliance | Anthropic            | Privacy-focused    |
| Government/Defense | Ollama               | Air-gapped capable |

### 2. Review AI Output

**Always verify:**

-   Server commands are correct for detected server type
-   Version numbers are accurate
-   Configuration syntax is valid
-   Remediation steps are complete
-   No hallucinated CVEs or references
-   Paths match detected server structure

### 3. Optimize for Your Use Case

-   Production: Quality over speed (GPT-4)
-   Development: Speed over quality (Ollama)
-   Budget-conscious: Balance (GPT-3.5-turbo)

---

## Examples

### Full Workflow with Provider Testing

```bash
# 1. Test providers to see which works best
python -m heph.core.ai openai    # Test OpenAI
python -m heph.core.ai anthropic # Test Anthropic
python -m heph.core.ai ollama    # Test Ollama

# 2. Choose provider and update config/defaults.yaml
vim config/defaults.yaml
# Set: provider: "anthropic"

# 3. Generate consent token
python -m heph --gen-consent myserver.com

# 4. Verify ownership (HTTP method)
# Create token file on server:
echo "verify-abc123" > /var/www/html/.well-known/verify-abc123.txt

# Verify
python -m heph --verify-consent http --domain myserver.com --token verify-abc123

# 5. Run scan with chosen provider
python -m heph \
  --target https://myserver.com \
  --aggressive \
  --use-ai \
  --ai-tone both \
  --html \
  -vv

# 6. Check reports
open ~/.hephaestus/reports/hephaestus_report_https_myserver.com_*.html
```

### Multi-Server Analysis

```bash
# Scan multiple servers with AI
for server in web1.com web2.com web3.com; do
  python -m heph --target "https://$server" --aggressive --use-ai --html
done

# Compare AI recommendations across servers
jq '.ai_analysis.technical_remediation' ~/.hephaestus/reports/*.json
```

---

## Report Integration

### JSON Report Structure

AI analysis is embedded in the JSON report:

```json
{
  "tool": "hephaestus",
  "version": "0.1.0",
  "target": "https://example.com",
  "findings": [...],
  "ai_analysis": {
    "executive_summary": "Your web server has MODERATE security...",
    "technical_remediation": "## 1. EXECUTIVE SUMMARY\n\nThe security audit...",
    "generated_at": "2025-10-21T14:30:00Z",
    "model_used": "openai/gpt-4-turbo-preview"
  }
}
```

### HTML Report Section

The HTML report includes a dedicated AI section with:

-   🤖 AI-Powered Analysis header
-   📊 Executive Summary (formatted)
-   🔧 Technical Hardening Guide (formatted)
-   Markdown rendering with syntax highlighting
-   Collapsible sections for readability

---

## Support

-   📖 [LangChain v1.0 Docs](https://python.langchain.com/docs/)
-   🤖 [OpenAI Platform](https://platform.openai.com/)
-   🔍 [Anthropic Claude](https://docs.anthropic.com/)
-   🦙 [Ollama](https://ollama.com/)

For Hephaestus AI issues:

-   GitHub: https://github.com/rodhnin/hephaestus-server-forger/issues
-   Website: https://rodhnin.com
