# Contributing to Hephaestus

Thank you for your interest in contributing to **Hephaestus Server Security Auditor**! We welcome contributions from the community to help make server security more accessible and robust.

## Table of Contents

-   [Code of Conduct](#code-of-conduct)
-   [How Can I Contribute?](#how-can-i-contribute)
-   [Development Setup](#development-setup)
-   [Development Workflow](#development-workflow)
-   [Code Style Guidelines](#code-style-guidelines)
-   [Testing Requirements](#testing-requirements)
-   [Commit Message Guidelines](#commit-message-guidelines)
-   [Pull Request Process](#pull-request-process)
-   [Project Structure](#project-structure)
-   [Contact](#contact)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and professional environment. We are committed to:

-   **Ethical Security Research**: All contributions must align with responsible disclosure practices
-   **Consent-First Approach**: Never encourage or enable unauthorized scanning
-   **Constructive Feedback**: Provide helpful, respectful code reviews
-   **Inclusive Language**: Use welcoming and inclusive language in all interactions

---

## How Can I Contribute?

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities!

Contact me on [https://rodhnin.com](https://rodhnin.com).

### Reporting Bugs

Before creating bug reports, please:

1. **Check existing issues** to avoid duplicates
2. **Use the latest version** to confirm the bug still exists
3. **Collect debug information**:
    ```bash
    python -m heph --target https://example.com --log-level debug --log-format json
    ```

**Bug Report Template**:

```markdown
**Hephaestus Version**: 0.1.0
**Python Version**: 3.11.5
**OS**: Ubuntu 22.04

**Description**: Brief description of the issue

**Steps to Reproduce**:

1. Run `python -m heph --target https://example.com`
2. Observe error at...

**Expected Behavior**: What should happen

**Actual Behavior**: What actually happens

**Logs** (if applicable):
```

[Paste debug logs here]

```

```

### Suggesting Enhancements

We welcome feature requests! Please open an issue with:

-   **Use Case**: Why is this feature valuable?
-   **Proposed Solution**: How should it work?
-   **Alternatives Considered**: Other approaches you've thought about
-   **Implementation Complexity**: Estimate if possible

### Contributing Code

Areas where contributions are especially welcome:

-   **New Check Modules**: Additional vulnerability checks (see `heph/checks/`)
-   **Server Detection**: Support for more web servers (IIS, LiteSpeed, Caddy)
-   **AI Providers**: Integration with additional LLM providers
-   **Report Templates**: New report formats (PDF, Markdown, SARIF)
-   **Database Enhancements**: Query optimizations, schema improvements
-   **Docker Labs**: Additional vulnerable configurations for testing
-   **Documentation**: Tutorials, examples, translations

---

## Development Setup

### Prerequisites

-   **Python 3.11+** (3.12 recommended)
-   **Git** for version control
-   **Docker** (optional, for testing vulnerable labs)

### Installation Steps

**1. Fork and clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/hephaestus-server-forger.git
cd hephaestus-server-forger
```

**2. Create virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

**3. Install development dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install -e ".[dev]"  # Installs pytest, black, flake8, mypy
```

**4. Verify installation**

```bash
python -m heph --version  # Should show: Hephaestus v0.1.0
python -m pytest          # Run test suite (55 tests)
```

**5. Set up vulnerable testing labs (optional)**

```bash
cd docker && ./deploy.sh  # Select option 2: Testing Lab
```

---

## Development Workflow

### Branch Strategy

-   **main**: Production-ready code (protected)
-   **develop**: Integration branch for features
-   **feature/\***: New features (e.g., `feature/add-caddy-support`)
-   **bugfix/\***: Bug fixes (e.g., `bugfix/fix-ssl-timeout`)
-   **docs/\***: Documentation updates

### Workflow Steps

**1. Create a feature branch**

```bash
git checkout -b feature/your-feature-name
```

**2. Make your changes**

-   Write code following our [style guidelines](#code-style-guidelines)
-   Add tests for new functionality
-   Update documentation if needed

**3. Run tests and linters**

```bash
# Run test suite
python -m pytest

# Run type checking
python -m mypy heph/

# Run code formatting
python -m black heph/ tests/

# Run linter
python -m flake8 heph/ tests/
```

**4. Commit your changes**

```bash
git add .
git commit -m "feat: add support for Caddy web server"
```

**5. Push to your fork**

```bash
git push origin feature/your-feature-name
```

**6. Open a Pull Request**

-   Go to the main repository on GitHub
-   Click "New Pull Request"
-   Select your branch
-   Fill out the PR template

---

## Code Style Guidelines

We follow **PEP 8** with some project-specific conventions:

### Python Code Style

```python
# Good: Descriptive names, type hints, docstrings
def check_sensitive_files(
    target: str,
    session: requests.Session,
    config: Config
) -> List[Finding]:
    """
    Check for exposed sensitive files (.env, .git, phpinfo.php).

    Args:
        target: Target URL (e.g., 'https://example.com')
        session: Configured requests session with timeout
        config: Application configuration object

    Returns:
        List of Finding objects for detected vulnerabilities
    """
    findings = []
    sensitive_files = ['.env', '.git/config', 'phpinfo.php']

    for file_path in sensitive_files:
        url = f"{target}/{file_path}"
        # Implementation...

    return findings
```

### Key Conventions

-   **Type Hints**: Required for all function signatures
-   **Docstrings**: Google-style docstrings for all public functions
-   **Line Length**: 100 characters max (not 79)
-   **Imports**: Group stdlib, third-party, local (separated by blank lines)
-   **Error Handling**: Use specific exceptions, never bare `except:`
-   **Logging**: Use `logger.debug()` for verbose output

### Naming Conventions

-   **Functions/Variables**: `snake_case`
-   **Classes**: `PascalCase`
-   **Constants**: `UPPER_SNAKE_CASE`
-   **Private Methods**: `_leading_underscore`

### File Organization

```python
"""Module-level docstring explaining purpose."""

# Standard library imports
import os
import sys
from pathlib import Path

# Third-party imports
import requests
from jinja2 import Template

# Local imports
from heph.core.config import Config
from heph.core.findings import Finding

# Module constants
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3

# Class definitions
class YourClass:
    """Class docstring."""
    pass

# Functions
def your_function():
    """Function docstring."""
    pass
```

---

## Testing Requirements

All code contributions **must include tests**. We use **pytest** with the following structure:

### Test Structure

```
tests/
├── unit/           # Unit tests (fast, isolated)
│   ├── test_config.py
│   ├── test_findings.py
│   └── test_checks.py
├── integration/    # Integration tests (slower, require Docker)
│   ├── test_apache_scan.py
│   └── test_nginx_scan.py
└── conftest.py     # Shared fixtures
```

### Writing Tests

**Unit Test Example**:

```python
import pytest
from heph.core.config import Config

def test_config_default_values():
    """Test that Config loads with correct defaults."""
    config = Config()
    assert config.general.version == "0.1.0"
    assert config.scan.timeout == 10
    assert config.scan.rate_limit == 3

def test_config_custom_values():
    """Test that Config can be customized."""
    config = Config(scan={"timeout": 20, "rate_limit": 5})
    assert config.scan.timeout == 20
    assert config.scan.rate_limit == 5
```

**Integration Test Example**:

```python
import pytest
from heph.cli import main

@pytest.fixture
def vulnerable_server():
    """Start Docker container with vulnerable Apache server."""
    # Setup Docker container
    yield "http://localhost:8080"
    # Teardown container

def test_apache_scan_detects_vulnerabilities(vulnerable_server):
    """Test that Apache scan detects .env and phpinfo.php."""
    result = main(["--target", vulnerable_server, "--json"])
    findings = result["findings"]

    assert any(f["id"] == "SENS-001" for f in findings)  # .env
    assert any(f["id"] == "SENS-004" for f in findings)  # phpinfo.php
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage report
python -m pytest --cov=heph --cov-report=html

# Run specific test file
python -m pytest tests/unit/test_config.py

# Run tests matching pattern
python -m pytest -k "test_apache"
```

### Test Coverage Requirements

-   **New modules**: Minimum 80% coverage
-   **Bug fixes**: Include regression test
-   **Critical paths**: 100% coverage (consent tokens, database operations)

---

## Commit Message Guidelines

We follow **Conventional Commits** for clear, semantic commit history:

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

-   **feat**: New feature
-   **fix**: Bug fix
-   **docs**: Documentation changes
-   **style**: Code formatting (no logic change)
-   **refactor**: Code restructuring (no behavior change)
-   **perf**: Performance improvements
-   **test**: Adding/updating tests
-   **chore**: Maintenance tasks (dependencies, build)

### Examples

```bash
# Good commits
feat(checks): add support for Caddy web server detection
fix(ssl): handle SSL timeout exceptions gracefully
docs(readme): update Docker deployment instructions
test(consent): add integration tests for DNS verification

# Bad commits (avoid these)
fix: stuff
update readme
misc changes
```

### Commit Body (Optional)

For complex changes, include:

-   **Why** the change is needed
-   **What** alternative approaches were considered
-   **References** to related issues

```
feat(ai): add support for Google Gemini API

Adds Gemini Pro as a fourth AI provider option alongside OpenAI,
Anthropic, and Ollama. Gemini offers competitive pricing and
performance for hardening guide generation.

Closes #42
```

---

## Pull Request Process

### Before Submitting

-   [ ] Tests pass locally (`pytest`)
-   [ ] Code follows style guidelines (`black`, `flake8`, `mypy`)
-   [ ] Documentation updated (if applicable)
-   [ ] CHANGELOG.md updated (for user-facing changes)
-   [ ] Commit messages follow conventions

### PR Template

```markdown
## Description

Brief description of changes

## Type of Change

-   [ ] Bug fix (non-breaking change)
-   [ ] New feature (non-breaking change)
-   [ ] Breaking change (fix/feature that changes existing behavior)
-   [ ] Documentation update

## Testing

-   [ ] Unit tests added/updated
-   [ ] Integration tests added/updated
-   [ ] Manual testing performed

## Checklist

-   [ ] My code follows the project's style guidelines
-   [ ] I have performed a self-review of my code
-   [ ] I have commented my code where necessary
-   [ ] I have updated the documentation
-   [ ] My changes generate no new warnings
-   [ ] I have added tests that prove my fix/feature works
-   [ ] New and existing tests pass locally

## Related Issues

Closes #issue_number
```

### Review Process

1. **Automated Checks**: CI pipeline runs tests and linters
2. **Code Review**: Maintainers review code for quality and correctness
3. **Feedback**: Address review comments
4. **Approval**: At least one maintainer approval required
5. **Merge**: Squash and merge to maintain clean history

---

## Project Structure

```
hephaestus-server-forger/
├── heph/                      # Main package
│   ├── __init__.py            # Package metadata
│   ├── cli.py                 # CLI entry point
│   ├── core/                  # Core functionality
│   │   ├── config.py          # Configuration management
│   │   ├── findings.py        # Finding dataclass
│   │   ├── scanner.py         # Main scanner logic
│   │   └── consent.py         # Consent token system
│   ├── checks/                # Vulnerability check modules
│   │   ├── server_info.py     # Server detection
│   │   ├── sensitive_files.py # File exposure checks
│   │   ├── headers.py         # Security headers
│   │   ├── methods.py         # HTTP methods
│   │   ├── ssl.py             # TLS/SSL checks
│   │   └── directory.py       # Directory listing
│   ├── ai/                    # AI integration
│   │   ├── providers.py       # OpenAI, Anthropic, Ollama
│   │   └── prompts.py         # Prompt templates
│   ├── db/                    # Database operations
│   │   ├── manager.py         # SQLite operations
│   │   └── schema.py          # Database schema
│   └── utils/                 # Utilities
│       ├── logger.py          # Logging configuration
│       ├── http.py            # HTTP helpers
│       └── decorators.py      # Rate limiting, retries
├── templates/                 # Jinja2 templates
│   └── report.html.j2         # HTML report template
├── config/                    # Configuration files
│   ├── defaults.yaml          # Default configuration
│   └── prompts/               # AI prompt templates
├── tests/                     # Test suite
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── docker/                     # Docker deployment
│   ├── vulnerable-apache/                 # Vulnerable Apache lab script
│   │   └── docker-entrypoint.sh
│   ├── vulnerable-nginx/                  # Vulnerable Nginx lab script
│   │   └── docker-entrypoint.sh
│   ├── compose.yml
│   └── Dockerfile              # Production image
├── docs/                      # Documentation
├── setup.py                   # Package setup
├── requirements.txt           # Dependencies
├── README.md                  # Main documentation
└── CONTRIBUTING.md            # This file
```

---

## Contact

-   **Project Maintainer**: Rodney Dhavid Jimenez Chacin (rodhnin)
-   **Website**: https://rodhnin.com
-   **GitHub Issues**: https://github.com/rodhnin/hephaestus-server-forger/issues
-   **Discussions**: https://github.com/rodhnin/hephaestus-server-forger/discussions

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

---

## 📞 Questions?

-   **General questions**: Open a GitHub Discussion
-   **Bug reports**: Open a GitHub Issue
-   **Project maintainer**: [rodhnin](https://github.com/rodhnin) | [https://rodhnin.com](https://rodhnin.com)

---

## 📜 License

By contributing to Hephaestus, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

**Thank you for helping make web security auditing more accessible!** 🛡️

Part of the **Argos Security Suite**:

-   👁️ [Argus](https://github.com/rodhnin/argus-wp-watcher) - WordPress Security Scanner
-   🐂 [Asterion](https://github.com/rodhnin/asterion-network-minotaur) - Network Security Auditor
-   🔮 [Pythia](https://github.com/rodhnin/pythia-sql-clairvoyance) - SQL Injection Detection Scanner
-   🔥 **Hephaestus** - Vulnerability Server Scanner (this project)
