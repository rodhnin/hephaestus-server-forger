"""
Hephaestus - Server Security Auditor
Setup script for package installation

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with requirements_path.open('r', encoding='utf-8') as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith('#')
        ]

setup(
    name="hephaestus-server-forger",
    version="0.1.0",
    description="Server Security Auditor - Forge Secure Configurations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Rodney Dhavid Jimenez Chacin (rodhnin)",
    url="https://github.com/rodhnin/hephaestus-server-forger",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*", "docs", "examples"]),
    include_package_data=True,
    package_data={
        "heph": [
            "config/*.yaml",
            "config/prompts/*.txt",
            "templates/*.j2",
            "assets/*.txt",
        ],
    },
    install_requires=requirements,
    extras_require={
        "pro": [
            "sslyze>=5.0.0",
            "python-nmap>=0.7.1",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.1.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "heph=heph.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Internet :: WWW/HTTP",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    keywords=[
        "security",
        "pentesting",
        "server-audit",
        "apache",
        "nginx",
        "php",
        "tls",
        "ssl",
        "web-server",
        "security-scanner",
        "vulnerability-scanner",
        "ethical-hacking",
    ],
    project_urls={
        "Bug Reports": "https://github.com/rodhnin/hephaestus-server-forger/issues",
        "Source": "https://github.com/rodhnin/hephaestus-server-forger",
        "Documentation": "https://github.com/rodhnin/hephaestus-server-forger#readme",
    },
)