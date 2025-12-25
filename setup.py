#!/usr/bin/env python3
"""
Setup script for DissectX -  Binary Analysis Framework
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read version from a version file
version = "1.0.0"
version_file = Path(__file__).parent / "src" / "__version__.py"
if version_file.exists():
    exec(version_file.read_text())
    version = __version__  # noqa: F821

setup(
    name="dissectx",
    version=version,
    description="   Binary Analysis & Reverse Engineering Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DissectX Contributors",
    author_email="dissectx@example.com",
    url="https://github.com/H4D3ZS/DissectX",
    project_urls={
        "Bug Tracker": "https://github.com/H4D3ZS/DissectX/issues",
        "Documentation": "https://github.com/H4D3ZS/DissectX/blob/main/README.md",
        "Source Code": "https://github.com/H4D3ZS/DissectX",
    },
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*", "docs", "htmlcov"]),
    package_data={
        "src": ["**/*.md"],
        "plugins": ["*.py", "README.md"],
    },
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=[
        "capstone>=5.0.0",
        "pefile>=2023.2.7",
        "networkx>=3.0",
        "unicorn>=2.0.0",
        "textual>=0.41.0",
        "flask>=3.0.0",
        "weasyprint>=60.0",
        "ROPGadget>=7.4",
        "r2pipe>=1.8.0",
        "fastmcp>=0.2.0",
        "beautifulsoup4>=4.12.0",
        "selenium>=4.15.0",
        "webdriver-manager>=4.0.0",
        "aiohttp>=3.8.0",
        "mitmproxy>=9.0.0",
        "angr>=9.2.0",
        "flask-socketio>=5.3.6",
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "python-multipart>=0.0.6",
        "sqlalchemy>=2.0.0",
        "alembic>=1.13.0",
        "redis>=5.0.0",
        "celery>=5.3.0",
        "python-jose[cryptography]>=3.3.0",
        "passlib[bcrypt]>=1.7.4",
        "python-dotenv>=1.0.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "python-dateutil>=2.8.0",
        "lxml>=4.9.0",
        "websockets>=12.0",
        "dnslib>=0.9.23",
        "playwright>=1.40.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "hypothesis>=6.82.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "dissectx=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
        "Topic :: Software Development :: Debuggers",
        "Topic :: System :: Software Distribution",
    ],
    keywords="ctf reverse-engineering disassembly assembly binary-analysis security malware-analysis decompiler",
    zip_safe=False,
)
