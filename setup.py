#!/usr/bin/env python3
"""
Setup script for DissectX - CTF Binary Analysis Tool
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="dissectx",
    version="1.0.0",
    description="DissectX - CTF Binary Analysis and Assembly Translation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DissectX Contributors",
    author_email="",
    url="https://github.com/H4D3ZS/DissectX",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "capstone>=5.0.0",
    ],
    entry_points={
        "console_scripts": [
            "dissectx=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
    ],
    keywords="ctf reverse-engineering disassembly assembly binary-analysis security",
)
