#!/usr/bin/env python3
"""
GlassTape SDK Setup
==================

Zero-trust runtime governance for AI agents.
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="glasstape",
    version="1.0.0",
    author="GlassTape Team",
    author_email="meetharsharora@proton.me",
    description="Zero-trust runtime governance for AI agents",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/glasstape/glasstape-sdk-python",
    project_urls={
        "Bug Tracker": "https://github.com/glasstape/glasstape-sdk-python/issues",
        "Source Code": "https://github.com/glasstape/glasstape-sdk-python",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "llm": [
            "openai>=1.0.0",
            "anthropic>=0.7.0",
        ],
        # Note: CEL evaluation is built-in, no external dependencies needed
    },
    include_package_data=True,
    package_data={
        "glasstape": ["py.typed"],
    },
    entry_points={
        "console_scripts": [
            "glasstape=glasstape.cli:main",
        ],
    },
    keywords="ai governance policy security agents llm",
)