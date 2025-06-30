#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="nimda-security",
    version="2.5.0",
    description="NIMDA Security System - AI-powered security monitoring",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="NIMDA Team",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        line.strip()
        for line in open("requirements.txt", encoding="utf-8")
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "nimda=nimda_tkinter:main",
            "nimda-security=nimda_integrated:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
