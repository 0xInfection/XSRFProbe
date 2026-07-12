#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import io
import re
from setuptools import setup, find_packages
from os import path

this_directory = path.abspath(path.dirname(__file__))
with io.open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    desc = f.read()

# Read version from core/__init__.py without importing the package
# (avoids needing dependencies installed at build time).
with io.open(path.join(this_directory, "xsrfprobe", "core", "__init__.py"), encoding="utf-8") as f:
    _version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', f.read())
    _version = _version_match.group(1) if _version_match else "0.0.0"

setup(
    name="xsrfprobe",
    version=_version,
    description="The Prime Cross Site Request Forgery (CSRF) Audit & Exploitation Toolkit",
    long_description=desc,
    long_description_content_type="text/markdown",
    author="Pinaki Mondal",
    author_email="theinfecteddrake@gmail.com",
    license="GPLv3",
    url="https://github.com/0xInfection/XSRFProbe",
    download_url="https://github.com/0xInfection/XSRFProbe/archive/v%s.zip" % _version,
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "xsrfprobe = xsrfprobe.xsrfprobe:startEngine",
        ],
    },
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.25",
        "beautifulsoup4>=4.9",
        "rapidfuzz>=2.0",
        "pydantic>=2.0",
        "selenium>=4.0",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    keywords=["csrf", "xsrf", "appsec", "vulnerability scanner", "webapps", "hacking"],
)
