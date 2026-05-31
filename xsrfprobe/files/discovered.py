#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from collections import defaultdict
from xsrfprobe.core.schema import DiscoveredToken

# Vulnerabilities which were noticed (preformatted strings, legacy/console use)
VULN_LIST = []

# Structured vulnerability records mirroring VULN_LIST, each a dict:
# {"url", "vuln", "content", "poc_paths": [...], "details": {...}}.
# Populated alongside VULN_LIST so the JSON report can carry PoC paths and
# structured metadata per finding instead of opaque strings.
VULN_RECORDS: list[dict] = []

# Strengths or positive sides of the application
STRENGTH_LIST = []

# Anti-CSRF tokens discovered during scanning. This list is consumed by the
# active token-tamper / bypass tests, so it must contain only the tokens that
# actually belong to the form/endpoint under test (injecting unrelated tokens
# here would cause false positives in T3/T5/T6).
ANTI_CSRF_TOKENS: list[DiscoveredToken] = []

# Distinct anti-CSRF token *samples* passively harvested from every response
# that flows through requestMaker. Used ONLY for post-scan predictability
# analysis (entropy / forgeability), never by the bypass tests.
TOKEN_SAMPLES: list[DiscoveredToken] = []

# Generated PoC artifacts, grouped per form/action. Surfaced as a single
# root-level "pocs" section in the JSON report (not duplicated per finding).
# Each entry: {"action", "method", "bypasses": [...], "paths": [...]}.
POC_RECORDS: list[dict] = []

# List of all Urls that we found
INTERNAL_URLS = []

# Forms that were tested: {url: [form1, form2, ...]}
FORMS_TESTED = defaultdict(list)

# Errors that were encountered
SCAN_ERRORS = []