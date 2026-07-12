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

# Structured vulnerability records. Each is created as
# {"url", "vuln", "content", "test_id", "details": {...}}; the handler later
# adds "poc_paths": [...] for findings that get a PoC. Consumed by the JSON
# report and the console summary.
VULN_RECORDS: list[dict] = []

# Structured strength records: {"url", "strength", "test_id"}.
STRENGTH_RECORDS: list[dict] = []

# Global accumulator of every anti-CSRF token discovered during the scan. Each
# TokenAnalyser mirrors the tokens it finds for its form into this pool (deduped
# by name/value/discovery_part). NOTE: the active token-tamper / bypass tests do
# NOT read this list — they use the per-form ``TokenAnalyser.tokens`` list to
# avoid cross-form contamination. This pool instead feeds the end-of-scan
# predictability analysis (A1), the encoding checks (E1), the PoC generator
# fallback, and the JSON report's token inventory.
ANTI_CSRF_TOKENS: list[DiscoveredToken] = []

# Distinct anti-CSRF token *samples* passively harvested from every response
# that flows through requestMaker. Used ONLY for post-scan predictability
# analysis (entropy / forgeability), never by the bypass tests.
TOKEN_SAMPLES: list[DiscoveredToken] = []

# List of all Urls that we found
INTERNAL_URLS = []

# Forms that were tested: {url: [form1, form2, ...]}
FORMS_TESTED = defaultdict(list)

# Errors that were encountered
SCAN_ERRORS = []