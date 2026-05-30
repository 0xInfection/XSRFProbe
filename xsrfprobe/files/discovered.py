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

# Vulnerabilities which were noticed
VULN_LIST = []

# Strengths or positive sides of the application
STRENGTH_LIST = []

# Anti-CSRF tokens discovered during scanning
ANTI_CSRF_TOKENS: list[DiscoveredToken] = []

# List of all Urls that we found
INTERNAL_URLS = []

# Forms that were tested: {url: [form1, form2, ...]}
FORMS_TESTED = defaultdict(list)

# Errors that were encountered
SCAN_ERRORS = []