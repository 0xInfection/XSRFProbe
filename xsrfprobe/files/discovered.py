#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# INFO: This file is for storing the various important parts of
# requests discovered during making of various requests.

# Vulnerabilities which were noticed
VULN_LIST = []

# Strengths or positive sides of the application
STRENGTH_LIST = []

# This is for storing the various tokens which got discovered
# during making the requests. This will be used for various
# analysis of token generation prototypes and logic used in
# generating them.
REQUEST_TOKENS = []

# List of all Urls that we found
INTERNAL_URLS = []

# Files/executables discovered during crawling
FILES_EXEC = []

# Forms that were tested
FORMS_TESTED = []

# Errors that were encountered
SCAN_ERRORS = []
