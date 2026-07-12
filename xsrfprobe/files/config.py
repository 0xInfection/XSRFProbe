#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# this module holds values for controlling the entire scan interface.
# You can modify these values as per your need.

# Site Url to be scanned (Required)
SITE_URL = ""

# Switch for whether to crawl the site or not
CRAWL_SITE = False

# Crawl bounds (only relevant when CRAWL_SITE is True). These keep the crawl
# bounded and deterministic instead of running until the queue drains.
#   CRAWL_MAX_URLS    : hard cap on the number of URLs fetched (0 = unlimited)
#   CRAWL_MAX_DEPTH   : maximum link depth from the seed URL (0 = unlimited)
#   CRAWL_TIMEOUT     : wall-clock budget for crawling, in seconds (0 = unlimited)
CRAWL_MAX_URLS = 200
CRAWL_MAX_DEPTH = 5
CRAWL_TIMEOUT = 0

# Print out verbose (turn it off for only brief outputs).
# Turning off is Highly Discouraged, since you will miss what the tool is doing.
DEBUG = False

# Switch between verbosity levels (25 = PROGRESS, shows phase summaries)
DEBUG_LEVEL = 25

# User-Agent to be used (If COOKIE_VALUE is not supplied)
USER_AGENT_RANDOM = False

# User-Agent to be used (If COOKIE_VALUE supplied).
#
# This is a standard User-Agent emulating Chrome on Windows 10.
#
# NOTE: This is a precaution in case the cookie value is supplied,
# if the user-agent gets changed from time to time, the remote
# application might trigger up some protection agents
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# Cookie value to be sent alongwith the requests. This option is particularly
# needed for a wholesome check on CSRFs. Since for a basic successful CSRF attack
# one needs to have a site with long-duration persistent session cookies and no
# Referer validation.
#
# Also you might want to keep this value to '' untill you want to scan your
# web application as a authorised user/admin with elevated priviledges,
# which might give XSRFProbe a wider scope to scan. This is typically
# recommended for websites which has logins/sessions feature. (eg. Social
# Networking Sites, E-Commerce Sites).
#
# NOTE: If this value is not supplied, XSRFProbe will only scan for simple
# cookies which the tool might encounter while making requests, especially
# POST requests.
COOKIE_VALUE = []

# Header values to be used (Modify it as per your need)
HEADER_VALUES = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Mode": "navigate",
    "DNT": "1",  # Do Not Track Request Header
    "Connection": "close",
}

# Email value to be supplied when parsing/filling forms
# You can modify it as per your need :)
EMAIL_VALUE = "xsrf.probe@0xinfection.xyz"

# Plaintext value to be supplied when parsing/filling forms
TEXT_VALUE = "csrftesting"

# Request Timeout (Keep the max. timeout value to 10s)
TIMEOUT_VALUE = 7

# The time delay between requests. This option is especially required
# when there is some sort of security measure such as load-balancers
# or a Firewall (WAF).
DELAY_VALUE = 0

# The similarity threshold for the diff engine to determine whether
# the responses are similar or not.
# (Recommended keeping 90)
# Values range between 0-100
SIMILARITY_THRESHOLD = 90

# Whether to include Cookie Based Checks everywhere
#
# Note: If you keep this to 'True', you must supply a
# cookie value in COOKIE_VALUE to test with full efficiency.
# Otherwise only a partial check will be done against the cookies
# which XSRFProbe might come across while requesting forms/data
# and other relevant areas.
#
# (Recommended Keeping True)
COOKIE_BASED = True

# Anti-CSRF Token Checks (Recommended keeping True)
TOKEN_CHECKS = True

# Referer/Origin Checks (Recommended keeping True)
REFERER_ORIGIN_CHECKS = True

# Force Referer/Origin header tests to run even when an anti-CSRF token is
# confirmed to be enforced. WARNING: research/opt-in only. The bypass requests
# still carry a valid token, so on token-protected endpoints these tests cannot
# isolate the header as the variable and will produce false positives.
FORCE_HEADER_TESTS = False

# Whether to submit Crafted Forms (Recommended keeping True)
# If you turn this to False, it will omit form submissions,
# so there will be more chances of missing out most possible
# cases of Form based (POST Based) CSRFs.
FORM_SUBMISSION = True

# A switch to determine whether to verify certificates upon
# requests. This will help devs test their web-app with self-signed
# certificates.
VERIFY_CERT = True

# Referer Url (Change It Accordingly)
# eg. Use one of your Subdomains (Same Origin Policy))
REFERER_URL = "http://not-a-valid-referer.github.com/0xinfection/xsrfprobe"

# Origin Url (Change It Accordingly)
# eg. Use one of your Subdomains (Same Origin Policy))
ORIGIN_URL = "http://not-a-valid-origin.xsrfprobe.0xinfection.xyz"

# Length of the random alphanumeric value XSRFProbe generates for the
# synthetic/forged token values used during the tamper tests: the corrupted
# token in the forged-token probe, the arbitrary header-token value (T8), and
# the fabricated double-submit token (T6). When the real token is longer, that
# real length is used instead so the forged value stays plausible.
#
# 6 is a sensible default; a larger value is harmless. Overridable via --max-chars.
TOKEN_GENERATION_LENGTH = 6

# List of Urls that are not to be scanned (excluded).
EXCLUDE_DIRS = []

# Output directory where everything (including logs) are to
# be stored
OUTPUT_DIR = ""

# Allow JSON output
JSON_OUTPUT = False

# Option for controlling post-scan analysis. Turning it off
# results in not analysing the tokens gathered.
SCAN_ANALYSIS = True

# Option to skip PoC Form Generation of POST_BASED Request Forgeries.
# The form will not be generated.
POC_GENERATION = True


# Browser Integration
BROWSER_ENABLED = False
AUTO_VALIDATE_POC = False
GECKODRIVER_PATH = ""
BROWSER_TIMEOUT = 30
ENUM_SUBDOMAINS = False

# Input types defaults
INPUT_TYPES_DEFAULTS = {
    "text": TEXT_VALUE,
    "email": EMAIL_VALUE,
    "password": TEXT_VALUE,
    "hidden": TEXT_VALUE,
    "number": "0",
    "date": "2000-01-01",
    "file": "",  # No default value for file inputs
    "checkbox": "on",  # Default browser behavior
    "radio": "on",     # Default browser behavior
    "url": "https://example.com",
    "tel": "+1234567890",
    "range": "50",
    "color": "#000000",
    "submit": "Submit",
    "reset": "Reset",
    "button": "Button",
    "search": "Search"
}