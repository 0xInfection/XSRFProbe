#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Lists of anti-CSRF parameter/header names sent for form verification, based on
# interactions with different web-applications. :)
#
# Feel free to add more of your tokens if you have. ;)
# High-confidence anti-CSRF token field names: framework-specific or explicitly
# CSRF-related. A name match alone is strong evidence of an anti-CSRF token, so
# these are accepted regardless of the field's value.
HIGH_CONFIDENCE_CSRF_NAMES = (
    "CSRFName",  # OWASP CSRF_Guard
    "CSRFToken",  # OWASP CSRF_Guard
    "csrf_token",  # PHP NoCSRF Class
    "anticsrf",  # AntiCsrfParam.java
    "__RequestVerificationToken",  # ASP.NET TokenParam
    "VerificationToken",  # AntiCSRFParam.java
    "form_build_id",  # Drupal CMS AntiCSRF
    "nonce",  # WordPress Nonce
    "authenticity_token",  # Ruby on Rails
    "csrf_param",  # Ruby on Rails
    "TransientKey",  # VanillaForums Param
    "csrf",  # PHP CSRFProtect
    "AntiCSURF",  # Anti CSURF (PHP)
    "YII_CSRF_TOKEN",  # http://www.yiiframework.com/
    "yii_anticsrf",  # http://www.yiiframework.com/
    "[_token]",  # Symfony 2.x
    "_csrf_token",  # Symfony 1.4
    "csrfmiddlewaretoken",  # Django 1.5
    "ccm_token",  # Concrete 5 CMS
    "XOOPS_TOKEN_REQUEST",  # Xoops CMS
    "_csrf",  # Express JS Default Anti-CSRF
)

# Low-confidence / generic names that also legitimately name many NON-CSRF
# fields (search hashes, API keys, boolean flags). A name match here is only
# treated as an anti-CSRF token when the field's VALUE also looks like a token
# (see xsrfprobe.modules.Token.looksLikeToken_value), which sharply reduces
# false positives that would otherwise suppress the header tests.
LOW_CONFIDENCE_CSRF_NAMES = (
    "token",
    "auth",
    "hash",
    "secret",
    "verify",
)

COMMON_CSRF_HEADERS = (
    # These are a list of HTTP Headers often found in requests
    # of web applications using various frameworks.
    "CSRF-Token",  # Express JS CSURF Middleware
    "XSRF-Token",  # Node JS/ Express JS
    "X-CSRF-Token",  # Ruby on Rails
    "X-XSRF-Token",  # Express JS CSURF Middleware
    # Some other probabilties
    "X-CSRF-Header",
    "X-XSRF-Header",
    "X-CSRF-Protection",
    "X-XSRF-Protection",
)

# TODO: Add and replace with more valid and arguable exclusion lists
EXCLUSIONS_LIST = (
    "sign-out",
    "signout",
    "logoff",
    "logout",
    "action=out",
    "action=logoff",
    "action=delete",
    "UserLogout",
    "osCsid",
    "action=logout",
    "action=signout"
)
