#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# List of anti-CSRF paramter values which are sent for form
# verification, I have seen. These values are collected based on
# my interactions with different web-applications. :)
#
# Feel free to add more of your tokens if you have. ;)
COMMON_CSRF_NAMES = (
                    # These are a list of known common tokens parameters
                    'CSRFName',                   # OWASP CSRF_Guard
                    'CSRFToken',                  # OWASP CSRF_Guard
                    'csrf_token',                 # PHP NoCSRF Class
                    'anticsrf',                   # AntiCsrfParam.java
                    '__RequestVerificationToken', # ASP.NET TokenParam
                    'VerificationToken',          # AntiCSRFParam.java
                    'form_build_id',              # Drupal CMS AntiCSRF
                    'nonce',                      # WordPress Nonce
                    'authenticity_token',         # Ruby on Rails
                    'csrf_param',                 # Ruby on Rails
                    'TransientKey',               # VanillaForums Param
                    'csrf',                       # PHP CSRFProtect
                    'AntiCSURF',                  # Anti CSURF (PHP)
                    'YII_CSRF_TOKEN',             # http://www.yiiframework.com/
                    'yii_anticsrf',               # http://www.yiiframework.com/
                    '[_token]',                   # Symfony 2.x
                    '_csrf_token',                # Symfony 1.4
                    'csrfmiddlewaretoken',        # Django 1.5
                    'ccm_token',                  # Concrete 5 CMS
                    'XOOPS_TOKEN_REQUEST',        # Xoops CMS
                    '_csrf',                      # Express JS Default Anti-CSRF

                    # These are some other various token names I have seen in
                    # various websites.
                    #
                    # TODO: Add more similar csrf token parameters
                    'token',
                    'auth',
                    'hash',
                    'debug_token',
                    'secret',
                    'timestamp',
                    'id',
                )

COMMON_CSRF_HEADERS = (
                    # These are a list of HTTP Headers often found in requests
                    # of web applications using various frameworks.
                    'CSRF-Token',               # Express JS CSURF Middleware
                    'XSRF-Token',               # Node JS/ Express JS
                    'X-CSRF-Token',             # Ruby on Rails
                    'X-XSRF-Token',             # Express JS CSURF Middleware
                    # Some other probabilties
                    'X-CSRF-Header',
                    'X-XSRF-Header',
                    'X-CSRF-Protection'
                )

# TODO: Add and replace with more valid and arguable exclusion lists
EXCLUSIONS_LIST = (
                    'logout',
                    'action=out',
                    'action=logoff',
                    'action=delete',
                    'UserLogout',
                    'osCsid',
                    'action=logout',
                )

# List of common errors shown when token is tampered.
TOKEN_ERRORS = (
                    'the required form field',
                    'token could not',
                    'invalid token',
                    'wrong',
                    'error',
                    'not valid',
                    'please check your request',
                    'your browser did something unexpected',
                    'clearing your cookies',
                    'tampered token',
                    'null',
                    'unacceptable',
                    'false',
                    'void',
                    'incorrect',
                    'inoperative',
                    'faulty',
                    'absurd',
                    'inconsistent',
                    'not acceptable',
            )
