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
                    'anticsrf',                   # AntiCsrfParam.java
                    '__RequestVerificationToken', # AntiCsrfParam.java
                    'authenticity_token',         # Ruby on Rails
                    'csrf_param',                 # Ruby on Rails
                    'TransientKey',               # VanillaForums
                    'YII_CSRF_TOKEN',             # http://www.yiiframework.com/
                    'yii_anticsrf'                # http://www.yiiframework.com/
                    '[_token]',                   # Symfony 2.x
                    '_csrf_token',                # Symfony 1.4
                    'csrfmiddlewaretoken',        # Django 1.5
                    'ccm_token',                  # Concrete 5
                    'XOOPS_TOKEN_REQUEST',        # Xoops CMS

                    # These are some other various token names I have seen in
                    # various websites.
                    #
                    # TODO: Add more similar csrf token parameters
                    'token',
                    'csrf',
                    'authenticity',
                    'auth_token',
                    'auth',
                    'anti_csrf',
                    'auth_value',
                    'csrf_value',
                    '_debugval',
                    'csrf_token',
                    'VerificationToken',
                    '__authvalue',
                    'authenticity_value',
                    '__token',
                    '__auth',
                    'secret',
                    'timestamp_id',
                    'auth_id',
                    'timestamp_secret',
                    'csrf_id',
                    '__csrf',
                    'dts_id',
                    'req_id',
                    '_id',
                    'request_id',
                    'sessionid',
                    '_sessionid',
                    'debug_id',
                    'vtoken'
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
