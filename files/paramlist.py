#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# List of anti-CSRF paramter values which are sent for form 
# verification of the token.
COMMON_CSRF_NAMES = (
        'CSRFName',                   # OWASP CSRF_Guard
        'CSRFToken',                  # OWASP CSRF_Guard
        'anticsrf',                   # AntiCsrfParam.java
        '__RequestVerificationToken', # AntiCsrfParam.java
        'YII_CSRF_TOKEN',             # http://www.yiiframework.com/
        'yii_anticsrf'                # http://www.yiiframework.com/
        '[_token]',                   # Symfony 2.x
        '_csrf_token',                # Symfony 1.4
        'csrfmiddlewaretoken',        # Django 1.5
        
        # These are some other various token names I have seen in 
        # various websites.
        #
        # TODO: Add more similar csrf token parameters
        'token',
        'csrf',
        'authenticity',
        'auth_token',
        'authenticity_token',
        'auth',
        'anti_csrf',
        'auth_value',
        'csrf_value',
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
        '__csrf'
    )
