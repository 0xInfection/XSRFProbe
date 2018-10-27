#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Print out verbose (turn it off for only brief outputs)
DEBUG = True

# Include checks for Form Based CSRFs (POST method) 
# (Recommended keeping True)
POST_BASED = True

# Anti-CSRF Token Checks (Recommended keeping True)
TOKEN_CHECKS = True

# Referer/Origin Checks (Recommended keeping True)
REFERER_CHECKS = True

# Whether to submit Crafted Forms (Recommended keeping True)
# If you turn this to False, it will omit form submissions, 
# so there will be more chances of missing out most possible 
# cases of Form based (POST Based) CSRFs.
FORM_SUBMISSION = True

# Referer Url (Change It Accordingly) 
# eg. Use one of your Subdomains (Same Origin Policy))
REFERER_URL = 'http://www.pwn.io'

# The length of the custom token to be generated for params
#
# The recommended value I prefer is 6. Greater value might
# result in database problems. since every form on the server 
# will be submitted 5+ times for various methods of CSRF attacks.
#
# Lower value wll not harm but it will make it difficult 
# identifying request parameters and token values in a. 
TOKEN_GENERATION_LENGTH = 6
