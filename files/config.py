#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# this module holds values for controlling the entire scan interface.

# Lets assign some global variables...
global SITE_URL, DEBUG, USER_AGENT, USER_AGENT_RANDOM, COOKIE_BASED, COOKIE_VALUE
global HEADER_VALUES, TIMEOUT_VALUE, REFERER_ORIGIN_CHECKS, REFERER_URL, POST_BASED
global DISPLAY_HEADERS, EXECUTABLES, FILE_EXTENSIONS, POC_GENERATION, OUTPUT_DIR
global CRAWL_SITE, TOKEN_CHECKS, DELAY_VALUE, SCAN_ANALYSIS, EXCLUDE_DIRS, GEN_MALICIOUS

# Site Url to be scanned (Required)
SITE_URL = ''

# Switch for whether to crawl the site or not
CRAWL_SITE = False

# Print out verbose (turn it off for only brief outputs).
# Turning off is Highly Discouraged, since you will miss what the tool is doing.
DEBUG = True

# Debug level of the output (beta test feature)
DEBUG_LEVEL = 3

# User-Agent to be used (If COOKIE_VALUE is not supplied)
USER_AGENT_RANDOM = False

# User-Agent to be used (If COOKIE_VALUE supplied).
#
# This is standard User-Agent emulating Chrome 68 on Windows 10 
#
# NOTE: This is a precaution in case the cookie value is supplied,
# if the user-agent gets changed from time to time, the remote
# application might trigger up some protection agents
USER_AGENT = 'Mozilla/5.0 (Windows; U; Windows NT 10.0; en-US) AppleWebKit/604.1.38 (KHTML, like Gecko) Chrome/68.0.3325.162'

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
COOKIE_VALUE = ''

# Header values to be used (Modify it as per your need)
HEADER_VALUES = {
                    'Accept'            : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language'   : 'en-US,en;q=0.5',
                    'Accept-Encoding'   : 'gzip',
                    'DNT'               : '1',  # Do Not Track Request Header :D
                    'Connection'        : 'close'
                }

# Request Timeout (Keep the max. timeout value to 10s)
TIMEOUT_VALUE = 7

# The time delay between requests. This option is especially required
# when there is some sort of security measure such as load-balancers
# or a Firewall (WAF).
DELAY_VALUE = 0

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

# Include checks for Form Based CSRFs (POST method)
# (Recommended keeping True)
POST_BASED = True

# Anti-CSRF Token Checks (Recommended keeping True)
TOKEN_CHECKS = True

# Referer/Origin Checks (Recommended keeping True)
REFERER_ORIGIN_CHECKS = True

# Whether to submit Crafted Forms (Recommended keeping True)
# If you turn this to False, it will omit form submissions,
# so there will be more chances of missing out most possible
# cases of Form based (POST Based) CSRFs.
FORM_SUBMISSION = True

# Referer Url (Change It Accordingly)
# eg. Use one of your Subdomains (Same Origin Policy))
REFERER_URL = 'http://www.pwn.io'

# Origin Url (Change It Accordingly)
# eg. Use one of your Subdomains (Same Origin Policy))
ORIGIN_URL = 'http://www.pwn.io'

# The length of the custom token to be generated for params
#
# The recommended value I prefer is 6. Greater value might
# result in database problems. since every form on the server
# will be submitted 5+ times for various methods of CSRF attacks.
#
# Lower value wll not harm but it will make it difficult
# identifying request parameters and token values in a.
TOKEN_GENERATION_LENGTH = 6

# List of Urls that are not to be scanned (excluded).
EXCLUDE_DIRS = []

# Output directory where everything (including logs) are to
# be stored
OUTPUT_DIR = ''

# This option is for displaying the headers received as response.
# Turn this off if you don't want to see the headers on the
# terminal, or if it feels irritating.
DISPLAY_HEADERS = False

# Option for controlling post-scan analysis. Turning it off
# results in not analysing the tokens gathered.
SCAN_ANALYSIS = True

# Option to skip PoC Form Generation of POST_BASED Request Forgeries.
# The form will not be generated.
POC_GENERATION = True

# Option whether or not to generate a malicious CSRF form with all
# hidden fields.
GEN_MALICIOUS = False

# A list of file extensions that might be come across while scanning
# and crawling
FILE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'pdf', 'js', 'css', 'ico', 'bmp', 'svg', 'json', 'xml', 'xls', 'csv', 'docx',]
# These are a list of executable files that are found on the web
EXECUTABLES = ['deb', 'bat', 'exe', 'msu', 'msi', 'apk', 'bin', 'csh', 'inf', 'ini', 'msc', 'osx' ,'out', 'vbe', 'ws', 'msp', 'jse']
