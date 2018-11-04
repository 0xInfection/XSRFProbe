#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import argparse
from files.config import *

# Processing command line arguments
parser = argparse.ArgumentParser()
# Options
parser.add_argument('-u', '--url', help='Main URL to test', dest='root_url')
parser.add_argument('-c', '--cookie', help='Cookie Value', dest='cook')
parser.add_argument('-o', '--output', help='Output Directory', dest='output')
parser.add_argument('-d', '--delay', help='Delay between requests', dest='delay', type=float)
parser.add_argument('-q', '--quiet', help='Decrease output to Minimal', dest='verbose', action='store_true')

# Other Options
parser.add_argument('--user-agent', help='Custom User-Agent', dest='user_agent')
parser.add_argument('--headers', help='Add headers', dest='headers', action='store_true')
parser.add_argument('--exclude', help='Exclude Urls (Not to be Scanned)', dest='exclude')
parser.add_argument('--timeout', help='HTTP Request Timeout', dest='timeout', type=float)
parser.add_argument('--max-chars', help='Length of token created', dest='maxchars', type=int)
parser.add_argument('--update', help='Update XSRFProbe', dest='update', action='store_true')
parser.add_argument('--random-agent', help='Use Random User-Agents for Requests', dest='randagent', action='store_true')
args = parser.parse_args()

# Now lets update some global config variables
if args.maxchars:
    TOKEN_GENERATION_LENGTH = args.maxchars

if args.user_agent:
    USER_AGENT = args.user_agent

if args.root_url:
    SITE_URL = args.root_url
    
if args.cook:
    # Assigning Cookie 
    COOKIE_VALUE = args.cook
    # This is necessary when a cookie value is supplied
    # Since if the user-agent used to make the request changes
    # from time to time, the remote site might trigger up
    # security mechanisms (or worse, perhaps block your ip?)
    USER_AGENT_RANDOM = False
    
if args.timeout:
    TIMEOUT_VALUE = args.timeout
    
if args.exclude:
    exc = args.exclude
    #EXCLUDE_URLS = [s for s in exc.split(',').strip()]
    m = exc.split(',').strip()
    for s in m:
        EXCLUDE_URLS.append(s)
        
if args.randagent:
    # If random-agent argument supplied...
    USER_AGENT_RANDOM = True
    # Turn of a single User-Agent mechanism
    USER_AGENT = ''
