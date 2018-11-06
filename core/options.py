#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Importing stuff
import argparse, sys
from files import config
from core.colors import R
from core.banabout import msg
from files.updater import updater

# Processing command line arguments
parser = argparse.ArgumentParser(prog='xsrfprobe.py')
parser._action_groups.pop()

# A simple hack to have required argumentsa and optional arguments separately
required = parser.add_argument_group('Required Arguments')
optional = parser.add_argument_group('Optional Arguments')

# Required Options
required.add_argument('-u', '--url', help='Main URL to test', dest='url')

# Optional Arguments (main stuff and necessary)
optional.add_argument('-c', '--cookie', help='Cookie value to be requested with each successive request. If there are multiple cookies, separate them with commas. For example: `-c PHPSESSID=i837c5n83u4, _gid=jdhfbuysf`.', dest='cookie')
optional.add_argument('-o', '--output', help='Output directory where files to be stored. Default is the`files` folder where all files generated will be stored.', dest='output')
optional.add_argument('-d', '--delay', help='Time delay between requests in seconds. Default is zero.', dest='delay', type=float)
optional.add_argument('-q', '--quiet', help='Set the DEBUG mode to quiet. Report only when vulnerabilities are found. Minimal output will be printed on screen. ', dest='quiet', action='store_true')

# Other Options
# optional.add_argument('-h', '--help', help='Show this help message and exit', dest='disp', default=argparse.SUPPRESS, action='store_true')
optional.add_argument('--user-agent', help='Custom user-agent to be used. Only one user-agent can be specified.', dest='user_agent', type=str)
optional.add_argument('--headers', help='Comma separated list of custom headers you\'d want to use. For example: ``--headers Accept=text/php, DNT=1``.', dest='headers', type=str)
optional.add_argument('--exclude', help='Comma separated list of paths or directories to be excluded which are not in scope. These paths/dirs won\'t be scanned. For example: `--exclude somepage/, sensitive-dir/, dontscan/`', dest='exclude', type=str)
optional.add_argument('--timeout', help='HTTP request timeout value in seconds. The entered value must be in floating point decimal. Example: ``--timeout 10.0``', dest='timeout', type=float)
optional.add_argument('--max-chars', help='Maximum allowed character length for the custom token value to be generated. For example: `--max-chars 5`. Default value is 6.', dest='maxchars', type=int)
optional.add_argument('--update', help='Update XSRFProbe to latest version on GitHub via git.', dest='update', action='store_true')
optional.add_argument('--random-agent', help='Use random user-agents for making requests', dest='randagent', action='store_true')
optional.add_argument('--version', help='Display the version of XSRFProbe and exit.', dest='version', action='store_true')
args = parser.parse_args()

if not len(sys.argv) > 1:
    print('''
    \033[1;91mXSRFProbe\033[0m, \033[1;97mA Cross Site Request Forgery Audit Toolkit\033[0m
''')
    parser.print_help()
    quit('')

# Update XSRFProbe to latest version
if args.update:
    update()
    quit()

# Print out XSRFProbe version
if args.version:
    print('\n [+] \033[1;91mXSRFProbe Version\033[0m : \033[1;97m'+open('files/VersionNum').read())
    quit()

# Now lets update some global config variables
if args.maxchars:
    config.TOKEN_GENERATION_LENGTH = args.maxchars

if args.user_agent:
    config.USER_AGENT = args.user_agent

# Updating main root url
if not args.version and not args.update:
    if args.url: # and not args.help:
        if 'http' in args.url:
            config.SITE_URL = args.url
        else:
            config.SITE_URL = 'http://'+args.url
    else:
        print(R+'You must supply a url.')
    
if args.cookie:
    # Assigning Cookie
    if ',' in args.cookie:
        for cook in args.cookie.split(','):
            config.COOKIE_VALUE.append(cook.strip())
            # This is necessary when a cookie value is supplied
            # Since if the user-agent used to make the request changes
            # from time to time, the remote site might trigger up
            # security mechanisms (or worse, perhaps block your ip?)
            config.USER_AGENT_RANDOM = False

# Timeout value
if args.timeout:
    config.TIMEOUT_VALUE = args.timeout
    
if args.exclude:
    exc = args.exclude
    #EXCLUDE_URLS = [s for s in exc.split(',').strip()]
    m = exc.split(',').strip()
    for s in m:
        config.EXCLUDE_URLS.append(s)
        
if args.randagent:
    # If random-agent argument supplied...
    config.USER_AGENT_RANDOM = True
    # Turn off a single User-Agent mechanism
    config.USER_AGENT = ''

if len(config.SITE_URL) != 0:
    if args.output:
        # If output directory is mentioned...
        config.OUTPUT_DIR = args.output + config.SITE_URL.split('//')[1]
    else:
        config.OUTPUT_DIR = 'files' + config.SITE_URL.split('//')[1]
    
if args.quiet:
    config.DEBUG = False

