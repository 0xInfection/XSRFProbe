#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Importing stuff
import argparse, sys, tld
import urllib.parse, os, re
from files import config
from core.colors import R, G
from core.updater import updater
from files.dcodelist import IP

# Processing command line arguments
parser = argparse.ArgumentParser('python3 xsrfprobe.py')
parser._action_groups.pop()

# A simple hack to have required argumentsa and optional arguments separately
required = parser.add_argument_group('Required Arguments')
optional = parser.add_argument_group('Optional Arguments')

# Required Options
required.add_argument('-u', '--url', help='Main URL to test', dest='url')

# Optional Arguments (main stuff and necessary)
optional.add_argument('-c', '--cookie', help='Cookie value to be requested with each successive request. If there are multiple cookies, separate them with commas. For example: `-c PHPSESSID=i837c5n83u4, _gid=jdhfbuysf`.', dest='cookie')
optional.add_argument('-o', '--output', help='Output directory where files to be stored. Default is the output/ folder where all files generated will be stored.', dest='output')
optional.add_argument('-d', '--delay', help='Time delay between requests in seconds. Default is zero.', dest='delay', type=float)
optional.add_argument('-q', '--quiet', help='Set the DEBUG mode to quiet. Report only when vulnerabilities are found. Minimal output will be printed on screen. ', dest='quiet', action='store_true')
optional.add_argument('-v', '--verbose', help='Increase the verbosity of the output (e.g., -vv is more than -v). ', dest='verbose', action='store_true')

# Other Options
# optional.add_argument('-h', '--help', help='Show this help message and exit', dest='disp', default=argparse.SUPPRESS, action='store_true')
optional.add_argument('--user-agent', help='Custom user-agent to be used. Only one user-agent can be specified.', dest='user_agent', type=str)
optional.add_argument('--headers', help='Comma separated list of custom headers you\'d want to use. For example: ``--headers "Accept=text/php, X-Requested-With=Dumb"``.', dest='headers', type=str)
optional.add_argument('--exclude', help='Comma separated list of paths or directories to be excluded which are not in scope. These paths/dirs won\'t be scanned. For example: `--exclude somepage/, sensitive-dir/, pleasedontscan/`', dest='exclude', type=str)
optional.add_argument('--timeout', help='HTTP request timeout value in seconds. The entered value may be either in floating point decimal or an integer. Example: ``--timeout 10.0``', dest='timeout', type=(float or int))
optional.add_argument('--max-chars', help='Maximum allowed character length for the custom token value to be generated. For example: `--max-chars 5`. Default value is 6.', dest='maxchars', type=int)
optional.add_argument('--crawl', help="Crawl the whole site and simultaneously test all discovered endpoints for CSRF.", dest='crawl', action='store_true')
optional.add_argument('--no-analysis', help='Skip the Post-Scan Analysis of Tokens which were gathered during requests', dest='skipal', action='store_true')
optional.add_argument('--malicious', help='Generate a malicious CSRF Form which can be used in real-world exploits.', dest='malicious', action='store_true')
optional.add_argument('--skip-poc', help='Skip the PoC Form Generation of POST-Based Cross Site Request Forgeries.', dest='skippoc', action='store_true')
optional.add_argument('--display', help='Print out response headers of requests while making requests.', dest='disphead', action='store_true')
optional.add_argument('--update', help='Update XSRFProbe to latest version on GitHub via git.', dest='update', action='store_true')
optional.add_argument('--random-agent', help='Use random user-agents for making requests.', dest='randagent', action='store_true')
optional.add_argument('--version', help='Display the version of XSRFProbe and exit.', dest='version', action='store_true')
args = parser.parse_args()

if not len(sys.argv) > 1:
    print('''
    \033[1;91mXSRFProbe\033[0m, \033[1;97mA \033[1;93mCross Site Request Forgery \033[1;97mAudit Toolkit\033[0m
''')
    parser.print_help()
    quit('')

# Update XSRFProbe to latest version
if args.update:
    updater()
    quit('')

# Print out XSRFProbe version
if args.version:
    print('\n\033[1;97m [+] \033[1;91mXSRFProbe Version\033[0m : \033[1;97m'+open('files/VersionNum').read())
    quit()

# Now lets update some global config variables
if args.maxchars:
    config.TOKEN_GENERATION_LENGTH = args.maxchars

# Setting custom user-agent
if args.user_agent:
    config.USER_AGENT = args.user_agent

# Option to skip analysis
if args.skipal:
    config.SCAN_ANALYSIS = False

# Option to skip poc generation
if args.skippoc:
    config.POC_GENERATION = False

# Option to generate malicious form
if args.malicious:
    config.GEN_MALICIOUS = True

# Updating main root url
if not args.version and not args.update:
    if args.url: # and not args.help:
        if 'http' in args.url:
            config.SITE_URL = args.url
        else:
            config.SITE_URL = 'http://'+args.url
    else:
        print(R+'You must supply a url/endpoint.')

# Crawl the site if --crawl supplied.
if args.crawl:
    config.CRAWL_SITE = True
    # Turning off the display header feature due to too much log generation.
    config.DISPLAY_HEADERS = False

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

# Set the headers displayer to 1 (actively display headers)
if args.disphead:
    config.DISPLAY_HEADERS = True

# Timeout value
if args.timeout:
    config.TIMEOUT_VALUE = args.timeout

# Custom header values if specified
if args.headers:
    # NOTE: As a default idea, when the user supplies custom headers, we
    # simply add the custom headers to a list of existing headers in
    # files/config.py.
    # Uncomment the following lines to just reinitialise the headers everytime
    # they make a request.
    #
    #config.HEADER_VALUES = {}
    for m in args.headers.split(','):
        config.HEADER_VALUES[m.split('=')[0]] = m.split('=')[1]  # nice hack ;)

if args.exclude:
    exc = args.exclude
    #config.EXCLUDE_URLS = [s for s in exc.split(',').strip()]
    m = exc.split(',').strip()
    for s in m:
        config.EXCLUDE_DIRS.append(urllib.parse.urljoin(config.SITE_URL, s))

if args.randagent:
    # If random-agent argument supplied...
    config.USER_AGENT_RANDOM = True
    # Turn off a single User-Agent mechanism...
    config.USER_AGENT = ''

if config.SITE_URL:
    try:
        if args.output:
            # If output directory is mentioned...
            try:
                if not os.path.exists(args.output+tld.get_fld(config.SITE_URL)):
                    os.makedirs(args.output+tld.get_fld(config.SITE_URL))
            except FileExistsError:
                pass
            config.OUTPUT_DIR = args.output+tld.get_fld(config.SITE_URL) + '/'
        else:
            try:
                os.makedirs('output/'+tld.get_fld(config.SITE_URL))
            except FileExistsError:
                pass
            config.OUTPUT_DIR = 'output/'+tld.get_fld(config.SITE_URL) + '/'
    # When this exception turns out, we know the user has supplied a IP not domain
    except tld.exceptions.TldDomainNotFound:
        direc = re.search(IP, config.SITE_URL).group(0)
        if args.output:
            # If output directory is mentioned...
            try:
                if not os.path.exists(args.output+direc):
                    os.makedirs(args.output+direc)
            except FileExistsError:
                pass
            config.OUTPUT_DIR = args.output+direc + '/'
        else:
            try:
                os.makedirs('output/'+direc)
            except FileExistsError:
                pass
            config.OUTPUT_DIR = 'output/'+direc + '/'        

if args.quiet:
    config.DEBUG = False
