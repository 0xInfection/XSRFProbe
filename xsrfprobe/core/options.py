#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Importing stuff
import argparse
import sys
import urllib.parse
import os
import re

import tld
import tld.exceptions

from files import config
from core.banner import banner
from core.updater import updater
from xsrfprobe import __version__, __license__

banner()

# Processing command line arguments
parser = argparse.ArgumentParser(usage="xsrfprobe -u <url> <args>")
parser._action_groups.pop()

# A simple hack to have required arguments and optional arguments separately
required = parser.add_argument_group("Required Arguments")
optional = parser.add_argument_group("Optional Arguments")

# Required Options
required.add_argument("-u", "--url", help="Main URL to test", dest="url")

# Optional Arguments (main stuff and necessary)
optional.add_argument(
    "-c",
    "--cookie",
    help="Cookie value to be requested with each successive request. If there are multiple cookies, separate them with commas. For example: `-c PHPSESSID=i837c5n83u4, _gid=jdhfbuysf`.",
    dest="cookie",
)
optional.add_argument(
    "-o",
    "--output",
    help="Output directory where files to be stored. Default is the output/ folder where all files generated will be stored.",
    dest="output",
)
optional.add_argument(
    "-d",
    "--delay",
    help="Time delay between requests in seconds. Default is zero.",
    dest="delay",
    type=float,
)
optional.add_argument(
    "-q",
    "--quiet",
    help="Set the DEBUG mode to quiet. Report only when vulnerabilities are found. Minimal output will be printed on screen. ",
    dest="quiet",
    action="store_true",
)
optional.add_argument(
    "-H",
    "--headers",
    help='Comma separated list of custom headers you\'d want to use. For example: ``--headers "Accept=text/php, X-Requested-With=Dumb"``.',
    dest="headers",
    type=str,
)
optional.add_argument(
    "-v",
    "--verbose",
    help="Increase the verbosity of the output (e.g., -vv is more than -v). ",
    dest="verbose",
    action="store_true",
)
optional.add_argument(
    "-t",
    "--timeout",
    help="HTTP request timeout value in seconds. The entered value may be either in floating point decimal or an integer. Example: ``--timeout 10.0``",
    dest="timeout",
    type=(float or int),
)
optional.add_argument(
    "-E",
    "--exclude",
    help="Comma-separated paths / file containing paths (separated by newlines) to exclude when crawling and scanning.",
    dest="exclude",
    type=str,
)

# Other Options
# optional.add_argument('-h', '--help', help='Show this help message and exit', dest='disp', default=argparse.SUPPRESS, action='store_true')
optional.add_argument(
    "--user-agent",
    help="Custom user-agent to be used. Only one user-agent can be specified.",
    dest="user_agent",
    type=str,
)
optional.add_argument(
    "--max-chars",
    help="Maximum allowed character length for the custom token value to be generated. For example: `--max-chars 5`. Default value is 6.",
    dest="maxchars",
    type=int,
)
optional.add_argument(
    "--crawl",
    help="Crawl the whole site and simultaneously test all discovered endpoints for CSRF.",
    dest="crawl",
    action="store_true",
)
optional.add_argument(
    "--no-analysis",
    help="Skip the Post-Scan Analysis of Tokens which were gathered during requests",
    dest="skipal",
    action="store_true",
)
optional.add_argument(
    "--malicious",
    help="Generate a malicious CSRF Form which can be used in real-world exploits.",
    dest="malicious",
    action="store_true",
)
optional.add_argument(
    "--skip-poc",
    help="Skip the PoC Form Generation of POST-Based Cross Site Request Forgeries.",
    dest="skippoc",
    action="store_true",
)
optional.add_argument(
    "--no-verify",
    help="Do not verify SSL certificates with requests.",
    dest="no_verify",
    action="store_true",
)
optional.add_argument(
    "--debug",
    help="Print out requests and responses while making requests.",
    dest="debug",
    action="store_true",
)
optional.add_argument(
    "--update",
    help="Update XSRFProbe to latest version on GitHub via git.",
    dest="update",
    action="store_true",
)
optional.add_argument(
    "--random-agent",
    help="Use random user-agents for making requests.",
    dest="randagent",
    action="store_true",
)
optional.add_argument(
    "--version",
    help="Display the version of XSRFProbe and exit.",
    dest="version",
    action="store_true",
)
optional.add_argument(
    "--json",
    help="Output the results into a JSON file.",
    dest="json",
    action="store_true",
)
args = parser.parse_args()

if not len(sys.argv) > 1:
    parser.print_help()
    quit()

# Update XSRFProbe to latest version
if args.update:
    updater()
    quit()

# Print out XSRFProbe version
if args.version:
    print("[+] XSRFProbe Version: v%s" % __version__)
    print("[+] XSRFProbe License: %s\n" % __license__)
    quit()

if not args.url:
    print("[-] You must supply a URL to test.")
    quit()
else:
    config.SITE_URL = args.url
    parsed_uri = urllib.parse.urlparse(args.url)

    if not parsed_uri.scheme:
        print("[-] Invalid URL format. Please provide a valid URL including a scheme.")
        quit()

    hostname = parsed_uri.hostname
    if args.output:
        if not args.output.endswith("/"):
            args.output = args.output + "/"
        # If output directory is mentioned...
        try:
            if not os.path.exists(f"{args.output}{hostname}"):
                os.makedirs(f"{args.output}{hostname}")
        except FileExistsError:
            pass

        config.OUTPUT_DIR = f"{args.output}{hostname}/"
    else:
        try:
            os.makedirs(f"xsrfprobe-output/{hostname}")
        except FileExistsError:
            pass

        config.OUTPUT_DIR = f"xsrfprobe-output/{hostname}/"

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

# Crawl the site if --crawl supplied.
if args.crawl:
    config.CRAWL_SITE = True
    # Turning off the display header feature due to too much log generation.

if args.cookie:
    # Assigning Cookie
    for cook in args.cookie.split(","):
        config.COOKIE_VALUE.append(cook)
        # This is necessary when a cookie value is supplied
        # Since if the user-agent used to make the request changes
        # from time to time, the remote site might trigger up
        # security mechanisms (or worse, perhaps block your ip?)
        config.USER_AGENT_RANDOM = False

# Set the requests not to verify SSL certificates
if args.no_verify:
    config.VERIFY_CERT = False

# Timeout value
if args.timeout:
    config.TIMEOUT_VALUE = args.timeout

# Custom header values if specified
if args.headers:
    # NOTE: As a default idea, when the user supplies custom headers, we
    # simply add the custom headers to a list of existing headers in
    # files/config.py.
    # Uncomment the following lines to just reinitialise the headers every time
    # they make a request.
    #
    # config.HEADER_VALUES = {}
    for head in args.headers.split(","):
        key, val = head.split("=")
        config.HEADER_VALUES[key.strip()] = val.strip()

if args.exclude:
    # check if the exclude parameter has a file path
    if os.path.exists(args.exclude):
        with open(args.exclude, "r") as f:
            m = f.readlines()
            for s in m:
                if not s.endswith("/"):
                    s += "/"
                config.EXCLUDE_DIRS.append(urllib.parse.urljoin(config.SITE_URL, s))
    else:
        exc = args.exclude
        m = exc.split(",").strip()
        path = config.SITE_URL.split("://")[1]
        for s in m:
            if not s.endswith("/"):
                s += "/"

            config.EXCLUDE_DIRS.append(urllib.parse.urljoin(config.SITE_URL, s))

if args.randagent:
    # If random-agent argument supplied...
    config.USER_AGENT_RANDOM = True
    print("[*] Random User-Agent mode activated.")
    # Turn off a single User-Agent mechanism...
    config.USER_AGENT = ""

if args.debug:
    config.DEBUG = True

if args.json:
    config.JSON_OUTPUT = True
