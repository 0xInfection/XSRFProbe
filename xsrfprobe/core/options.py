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

from xsrfprobe.files import config
from xsrfprobe.core.banner import banner
from xsrfprobe.core import __version__, __license__


def options() -> argparse.Namespace:
    """
    This function is intended to parse the command line arguments
    and set the global variables accordingly.
    """
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
        help='Comma separated list of custom headers you\'d want to use. For example: ``--headers "Accept=text/php, X-Requested-With=XHR"``.',
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
    optional.add_argument(
        "--force-header-tests",
        help="Run Referer/Origin header tests even when an anti-CSRF token is confirmed enforced. Research/opt-in only: bypass requests still carry a valid token, so results on token-protected endpoints are false positives.",
        dest="force_header_tests",
        action="store_true",
    )

    # Browser integration
    browser_group = parser.add_argument_group("Browser Integration")
    browser_group.add_argument(
        "--browser",
        help="Enable headless Firefox browser for SameSite and browser-dependent tests.",
        dest="browser",
        action="store_true",
    )
    browser_group.add_argument(
        "--auto-validate-poc",
        help="Auto-validate generated PoC files in headless browser (requires --browser).",
        dest="auto_validate_poc",
        action="store_true",
    )
    browser_group.add_argument(
        "--geckodriver-path",
        help="Path to geckodriver binary. Default: assumes geckodriver is in PATH.",
        dest="geckodriver_path",
        type=str,
        default="",
    )
    browser_group.add_argument(
        "--browser-timeout",
        help="Page load timeout for headless browser in seconds. Default: 30.",
        dest="browser_timeout",
        type=int,
        default=30,
    )
    browser_group.add_argument(
        "--enum-subdomains",
        help="Enable subdomain enumeration via crt.sh for SameSite=Strict sibling domain bypass tests.",
        dest="enum_subdomains",
        action="store_true",
    )
    browser_group.add_argument(
        "--no-form-submit",
        help="Do not submit forms during scanning. Only perform passive token detection.",
        dest="no_form_submit",
        action="store_true",
    )

    args = parser.parse_args()

    if not len(sys.argv) > 1:
        parser.print_help()
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

    # Crawl the site if --crawl supplied.
    if args.crawl:
        config.CRAWL_SITE = True

    if args.cookie:
        # Assigning Cookie
        for cook in args.cookie.split(","):
            config.COOKIE_VALUE.append(cook.strip())
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

    # Delay between requests
    if args.delay:
        config.DELAY_VALUE = args.delay

    # Custom header values if specified
    if args.headers:
        # NOTE: As a default idea, when the user supplies custom headers, we
        # simply add the custom headers to a list of existing headers in
        # files/config.py.
        for head in args.headers.split(","):
            key, val = head.split("=")
            config.HEADER_VALUES[key.strip()] = val.strip()

    if args.exclude:
        # check if the exclude parameter has a file path
        if os.path.exists(args.exclude):
            with open(args.exclude, "r") as f:
                m = f.readlines()
                for s in m:
                    if not s.startswith("/"):
                        s = "/" + s
                    config.EXCLUDE_DIRS.append(urllib.parse.urljoin(config.SITE_URL, s))
        else:
            exc = args.exclude
            m = [s.strip() for s in exc.split(",")]
            for s in m:
                if not s.endswith("/"):
                    s += "/"

                config.EXCLUDE_DIRS.append(urllib.parse.urljoin(config.SITE_URL, s))

    if args.randagent:
        # If random-agent argument supplied we override the default user-agent and force override cookies
        config.USER_AGENT_RANDOM = True
        print("[*] Random User-Agent mode activated.")
        # Turn off a single User-Agent mechanism...
        config.USER_AGENT = ""

    if args.debug:
        config.DEBUG = True

    if args.json:
        config.JSON_OUTPUT = True

    if args.force_header_tests:
        config.FORCE_HEADER_TESTS = True

    # Browser integration config
    if args.browser:
        config.BROWSER_ENABLED = True

    if args.auto_validate_poc:
        config.AUTO_VALIDATE_POC = True
        if not config.BROWSER_ENABLED:
            print("[!] --auto-validate-poc requires --browser. Enabling browser mode.")
            config.BROWSER_ENABLED = True

    if args.geckodriver_path:
        config.GECKODRIVER_PATH = args.geckodriver_path

    if args.browser_timeout:
        config.BROWSER_TIMEOUT = args.browser_timeout

    if args.enum_subdomains:
        config.ENUM_SUBDOMAINS = True

    if args.no_form_submit:
        config.FORM_SUBMISSION = False

    return args