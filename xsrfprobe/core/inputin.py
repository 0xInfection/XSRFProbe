#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection (@_tID)
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from urllib.parse import urlparse
import re

import requests

from xsrfprobe.files.config import TIMEOUT_VALUE
import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.core.verbout import verbout
from xsrfprobe.files.dcodelist import IP
from xsrfprobe.core.logger import ErrorLogger
from xsrfprobe.files.config import SITE_URL, CRAWL_SITE, VERIFY_CERT


def inputin():
    """
    This module actually parses the url passed by the user.
    """
    web = ""
    if SITE_URL:
        web = SITE_URL  # If already assigned

    if not web.endswith("/"):
        web = web + "/"

    if "http" not in web:  # add protocol to site
        web = "http://" + web

    try:
        web0 = urlparse(web).netloc
    except Exception:
        web0 = re.search(IP, web).group(0)

    try:
        print(
            colors.O + "Testing site " + colors.CYAN + web0 + colors.END + " status..."
        )
        requests.get(web, timeout=TIMEOUT_VALUE)  # test whether site is up or not
        print(colors.GREEN + " [+] Site seems to be up!" + colors.END)
    except requests.exceptions.RequestException:  # if site is down
        print(colors.R + "Site seems to be down...")
        quit()

    # We'll test for endpoint only when the --crawl isn't supplied.
    if not CRAWL_SITE:
        try:
            end_point = web.split("//")[1].split("/", 1)[1]
            if end_point == "":
                end_point = "/"

            print(
                f"{colors.O}Testing {colors.CYAN}{end_point}{colors.END} endpoint status..."
            )
            requests.get(web, timeout=TIMEOUT_VALUE, verify=VERIFY_CERT)
            print(f"{colors.GREEN}[+] Endpoint seems to be up!{colors.END}")
        except requests.exceptions.RequestException as e:
            verbout(colors.R, "Endpoint error: " + end_point)
            ErrorLogger(web0, e.__str__())
            quit()
        except Exception as e:
            verbout(colors.R, "Exception Caught: " + e.__str__())
            ErrorLogger(web0, e.__str__())
            quit()

    if not web0.endswith("/"):
        web0 = web0 + "/"

    if web.split("//")[1] == web0:
        return web, ""

    return (web, web0)
