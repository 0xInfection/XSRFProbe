#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection (@_tID)
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import requests
import traceback

from urllib.parse import urlparse
from files.dcodelist import IP
from core.logger import ErrorLogger
from files.config import TIMEOUT_VALUE
from files.config import SITE_URL, VERIFY_CERT


def inputin():
    """
    This module actually parses the url passed by the user.
    """
    web = ""
    if SITE_URL:
        web = SITE_URL  # If already assigned

    if not web.endswith("/"):
        web = web + "/"

    if "://" not in web:  # add protocol to site
        print("[*] Protocol not provided. Assuming HTTP...")
        web = "http://" + web  # assume http if not provided

    try:
        parsed_uri = urlparse(web).netloc
        print("[+] URL seems to be a domain.")
    except Exception:
        print("[-] Invalid URL format. Please provide a valid URL.")
        quit()

    resp = None
    try:
        end_point = web.split("://")[1].split("/", 1)[1]
        if end_point == "":
            end_point = "/"

        print("[*] Testing %s endpoint status..." % end_point)
        resp = requests.get(web, timeout=TIMEOUT_VALUE, verify=VERIFY_CERT)
        print(f"[+] Endpoint seems to be up! Status code: {resp.status_code}")
    except requests.exceptions.RequestException as e:
        print("Endpoint error: ", e.__str__())
        ErrorLogger(parsed_uri, traceback.format_exc())
        quit()
    except Exception as e:
        print("Exception Caught: ", e.__str__())
        ErrorLogger(parsed_uri, traceback.format_exc())
        quit()

    if web.split("//")[1] == parsed_uri:
        return web, ""

    return web, parsed_uri
