#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
import requests
import traceback

from files.config import SITE_URL
from urllib.parse import urlparse
from core.logger import ErrorLogger
from core.request import requestMaker


def inputProcessor():
    """
    This module actually parses the url passed by the user.
    """
    logger = logging.getLogger("inputProcessor")
    web = ""
    if SITE_URL:
        web = SITE_URL  # If already assigned

    if not web.endswith("/"):
        web = web + "/"

    if "://" not in web:  # add protocol to site
        logger.warning("[*] Protocol not provided. Assuming HTTP.")
        web = "http://" + web  # assume http if not provided

    try:
        parsed_uri = urlparse(web).netloc
        logger.debug("URL seems to be a domain.")

    except Exception:
        logger.critical("[-] Invalid URL format. Please provide a valid URL.")
        quit()

    resp = None
    try:
        endpoint = web.split("://")[1].split("/", 1)[1]
        if endpoint == "":
            endpoint = "/"

        logger.info("Testing %s endpoint status..." % endpoint)
        resp = requestMaker(web)
        if resp is None:
            logger.critical("Endpoint seems to be not reachable.")
            ErrorLogger(web, "Endpoint seems to be not reachable.")
            quit()

        logger.info(f"[+] Endpoint seems to be up! Status code: {resp.status_code}")

    except requests.exceptions.RequestException as e:
        logger.critical("Endpoint error: ", e.__str__())
        ErrorLogger(parsed_uri, traceback.format_exc())
        quit()

    except Exception as e:
        logger.critical("Exception Caught: ", e.__str__())
        ErrorLogger(parsed_uri, traceback.format_exc())
        quit()

    if web.split("//")[1] == parsed_uri:
        return web, ""

    return web, parsed_uri
