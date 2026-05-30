#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import sys
import logging
import requests

from xsrfprobe.files import config
from urllib.parse import urlparse
from xsrfprobe.core.request import requestMaker


def inputProcessor() -> tuple[str, str]:
    """
    This module actually parses the url passed by the user.
    """
    logger = logging.getLogger("inputProcessor")
    web = config.SITE_URL

    if "://" not in web:  # add protocol to site
        logger.warning("Protocol not provided. Assuming HTTP.")
        web = "http://" + web  # assume http if not provided

    try:
        parsed_uri = urlparse(web)
        logger.debug("URL seems to be a domain.")

    except Exception:
        logger.critical("Invalid URL format. Please provide a valid URL.")
        sys.exit(1)

    endpoint = '/' if not parsed_uri.path else parsed_uri.path
    resp = None
    try:
        logger.info(f"Testing '{endpoint}' endpoint status...")
        resp = requestMaker(web)
        if resp is None:
            logger.critical("Endpoint seems to be not reachable.")
            sys.exit(1)

        logger.info(f"[+] Endpoint seems to be up! Status code: {resp.status_code}")

    except requests.exceptions.RequestException:
        logger.exception("Error reaching the endpoint")
        sys.exit(1)

    except Exception:
        logger.exception("Exception caught")
        sys.exit(1)

    return web, endpoint
