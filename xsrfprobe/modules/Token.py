#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import requests
import logging
from urllib.parse import urlparse

from files import config
from files import discovered
from files.paramlist import COMMON_CSRF_NAMES, COMMON_CSRF_HEADERS

def Token(response: requests.Response) -> bool:
    """
    This method checks for whether Anti-CSRF Tokens are
               present in the request.
    """
    logger = logging.getLogger("TokenAnalyzer")
    found = False

    # first let's have a look at config.py and see if it's set
    if not config.TOKEN_CHECKS:
        return False

    logger.info("Parsing request for detecting anti-csrf tokens...")

    try:
        parsed_uri = urlparse(response.url)
        # check for the request query parameters
        con = parsed_uri.query.split("&")
        for c in con:
            for name in COMMON_CSRF_NAMES:
                param_name, param_value = c.split("=")
                if name.lower() in param_name.lower():
                    logger.debug(f"The form was requested with an Anti-CSRF Token in the query: {response.url}")
                    logger.info(f"Anti-CSRF Query Parameter: {param_name}={param_value}")
                    discovered.REQUEST_TOKENS.append(param_value)
                    found = True
                    break

        if not found:
            logger.debug("Searching for Anti-CSRF Token in Request Body...")
            # check for the request body
            req_body = response.request.body.__str__()
            # handle
            if req_body:
                params = req_body.split("&")
                for param in params:
                    param_name, param_value = param.split("=")
                    for name in COMMON_CSRF_NAMES:
                        if name.lower() in param_name.lower():
                            logger.debug(f"The form was requested with an Anti-CSRF Token in the body: {response.url}")
                            logger.info(f"Anti-CSRF Request Body Parameter: {param_name}={param_value}")
                            # We are appending the token to a variable for further analysis
                            discovered.REQUEST_TOKENS.append(param_value)
                            found = True
                            break

        # if we haven't found the anti-CSRF token in the query, we'll search for it in headers
        if not found:
            for key, value in response.headers.items():
                for name in COMMON_CSRF_HEADERS:  # Iterate over the list
                    # Search if the token is there in request...
                    if name.lower() in key.lower():
                        logger.debug(f"The form was requested with an Anti-CSRF Token Header: {response.url}")
                        logger.info(f"Anti-CSRF Token Header: {key}={value}")
                        # We are appending the token to a variable for further analysis
                        found = True
                        discovered.REQUEST_TOKENS.append(value)
                        break  # Break execution if an Anti-CSRF token is found
    except Exception as e:
        logger.error("Request Parsing Exception!")
        logger.error(f"Error: {e}")

    if found:
        return True

    logger.warning(f"The form was requested without an Anti-CSRF Token: {response.url}")
    logger.info("Endpoint seems VULNERABLE to POST-Based Request Forgery")
    return False
