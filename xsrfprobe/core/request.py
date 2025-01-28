#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import time
import logging
import requests
import traceback
from typing import Any

from files.config import (
    HEADER_VALUES,
    COOKIE_VALUE,
    USER_AGENT_RANDOM,
    USER_AGENT,
    DELAY_VALUE,
    TIMEOUT_VALUE,
    VERIFY_CERT,
)
from core.verbout import verbout
from core.randua import RandomAgent
from core.logger import ErrorLogger

default_headers = HEADER_VALUES.copy()

# Set Cookie
if COOKIE_VALUE:
    default_headers["Cookie"] = ",".join(cookie for cookie in COOKIE_VALUE)

# Set User-Agent
if USER_AGENT_RANDOM:
    default_headers["User-Agent"] = RandomAgent()

if USER_AGENT:
    default_headers["User-Agent"] = USER_AGENT

SESSION = requests.Session()

def getRequestRaw(response: requests.Response):
    """
    This function is intended to return the raw
                response of the request.
    """
    raw_request = f"{response.request.method} {response.request.url} HTTP/{'.'.join(list(str(response.raw.version)))}\n"
    for k, v in response.request.headers.items():
        raw_request += f"{k}: {v}\n"
    if response.request.body:
        raw_request += f"\n{response.request.body}"
    return raw_request

def getResponseRaw(response: requests.Response):
    """
    This function is intended to return the raw
                response of the request.
    """
    raw_response = f"HTTP/{'.'.join(list(str(response.raw.version)))} {response.status_code} {response.reason}\n"
    for k, v in response.headers.items():
        raw_response += f"{k}: {v}\n"
    raw_response += f"\n{response.text}"
    return raw_response

def requestMaker(url, method: str="GET", session: requests.Session=SESSION, data: Any | None=None, headers: dict={}):
    """
    This function is intended to make requests
                to the target URL.
    """
    logger = logging.getLogger("requestMaker")
    if DELAY_VALUE > 0:
        time.sleep(DELAY_VALUE)

    if not headers:
        headers = default_headers

    try:
        resp = session.request(
            method=method,
            url=url,
            data=data,
            headers=headers,
            timeout=TIMEOUT_VALUE,
            verify=VERIFY_CERT,
        )
        if resp is None:
            logger.error(f"No response received; the site is likely down: {url}")
            ErrorLogger(url, "No response received; the site is likely down.")
            return None
        logger.debug(f"Request made to {url} with method: {method}")
        logger.debug(f"\nRequest Raw: \n{getRequestRaw(resp)}\n")
        logger.debug(f"\nResponse Raw: \n{getResponseRaw(resp)}\n")

        return resp

    except Exception as e:
        print('Error during request processing:', e.__str__())
        ErrorLogger(url, traceback.format_exc())
        return None
