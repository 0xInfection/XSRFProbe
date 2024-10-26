#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import time
import requests
import traceback

from files.config import (
    HEADER_VALUES,
    COOKIE_VALUE,
    USER_AGENT_RANDOM,
    USER_AGENT,
    DELAY_VALUE,
    TIMEOUT_VALUE,
    VERIFY_CERT,
    DEBUG
)
from core.verbout import verbout
from core.randua import RandomAgent
from core.logger import ErrorLogger

headers = HEADER_VALUES.copy()

# Set Cookie
if COOKIE_VALUE:
    headers["Cookie"] = ",".join(cookie for cookie in COOKIE_VALUE)

# Set User-Agent
if USER_AGENT_RANDOM:
    headers["User-Agent"] = RandomAgent()
if USER_AGENT:
    headers["User-Agent"] = USER_AGENT

def requestMaker(url, method, session: requests.Session=requests.Session(), data: str='', headers: dict={}):
    """
    This function is intended to make requests
                to the target URL.
    """
    if DELAY_VALUE > 0:
        time.sleep(DELAY_VALUE)

    try:
        resp = session.request(
            method=method,
            url=url,
            data=data,
            headers=headers,
            timeout=TIMEOUT_VALUE,
            verify=VERIFY_CERT,
        )
        verbout(f"[+] Request made to {url} with status code: {resp.status_code}")
        verbout(f"\n  [REQUEST]\n\n")
        verbout(f"{method} {url} HTTP/1.1")
        for k, v in resp.request.headers.items():
            verbout(f"{k}: {v}")
        if data:
            verbout(f"\n{data}")

        verbout(f"\n  [RESPONSE]\n\n")
        for k, v in resp.headers.items():
            verbout(f"{k}: {v}")
        verbout(f"\n{resp.text}")

        return resp

    except Exception as e:
        print('Error during request processing:', e.__str__())
        ErrorLogger(url, traceback.format_exc())
        return None
