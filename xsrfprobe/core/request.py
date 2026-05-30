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
from typing import Any
from urllib.parse import urlparse

from xsrfprobe.files import config
from xsrfprobe.core.randua import RandomAgent
from xsrfprobe.core.logger import ErrorLogger

SESSION = requests.Session()

_default_headers: dict | None = None
_session_cookies_initialized: bool = False

def _init_session_cookies() -> None:
    """Inject user-supplied cookies into the SESSION jar (once)."""
    global _session_cookies_initialized
    if _session_cookies_initialized:
        return
    _session_cookies_initialized = True

    if not config.COOKIE_VALUE:
        return

    parsed_uri = urlparse(config.SITE_URL)
    domain = parsed_uri.hostname or ""

    for raw in config.COOKIE_VALUE:
        raw = raw.strip()
        if "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        SESSION.cookies.set(name.strip(), value.strip(), domain=domain, path="/")


def _build_default_headers() -> dict:
    """Build default headers lazily, after CLI has populated config values."""
    global _default_headers

    _init_session_cookies()

    if _default_headers is not None:
        if config.USER_AGENT_RANDOM:
            _default_headers["User-Agent"] = RandomAgent()
        return _default_headers

    headers = config.HEADER_VALUES.copy()
    parsed_uri = urlparse(config.SITE_URL)

    headers["Origin"] = f"{parsed_uri.scheme}://{parsed_uri.netloc}"
    headers["Referer"] = config.SITE_URL

    if config.USER_AGENT_RANDOM:
        headers["User-Agent"] = RandomAgent()
    elif config.USER_AGENT:
        headers["User-Agent"] = config.USER_AGENT

    _default_headers = headers
    return _default_headers

def getRequestRaw(response: requests.Response):
    """
    This function is intended to return the raw response of the request.
    """
    raw_request = f"{response.request.method} {response.request.url} HTTP/{'.'.join(list(str(response.raw.version)))}\n"
    for k, v in response.request.headers.items():
        raw_request += f"{k}: {v}\n"
    if response.request.body:
        raw_request += f"\n{response.request.body}"
    return raw_request

def getResponseRaw(response: requests.Response):
    """
    This function is intended to return the raw response of the request.
    """
    raw_response = f"HTTP/{'.'.join(list(str(response.raw.version)))} {response.status_code} {response.reason}\n"
    for k, v in response.headers.items():
        raw_response += f"{k}: {v}\n"
    raw_response += f"\n{response.text}"
    return raw_response

def requestMaker(url: str, method: str="GET", session: requests.Session=SESSION, params: Any | None=None, data: Any | None=None, headers: dict | None=None) -> requests.Response | None:
    """
    This function is intended to make requests to the target URL.
    """
    logger = logging.getLogger("requestMaker")
    if config.DELAY_VALUE > 0:
        time.sleep(config.DELAY_VALUE)

    if headers is None:
        headers = _build_default_headers()

    try:
        resp = session.request(
            method=method,
            url=url,
            data=data,
            params=params,
            headers=headers,
            timeout=config.TIMEOUT_VALUE,
            verify=config.VERIFY_CERT,
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
        logger.error(f"Error during request processing: {e.__str__()}")
        return None
