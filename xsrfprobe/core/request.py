#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import time
import logging
import requests
from typing import Any
from urllib.parse import urlparse

from xsrfprobe.files import config
from xsrfprobe.files import discovered
from xsrfprobe.core.randua import RandomAgent
from xsrfprobe.core.logger import ErrorLogger
from xsrfprobe.core.schema import (
    DiscoveredToken, TokenDiscoveryModeEnum, TokenDiscoveryPartEnum,
)

SESSION = requests.Session()

_INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.I)
_ATTR_NAME_RE = re.compile(r"\bname=['\"]([^'\"]+)['\"]", re.I)
_ATTR_VALUE_RE = re.compile(r"\bvalue=['\"]([^'\"]*)['\"]", re.I)

_default_headers: dict | None = None
_session_cookies_initialized: bool = False

# User-supplied cookies are "pinned": re-asserted on every request so a server
# Set-Cookie (or an isolated session) can never overwrite the value the user
# provided for the lifetime of the scan.
_PINNED_COOKIES: dict[str, str] = {}
_PINNED_DOMAIN: str = ""

def initSessionCookie() -> None:
    """Parse user-supplied cookies once and pin them onto the SESSION jar."""
    global _session_cookies_initialized, _PINNED_DOMAIN
    if _session_cookies_initialized:
        return
    _session_cookies_initialized = True

    if not config.COOKIE_VALUE:
        return

    parsed_uri = urlparse(config.SITE_URL)
    _PINNED_DOMAIN = parsed_uri.hostname or ""

    for raw in config.COOKIE_VALUE:
        raw = raw.strip()
        if "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        _PINNED_COOKIES[name.strip()] = value.strip()

    pinUserCookies(SESSION)


def pinUserCookies(session: requests.Session) -> None:
    """(Re-)assert the user-supplied cookies on the given session jar so they
    always retain the user's value regardless of any server-side rotation."""
    if not _PINNED_COOKIES:
        return
    for name, value in _PINNED_COOKIES.items():
        try:
            session.cookies.set(name, value, domain=_PINNED_DOMAIN, path="/")
        except Exception:
            pass


def buildDefaultHeaders() -> dict:
    """Build default headers lazily, after CLI has populated config values."""
    global _default_headers

    initSessionCookie()

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


def cors_allows_credentialed_header(url: str, method: str, header_name: str) -> bool:
    """Probe whether the server's CORS policy would allow a CREDENTIALED
    cross-origin request (from an attacker origin) carrying ``header_name``.

    This is the precondition for a custom-header CSRF bypass (e.g. M2's
    X-HTTP-Method-Override, or T8's custom token header) to actually work in a
    victim's browser: setting a non-safelisted header triggers a CORS preflight,
    and the request only proceeds with cookies if the server returns
    ``Access-Control-Allow-Origin: <attacker-origin>`` (NOT ``*`` — that's
    invalid with credentials), ``Access-Control-Allow-Credentials: true`` and an
    ``Access-Control-Allow-Headers`` that lists the header. Without all three the
    browser blocks it, so the bypass is server-side only.
    """
    logger = logging.getLogger("CORSProbe")
    attacker_origin = "https://xsrfprobe-cors-probe.example"
    headers = buildDefaultHeaders().copy()
    headers["Origin"] = attacker_origin
    headers["Access-Control-Request-Method"] = method.upper()
    headers["Access-Control-Request-Headers"] = header_name.lower()

    r = requestMaker(url, method="OPTIONS", headers=headers)
    if r is None:
        return False

    h = {k.lower(): v for k, v in r.headers.items()}
    acao = h.get("access-control-allow-origin", "").strip()
    acac = h.get("access-control-allow-credentials", "").strip().lower()
    acah = h.get("access-control-allow-headers", "").lower()

    allowed = (acao == attacker_origin and acac == "true"
               and (header_name.lower() in acah or acah.strip() == "*"))
    logger.debug("[CORS] %s | ACAO=%r ACAC=%r ACAH=%r | credentialed '%s' allowed=%s",
                 url, acao, acac, acah, header_name, allowed)
    return allowed

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

def _harvest_tokens_passively(resp: requests.Response) -> None:
    """Record distinct anti-CSRF token samples from any response flowing through
    requestMaker, so post-scan predictability analysis has enough independently
    generated samples. Samples go into the analysis-only ``TOKEN_SAMPLES`` pool
    (never ``ANTI_CSRF_TOKENS``) so the active bypass tests are unaffected. This
    function never issues requests and swallows its own errors."""
    if not getattr(config, "TOKEN_CHECKS", True):
        return
    # Token imports request (requestMaker/SESSION), so importing it at module
    # top level would be a circular import; defer it until the function runs.
    try:
        from xsrfprobe.modules.Token import isCSRField
    except Exception:
        return

    def _record(name: str, value: str, part) -> None:
        if not value:
            return
        for s in discovered.TOKEN_SAMPLES:
            if s.name == name and s.token == value and s.discovery_part == part:
                return
        discovered.TOKEN_SAMPLES.append(DiscoveredToken(
            name=name, token=value, url=getattr(resp, "url", "") or "",
            mode=TokenDiscoveryModeEnum.PASSIVE, discovery_part=part,
        ))

    # 1) Hidden form tokens in the response body.
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    if body:
        for tag in _INPUT_TAG_RE.findall(body):
            nm = _ATTR_NAME_RE.search(tag)
            vm = _ATTR_VALUE_RE.search(tag)
            if nm and vm and isCSRField(nm.group(1), vm.group(1)):
                _record(nm.group(1), vm.group(1), TokenDiscoveryPartEnum.REQUEST_BODY)

    # 2) Token-bearing cookies set on this response.
    try:
        for cookie in resp.cookies:
            if cookie.value and isCSRField(cookie.name, cookie.value):
                _record(cookie.name, cookie.value, TokenDiscoveryPartEnum.COOKIE)
    except Exception:
        pass


def requestMaker(url: str, method: str="GET", session: requests.Session=SESSION, params: Any | None=None, data: Any | None=None, headers: dict | None=None) -> requests.Response | None:
    """
    This function is intended to make requests to the target URL.
    """
    logger = logging.getLogger("requestMaker")
    if config.DELAY_VALUE > 0:
        time.sleep(config.DELAY_VALUE)

    # Ensure user-supplied cookies are loaded and re-pinned on this session
    # (any session, including isolated ones) so they persist for the whole scan.
    initSessionCookie()
    pinUserCookies(session)

    if headers is None:
        headers = buildDefaultHeaders()

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

        _harvest_tokens_passively(resp)

        return resp

    except Exception as e:
        logger.error(f"Error during request processing: {e.__str__()}")
        return None
