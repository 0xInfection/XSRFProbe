#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
import requests

from xsrfprobe.core.request import requestMaker, pinUserCookies, initSessionCookie
from xsrfprobe.modules.Token import isCSRField, extractInputValue


def looksLikeToken(param_name: str, value=None) -> bool:
    """
    Whether a form field looks like an anti-CSRF token field. High-confidence
    framework names match on name alone; generic names require a token-like
    value (pass ``value`` whenever it is available).
    """
    return isCSRField(param_name, value)


def refreshTokenPair(url: str, params: dict) -> tuple[dict, requests.Session | None]:
    """
    Re-fetch ``url`` to obtain a fresh anti-CSRF token bound to its cookie.

    For double-submit / cookie-bound token schemes the body token must equal the
    token cookie set on the *same* response. XSRFProbe shares one global session
    jar, so an intervening GET (issued by an unrelated check) can overwrite that
    cookie and desynchronise it from the body token captured earlier, making a
    perfectly forgeable endpoint look like it validates Referer/Origin.
    """
    logger = logging.getLogger("TokenPairRefresh")
    new_params = dict(params)

    token_keys = [key for key in params if looksLikeToken(key, params[key])]
    if not token_keys:
        return new_params, None

    session = requests.Session()
    # Pristine jar + user-supplied cookies only. The fresh GET below issues a
    # token bound to the cookie set on that same response, with no stale cookie
    # to break the pairing. (requestMaker also re-pins user cookies, but we seed
    # them here so the session carries them even before the first request.)
    initSessionCookie()
    pinUserCookies(session)

    response = requestMaker(url, method="GET", session=session)
    if response is None:
        logger.info("Token-pair refresh GET failed; falling back to stale params.")
        return new_params, None

    for key in token_keys:
        fresh_value = extractInputValue(response.text, key)
        if fresh_value:
            new_params[key] = fresh_value
            logger.info("Refreshed token field '%s' with a freshly issued value.", key)

    return new_params, session
