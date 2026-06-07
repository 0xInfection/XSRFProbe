#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import logging
import requests

from xsrfprobe.core.request import requestMaker, _pin_user_cookies, _init_session_cookies
from xsrfprobe.files.paramlist import COMMON_CSRF_NAMES
from xsrfprobe.modules.Token import _is_csrf_name_match


def _looks_like_token(param_name: str) -> bool:
    """Whether a form field name looks like an anti-CSRF token field."""
    return any(_is_csrf_name_match(name, param_name) for name in COMMON_CSRF_NAMES)


def _extract_input_value(html: str, name: str) -> str | None:
    """Extract the value of <input name="<name>" value="..."> from HTML.

    Handles both attribute orderings (name-before-value and value-before-name).
    """
    escaped = re.escape(name)
    name_then_value = (
        r'<input\b[^>]*?\bname=[\'"]' + escaped +
        r'[\'"][^>]*?\bvalue=[\'"]([^\'"]*)[\'"]'
    )
    match = re.search(name_then_value, html, re.I)
    if match:
        return match.group(1)

    value_then_name = (
        r'<input\b[^>]*?\bvalue=[\'"]([^\'"]*)[\'"][^>]*?\bname=[\'"]' +
        escaped + r'[\'"]'
    )
    match = re.search(value_then_name, html, re.I)
    if match:
        return match.group(1)

    return None


def refresh_token_pair(url: str, params: dict) -> tuple[dict, requests.Session | None]:
    """Re-fetch ``url`` to obtain a fresh anti-CSRF token bound to its cookie.

    For double-submit / cookie-bound token schemes the body token must equal the
    token cookie set on the *same* response. XSRFProbe shares one global session
    jar, so an intervening GET (issued by an unrelated check) can overwrite that
    cookie and desynchronise it from the body token captured earlier, making a
    perfectly forgeable endpoint look like it validates Referer/Origin.

    Refreshing the pair on a PRISTINE session keeps the header under test as the
    only variable. We deliberately do NOT seed the shared global jar here: stale
    cookies accumulated during the scan (e.g. an earlier ``_gh_sess``) can
    desynchronise the token<->session pairing so the server bounces every
    submission back to a generic page, making the endpoint look untestable.
    Only the USER-SUPPLIED cookies (``--cookie``) are preserved, so explicit
    authentication is never lost.

    Returns ``(new_params, session)``. ``session`` is ``None`` when there is no
    token-like field to refresh, in which case callers should fall back to the
    default global session and the original params.
    """
    logger = logging.getLogger("TokenPairRefresh")
    new_params = dict(params)

    token_keys = [key for key in params if _looks_like_token(key)]
    if not token_keys:
        return new_params, None

    session = requests.Session()
    # Pristine jar + user-supplied cookies only. The fresh GET below issues a
    # token bound to the cookie set on that same response, with no stale cookie
    # to break the pairing. (requestMaker also re-pins user cookies, but we seed
    # them here so the session carries them even before the first request.)
    _init_session_cookies()
    _pin_user_cookies(session)

    response = requestMaker(url, method="GET", session=session)
    if response is None:
        logger.info("Token-pair refresh GET failed; falling back to stale params.")
        return new_params, None

    for key in token_keys:
        fresh_value = _extract_input_value(response.text, key)
        if fresh_value:
            new_params[key] = fresh_value
            logger.info("Refreshed token field '%s' with a freshly issued value.", key)

    return new_params, session
