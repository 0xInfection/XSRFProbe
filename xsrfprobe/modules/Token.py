#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import string
import random
import requests
import logging
from urllib.parse import urlparse, unquote

from xsrfprobe.files import config
from xsrfprobe.files import discovered
from xsrfprobe.core.request import requestMaker, SESSION, _build_default_headers, cors_allows_credentialed_header
from xsrfprobe.core.diff import DiffEngine
from xsrfprobe.core.schema import DiscoveredToken, TokenDiscoveryPartEnum, TokenDiscoveryModeEnum, BenchmarkResult
from xsrfprobe.files.paramlist import COMMON_CSRF_NAMES, COMMON_CSRF_HEADERS
from xsrfprobe.core.logger import VulnLogger, NovulLogger, PROGRESS, test_progress, phase_header


def _is_csrf_name_match(csrf_name: str, param_name: str) -> bool:
    """Check if csrf_name appears as a word-boundary segment in param_name.
    e.g. 'auth' matches 'auth_token' or 'csrf-auth' but NOT 'webauthn'."""
    pattern = r'(?:^|[\-_\[\].])' + re.escape(csrf_name) + r'(?:$|[\-_\[\].])'
    return bool(re.search(pattern, param_name, re.I))


def _norm_token(value: str) -> str:
    """Normalise a token value for comparison across cookie/body encodings.

    Real-world frameworks frequently URL-encode the cookie copy of a token
    while sending it raw in the body (or vice versa), so a naive ``==`` would
    miss a genuine double-submit pair. Unquoting + stripping makes the two
    halves comparable."""
    return unquote(value or "").strip()


class TokenAnalyser:
    def __init__(self) -> None:
        self.postfix_regex = r'<input.*?name=[\'"]%s[\'"].*?value=[\'"](.+?)[\'"]'

    def detectTokens(self, response: requests.Response, passive: bool = False,
                     sent_params: dict | None = None, sent_method: str = "POST") -> bool:
        """
        Checks whether Anti-CSRF Tokens are present in the request/response.

        When ``sent_params`` is provided, request-side detection inspects the
        parameters WE actually submitted (authoritative and redirect-proof),
        instead of reverse-parsing ``response.request`` — which a 3xx replaces
        with the final, body-less request.
        """
        logger = logging.getLogger("TokenDetector")
        found = False

        if not config.TOKEN_CHECKS:
            return False

        logger.info("Parsing request/response for detecting anti-csrf tokens...")

        if passive:
            logger.debug("Passive mode enabled. Trying to detect tokens in response...")
            for name in COMMON_CSRF_NAMES:
                name_regex = self.postfix_regex % name
                value = re.search(name_regex, response.text, re.I)
                if value:
                    value = value.group(1)
                    logger.info(f"Anti-CSRF token detected in response: {name}={value}")
                    discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                        name=name,
                        token=value,
                        url=response.url,
                        mode=TokenDiscoveryModeEnum.PASSIVE,
                        discovery_part=TokenDiscoveryPartEnum.RESPONSE_BODY
                    ))
                    found = True
            return found

        try:
            if sent_params is not None:
                # Authoritative path: inspect the request WE actually built and
                # sent. Redirect-proof — no need to reverse-parse the response's
                # (post-redirect) request.
                part = (TokenDiscoveryPartEnum.REQUEST_QUERY
                        if sent_method.upper() == "GET"
                        else TokenDiscoveryPartEnum.REQUEST_BODY)
                logger.debug("Searching for Anti-CSRF Token in the submitted parameters...")
                for param_name, param_value in sent_params.items():
                    for name in COMMON_CSRF_NAMES:
                        if _is_csrf_name_match(name, param_name):
                            logger.info(f"Anti-CSRF Parameter ({part.value}): {param_name}={param_value}")
                            discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                name=param_name,
                                token=str(param_value),
                                url=response.url,
                                mode=TokenDiscoveryModeEnum.ACTIVE,
                                discovery_part=part,
                            ))
                            found = True
                            break
                    if found:
                        break
            else:
                # Fallback: reverse-parse the (redirect-aware, same-origin)
                # request chain when the caller didn't tell us what it sent.
                request_chain = [r.request for r in response.history] + [response.request]
                origin_netloc = urlparse(request_chain[0].url).netloc
                request_chain = [req for req in request_chain
                                 if urlparse(req.url).netloc == origin_netloc]

                logger.debug("Searching for Anti-CSRF Token in Request URL...")
                for req in request_chain:
                    req_url = str(req.url)
                    parsed_uri = urlparse(req_url)
                    if not parsed_uri.query:
                        continue
                    for c in parsed_uri.query.split("&"):
                        if "=" not in c:
                            continue
                        param_name, param_value = c.split("=", 1)
                        for name in COMMON_CSRF_NAMES:
                            if _is_csrf_name_match(name, param_name):
                                logger.info(f"Anti-CSRF Query Parameter: {param_name}={param_value}")
                                discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                    name=param_name,
                                    token=param_value,
                                    url=req_url,
                                    mode=TokenDiscoveryModeEnum.ACTIVE,
                                    discovery_part=TokenDiscoveryPartEnum.REQUEST_QUERY
                                ))
                                found = True
                                break
                        if found:
                            break
                    if found:
                        break

                if not found:
                    logger.debug("Searching for Anti-CSRF Token in Request Body...")
                    for req in request_chain:
                        if not req.body:
                            continue
                        req_url = str(req.url)
                        req_body = str(req.body)
                        for param in req_body.split("&"):
                            if "=" not in param:
                                continue
                            param_name, param_value = param.split("=", 1)
                            for name in COMMON_CSRF_NAMES:
                                if _is_csrf_name_match(name, param_name):
                                    logger.info(f"Anti-CSRF Request Body Parameter: {param_name}={param_value}")
                                    discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                        name=param_name,
                                        token=param_value,
                                        url=req_url,
                                        mode=TokenDiscoveryModeEnum.ACTIVE,
                                        discovery_part=TokenDiscoveryPartEnum.REQUEST_BODY
                                    ))
                                    found = True
                                    break
                            if found:
                                break
                        if found:
                            break

            if not found:
                logger.debug("Searching for Anti-CSRF Token in Response Headers...")
                for key, value in response.headers.items():
                    if key.lower() == "set-cookie":
                        continue
                    for name in COMMON_CSRF_HEADERS:
                        if name.lower() in key.lower():
                            logger.info(f"Anti-CSRF Token Header: {key}={value}")
                            found = True
                            discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                name=key,
                                token=value,
                                url=response.url,
                                mode=TokenDiscoveryModeEnum.ACTIVE,
                                discovery_part=TokenDiscoveryPartEnum.RESPONSE_HEADERS
                            ))
                            break

                    if found:
                        break

            # Cookie-borne tokens are recorded unconditionally (in addition to
            # any body/query token), because the double-submit pattern requires
            # observing the SAME token in both the body and a cookie. Gating
            # this behind "if not found" used to make body and cookie tokens
            # mutually exclusive, so T6 could never see the cookie half.
            if self._detect_cookie_tokens(response):
                found = True

        except Exception as e:
            logger.error("Request Parsing Exception!")
            logger.error(f"Error: {e}")

        if found:
            return True

        logger.warning(f"No Anti-CSRF Token found in request: {response.url}")
        logger.info("Endpoint seems VULNERABLE to POST-Based Request Forgery")
        return False

    def _detect_cookie_tokens(self, response: requests.Response) -> bool:
        """Record anti-CSRF tokens carried in cookies.

        Reads from proper cookie jars (the response's own jar plus the
        persistent session jar) rather than string-splitting the Set-Cookie
        header, which is unreliable in the wild: real Set-Cookie values contain
        commas (in Expires) and libraries fold multiple cookies into one
        header. The session jar is consulted too because the CSRF cookie is
        commonly issued on an earlier page-load GET, not on the request being
        analysed.

        A cookie is treated as a token if either its name matches a known
        anti-CSRF name, or its (normalised) value mirrors a token already
        discovered in the body/query — the latter catches double-submit cookies
        with unconventional names. Returns True if any cookie token was found.
        """
        logger = logging.getLogger("TokenDetector")
        found = False

        candidates: dict[str, str] = {}
        try:
            for cookie in response.cookies:
                if cookie.value is not None:
                    candidates[cookie.name] = cookie.value
        except Exception:
            pass
        try:
            for cookie in SESSION.cookies:
                if cookie.value is not None:
                    candidates.setdefault(cookie.name, cookie.value)
        except Exception:
            pass

        if not candidates:
            return False

        body_values = {
            _norm_token(t.token)
            for t in discovered.ANTI_CSRF_TOKENS
            if t.token and t.discovery_part in (
                TokenDiscoveryPartEnum.REQUEST_BODY,
                TokenDiscoveryPartEnum.REQUEST_QUERY,
            )
        }

        for cookie_name, cookie_value in candidates.items():
            name_match = any(_is_csrf_name_match(name, cookie_name) for name in COMMON_CSRF_NAMES)
            value_match = bool(body_values) and _norm_token(cookie_value) in body_values
            if not (name_match or value_match):
                continue

            already = any(
                t.discovery_part == TokenDiscoveryPartEnum.COOKIE
                and t.name == cookie_name
                and t.token == cookie_value
                for t in discovered.ANTI_CSRF_TOKENS
            )
            if already:
                continue

            logger.info(f"Anti-CSRF Token Cookie: {cookie_name}={cookie_value}")
            discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                name=cookie_name,
                token=cookie_value,
                url=response.url,
                mode=TokenDiscoveryModeEnum.ACTIVE,
                discovery_part=TokenDiscoveryPartEnum.COOKIE
            ))
            found = True

        return found

    # ----------------------------------------------------------------
    # T2: Validation depends on request method (PortSwigger Lab 2)
    # ----------------------------------------------------------------
    def bypassTokenValidationRequestMethod(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Switch GET<->POST to bypass method-conditioned CSRF validation."""
        logger = logging.getLogger("RequestMethodBypass")
        logger.debug("[T2] Trying request method switch bypass...")
        differ = DiffEngine()

        if method.lower() == "get":
            r = requestMaker(url, method="POST", data=params)
        elif method.lower() == "post":
            r = requestMaker(url, method="GET", params=params)
        else:
            return False

        if r is None:
            return False

        if differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
            alt = "POST" if method.upper() == "GET" else "GET"
            logger.warning(f"[T2] VULNERABLE: Server accepted {alt} method bypass.")
            VulnLogger(url, f"CSRF token validation bypassed via {alt} method switch.", test_id="T2")
            return True

        logger.debug("[T2] Method switch bypass failed. Server validates across methods.")
        NovulLogger(url, "CSRF token validated regardless of request method.", test_id="T2")
        return False

    # ----------------------------------------------------------------
    # T3: Validation depends on token being present (PortSwigger Lab 3)
    # ----------------------------------------------------------------
    def bypassTokenValidationPresence(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Remove the CSRF token parameter entirely to test presence-based validation."""
        logger = logging.getLogger("TokenPresenceBypass")
        logger.debug("[T3] Trying token removal bypass...")
        differ = DiffEngine()

        cookie_token_names = {t.name.lower() for t in discovered.ANTI_CSRF_TOKENS
                              if t.discovery_part == TokenDiscoveryPartEnum.COOKIE}

        for token in discovered.ANTI_CSRF_TOKENS:
            test_params = params.copy()

            if token.discovery_part in (TokenDiscoveryPartEnum.REQUEST_QUERY, TokenDiscoveryPartEnum.REQUEST_BODY):
                test_params.pop(token.name, None)

                # Also remove matching cookie for double-submit patterns
                matching_cookie = token.name.lower() in cookie_token_names
                if matching_cookie:
                    cookies_without = SESSION.cookies.get_dict()
                    cookies_without.pop(token.name, None)
                    for k in list(cookies_without.keys()):
                        if k.lower() == token.name.lower():
                            cookies_without.pop(k)
                    try:
                        r = requests.request(
                            method=method.upper(), url=url,
                            headers=_build_default_headers(),
                            cookies=cookies_without,
                            data=test_params if method.lower() == "post" else None,
                            params=test_params if method.lower() == "get" else None,
                            timeout=config.TIMEOUT_VALUE, verify=config.VERIFY_CERT,
                        )
                    except Exception as e:
                        logger.error(f"Request failed: {e}")
                        r = None
                else:
                    r = requestMaker(
                        url,
                        method=method.upper(),
                        data=test_params if method.lower() == "post" else None,
                        params=test_params if method.lower() == "get" else None
                    )

                if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                    logger.warning(f"[T3] VULNERABLE: Server accepted request without token '{token.name}'.")
                    VulnLogger(url, f"CSRF token '{token.name}' can be omitted entirely.", test_id="T3")
                    return True

            elif token.discovery_part == TokenDiscoveryPartEnum.COOKIE:
                cookie = SESSION.cookies.get_dict()
                cookie.pop(token.name, None)

                try:
                    r = requests.request(
                        method=method.upper(), url=url,
                        headers=_build_default_headers(),
                        cookies=cookie,
                        data=test_params if method.lower() == "post" else None,
                        params=test_params if method.lower() == "get" else None,
                        timeout=config.TIMEOUT_VALUE, verify=config.VERIFY_CERT,
                    )
                except Exception as e:
                    logger.error(f"Request failed: {e}")
                    continue

                if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                    logger.warning(f"[T3] VULNERABLE: Server accepted request without cookie token '{token.name}'.")
                    VulnLogger(url, f"CSRF cookie token '{token.name}' can be omitted entirely.", test_id="T3")
                    return True

        logger.debug("[T3] Token removal bypass failed.")
        NovulLogger(url, "CSRF token presence is required by the server.", test_id="T3")
        return False

    # ----------------------------------------------------------------
    # T7: Empty token value accepted (PortSwigger Lab 3 variant)
    # ----------------------------------------------------------------
    def bypassEmptyTokenValue(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Submit the request with the token parameter present but set to an empty string."""
        logger = logging.getLogger("EmptyTokenBypass")
        logger.debug("[T7] Trying empty token value bypass...")
        differ = DiffEngine()

        cookie_token_names = {t.name.lower() for t in discovered.ANTI_CSRF_TOKENS
                              if t.discovery_part == TokenDiscoveryPartEnum.COOKIE}

        for token in discovered.ANTI_CSRF_TOKENS:
            if token.discovery_part not in (TokenDiscoveryPartEnum.REQUEST_QUERY, TokenDiscoveryPartEnum.REQUEST_BODY):
                continue

            test_params = params.copy()
            test_params[token.name] = ""

            # For double-submit patterns, also empty the matching cookie
            matching_cookie = token.name.lower() in cookie_token_names
            if matching_cookie:
                cookies_emptied = SESSION.cookies.get_dict()
                for k in list(cookies_emptied.keys()):
                    if k.lower() == token.name.lower():
                        cookies_emptied[k] = ""
                try:
                    r = requests.request(
                        method=method.upper(), url=url,
                        headers=_build_default_headers(),
                        cookies=cookies_emptied,
                        data=test_params if method.lower() == "post" else None,
                        params=test_params if method.lower() == "get" else None,
                        timeout=config.TIMEOUT_VALUE, verify=config.VERIFY_CERT,
                    )
                except Exception as e:
                    logger.error(f"Request failed: {e}")
                    r = None
            else:
                r = requestMaker(
                    url,
                    method=method.upper(),
                    data=test_params if method.lower() == "post" else None,
                    params=test_params if method.lower() == "get" else None
                )

            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[T7] VULNERABLE: Server accepted empty token value for '{token.name}'.")
                VulnLogger(url, f"CSRF token '{token.name}' accepts empty value.", test_id="T7")
                return True

        logger.debug("[T7] Empty token bypass failed.")
        return False

    # ----------------------------------------------------------------
    # M1/M2/S1: Method override bypass (_method param + override headers)
    # (PortSwigger SameSite Lax Lab 7 + HackTricks)
    # ----------------------------------------------------------------
    def bypassMethodOverride(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> set[str]:
        """Test HTTP method override via _method param and X-HTTP-Method-Override headers.
        Returns set of bypass IDs that passed: 'M1' for _method param, 'M2' for override headers."""
        logger = logging.getLogger("MethodOverrideBypass")
        logger.debug("[M1/M2] Trying method override bypass...")
        differ = DiffEngine()
        passed = set()

        if method.upper() != "POST":
            return passed

        override_params = params.copy()
        for token in discovered.ANTI_CSRF_TOKENS:
            override_params.pop(token.name, None)

        # Test 1: GET request with _method=POST in query string.
        # Only meaningful if a plain GET (no _method) fails — otherwise the
        # server simply accepts GET and _method override isn't what enables it.
        plain_get = requestMaker(url, method="GET", params=override_params)
        plain_get_passes = (plain_get and
                            differ.benchmarkPassed(base_benchmark, plain_get.text, plain_get.status_code))

        if not plain_get_passes:
            override_params["_method"] = "POST"
            r = requestMaker(url, method="GET", params=override_params)
            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning("[M1] VULNERABLE: Server accepted GET with _method=POST override.")
                VulnLogger(url, "CSRF bypass via _method=POST on GET request.", test_id="M1")
                passed.add("M1")
            override_params.pop("_method", None)

        # Test 2: POST with X-HTTP-Method-Override header set to GET
        # Only meaningful if POST-without-token alone fails (otherwise it's T3)
        baseline_no_token = requestMaker(url, method="POST", data=override_params)
        baseline_passes = (baseline_no_token and
                           differ.benchmarkPassed(base_benchmark, baseline_no_token.text, baseline_no_token.status_code))

        if not baseline_passes:
            override_headers = _build_default_headers().copy()
            for header_name in ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"):
                override_headers[header_name] = "GET"
                r = requestMaker(url, method="POST", data=override_params, headers=override_headers)
                if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                    # The server accepts the override header, but a browser can
                    # only send this non-safelisted header cross-site if CORS
                    # permits a credentialed request carrying it. Otherwise it's
                    # server-side only (not browser-exploitable as CSRF).
                    if cors_allows_credentialed_header(url, "POST", header_name):
                        logger.warning(f"[M2] VULNERABLE: Server accepted {header_name}: GET override (CORS permits a credentialed cross-site request).")
                        VulnLogger(url, f"CSRF bypass via {header_name}: GET header (permissive CORS allows the cross-site preflight).", test_id="M2")
                        passed.add("M2")
                    else:
                        logger.info(f"[M2] Server accepts {header_name} override, but CORS does not permit a credentialed cross-site request with it — server-side only, not browser-exploitable.")
                override_headers.pop(header_name)

        if not passed:
            logger.debug("[M1/M2] Method override bypass failed.")

        return passed

    # ----------------------------------------------------------------
    # T8: Custom header token bypass (HackTricks)
    # ----------------------------------------------------------------
    def bypassCustomHeaderToken(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Strip or replace anti-CSRF tokens sent via custom HTTP headers."""
        logger = logging.getLogger("CustomHeaderBypass")
        logger.debug("[T8] Trying custom header token bypass...")
        differ = DiffEngine()
        bypassed = False

        header_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                         if t.discovery_part == TokenDiscoveryPartEnum.RESPONSE_HEADERS]

        if not header_tokens:
            logger.debug("[T8] No header-based tokens found. Skipping.")
            return False

        for token in header_tokens:
            # First verify: does including the header in requests actually work?
            verify_headers = _build_default_headers().copy()
            verify_headers[token.name] = token.token
            r_with = requestMaker(url, method=method.upper(),
                                  data=params if method.lower() == "post" else None,
                                  params=params if method.lower() == "get" else None,
                                  headers=verify_headers)
            if not r_with or not differ.benchmarkPassed(base_benchmark, r_with.text, r_with.status_code):
                logger.debug(f"[T8] Request with '{token.name}' header doesn't match benchmark. Skipping.")
                continue

            # Test 1: Remove the header entirely
            test_headers = _build_default_headers().copy()

            r = requestMaker(url, method=method.upper(), data=params if method.lower() == "post" else None,
                             params=params if method.lower() == "get" else None, headers=test_headers)
            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[T8] VULNERABLE: Server accepted request without '{token.name}' header.")
                VulnLogger(url, f"CSRF header token '{token.name}' can be omitted.", test_id="T8")
                bypassed = True

            # Test 2: Replace with same-length random string
            test_headers = _build_default_headers().copy()
            fake_token = "".join(random.choices(string.ascii_letters + string.digits, k=len(token.token)))
            test_headers[token.name] = fake_token

            r = requestMaker(url, method=method.upper(), data=params if method.lower() == "post" else None,
                             params=params if method.lower() == "get" else None, headers=test_headers)
            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[T8] VULNERABLE: Server accepted forged '{token.name}' header value.")
                VulnLogger(url, f"CSRF header token '{token.name}' accepts arbitrary values.", test_id="T8")
                bypassed = True

        if not bypassed:
            logger.debug("[T8] Custom header token bypass failed.")

        return bypassed

    # ----------------------------------------------------------------
    # T4: Token not tied to user session (PortSwigger Lab 4)
    # ----------------------------------------------------------------
    def bypassTokenNotTiedToSession(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Obtain a token from a fresh (unauthenticated) session and replay it."""
        logger = logging.getLogger("SessionBindingBypass")
        logger.debug("[T4] Trying cross-session token replay bypass...")
        differ = DiffEngine()

        body_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                       if t.discovery_part in (TokenDiscoveryPartEnum.REQUEST_BODY, TokenDiscoveryPartEnum.REQUEST_QUERY)]
        if not body_tokens:
            return False

        fresh_session = requests.Session()
        try:
            fresh_resp = fresh_session.get(url, timeout=config.TIMEOUT_VALUE, verify=config.VERIFY_CERT)
        except Exception as e:
            logger.error(f"[T4] Failed to create fresh session: {e}")
            return False

        for token in body_tokens:
            fresh_match = re.search(self.postfix_regex % token.name, fresh_resp.text, re.I)
            if not fresh_match:
                continue

            fresh_token_value = fresh_match.group(1)

            test_params = params.copy()
            test_params[token.name] = fresh_token_value

            r = requestMaker(
                url, method=method.upper(),
                data=test_params if method.lower() == "post" else None,
                params=test_params if method.lower() == "get" else None
            )

            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning("[T4] VULNERABLE: Server accepted token from a different session.")
                VulnLogger(url, "CSRF token is not tied to user session (global token pool).", test_id="T4")
                return True

        logger.debug("[T4] Cross-session token replay failed.")
        NovulLogger(url, "CSRF token is tied to user session.", test_id="T4")
        return False

    # ----------------------------------------------------------------
    # T6: Token duplicated in cookie / double submit bypass (PortSwigger Lab 6)
    # ----------------------------------------------------------------
    def bypassDoubleSubmitCookie(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """
        Detect double-submit cookie pattern: same token in cookie and body param.
        Set both to an attacker-controlled arbitrary value.
        """
        logger = logging.getLogger("DoubleSubmitBypass")
        logger.debug("[T6] Trying double-submit cookie bypass...")
        differ = DiffEngine()

        body_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                       if t.discovery_part in (TokenDiscoveryPartEnum.REQUEST_BODY, TokenDiscoveryPartEnum.REQUEST_QUERY)]
        cookie_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                         if t.discovery_part == TokenDiscoveryPartEnum.COOKIE]

        for bt in body_tokens:
            for ct in cookie_tokens:
                if _norm_token(bt.token) == _norm_token(ct.token) or bt.name.lower() == ct.name.lower():
                    logger.info(f"[T6] Double-submit pattern detected: body='{bt.name}', cookie='{ct.name}'")

                    forged_value = "xsrfprobe_" + "".join(random.choices(string.ascii_lowercase, k=16))

                    test_params = params.copy()
                    test_params[bt.name] = forged_value

                    forged_cookies = SESSION.cookies.get_dict()
                    forged_cookies[ct.name] = forged_value

                    try:
                        r = requests.request(
                            method=method.upper(), url=url,
                            headers=_build_default_headers(),
                            cookies=forged_cookies,
                            data=test_params if method.lower() == "post" else None,
                            params=test_params if method.lower() == "get" else None,
                            timeout=config.TIMEOUT_VALUE, verify=config.VERIFY_CERT,
                        )
                    except Exception as e:
                        logger.error(f"[T6] Request failed: {e}")
                        continue

                    if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                        logger.warning("[T6] VULNERABLE: Server only checks cookie==body equality (naive double submit, no session binding).")
                        VulnLogger(url, "Naive double-submit cookie: server only verifies cookie==body with no session/crypto binding. Exploitable IF the attacker can write the CSRF cookie (subdomain cookie-tossing, a cookie-injection gadget, or HTTP MITM). Not exploitable from an unrelated cross-site origin alone.", test_id="T6")
                        return True

        logger.debug("[T6] Double-submit cookie bypass not applicable or failed.")
        return False

    # ----------------------------------------------------------------
    # T5: Token tied to non-session cookie (PortSwigger Lab 5)
    # ----------------------------------------------------------------
    def bypassTokenTiedToNonSessionCookie(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """
        Detect if CSRF token is tied to a separate cookie (e.g., csrfKey)
        rather than the session cookie. Obtain a fresh token+cookie pair
        and replay them with the victim's session cookie.
        """
        logger = logging.getLogger("NonSessionCookieBypass")
        logger.debug("[T5] Trying non-session cookie token bypass...")
        differ = DiffEngine()

        csrf_cookie_names = {"csrfkey", "csrf_key", "csrftoken", "csrf_token", "_csrf_cookie"}
        session_cookies = SESSION.cookies.get_dict()

        csrf_cookies = {k: v for k, v in session_cookies.items()
                        if k.lower() in csrf_cookie_names}

        if not csrf_cookies:
            logger.debug("[T5] No separate CSRF cookies detected. Skipping.")
            return False

        fresh_session = requests.Session()
        try:
            fresh_resp = fresh_session.get(url, timeout=config.TIMEOUT_VALUE, verify=config.VERIFY_CERT)
        except Exception as e:
            logger.error(f"[T5] Failed to create fresh session: {e}")
            return False

        fresh_cookies = fresh_session.cookies.get_dict()
        body_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                       if t.discovery_part in (TokenDiscoveryPartEnum.REQUEST_BODY, TokenDiscoveryPartEnum.REQUEST_QUERY)]

        for token in body_tokens:
            fresh_match = re.search(self.postfix_regex % token.name, fresh_resp.text, re.I)
            if not fresh_match:
                continue

            fresh_token_value = fresh_match.group(1)

            combined_cookies = session_cookies.copy()
            for ck_name in csrf_cookies:
                if ck_name in fresh_cookies:
                    combined_cookies[ck_name] = fresh_cookies[ck_name]

            test_params = params.copy()
            test_params[token.name] = fresh_token_value

            try:
                r = requests.request(
                    method=method.upper(), url=url,
                    headers=_build_default_headers(),
                    cookies=combined_cookies,
                    data=test_params if method.lower() == "post" else None,
                    params=test_params if method.lower() == "get" else None,
                    timeout=config.TIMEOUT_VALUE, verify=config.VERIFY_CERT,
                )
            except Exception as e:
                logger.error(f"[T5] Request failed: {e}")
                continue

            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning("[T5] VULNERABLE: CSRF token is tied to a non-session cookie.")
                VulnLogger(url, "CSRF token tied to a non-session cookie (e.g. csrfKey) rather than the session. Attacker can supply their own valid token+cookie pair. Exploitable IF the attacker can write that cookie (subdomain cookie-tossing, a cookie-injection gadget, or HTTP MITM).", test_id="T5")
                return True

        logger.debug("[T5] Non-session cookie bypass not applicable or failed.")
        return False

    # ----------------------------------------------------------------
    # Orchestrator: run all token tamper tests
    # ----------------------------------------------------------------
    def performTokenTamperTests(self, url: str, method: str, params: dict, base_benchmark: BenchmarkResult,
                                run_method_switch: bool = True) -> set[str]:
        """Run all token bypass tests in sequence. Returns set of passed test IDs.

        ``run_method_switch`` gates only T2 (the GET<->POST method switch): it
        keeps the token and merely changes the method, so its GET trivially
        matches the baseline when a plain page load already looks like success
        (e.g. a login we can't complete). The other tests tamper with the token
        and produce a distinct rejection, so they remain reliable regardless.
        """
        logger = logging.getLogger("TokenTamperTests")
        passed = set()

        tests = []
        if run_method_switch:
            tests.append(("T2", "Request method switch bypass", self.bypassTokenValidationRequestMethod))
        else:
            logger.log(PROGRESS, "Skipping T2 (method-switch): plain GET matches baseline.")
        tests += [
            ("T3", "Token removal bypass", self.bypassTokenValidationPresence),
            ("T7", "Empty token value bypass", self.bypassEmptyTokenValue),
            ("T4", "Cross-session token replay", self.bypassTokenNotTiedToSession),
            ("T5", "Non-session cookie token bypass", self.bypassTokenTiedToNonSessionCookie),
            ("T6", "Double-submit cookie bypass", self.bypassDoubleSubmitCookie),
            ("T8", "Custom header token bypass", self.bypassCustomHeaderToken),
        ]

        for test_id, description, test_fn in tests:
            try:
                with test_progress(logger, test_id, description) as tp_result:
                    result = test_fn(url, base_benchmark, method, params.copy())
                    if result:
                        passed.add(test_id)
                        tp_result["status"] = "VULNERABLE"
                    else:
                        tp_result["status"] = "failed"
            except Exception as e:
                logger.error("Error in %s: %s", test_id, e)

        # --- Method Override Tests ---
        phase_header(logger, "Method Override Tests")
        try:
            with test_progress(logger, "M1/M2", "Method override bypass") as tp_result:
                m_results = self.bypassMethodOverride(url, base_benchmark, method, params.copy())
                passed.update(m_results)
                if m_results:
                    tp_result["status"] = "VULNERABLE (%s)" % ", ".join(sorted(m_results))
                else:
                    tp_result["status"] = "failed"
        except Exception as e:
            logger.error("Error in M1/M2: %s", e)

        if not passed:
            logger.log(PROGRESS, "All token tamper tests passed. Endpoint token validation is robust.")
        else:
            logger.warning("%d token tamper test(s) succeeded. Endpoint is VULNERABLE.", len(passed))

        return passed
