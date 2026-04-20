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
from urllib.parse import urlparse, urlencode

from xsrfprobe.files import config
from xsrfprobe.files import discovered
from xsrfprobe.core.request import requestMaker, SESSION, _build_default_headers
from xsrfprobe.core.diff import DiffEngine
from xsrfprobe.core.schema import DiscoveredToken, TokenDiscoveryPartEnum, TokenDiscoveryModeEnum, BenchmarkResult
from xsrfprobe.files.paramlist import COMMON_CSRF_NAMES, COMMON_CSRF_HEADERS
from xsrfprobe.core.logger import VulnLogger, NovulLogger


class TokenAnalyser:
    def __init__(self) -> None:
        self.postfix_regex = r'<input.*?name=[\'"]%s[\'"].*?value=[\'"](.+?)[\'"]'

    def detectTokens(self, response: requests.Response, passive: bool = False) -> bool:
        """
        Checks whether Anti-CSRF Tokens are present in the request/response.
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
            logger.debug("Searching for Anti-CSRF Token in Request URL...")
            parsed_uri = urlparse(response.url)
            if parsed_uri.query:
                con = parsed_uri.query.split("&")
                for c in con:
                    if "=" not in c:
                        continue
                    param_name, param_value = c.split("=", 1)
                    for name in COMMON_CSRF_NAMES:
                        if name.lower() in param_name.lower():
                            logger.info(f"Anti-CSRF Query Parameter: {param_name}={param_value}")
                            discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                name=param_name,
                                token=param_value,
                                url=response.url,
                                mode=TokenDiscoveryModeEnum.ACTIVE,
                                discovery_part=TokenDiscoveryPartEnum.REQUEST_QUERY
                            ))
                            found = True
                            break

            if not found and response.request.body:
                logger.debug("Searching for Anti-CSRF Token in Request Body...")
                req_body = str(response.request.body)
                if req_body:
                    params = req_body.split("&")
                    for param in params:
                        if "=" not in param:
                            continue
                        param_name, param_value = param.split("=", 1)
                        for name in COMMON_CSRF_NAMES:
                            if name.lower() in param_name.lower():
                                logger.info(f"Anti-CSRF Request Body Parameter: {param_name}={param_value}")
                                discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                    name=param_name,
                                    token=param_value,
                                    url=response.url,
                                    mode=TokenDiscoveryModeEnum.ACTIVE,
                                    discovery_part=TokenDiscoveryPartEnum.REQUEST_BODY
                                ))
                                found = True
                                break

            if not found:
                logger.debug("Searching for Anti-CSRF Token in Response Headers...")
                for key, value in response.headers.items():
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

                    if "set-cookie" in key.lower():
                        cookie_values = value.split(",")
                        for cookie_val in cookie_values:
                            for name in COMMON_CSRF_NAMES:
                                if name.lower() in cookie_val.lower() and "=" in cookie_val:
                                    cookie_name, cookie_value = cookie_val.split("=", 1)
                                    logger.info(f"Anti-CSRF Token Cookie: {cookie_name.strip()}={cookie_value.strip()}")
                                    found = True
                                    discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                        name=cookie_name.strip(),
                                        token=cookie_value.strip(),
                                        url=response.url,
                                        mode=TokenDiscoveryModeEnum.ACTIVE,
                                        discovery_part=TokenDiscoveryPartEnum.COOKIE
                                    ))
                                    break

            if not found:
                logger.debug("Searching for Anti-CSRF Token in Request Cookies...")
                for key, value in response.request.headers.items():
                    if key.lower() == "cookie":
                        for name in COMMON_CSRF_HEADERS:
                            if name.lower() in value.lower():
                                cookie_values = value.split(",")
                                for cookie_val in cookie_values:
                                    if "=" not in cookie_val:
                                        continue
                                    cookie_name, cookie_value = cookie_val.split("=", 1)
                                    logger.info(f"Anti-CSRF Token Cookie: {cookie_name.strip()}")
                                    found = True
                                    discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                        name=cookie_name.strip(),
                                        token=cookie_value.strip(),
                                        url=response.url,
                                        mode=TokenDiscoveryModeEnum.ACTIVE,
                                        discovery_part=TokenDiscoveryPartEnum.COOKIE
                                    ))
                                    break

        except Exception as e:
            logger.error("Request Parsing Exception!")
            logger.error(f"Error: {e}")

        if found:
            return True

        logger.warning(f"No Anti-CSRF Token found in request: {response.url}")
        logger.info("Endpoint seems VULNERABLE to POST-Based Request Forgery")
        return False

    # ----------------------------------------------------------------
    # T2: Validation depends on request method (PortSwigger Lab 2)
    # ----------------------------------------------------------------
    def bypassTokenValidationRequestMethod(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Switch GET<->POST to bypass method-conditioned CSRF validation."""
        logger = logging.getLogger("RequestMethodBypass")
        logger.info("[T2] Trying request method switch bypass...")
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
            VulnLogger(url, f"CSRF token validation bypassed via {alt} method switch.")
            return True

        logger.info("[T2] Method switch bypass failed. Server validates across methods.")
        NovulLogger(url, "CSRF token validated regardless of request method.")
        return False

    # ----------------------------------------------------------------
    # T3: Validation depends on token being present (PortSwigger Lab 3)
    # ----------------------------------------------------------------
    def bypassTokenValidationPresence(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Remove the CSRF token parameter entirely to test presence-based validation."""
        logger = logging.getLogger("TokenPresenceBypass")
        logger.info("[T3] Trying token removal bypass...")
        differ = DiffEngine()

        for token in discovered.ANTI_CSRF_TOKENS:
            test_params = params.copy()

            if token.discovery_part in (TokenDiscoveryPartEnum.REQUEST_QUERY, TokenDiscoveryPartEnum.REQUEST_BODY):
                test_params.pop(token.name, None)

                r = requestMaker(
                    url,
                    method=method.upper(),
                    data=test_params if method.lower() == "post" else None,
                    params=test_params if method.lower() == "get" else None
                )

                if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                    logger.warning(f"[T3] VULNERABLE: Server accepted request without token '{token.name}'.")
                    VulnLogger(url, f"CSRF token '{token.name}' can be omitted entirely.")
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
                    VulnLogger(url, f"CSRF cookie token '{token.name}' can be omitted entirely.")
                    return True

        logger.info("[T3] Token removal bypass failed.")
        NovulLogger(url, "CSRF token presence is required by the server.")
        return False

    # ----------------------------------------------------------------
    # T7: Empty token value accepted (PortSwigger Lab 3 variant)
    # ----------------------------------------------------------------
    def bypassEmptyTokenValue(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Submit the request with the token parameter present but set to an empty string."""
        logger = logging.getLogger("EmptyTokenBypass")
        logger.info("[T7] Trying empty token value bypass...")
        differ = DiffEngine()

        for token in discovered.ANTI_CSRF_TOKENS:
            if token.discovery_part not in (TokenDiscoveryPartEnum.REQUEST_QUERY, TokenDiscoveryPartEnum.REQUEST_BODY):
                continue

            test_params = params.copy()
            test_params[token.name] = ""

            r = requestMaker(
                url,
                method=method.upper(),
                data=test_params if method.lower() == "post" else None,
                params=test_params if method.lower() == "get" else None
            )

            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[T7] VULNERABLE: Server accepted empty token value for '{token.name}'.")
                VulnLogger(url, f"CSRF token '{token.name}' accepts empty value.")
                return True

        logger.info("[T7] Empty token bypass failed.")
        return False

    # ----------------------------------------------------------------
    # M1/M2/S1: Method override bypass (_method param + override headers)
    # (PortSwigger SameSite Lax Lab 7 + HackTricks)
    # ----------------------------------------------------------------
    def bypassMethodOverride(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Test HTTP method override via _method param and X-HTTP-Method-Override headers."""
        logger = logging.getLogger("MethodOverrideBypass")
        logger.info("[M1/M2] Trying method override bypass...")
        differ = DiffEngine()
        bypassed = False

        if method.upper() != "POST":
            return False

        override_params = params.copy()
        for token in discovered.ANTI_CSRF_TOKENS:
            override_params.pop(token.name, None)

        # Test 1: GET request with _method=POST in query string
        override_params["_method"] = "POST"
        r = requestMaker(url, method="GET", params=override_params)
        if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
            logger.warning("[M1] VULNERABLE: Server accepted GET with _method=POST override.")
            VulnLogger(url, "CSRF bypass via _method=POST on GET request.")
            bypassed = True
        override_params.pop("_method")

        # Test 2: POST with X-HTTP-Method-Override header set to GET
        override_headers = _build_default_headers().copy()
        for header_name in ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"):
            override_headers[header_name] = "GET"
            r = requestMaker(url, method="POST", data=override_params, headers=override_headers)
            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[M2] VULNERABLE: Server accepted {header_name}: GET override.")
                VulnLogger(url, f"CSRF bypass via {header_name}: GET header.")
                bypassed = True
            override_headers.pop(header_name)

        if not bypassed:
            logger.info("[M1/M2] Method override bypass failed.")

        return bypassed

    # ----------------------------------------------------------------
    # T8: Custom header token bypass (HackTricks)
    # ----------------------------------------------------------------
    def bypassCustomHeaderToken(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Strip or replace anti-CSRF tokens sent via custom HTTP headers."""
        logger = logging.getLogger("CustomHeaderBypass")
        logger.info("[T8] Trying custom header token bypass...")
        differ = DiffEngine()
        bypassed = False

        header_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                         if t.discovery_part == TokenDiscoveryPartEnum.RESPONSE_HEADERS]

        if not header_tokens:
            logger.debug("[T8] No header-based tokens found. Skipping.")
            return False

        for token in header_tokens:
            # Test 1: Remove the header entirely
            test_headers = _build_default_headers().copy()
            test_headers.pop(token.name, None)

            r = requestMaker(url, method=method.upper(), data=params if method.lower() == "post" else None,
                             params=params if method.lower() == "get" else None, headers=test_headers)
            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[T8] VULNERABLE: Server accepted request without '{token.name}' header.")
                VulnLogger(url, f"CSRF header token '{token.name}' can be omitted.")
                bypassed = True

            # Test 2: Replace with same-length random string
            test_headers = _build_default_headers().copy()
            fake_token = "".join(random.choices(string.ascii_letters + string.digits, k=len(token.token)))
            test_headers[token.name] = fake_token

            r = requestMaker(url, method=method.upper(), data=params if method.lower() == "post" else None,
                             params=params if method.lower() == "get" else None, headers=test_headers)
            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[T8] VULNERABLE: Server accepted forged '{token.name}' header value.")
                VulnLogger(url, f"CSRF header token '{token.name}' accepts arbitrary values.")
                bypassed = True

        if not bypassed:
            logger.info("[T8] Custom header token bypass failed.")

        return bypassed

    # ----------------------------------------------------------------
    # T4: Token not tied to user session (PortSwigger Lab 4)
    # ----------------------------------------------------------------
    def bypassTokenNotTiedToSession(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Obtain a token from a fresh (unauthenticated) session and replay it."""
        logger = logging.getLogger("SessionBindingBypass")
        logger.info("[T4] Trying cross-session token replay bypass...")
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
            if fresh_token_value == token.token:
                logger.debug("[T4] Fresh session returned same token. Not useful for this test.")
                continue

            test_params = params.copy()
            test_params[token.name] = fresh_token_value

            r = requestMaker(
                url, method=method.upper(),
                data=test_params if method.lower() == "post" else None,
                params=test_params if method.lower() == "get" else None
            )

            if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.warning(f"[T4] VULNERABLE: Server accepted token from a different session.")
                VulnLogger(url, "CSRF token is not tied to user session (global token pool).")
                return True

        logger.info("[T4] Cross-session token replay failed.")
        NovulLogger(url, "CSRF token is tied to user session.")
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
        logger.info("[T6] Trying double-submit cookie bypass...")
        differ = DiffEngine()

        body_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                       if t.discovery_part in (TokenDiscoveryPartEnum.REQUEST_BODY, TokenDiscoveryPartEnum.REQUEST_QUERY)]
        cookie_tokens = [t for t in discovered.ANTI_CSRF_TOKENS
                         if t.discovery_part == TokenDiscoveryPartEnum.COOKIE]

        for bt in body_tokens:
            for ct in cookie_tokens:
                if bt.token == ct.token or bt.name.lower() == ct.name.lower():
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
                        logger.warning("[T6] VULNERABLE: Server only checks cookie==body equality (double submit).")
                        VulnLogger(url, "CSRF double-submit cookie bypass: attacker can set both cookie and body to same arbitrary value.")
                        return True

        logger.info("[T6] Double-submit cookie bypass not applicable or failed.")
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
        logger.info("[T5] Trying non-session cookie token bypass...")
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
                logger.warning("[T5] VULNERABLE: CSRF token is tied to non-session cookie.")
                VulnLogger(url, "CSRF token tied to non-session cookie. Attacker can supply own token+csrfKey pair.")
                return True

        logger.info("[T5] Non-session cookie bypass not applicable or failed.")
        return False

    # ----------------------------------------------------------------
    # Orchestrator: run all token tamper tests
    # ----------------------------------------------------------------
    def performTokenTamperTests(self, url: str, method: str, params: dict, base_benchmark: BenchmarkResult) -> None:
        """Run all token bypass tests in sequence."""
        logger = logging.getLogger("TokenTamperTests")
        results = []

        tests = [
            ("T2: Method switch", self.bypassTokenValidationRequestMethod),
            ("T3: Token removal", self.bypassTokenValidationPresence),
            ("T7: Empty token", self.bypassEmptyTokenValue),
            ("T4: Cross-session replay", self.bypassTokenNotTiedToSession),
            ("T5: Non-session cookie", self.bypassTokenTiedToNonSessionCookie),
            ("T6: Double-submit cookie", self.bypassDoubleSubmitCookie),
            ("T8: Custom header token", self.bypassCustomHeaderToken),
            ("M1/M2: Method override", self.bypassMethodOverride),
        ]

        for name, test_fn in tests:
            try:
                result = test_fn(url, base_benchmark, method, params.copy())
                results.append((name, result))
                if result:
                    logger.warning(f"Token bypass succeeded: {name}")
            except Exception as e:
                logger.error(f"Error in {name}: {e}")
                results.append((name, False))

        passed_count = sum(1 for _, r in results if r)
        if passed_count == 0:
            logger.info("All token tamper tests failed. Endpoint token validation is robust.")
        else:
            logger.warning(f"{passed_count}/{len(results)} token tamper tests passed. Endpoint is VULNERABLE.")
