#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import requests
import logging
from urllib.parse import urlparse

from files import config
from files import discovered
from core.request import requestMaker, SESSION
from core.diff import DiffEngine
from core.schema import DiscoveredToken, TokenDiscoveryPartEnum, TokenDiscoveryModeEnum, BenchmarkResult
from files.paramlist import COMMON_CSRF_NAMES, COMMON_CSRF_HEADERS

class TokenAnalyser:
    def __init__(self) -> None:
        self.postfix_regex = r'<input.*?name=[\'"]%s[\'"].*?value=[\'"](.+?)[\'"]'

    def detectTokens(self, response: requests.Response, passive: bool=False) -> bool:
        """
        This method checks for whether Anti-CSRF Tokens are
                present in the request.
        """
        logger = logging.getLogger("TokenDetector")
        found = False

        # first let's have a look at config.py and see if it's set
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
            # check for the request query parameters
            con = parsed_uri.query.split("&")
            for c in con:
                for name in COMMON_CSRF_NAMES:
                    param_name, param_value = c.split("=")
                    if name.lower() in param_name.lower():
                        logger.debug(f"The form was requested with an Anti-CSRF Token in the query: {response.url}")
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

            # search for anti-csrf tokens in request params
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
                                discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                    name=param_name,
                                    token=param_value,
                                    url=response.url,
                                    mode=TokenDiscoveryModeEnum.ACTIVE,
                                    discovery_part=TokenDiscoveryPartEnum.REQUEST_BODY
                                ))
                                found = True
                                break

            # if we haven't found the anti-CSRF token in the query, we'll search for it in headers
            if not found:
                logger.debug("Searching for Anti-CSRF Token in Response Headers...")
                for key, value in response.headers.items():
                    for name in COMMON_CSRF_HEADERS:  # Iterate over the list
                        # Search if the token is there in request...
                        if name.lower() in key.lower():
                            logger.debug(f"The form was requested with an Anti-CSRF Token Header: {response.url}")
                            logger.info(f"Anti-CSRF Token Header: {key}={value}")
                            # We are appending the token to a variable for further analysis
                            found = True
                            discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                name=key,
                                token=value,
                                url=response.url,
                                mode=TokenDiscoveryModeEnum.ACTIVE,
                                discovery_part=TokenDiscoveryPartEnum.RESPONSE_HEADERS
                            ))
                            break  # Break execution if an Anti-CSRF token is found

                    if found:
                        break

                    else:
                        logger.debug("Checking for anti-CSRF tokens in Set-Cookie headers...")
                        # Check for anti-csrf tokens in Set-Cookie headers
                        if "set-cookie" in key.lower():
                            # Extract the cookie value
                            cookie_values = value.split(",")
                            for cookie_val in cookie_values:
                                for name in COMMON_CSRF_NAMES:
                                    if name.lower() in cookie_val.lower():
                                        cookie_name, cookie_value = cookie_val.split("=")
                                        logger.debug(f"The form was requested with an Anti-CSRF Token in the cookie: {response.url}")
                                        logger.info(f"Anti-CSRF Token Cookie: {cookie_value}")
                                        found = True
                                        discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                            name=cookie_name,
                                            token=cookie_value,
                                            url=response.url,
                                            mode=TokenDiscoveryModeEnum.ACTIVE,
                                            discovery_part=TokenDiscoveryPartEnum.COOKIE
                                        ))
                                        break

            if not found:
                logger.debug("Searching for Anti-CSRF Token in Request Cookies...")
                # finally check if the token is in the cookie we sent
                for key, value in response.request.headers.items():
                    if key.lower() == "cookie":
                        for name in COMMON_CSRF_HEADERS:
                            if name.lower() in value.lower():
                                cookie_values = value.split(",")
                                for cookie_val in cookie_values:
                                    cookie_name, cookie_value = cookie_val.split("=")
                                    logger.debug(f"The form was requested with an Anti-CSRF Token in the cookie: {response.url}")
                                    logger.info(f"Anti-CSRF Token Cookie: {cookie_value}")
                                    found = True
                                    discovered.ANTI_CSRF_TOKENS.append(DiscoveredToken(
                                        name=cookie_name,
                                        token=cookie_value,
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

        logger.warning(f"The form was requested without an Anti-CSRF Token: {response.url}")
        logger.info("Endpoint seems VULNERABLE to POST-Based Request Forgery")
        return False

    def bypassTokenValidationRequestMethod(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        '''
        This method tries to bypass CSRF token based on request method.
        '''
        logger = logging.getLogger("RequestBasedTokenBypass")
        logger.info("Trying to bypass CSRF token based on request method tampering...")
        differ = DiffEngine()

        if method.lower() == "get":
            logger.debug("Tampering with the request method GET...")
            r = requestMaker(url, method="POST", data=params)

            if r is None:
                logger.error("Request failed. Skipping tamper bypass method...")
                return False

            if differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.info("Server possibly accepted the request with POST method.")
                return True

            logger.info("Server did not accept the request with POST method.")

        elif method.lower() == "post":
            logger.debug("Tampering with the request method POST...")
            r = requestMaker(url, method="GET", params=params)

            if r is None:
                logger.error("Request failed. Skipping tamper bypass method...")
                return False

            if differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                logger.info("Server possibly accepted the request with GET method.")
                return True

            logger.info("Server did not accept the request with GET method.")

        return False

    def bypassTokenValidationPresence(self, url: str, base_benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        '''
        This method tries to bypass CSRF tokens by removing them entirely.
        '''
        logger = logging.getLogger("TokenPresenceBypass")
        logger.info("Trying to bypass CSRF token by removing it entirely...")
        differ = DiffEngine()

        for token in discovered.ANTI_CSRF_TOKENS:
            logger.debug(f"Removing Anti-CSRF token {token.name} from request...")
            if token.discovery_part == TokenDiscoveryPartEnum.REQUEST_QUERY or \
                token.discovery_part == TokenDiscoveryPartEnum.REQUEST_BODY:
                params.pop(token.name)

                r = requestMaker(
                    url,
                    method=method.upper(),
                    data=params if method.lower() == "post" else None,
                    params=params if method.lower() == "get" else None
                )

                if r is None:
                    logger.error("Request failed. Skipping tamper bypass method...")
                    return False

                if differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                    logger.info("Server possibly accepted the request with token removed.")
                    return True

            elif token.discovery_part == TokenDiscoveryPartEnum.COOKIE:
                # remove the cookie
                cookie = SESSION.cookies.get_dict()
                if cookie:
                    cookie.pop(token.name)

                try:
                    r = requests.request(
                        method=method.upper(),
                        url=url,
                        headers=SESSION.headers,
                        cookies=cookie,
                        data=params if method.lower() == "post" else None,
                        params=params if method.lower() == "get" else None,
                        timeout=config.TIMEOUT_VALUE,
                        verify=config.VERIFY_CERT,
                    )
                    if r is None:
                        logger.error("Request failed. Skipping tamper bypass method...")
                        return False

                except Exception as e:
                    logger.error(f"Error during request processing: {e.__str__()}")
                    return False

                if differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
                    logger.info("Server possibly accepted the request with token removed.")
                    return True

        logger.info("Server did not accept the request with token removed.")
        return False

    def performTokenTamperTests(self, url: str, method: str, params: dict, base_benchmark: BenchmarkResult) -> None:
        '''
        This method is a wrap around for all token tamper tests.
        '''
        logger = logging.getLogger("TokenTamperTests")
        passed = False
        passed = self.bypassTokenValidationRequestMethod(url, base_benchmark, method, params)
        passed = self.bypassTokenValidationPresence(url, base_benchmark, method, params)

        if not passed:
            logger.info("All token tamper tests failed. Endpoint is secure.")

        else:
            logger.info("At least one token tamper test passed. Endpoint is vulnerable.")
