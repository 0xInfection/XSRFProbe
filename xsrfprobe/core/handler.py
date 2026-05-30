#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from xsrfprobe.core.request import requestMaker, _build_default_headers
from xsrfprobe.core.diff import DiffEngine
from xsrfprobe.core.logger import NovulLogger, VulnLogger
from xsrfprobe.modules.Origin import OriginAnalyser
from xsrfprobe.modules.Cookie import CookieAnalyzer
from xsrfprobe.modules.Referer import RefererAnalyser
from xsrfprobe.modules.Encoding import Encoding
from xsrfprobe.modules.Parser import FormParser
from xsrfprobe.modules.Token import TokenAnalyser

from xsrfprobe.files import config
from xsrfprobe.files.config import REFERER_ORIGIN_CHECKS, FORM_SUBMISSION, COOKIE_BASED, TOKEN_CHECKS
from xsrfprobe.files.discovered import FORMS_TESTED

LOGIN_FIELD_PATTERNS = {"username", "user", "login", "email", "password", "passwd", "pass"}


def _detect_login_csrf(form, url: str) -> None:
    """O1: Detect login forms without CSRF tokens (login CSRF vulnerability)."""
    logger = logging.getLogger("LoginCSRF")
    field_names = set()
    for inp in form.findAll("input", {"name": True}):
        field_names.add(inp.get("name", "").lower())

    has_password = any("pass" in f for f in field_names)
    has_user = any(f in LOGIN_FIELD_PATTERNS for f in field_names)

    if has_password and has_user:
        logger.warning("[O1] Login form detected at %s. Checking for CSRF token...", url)
        has_token = False
        for inp in form.findAll("input", {"type": "hidden"}):
            name = inp.get("name", "").lower()
            if any(t in name for t in ("csrf", "token", "nonce", "authenticity", "verify")):
                has_token = True
                break

        if not has_token:
            logger.warning("[O1] VULNERABLE: Login form has no CSRF token. Login CSRF possible.")
            VulnLogger(url, "Login form lacks CSRF token. Attacker can force victim to authenticate into attacker-controlled account.")


def _bypass_content_type(url: str, base_benchmark, method: str, params: dict) -> bool:
    """M4: Re-submit form data with alternative Content-Type values. Returns True if any bypass found."""
    logger = logging.getLogger("ContentTypeBypass")
    differ = DiffEngine()
    found = False

    if method.upper() != "POST":
        return False

    alt_types = [
        "text/plain",
        "application/json",
        "text/plain; application/json",
    ]

    for ct in alt_types:
        headers = _build_default_headers().copy()
        headers["Content-Type"] = ct

        if ct == "application/json" or "json" in ct:
            import json
            body = json.dumps(params)
        else:
            body = "&".join(f"{k}={v}" for k, v in params.items())

        r = requestMaker(url, method="POST", data=body, headers=headers)
        if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
            logger.warning(f"[M4] VULNERABLE: Server accepted Content-Type: {ct}")
            VulnLogger(url, f"CSRF bypass via Content-Type change to: {ct}")
            found = True

    return found


def _bypass_head_method(url: str, base_benchmark, _method: str, params: dict) -> None:
    """M3: Send HEAD request to test if server processes it as GET."""
    logger = logging.getLogger("HEADMethodBypass")

    r = requestMaker(url, method="HEAD", params=params)
    if r is None:
        return

    if r.status_code == base_benchmark.status_code and base_benchmark.status_code != 0:
        logger.warning("[M3] HEAD request returned same status code as benchmark. Server may treat HEAD as GET.")
        VulnLogger(url, "HEAD method may bypass CSRF checks (same status as GET).")


def noCrawlProcessor(url: str, soup: BeautifulSoup | None = None) -> None:
    """
    Handles endpoint processing and security validation.
    Either a URL or a BeautifulSoup object has to be passed to this function.
    """
    logger = logging.getLogger("Engine")
    if not url and not soup:
        logger.error("No endpoint or BeautifulSoup object provided.")
        return

    if soup is None:
        response = requestMaker(url)
        logger.debug("Parsing the response from: %s" % url)
        if response is None:
            logger.error("No response received; the site is likely down: %s" % url)
            return
        soup = BeautifulSoup(response.text, "html.parser")
    else:
        response = None

    parsed_uri = urlparse(url)
    action_done = set()

    referee = RefererAnalyser()
    origame = OriginAnalyser()
    if REFERER_ORIGIN_CHECKS:
        logger.info("[Heuristics] Performing GET-based Referer validation checks.")
        referee.performBasicHeuristics(url)

        logger.info("[Heuristics] Performing GET-based Origin validation checks.")
        origame.performBasicHeuristics(url)

    logger.debug("Retrieving all forms on %s...", url)

    token_analyzer = TokenAnalyser()
    parser = FormParser(soup)
    for form in parser.getAllForms():
        logger.debug("Testing the following form:")
        logger.debug("\n%s", form.prettify())
        FORMS_TESTED[url].append(form.prettify())

        _detect_login_csrf(form, url)

        if parser.checkBadInputs(form):
            continue

        action_uri: str = parser.extractFormAction(form)
        action_method: str = parser.extractFormMethod(form)
        action_enctype: str = parser.extractFormEnctype(form)
        if action_method == "dialog":
            continue

        try:
            if not action_uri:
                action_uri = parsed_uri.path
                form["action"] = action_uri
                logger.warning(f"Form action attribute missing; defaulting to: {action_uri}")

            action = parser.buildAction(url, action=action_uri)

            if action and action not in action_done:
                action_done.add(action)

                if not FORM_SUBMISSION:
                    logger.warning("Form submission is turned off. Gathering tokens from basic requests / responses...")
                    if response is None:
                        response = requestMaker(url)
                    if response:
                        token_analyzer.detectTokens(response, passive=True)

                else:
                    logger.debug("Preparing form inputs for submission...")

                    result = parser.prepareFormInputs(form)
                    logger.debug("Submitting the form as first user with inputs: %s", result)
                    if action_method.upper() == "GET":
                        respx = requestMaker(action, method=action_method, params=result)
                    else:
                        respx = requestMaker(action, method=action_method, data=result)

                    result = parser.prepareFormInputs(form)
                    logger.debug("Submitting the form as second user with inputs: %s", result)
                    if action_method.upper() == "GET":
                        respy = requestMaker(action, method=action_method, params=result)
                    else:
                        respy = requestMaker(action, method=action_method, data=result)

                    if respx is None or respy is None:
                        logger.critical("Benchmark requests failed. Aborting form: %s", url)
                        continue

                    logger.debug("Benchmarking form submission responses...")
                    diff = DiffEngine()
                    base_benchmark = diff.prepareBenchmarkResponse(
                        response_bodies=(respx.text, respy.text),
                        statuses=(respx.status_code, respy.status_code),
                        headers=(respx.headers, respy.headers)
                    )

                    bypasses_found = set()

                    if TOKEN_CHECKS:
                        if token_analyzer.detectTokens(respx) or token_analyzer.detectTokens(respy):
                            logger.info("Anti-CSRF tokens detected in response.")

                            passed_tests = token_analyzer.performTokenTamperTests(
                                url=action,
                                method=action_method,
                                params=result,
                                base_benchmark=base_benchmark
                            )
                            bypasses_found.update(passed_tests)

                        else:
                            logger.warning("No Anti-CSRF tokens detected in response.")
                            VulnLogger(url, "No Anti-CSRF tokens detected. Endpoint vulnerable to POST-Based Request Forgery.")
                            bypasses_found.add("NO_TOKEN")

                    if COOKIE_BASED:
                        cookie_analyzer = CookieAnalyzer()
                        is_vulnerable = cookie_analyzer.performSameSiteTests(url)

                        if is_vulnerable:
                            logger.warning("No cookies with SameSite attribute detected.")
                            VulnLogger(url, "No cookies with SameSite attribute detected.")

                    if REFERER_ORIGIN_CHECKS:
                        logger.info("Checking Referer header validation in form submissions...")
                        referer_not_validated = referee.checkRefererValidation(action, base_benchmark, action_method, result)
                        if not referer_not_validated:
                            referee.performRefererBypassChecks(action, base_benchmark, action_method, result)

                        origame.performOriginBypassChecks(action, base_benchmark, action_method, result)

                    if _bypass_content_type(action, base_benchmark, action_method, result):
                        bypasses_found.add("M4")
                    _bypass_head_method(action, base_benchmark, action_method, result)

                    encoding_detector = Encoding()
                    detected = encoding_detector.performTokenEncodingChecks()
                    if detected:
                        logger.warning("Token detected as string-encoded / weak hashes and potentially decryptable.")
                    else:
                        logger.info("Token is not string-encoded.")
                        NovulLogger(url, "Anti-CSRF token is not string-encoded.")

                    # Browser-dependent tests
                    if config.BROWSER_ENABLED:
                        from xsrfprobe.core.main import get_browser_session
                        from xsrfprobe.modules.Browser import BrowserCSRFTests

                        browser = get_browser_session()
                        if browser:
                            bt = BrowserCSRFTests(browser)
                            bt.runAllBrowserTests(action, base_benchmark, action_method, result)

                    # PoC generation — only if an exploitable bypass was found
                    if config.POC_GENERATION and bypasses_found:
                        from xsrfprobe.modules.Generator import PoCGenerator
                        poc_gen = PoCGenerator()
                        poc_paths = poc_gen.generate_all_variants(action, action_method, result, bypasses_found, action_enctype)

                        if config.AUTO_VALIDATE_POC and config.BROWSER_ENABLED:
                            from xsrfprobe.core.main import get_browser_session
                            from xsrfprobe.modules.Browser import BrowserCSRFTests

                            browser = get_browser_session()
                            if browser:
                                bt = BrowserCSRFTests(browser)
                                for poc_path in poc_paths:
                                    bt.autoValidatePoC(poc_path, action, base_benchmark)

        except Exception as e:
            logger.error("Error while processing form: %s", e)
