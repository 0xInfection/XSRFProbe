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
from core.request import requestMaker
from core.diff import DiffEngine
from core.logger import ErrorLogger, NovulLogger, VulnLogger
from modules.Origin import OriginAnalyser
from modules.Cookie import CookieAnalyzer
from modules.Referer import RefererAnalyser
from modules.Encoding import Encoding
from modules.Parser import FormParser
from modules.Token import TokenAnalyser

from files.config import REFERER_ORIGIN_CHECKS, FORM_SUBMISSION, COOKIE_BASED, TOKEN_CHECKS
from files.discovered import FORMS_TESTED

def noCrawlProcessor(endpoint: str="", soup: BeautifulSoup=None) -> None:  # type: ignore
    """
    Handles endpoint processing and security validation.

    Either a URL or a BeautifulSoup object has to be passed to this function.
    """
    logger = logging.getLogger("Engine")
    if not endpoint or not soup:
        logger.error("No endpoint or BeautifulSoup object provided.")
        return

    url = endpoint
    response = requestMaker(url)
    logger.debug("Parsing the response from: %s" % url)
    if response is None:
        logger.error("No response received; the site is likely down: %s" % url)
        return

    if not soup:
        parsed_uri = urlparse(url)
        soup = BeautifulSoup(response.text, "html.parser")

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

        if parser.checkBadInputs(form):
            continue

        action_uri: str = parser.extractFormAction(form)  # type: ignore
        action_method: str = parser.extractFormMethod(form)  # type: ignore
        # we ignore forms with dialog action
        if action_method == "dialog":
            continue

        try:
            if not action_uri:
                action_uri = parsed_uri.path  # type: ignore
                form["action"] = action_uri
                logger.warning(f"Form action attribute missing; defaulting to inferred value: {form['action']}.")

            action = parser.buildAction(url, action=action_uri)

            if action and action not in action_done:
                if not FORM_SUBMISSION:
                    logger.warning("Form submission is turned off. Gathering tokens from basic requests / responses...")
                    token_analyzer.detectTokens(response, passive=True)

                else:
                    logger.debug("Preparing form inputs for submission...")

                    # make 2 requests as separate users
                    result, gen_poc = parser.prepareFormInputs(form)
                    logger.debug("Submitting the form as first user with the following inputs: %s", result)
                    respx = requestMaker(action, method=action_method, data=result)

                    result, gen_poc = parser.prepareFormInputs(form)
                    logger.debug("Submitting the form as second user with the following inputs: %s", result)
                    respy = requestMaker(action, method=action_method, data=result)

                    if not respx or not respy:
                        logger.critical("One or more benchmark requests failed. Aborting testing form endpoint: %s", url)
                        continue

                    logger.debug("Benchmarking the form submission responses for a base response...")
                    diff = DiffEngine()
                    base_benchmark = diff.prepareBenchmarkResponse(
                        response_bodies=(respx.text, respy.text),
                        statuses=(respx.status_code, respy.status_code),
                        headers=(respx.headers, respy.headers)
                    )

                    if TOKEN_CHECKS:
                        # detect the tokens in the response/request
                        if token_analyzer.detectTokens(respx) or token_analyzer.detectTokens(respy):
                            logger.info("Anti-CSRF tokens detected in response.")

                            token_analyzer.performTokenTamperTests(
                                url=url,
                                base_benchmark=base_benchmark,
                                method=action_method,
                                params=result
                            )

                        else:
                            logger.warning("No Anti-CSRF tokens detected in response.")
                            logger.info("Endpoint seems VULNERABLE to POST-Based Request Forgery")
                            VulnLogger(url, "No Anti-CSRF tokens detected in response.")

                    if COOKIE_BASED:
                        cookie_analyzer = CookieAnalyzer()
                        results = cookie_analyzer.performSameSiteTests(url)

                        if results:
                            logger.info("No cookies with SameSite attribute detected.")
                            logger.info("Endpoint seems VULNERABLE to CSRF attacks.")
                            VulnLogger(url, "No cookies with SameSite attribute detected.")

                    if REFERER_ORIGIN_CHECKS:
                        logger.info("Checking Referer header validation in form submissions...")
                        if referee.checkRefererValidation(url, base_benchmark, action_method, result):
                            logger.debug("Referer header is validated in form submissions. Trying to bypass validation checks.")
                            referee.performRefererBypassChecks(url, base_benchmark, action, result)

                    encoding_detector = Encoding()
                    detected = encoding_detector.performTokenEncodingChecks()
                    if detected:
                        logger.warning("Token detected as string-encoded / weak hashes and potentially decryptable.")
                    else:
                        logger.info("Token is not string-encoded.")
                        NovulLogger(url, "Anti-CSRF token is not string-encoded.")

        except Exception as e:
            logger.error("Error while processing the form: %s", e)
