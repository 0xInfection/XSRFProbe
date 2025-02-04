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
from requests.exceptions import HTTPError
from core.request import requestMaker
from core.diff import DiffEngine
from core.logger import ErrorLogger, NovulLogger, VulnLogger
from modules.Origin import OriginAnalyser
from modules.Cookie import CookieAnalyzer
from modules.Tamper import Tamper
from modules.Entropy import Entropy
from modules.Referer import RefererAnalyser
from modules.Encoding import Encoding
from modules.Checkpost import PostBased
from modules.Parser import FormParser
from modules.Token import TokenAnalyser

from files.config import REFERER_ORIGIN_CHECKS, FORM_SUBMISSION, COOKIE_BASED, POST_BASED, TOKEN_CHECKS
from files.discovered import FORMS_TESTED

def noCrawlProcessor(endpoint: str) -> None:
    """
    Handles endpoint processing and security validation.
    """
    logger = logging.getLogger("Engine")
    url = endpoint
    parsed_uri = urlparse(url)
    response = requestMaker(url)
    logger.debug("Parsing the response from: %s" % url)
    if response is None:
        logger.error("No response received; the site is likely down: %s" % url)
        return
    soup = BeautifulSoup(response.text, "html.parser")

    i = 0  # Initialize user iteration
    action_done = set()

    if REFERER_ORIGIN_CHECKS:
        referee = RefererAnalyser()
        logger.info("[Heuristics] Performing GET-based Referer validation checks.")
        referee.performBasicHeuristics(url)

        logger.info("[Heuristics] Performing GET-based Origin validation checks.")
        origame = OriginAnalyser()
        origame.performBasicHeuristics(url)

    logger.debug("Retrieving all forms on %s...", url)

    token_analyzer = TokenAnalyser()
    parser = FormParser(soup)
    for form in parser.getAllForms():
        logger.debug("Testing the following form:")
        logger.debug("\n%s", form.prettify())
        FORMS_TESTED.append(f"(i) {url}:\n\n{form.prettify()}\n")

        action_uri: str = form.get("action")  # type: ignore
        action_method: str = form.get("method", "GET").upper()  # type: ignore

        foundx1, foundx2, foundx3 = False, False, False

        try:
            if not form.get("action"):
                form["action"] = parsed_uri.path
                logger.warning(f"Form action attribute missing; defaulting to inferred value: {form['action']}.")
                ErrorLogger(url, 'No standard form "action".')

            action = parser.buildAction(url, action=action_uri)

            if action and action not in action_done:
                if not FORM_SUBMISSION:
                    logger.warning("Form submission is turned off. Gathering tokens from HTML responses...")
                    token_analyzer.detectTokens(response, passive=True)

                else:
                    logger.debug("Preparing form inputs for submission...")

                    # make 2 requests as separate users
                    result, gen_poc = parser.prepareFormInputs(form)
                    respx = requestMaker(action, method=action_method, data=result)
                    result, gen_poc = parser.prepareFormInputs(form)
                    respy = requestMaker(action, method=action_method, data=result)

                    if not respx or not respy:
                        logger.critical("One or more benchmark requests failed. Aborting testing form endpoint: %s", url)
                        ErrorLogger(url, "Benchmark request failed.")
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
                        if cookie_analyzer.parseCookies(respx) or cookie_analyzer.parseCookies(respy):
                            logger.info("Cookies with SameSite attribute detected.")
                            cookie_analyzer.performSameSiteTests(url)

                        else:
                            logger.info("No cookies with SameSite attribute detected.")
                            logger.info("Endpoint seems VULNERABLE to CSRF attacks.")
                            VulnLogger(url, "No cookies with SameSite attribute detected.")

                    if REFERER_ORIGIN_CHECKS:
                        logger.info("Checking Referer header validation in form submissions...")
                        if referee.checkRefererValidation(url, base_benchmark, action_method, result):
                            logger.debug("Referer header is validated in form submissions. Trying to bypass validation checks.")
                            referee.performRefererBypassChecks(url, base_benchmark, action, result)




                    fnd, detct = Encoding(token)
                    if fnd and detct:
                        logger.warning("Token detected as string-encoded and potentially decryptable.")
                        VulnLogger(url, "Potentially decryptable token.", f"Encoding: {detct}")
                    else:
                        logger.info("Token is not string-encoded.")
                        NovulLogger(url, "Anti-CSRF token is not string-encoded.")

                    if query and token:
                        txor = Tamper(url, action, result, r2.text, query, token)

                    o2 = requestMaker(url).text
                    try:
                        form2 = Parser.getAllForms(BeautifulSoup(o2, "html.parser"))[i]
                    except IndexError:
                        logger.error("Form index error while processing user iteration %d.", i)
                        ErrorLogger(url, "Form Index Error.")
                        continue

                    logger.info("Preparing inputs for the next user iteration.")
                    contents2, gen_poc = form.prepareFormInputs(form2)
                    r3 = Post(url, action, contents2)

                    if POST_BASED and (not query or txor):
                        try:
                            if form.get("name"):
                                PostBased(
                                    url, r1.text, r2.text, r3.text, action, result, gen_poc, form.prettify(), form["name"]
                                )
                            else:
                                PostBased(
                                    url, r1.text, r2.text, r3.text, action, result, gen_poc, form.prettify()
                                )
                        except KeyError:
                            PostBased(
                                url, r1.text, r2.text, r3.text, action, result, gen_poc, form.prettify()
                            )
                    else:
                        logger.info("Endpoint is not vulnerable to POST-based CSRF attacks.")
                        NovulLogger(url, "Not vulnerable to POST-based CSRF attacks.")

                action_done.append(action)
        except Exception as e:
            logger.error("Error while processing the form: %s", e)
        i += 1
