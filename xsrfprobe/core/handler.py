import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from requests.exceptions import HTTPError
from core.request import requestMaker
from core.logger import ErrorLogger, NovulLogger, VulnLogger
from modules.Origin import Origin
from modules.Cookie import Cookie
from modules.Tamper import Tamper
from modules.Entropy import Entropy
from modules.Referer import Referer
from modules.Encoding import Encoding
from modules.Checkpost import PostBased
from modules.Parser import FormParser

from files.config import REFERER_ORIGIN_CHECKS, FORM_SUBMISSION, COOKIE_BASED, POST_BASED
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
        logger.info("[Heuristics] Performing GET-based Referer validation checks.")
        Referer(url)

        logger.info("[Heuristics] Performing GET-based Origin validation checks.")
        Origin(url)

    logger.debug("Retrieving all forms on %s...", url)

    parser = FormParser(soup)
    for form in parser.getAllForms():
        logger.debug("Testing the following form:")
        logger.debug("\n%s", form.prettify())
        FORMS_TESTED.append(f"(i) {url}:\n\n{form.prettify()}\n")

        try:
            if not form.get("action"):
                form["action"] = parsed_uri.path
                logger.warning(f"Form action attribute missing; defaulting to inferred value: {form['action']}.")
                ErrorLogger(url, 'No standard form "action".')

            action = parser.buildAction(url, action=form["action"])

            if action and action not in action_done:
                if FORM_SUBMISSION:
                    try:
                        logger.debug("Preparing form inputs for submission...")

                        # make 2 requests as separate users
                        result, gen_poc = parser.prepareFormInputs(form)
                        _ = requestMaker(action, method="POST", data=result)
                        result, gen_poc = parser.prepareFormInputs(form)
                        resp2 = requestMaker(action, method="POST", data=result)

                        if resp2:
                            Cookie(url, resp2)
                            Entropy(resp2, form.prettify())

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

                    except HTTPError as err:
                        logger.error("HTTP error encountered: %s", err)
                        ErrorLogger(url, err)

                action_done.append(action)
        except Exception as e:
            logger.error("Error while processing the form: %s", e)
        i += 1
