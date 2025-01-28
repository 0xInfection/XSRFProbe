import sys
import logging
import time
import requests
import warnings
from bs4 import BeautifulSoup
from requests.exceptions import HTTPError, RequestException
from urllib.error import URLError

from core.options import options
from core.inputin import inputProcessor
from core.utils import calcLogLevel
from core.handler import noCrawlProcessor
from files.discovered import FORMS_TESTED
from core.logger import ErrorLogger, GetLogger, VulnLogger, NovulLogger, CustomFormatter
from files.config import (
    CRAWL_SITE,
    REFERER_ORIGIN_CHECKS,
    FORM_SUBMISSION,
    COOKIE_BASED,
    POST_BASED,
)
from modules import Parser, Crawler
from modules.Origin import Origin
from modules.Cookie import Cookie
from modules.Tamper import Tamper
from modules.Entropy import Entropy
from modules.Referer import Referer
from modules.Encoding import Encoding
from modules.Analysis import Analysis
from modules.Checkpost import PostBased
from xsrfprobe.modules import Parser

# Suppress warnings
warnings.filterwarnings("ignore")

def Engine():
    args = options()

    # Configure logging
    formatter = CustomFormatter()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)
    logging.root.setLevel(calcLogLevel(args))

    timestart = time.time()
    web, fld = inputProcessor()
    session1, session2 = requests.Session(), requests.Session()

    action_done = []

    try:
        if not CRAWL_SITE:
            logging.info("Initializing endpoint testing...")
            noCrawlProcessor(web)
        else:
            logging.info("Initializing crawling and scanning...")
            crawler = Crawler.Handler(session1, session2)

            while crawler.noinit():
                url = next(crawler)
                logging.info(f"Testing: {url}")

                try:
                    soup = crawler.process(fld)
                    if not soup:
                        continue

                    if REFERER_ORIGIN_CHECKS:
                        logging.info("Performing Referer and Origin header validation checks...")
                        Referer(url)
                        Origin(url)

                    logging.info(f"Retrieving all forms on {url}...")

                    for i, form in enumerate(Parser.getAllForms(soup)):
                        FORMS_TESTED.append(f"(i) {url}:\n\n{form.prettify()}\n")

                        try:
                            action = form.get("action", f"/{url.rsplit('/', 1)[1]}")
                            form["action"] = action

                            action_url = Parser.buildAction(url, action)

                            if action_url and action_url not in action_done:
                                if FORM_SUBMISSION:
                                    try:
                                        result, genpoc = form_parser.prepareFormInputs(form)
                                        r1 = session1.post(action_url, data=result)

                                        result, genpoc = form_parser.prepareFormInputs(form)
                                        r2 = session2.post(action_url, data=result)

                                        if COOKIE_BASED:
                                            Cookie(url, r1)

                                        query, token = Entropy(result, url, r1.headers, form.prettify(), action)

                                        if Encoding(token):
                                            VulnLogger(url, "Detected string-encoded token.", "Potentially decryptable token.")
                                        else:
                                            NovulLogger(url, "Token is not string-encoded.")

                                        if query and token:
                                            Tamper(url, action_url, result, r2.text, query, token)

                                        form2 = Parser.getAllForms(BeautifulSoup(session2.get(url).text))[i]
                                        contents2, genpoc = form_parser.prepareFormInputs(form2)
                                        session2.post(action_url, data=contents2)

                                        if POST_BASED:
                                            PostBased(url, r1.text, r2.text, r3.text, action, result, genpoc, form.prettify())
                                        else:
                                            NovulLogger(url, "Not vulnerable to POST-Based CSRF attacks.")
                                    except RequestException as e:
                                        logging.error(f"Request error: {e}")
                                        ErrorLogger(url, e)

                                action_done.append(action_url)
                        except Exception as e:
                            logging.error(f"Error processing form: {e}")

                except HTTPError as e:
                    logging.error(f"HTTP Error {e.code} while testing {url}.")
                    ErrorLogger(url, e)
                except URLError as e:
                    logging.warning(f"URL error at {url}. Skipping.")
                    ErrorLogger(url, e)

        GetLogger()
        logging.info("Scan completed.")
        Analysis()

    except KeyboardInterrupt:
        logging.warning("User interrupted the process.")
        Analysis()
    except Exception as e:
        logging.error("Unexpected error occurred.")
        ErrorLogger("Engine", e)
    finally:
        GetLogger()
