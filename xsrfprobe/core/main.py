import sys
import logging
import time
import warnings

from core.options import options
from core.inputin import inputProcessor
from core.utils import calcLogLevel
from core.handler import noCrawlProcessor
from core.logger import CustomFormatter, CustomLogger
from files.config import CRAWL_SITE

from modules.Crawler import Crawler
from modules.Analysis import Analysis

# Suppress warnings
warnings.filterwarnings("ignore")

def Engine():
    args = options()

    # Configure logging
    formatter = CustomFormatter()
    logging.root.setLevel(calcLogLevel(args))
    logging.setLoggerClass(CustomLogger)

    error_handler = logging.FileHandler("errors.log", mode="a")
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(formatter)
    logging.root.addHandler(error_handler)

    logging.info("Booting up XSRFProbe engine...")

    timestart = time.time()
    web, _ = inputProcessor()
    print(web)

    try:
        if CRAWL_SITE:
            logging.info("Initializing crawling and scanning...")
            crawler = Crawler(web)

            while crawler.has_urls_to_visit():
                url = crawler.__next__()
                logging.info(f"Testing: {url}")

                soup = crawler.process(url)
                if not soup:
                    continue

                noCrawlProcessor("", soup)

        else:
            logging.info("Initializing endpoint testing...")
            noCrawlProcessor(endpoint=web)

        logging.info("Scan completed.")
        #Analysis()

    except KeyboardInterrupt:
        logging.warning("User interrupted the process.")
        #Analysis()

    finally:
        timend = time.time()
        logging.info(f"Time taken: {timend - timestart:.2f} seconds.")
        logging.info("Shutting down XSRFProbe.")
