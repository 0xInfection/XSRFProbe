#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import time
import difflib
from urllib.parse import urlencode

import logging
from core.logger import VulnLogger
from files.config import POC_GENERATION, GEN_MALICIOUS
from modules.Generator import GenNormalPoC, GenMalicious

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def PostBased(url, r1, r2, r3, m_action, result, genpoc, form, m_name=""):
    """
    This method is for detecting POST-Based Request Forgeries
        on basis of fuzzy string matching and comparison
            based on Ratcliff-Obershelp Algorithm.
    """
    logger.info("+------------------------------+")
    logger.info("|   POST-Based Forgery Check   |")
    logger.info("+------------------------------+")
    logger.info("Matching response query differences...")

    checkdiffx1 = difflib.ndiff(r1.splitlines(1), r2.splitlines(1))
    checkdiffx2 = difflib.ndiff(r1.splitlines(1), r3.splitlines(1))

    result12 = [n for n in checkdiffx1 if re.match(r"\+|-", n)]
    result13 = [n for n in checkdiffx2 if re.match(r"\+|-", n)]

    logger.info("Matching results...")

    if len(result12) <= len(result13):
        logger.info(f"CSRF Vulnerability Detected: {url}!")
        logger.info("Vulnerability Type: POST-Based Request Forgery")

        VulnLogger(
            url,
            "POST-Based Request Forgery on Forms.",
            f"[i] Form: {form}\n[i] POST Query: {result}\n",
        )

        time.sleep(0.3)
        logger.info("Generating PoC of response and request...")

        if m_name:
            logger.info("+-----------------+")
            logger.info("|   Request PoC   |")
            logger.info("+-----------------+")
            logger.info(f"URL: {url}")
            logger.info(f"Name: {m_name}")

            if m_action.count("/") > 1:
                logger.info(f"Action: /{m_action.rsplit('/', 1)[1]}")
            else:
                logger.info(f"Action: {m_action}")
        else:
            logger.info("+-----------------+")
            logger.info("|   Request PoC   |")
            logger.info("+-----------------+")
            logger.info(f"URL: {url}")

            if m_action.count("/") > 1:
                logger.info(f"Action: /{m_action.rsplit('/', 1)[1]}")
            else:
                logger.info(f"Action: {m_action}")

        logger.info(f"POST Query: {urlencode(result).strip()}")

        if POC_GENERATION:
            if GEN_MALICIOUS:
                GenMalicious(url, genpoc.__str__())
            else:
                GenNormalPoC(url, genpoc.__str__())
