#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
from core.request import requestMaker
from core.diff import DiffEngine
from urllib.parse import urlparse
from files.config import HEADER_VALUES, REFERER_URL
from core.logger import VulnLogger, NovulLogger
from core.schema import BenchmarkResult

class RefererAnalyser:
    def __init__(self) -> None:
        self.referer_value = REFERER_URL
        self.diff = DiffEngine()

    def performBasicHeuristics(self, url: str) -> bool:
        '''
        Performs basic heuristics to check if the Referer header is being validated using GET.
        '''
        logger = logging.getLogger("RefererHeuristics")
        logger.info("Performing basic Referer header heuristics using GET requests...")
        headers = HEADER_VALUES.copy()

        # these requests will be used to prepare the benchmark response
        r1 = requestMaker(url)
        r2 = requestMaker(url)
        # modify the referer header and check if the response changes
        r3 = requestMaker(url, headers={headers["Referer"]: self.referer_value})

        if r1 is None or r2 is None or r3 is None:
            logger.error("No response received for the Referer heuristic checks.")
            return False

        benchmark = self.diff.prepareBenchmarkResponse(
            response_bodies=(r1.text, r2.text),
            statuses=(r1.status_code, r2.status_code),
            headers=(r1.headers, r2.headers)
        )

        if self.diff.benchmarkPassed(benchmark, r3.text, r3.status_code):
            logger.warning("Referer header is not validated in GET requests.")
            VulnLogger(url, "Referer header is not validated in GET requests.")
            return False

        logger.info("Referer header is validated in GET requests.")
        NovulLogger(url, "Referer header is validated in GET requests.")
        return True

    def checkRefererValidation(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        '''
        Checks if the Referer header is validated in form submissions.
        '''
        logger = logging.getLogger("RefererValidationCheck")
        logger.info("Checking Referer header validation in form submissions...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers["Referer"] = self.referer_value

        r = requestMaker(
            url=url,
            headers=headers,
            method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            logger.error("No response received for the Referer validation checks.")
            return False

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("Referer header is not validated in form submissions.")
            NovulLogger(url, "Referer header is not validated in form submissions.")
            return True

        logger.info("Referer header is validated in form submissions.")
        VulnLogger(url, "Referer header is validated in form submissions.")
        return False

    def bypassRefererPresenceCheck(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> None:
        '''
        Performs Referer header validation checks when submitting forms.
        '''
        logger = logging.getLogger("RefererPresenceBypass")
        logger.info("Performing Referer header presence bypass checks...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers.pop("Referer")
        headers.pop("Origin")
        r = requestMaker(
            url=url,
            headers=headers,
            method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            logger.error("No response received for the Referer presence bypass checks.")
            return

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("Referer header is not validated in form submissions.")
            VulnLogger(url, "Referer header is not validated in form submissions.")
            return

        logger.info("Referer header is validated in form submissions.")
        NovulLogger(url, "Referer header is validated in form submissions.")

    def bypassRefererValidationCheck(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> None:
        '''
        Performs Referer header validation checks when submitting forms.
        '''
        logger = logging.getLogger("RefererValidationBypass")
        logger.info("Performing Referer header validation bypass checks...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        parsed_original = urlparse(url)
        parsed_modified = urlparse(self.referer_value)
        headers["Referer"] = f"{parsed_original.scheme}://{parsed_original}.{parsed_modified}/{parsed_modified.path}"

        r = requestMaker(
            url=url,
            headers=headers,
            method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            logger.error("No response received for the Referer validation bypass checks.")
            return

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("Referer header is not validated in form submissions.")
            VulnLogger(url, "Referer header is not validated in form submissions.")
            return

        logger.info("Referer header is validated in form submissions.")

    def performRefererBypassChecks(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> None:
        '''
        Performs Referer header bypass checks.
        '''
        self.bypassRefererPresenceCheck(url, benchmark, method, params)
        self.bypassRefererValidationCheck(url, benchmark, method, params)