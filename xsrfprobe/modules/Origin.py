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
from files.config import HEADER_VALUES, ORIGIN_URL
from core.logger import VulnLogger, NovulLogger


class OriginAnalyser:
    def __init__(self) -> None:
        self.origin_value = ORIGIN_URL

    def performBasicHeuristics(self, url: str) -> bool:
        '''
        Performs basic heuristics to check if the Origin header is being validated using GET.
        '''
        logger = logging.getLogger("OriginHeuristics")
        logger.info("Performing basic Origin header heuristics using GET requests...")

        # these requests will be used to prepare the benchmark response
        r1 = requestMaker(url)
        r2 = requestMaker(url)
        # modify the origin header and check if the response changes
        r3 = requestMaker(url, headers={HEADER_VALUES["Origin"]: self.origin_value})

        if r1 is None or r2 is None or r3 is None:
            logger.error("No response received for the Origin heuristic checks.")
            return False

        diff = DiffEngine()
        benchmark = diff.prepareBenchmarkResponse(
            response_bodies=(r1.text, r2.text),
            statuses=(r1.status_code, r2.status_code),
            headers=(r1.headers, r2.headers)
        )

        if diff.benchmarkPassed(benchmark, r3.text, r3.status_code):
            logger.warning("Origin header is not validated in GET requests.")
            VulnLogger(url, "Origin header is not validated in GET requests.")
            return False

        logger.info("Origin header is validated in GET requests.")
        NovulLogger(url, "Origin header is validated in GET requests.")
        return True