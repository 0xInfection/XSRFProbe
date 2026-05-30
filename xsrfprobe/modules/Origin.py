#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
import requests
from urllib.parse import urlparse
from xsrfprobe.core.request import requestMaker
from xsrfprobe.core.diff import DiffEngine
from xsrfprobe.core.schema import BenchmarkResult
from xsrfprobe.files.config import HEADER_VALUES, ORIGIN_URL
from xsrfprobe.core.logger import VulnLogger, NovulLogger


class OriginAnalyser:
    def __init__(self) -> None:
        self.origin_value = ORIGIN_URL

    def performBasicHeuristics(self, url: str) -> bool:
        """Perform basic heuristics to check if Origin header is validated using GET."""
        logger = logging.getLogger("OriginHeuristics")
        logger.info("Performing basic Origin header heuristics using GET requests...")

        heuristic_session = requests.Session()
        r1 = requestMaker(url, session=heuristic_session)
        r2 = requestMaker(url, session=heuristic_session)
        modified_headers = HEADER_VALUES.copy()
        modified_headers["Origin"] = self.origin_value
        r3 = requestMaker(url, headers=modified_headers, session=heuristic_session)

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

    # ----------------------------------------------------------------
    # R3: Origin null bypass (HackTricks)
    # ----------------------------------------------------------------
    def bypassOriginNull(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """
        Send Origin: null (produced by sandboxed iframes, file:// URLs,
        and cross-origin redirects).
        """
        logger = logging.getLogger("OriginNullBypass")
        logger.info("[R3] Trying Origin: null bypass...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers["Origin"] = "null"

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        diff = DiffEngine()
        if diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("[R3] VULNERABLE: Server accepted Origin: null.")
            VulnLogger(url, "Origin validation bypassed with Origin: null.")
            return True

        logger.info("[R3] Origin null bypass failed.")
        NovulLogger(url, "Server rejects Origin: null.")
        return False

    # ----------------------------------------------------------------
    # R4: Origin subdomain bypass (HackTricks)
    # ----------------------------------------------------------------
    def bypassOriginSubdomain(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Send Origin: http://target.com.evil.com to bypass regex-based checks."""
        logger = logging.getLogger("OriginSubdomainBypass")
        logger.info("[R4] Trying Origin subdomain bypass...")

        method = method.upper()
        parsed = urlparse(url)
        target_domain = parsed.netloc

        attacker_origin = f"{parsed.scheme}://{target_domain}.evil-attacker.com"

        headers = HEADER_VALUES.copy()
        headers["Origin"] = attacker_origin

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        diff = DiffEngine()
        if diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning(f"[R4] VULNERABLE: Server accepted Origin: {attacker_origin}")
            VulnLogger(url, f"Origin validation bypassed with subdomain trick: {attacker_origin}")
            return True

        logger.info("[R4] Origin subdomain bypass failed.")
        return False

    # ----------------------------------------------------------------
    # Origin absent bypass
    # ----------------------------------------------------------------
    def bypassOriginAbsent(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Remove Origin header entirely."""
        logger = logging.getLogger("OriginAbsentBypass")
        logger.info("Trying Origin absent bypass...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers.pop("Origin", None)

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        diff = DiffEngine()
        if diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("VULNERABLE: Server accepts requests without Origin header.")
            VulnLogger(url, "Origin validation bypassed by omitting the header.")
            return True

        logger.info("Origin absent bypass failed.")
        NovulLogger(url, "Server requires Origin header.")
        return False

    def performOriginBypassChecks(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> None:
        """Run all Origin bypass checks."""
        self.bypassOriginNull(url, benchmark, method, params)
        self.bypassOriginSubdomain(url, benchmark, method, params)
        self.bypassOriginAbsent(url, benchmark, method, params)
