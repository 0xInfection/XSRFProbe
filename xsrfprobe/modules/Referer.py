#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#     XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
from xsrfprobe.core.request import requestMaker
from xsrfprobe.core.diff import DiffEngine
from urllib.parse import urlparse
from xsrfprobe.files.config import HEADER_VALUES, REFERER_URL
from xsrfprobe.core.logger import VulnLogger, NovulLogger
from xsrfprobe.core.schema import BenchmarkResult


class RefererAnalyser:
    def __init__(self) -> None:
        self.referer_value = REFERER_URL
        self.diff = DiffEngine()

    def performBasicHeuristics(self, url: str) -> bool:
        """Perform basic heuristics to check if the Referer header is validated using GET."""
        logger = logging.getLogger("RefererHeuristics")
        logger.info("Performing basic Referer header heuristics using GET requests...")
        headers = HEADER_VALUES.copy()

        r1 = requestMaker(url)
        r2 = requestMaker(url)
        modified_headers = headers.copy()
        modified_headers["Referer"] = self.referer_value
        r3 = requestMaker(url, headers=modified_headers)

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
        """Check if the Referer header is validated in form submissions."""
        logger = logging.getLogger("RefererValidationCheck")
        logger.info("Checking Referer header validation in form submissions...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers["Referer"] = self.referer_value

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("Referer header is not validated in form submissions.")
            VulnLogger(url, "Referer header is not validated in form submissions.")
            return True

        logger.info("Referer header is validated in form submissions.")
        return False

    # ----------------------------------------------------------------
    # R1: Referer validation depends on header being present
    # (PortSwigger Lab 11)
    # ----------------------------------------------------------------
    def bypassRefererPresenceCheck(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Remove Referer and Origin headers entirely. Server may skip validation when absent."""
        logger = logging.getLogger("RefererPresenceBypass")
        logger.info("[R1] Trying Referer presence bypass (remove Referer + Origin)...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers.pop("Referer", None)
        headers.pop("Origin", None)

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("[R1] VULNERABLE: Server accepts requests without Referer header.")
            VulnLogger(url, "Referer validation bypassed by omitting the header entirely.")
            return True

        logger.info("[R1] Referer presence bypass failed. Server requires the header.")
        NovulLogger(url, "Server rejects requests without Referer header.")
        return False

    # ----------------------------------------------------------------
    # R2 variant 1: Referer regex bypass -- target as subdomain
    # (PortSwigger Lab 12)
    # ----------------------------------------------------------------
    def bypassRefererRegexSubdomain(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """
        Set Referer to http://target.com.evil.com/csrf to bypass
        'starts with' domain checks.
        """
        logger = logging.getLogger("RefererRegexBypass")
        logger.info("[R2a] Trying Referer regex bypass (target as subdomain of attacker)...")

        method = method.upper()
        parsed = urlparse(url)
        target_domain = parsed.netloc

        attacker_referer = f"{parsed.scheme}://{target_domain}.evil-attacker.com/csrf"

        headers = HEADER_VALUES.copy()
        headers["Referer"] = attacker_referer

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning(f"[R2a] VULNERABLE: Server accepted Referer: {attacker_referer}")
            VulnLogger(url, f"Referer validation bypassed with subdomain trick: {attacker_referer}")
            return True

        logger.info("[R2a] Subdomain Referer bypass failed.")
        return False

    # ----------------------------------------------------------------
    # R2 variant 2: Referer regex bypass -- target in query string
    # (PortSwigger Lab 12)
    # ----------------------------------------------------------------
    def bypassRefererRegexQueryParam(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """
        Set Referer to http://evil.com/csrf?target.com to bypass
        'contains' domain checks. Must also set Referrer-Policy: unsafe-url
        so browsers include the query string.
        """
        logger = logging.getLogger("RefererRegexBypass")
        logger.info("[R2b] Trying Referer regex bypass (target in query param)...")

        method = method.upper()
        parsed = urlparse(url)
        target_domain = parsed.netloc

        attacker_referer = f"http://evil-attacker.com/csrf?{target_domain}"

        headers = HEADER_VALUES.copy()
        headers["Referer"] = attacker_referer
        headers["Referrer-Policy"] = "unsafe-url"

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning(f"[R2b] VULNERABLE: Server accepted Referer: {attacker_referer}")
            VulnLogger(url, f"Referer validation bypassed with query-param trick: {attacker_referer}")
            return True

        logger.info("[R2b] Query-param Referer bypass failed.")
        return False

    # ----------------------------------------------------------------
    # R2 variant 3: Referer regex bypass -- target in path
    # ----------------------------------------------------------------
    def bypassRefererRegexPath(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """Set Referer to http://evil.com/target.com to bypass path-based checks."""
        logger = logging.getLogger("RefererRegexBypass")
        logger.info("[R2c] Trying Referer regex bypass (target in path)...")

        method = method.upper()
        parsed = urlparse(url)
        target_domain = parsed.netloc

        attacker_referer = f"http://evil-attacker.com/{target_domain}/csrf"

        headers = HEADER_VALUES.copy()
        headers["Referer"] = attacker_referer

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None
        )
        if r is None:
            return False

        if self.diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning(f"[R2c] VULNERABLE: Server accepted Referer: {attacker_referer}")
            VulnLogger(url, f"Referer validation bypassed with path trick: {attacker_referer}")
            return True

        logger.info("[R2c] Path Referer bypass failed.")
        return False

    # ----------------------------------------------------------------
    # Orchestrator
    # ----------------------------------------------------------------
    def performRefererBypassChecks(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> None:
        """Run all Referer bypass checks."""
        self.bypassRefererPresenceCheck(url, benchmark, method, params)
        self.bypassRefererRegexSubdomain(url, benchmark, method, params)
        self.bypassRefererRegexQueryParam(url, benchmark, method, params)
        self.bypassRefererRegexPath(url, benchmark, method, params)
