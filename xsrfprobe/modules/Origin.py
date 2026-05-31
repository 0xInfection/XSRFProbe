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
from xsrfprobe.core.request import requestMaker, SESSION
from xsrfprobe.core.refresh import refresh_token_pair
from xsrfprobe.core.diff import DiffEngine
from xsrfprobe.core.schema import BenchmarkResult
from xsrfprobe.files.config import HEADER_VALUES, ORIGIN_URL
from xsrfprobe.core.logger import VulnLogger, NovulLogger


class OriginAnalyser:
    def __init__(self) -> None:
        self.origin_value = ORIGIN_URL

    # ----------------------------------------------------------------
    # O1: Origin null bypass (HackTricks)
    # ----------------------------------------------------------------
    def bypassOriginNull(self, url: str, benchmark: BenchmarkResult, method: str, params: dict, session: requests.Session | None = None) -> bool:
        """
        Send Origin: null (produced by sandboxed iframes, file:// URLs,
        and cross-origin redirects).
        """
        logger = logging.getLogger("OriginNullBypass")
        logger.info("[O1] Trying Origin: null bypass...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers["Origin"] = "null"

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None,
            session=session if session is not None else SESSION
        )
        if r is None:
            return False

        diff = DiffEngine()
        if diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("[O1] VULNERABLE: Server accepted Origin: null.")
            VulnLogger(url, "Origin validation bypassed with Origin: null.", test_id="O1")
            return True

        logger.info("[O1] Origin null bypass failed.")
        NovulLogger(url, "Server rejects Origin: null.", test_id="O1")
        return False

    # ----------------------------------------------------------------
    # O2: Origin subdomain bypass (HackTricks)
    # ----------------------------------------------------------------
    def bypassOriginSubdomain(self, url: str, benchmark: BenchmarkResult, method: str, params: dict, session: requests.Session | None = None) -> bool:
        """Send Origin: http://target.com.evil.com to bypass regex-based checks."""
        logger = logging.getLogger("OriginSubdomainBypass")
        logger.info("[O2] Trying Origin subdomain bypass...")

        method = method.upper()
        parsed = urlparse(url)
        target_domain = parsed.netloc

        attacker_origin = f"{parsed.scheme}://{target_domain}.evil-attacker.com"

        headers = HEADER_VALUES.copy()
        headers["Origin"] = attacker_origin

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None,
            session=session if session is not None else SESSION
        )
        if r is None:
            return False

        diff = DiffEngine()
        if diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning(f"[O2] VULNERABLE: Server accepted Origin: {attacker_origin}")
            VulnLogger(url, f"Origin validation bypassed with subdomain trick: {attacker_origin}", test_id="O2")
            return True

        logger.info("[O2] Origin subdomain bypass failed.")
        return False

    # ----------------------------------------------------------------
    # O3: Origin absent bypass
    # ----------------------------------------------------------------
    def bypassOriginAbsent(self, url: str, benchmark: BenchmarkResult, method: str, params: dict, session: requests.Session | None = None) -> bool:
        """Remove Origin header entirely."""
        logger = logging.getLogger("OriginAbsentBypass")
        logger.info("[O3] Trying Origin absent bypass...")

        method = method.upper()
        headers = HEADER_VALUES.copy()
        headers.pop("Origin", None)

        r = requestMaker(
            url=url, headers=headers, method=method,
            params=params if method == "GET" else None,
            data=params if method == "POST" else None,
            session=session if session is not None else SESSION
        )
        if r is None:
            return False

        diff = DiffEngine()
        if diff.benchmarkPassed(benchmark, r.text, r.status_code):
            logger.warning("[O3] VULNERABLE: Server accepts requests without Origin header.")
            VulnLogger(url, "Origin validation bypassed by omitting the header.", test_id="O3")
            return True

        logger.info("[O3] Origin absent bypass failed.")
        NovulLogger(url, "Server requires Origin header.", test_id="O3")
        return False

    def performOriginBypassChecks(self, url: str, benchmark: BenchmarkResult, method: str, params: dict) -> None:
        """Run all Origin bypass checks."""
        # Refresh the token+cookie pair once on an isolated session so every
        # bypass attempt submits a body token that matches its cookie. This
        # isolates the Origin header as the only variable under test.
        params, session = refresh_token_pair(url, params)
        self.bypassOriginNull(url, benchmark, method, params, session)
        self.bypassOriginSubdomain(url, benchmark, method, params, session)
        self.bypassOriginAbsent(url, benchmark, method, params, session)
