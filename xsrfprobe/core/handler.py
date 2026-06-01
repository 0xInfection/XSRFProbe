#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import string
import random
import logging
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from xsrfprobe.core.request import requestMaker, _build_default_headers, SESSION
from xsrfprobe.core.refresh import refresh_token_pair, _looks_like_token
from xsrfprobe.core.diff import DiffEngine
from xsrfprobe.core.logger import NovulLogger, VulnLogger, PROGRESS, phase_header, test_progress
from xsrfprobe.modules.Origin import OriginAnalyser
from xsrfprobe.modules.Cookie import CookieAnalyzer
from xsrfprobe.modules.Referer import RefererAnalyser
from xsrfprobe.modules.Encoding import Encoding
from xsrfprobe.modules.Parser import FormParser
from xsrfprobe.modules.Token import TokenAnalyser

from xsrfprobe.files import config
from xsrfprobe.files.config import REFERER_ORIGIN_CHECKS, FORM_SUBMISSION, COOKIE_BASED, TOKEN_CHECKS
from xsrfprobe.files.discovered import FORMS_TESTED, VULN_RECORDS

LOGIN_FIELD_PATTERNS = {"username", "user", "login", "email", "password", "passwd", "pass"}


def _is_login_form(form) -> bool:
    """Heuristic: does this form look like a login form (username/email + password)?
    Used to specialise the no-token finding into login-CSRF (D2)."""
    field_names = {inp.get("name", "").lower() for inp in form.findAll("input", {"name": True})}
    has_password = any("pass" in f for f in field_names)
    has_user = any(f in LOGIN_FIELD_PATTERNS for f in field_names)
    return has_password and has_user


def _forge_value(value: str) -> str:
    """Return a same-length-ish random string that differs from ``value``, used
    to corrupt an anti-CSRF token for the rejection-control probe."""
    n = max(len(value or ""), 16)
    forged = "".join(random.choices(string.ascii_letters + string.digits, k=n))
    if forged == value:
        forged = ("A" if not forged.endswith("A") else "B") + forged[1:]
    return forged


def _probe_token_validated(url: str, action: str, method: str, result: dict,
                           diff, base_benchmark):
    """Submit once with a CORRUPTED anti-CSRF token (but a valid session/cookie)
    and report whether the server rejected it.

    Returns:
        True  -> forged token rejected (response differs from success baseline):
                 the token is genuinely validated.
        False -> forged token accepted (response matches baseline): the token is
                 not enforced.
        None  -> there was no token field to forge (cannot calibrate this way).

    This is a more reliable discriminator than comparing against a plain GET,
    because the "success" baseline may itself be a re-rendered form (e.g. a login
    that failed on empty credentials) that coincidentally resembles a page load.
    """
    logger = logging.getLogger("ForgedTokenProbe")
    forged_params, forged_session = refresh_token_pair(url, result)
    token_field = next((k for k in forged_params if _looks_like_token(k)), None)
    if not token_field:
        logger.debug("[ForgedProbe] No token field in submitted params; cannot calibrate via forging.")
        return None

    forged_params = dict(forged_params)
    forged_params[token_field] = _forge_value(str(forged_params.get(token_field, "")))
    sess = forged_session if forged_session is not None else SESSION

    if method.upper() == "GET":
        r = requestMaker(action, method=method, params=forged_params, session=sess)
    else:
        r = requestMaker(action, method=method, data=forged_params, session=sess)
    if r is None:
        logger.debug("[ForgedProbe] Forged-token request failed (no response, e.g. timeout/throttle); cannot calibrate.")
        return None

    rejected = not diff.benchmarkPassed(base_benchmark, r.text, r.status_code)
    logger.debug(
        "[ForgedProbe] field=%s | benchmark status=%s | forged-token response status=%s len=%d "
        "| matches benchmark=%s | verdict=%s",
        token_field, base_benchmark.status_code, r.status_code, len(r.text or ""),
        (not rejected), ("REJECTED -> token validated" if rejected else "ACCEPTED -> token NOT enforced"),
    )
    return rejected


def _bypass_content_type(url: str, base_benchmark, method: str, params: dict) -> bool:
    """M4: token-bypass via Content-Type. Re-submit the form under an alternate
    Content-Type WITHOUT a valid anti-CSRF token, to test whether the server
    skips token validation for that Content-Type (a real bypass) rather than
    merely tolerating the header with a valid token. Returns True if bypassed."""
    logger = logging.getLogger("ContentTypeBypass")
    differ = DiffEngine()
    found = False

    if method.upper() != "POST":
        return False

    # Strip the anti-CSRF token: the bypass is only demonstrated if the request
    # is processed despite the token being absent.
    stripped = {k: v for k, v in params.items() if not _looks_like_token(k)}

    alt_types = [
        "text/plain",
        "application/json",
        "text/plain; application/json",
    ]

    for ct in alt_types:
        headers = _build_default_headers().copy()
        headers["Content-Type"] = ct

        if ct == "application/json" or "json" in ct:
            import json
            body = json.dumps(stripped)
        else:
            body = "&".join(f"{k}={v}" for k, v in stripped.items())

        r = requestMaker(url, method="POST", data=body, headers=headers)
        if r and differ.benchmarkPassed(base_benchmark, r.text, r.status_code):
            logger.warning(f"[M4] VULNERABLE: Server accepted Content-Type: {ct}")
            VulnLogger(url, f"CSRF bypass via Content-Type change to: {ct} (token omitted)", test_id="M4")
            found = True

    return found


def noCrawlProcessor(url: str, soup: BeautifulSoup | None = None) -> None:
    """
    Handles endpoint processing and security validation.
    Either a URL or a BeautifulSoup object has to be passed to this function.
    """
    logger = logging.getLogger("Engine")
    if not url and not soup:
        logger.error("No endpoint or BeautifulSoup object provided.")
        return

    if soup is None:
        response = requestMaker(url)
        logger.debug("Parsing the response from: %s" % url)
        if response is None:
            logger.error("No response received; the site is likely down: %s" % url)
            return
        soup = BeautifulSoup(response.text, "html.parser")
    else:
        response = None

    parsed_uri = urlparse(url)
    action_done = set()

    referee = RefererAnalyser()
    origame = OriginAnalyser()

    logger.debug("Retrieving all forms on %s...", url)

    token_analyzer = TokenAnalyser()
    parser = FormParser(soup)

    # --- Form Discovery Phase ---
    phase_header(logger, "Form Discovery")
    all_forms = parser.getAllForms()
    logger.log(PROGRESS, "Found %d form(s) to analyse.", len(all_forms))

    for form in all_forms:
        logger.debug("Testing the following form:")
        logger.debug("\n%s", form.prettify())
        FORMS_TESTED[url].append(form.prettify())

        if parser.checkBadInputs(form):
            continue

        action_uri: str = parser.extractFormAction(form)
        action_method: str = parser.extractFormMethod(form)
        action_enctype: str = parser.extractFormEnctype(form)
        if action_method == "dialog":
            continue

        try:
            if not action_uri:
                action_uri = parsed_uri.path
                form["action"] = action_uri
                logger.warning(f"Form action attribute missing; defaulting to: {action_uri}")

            action = parser.buildAction(url, action=action_uri)

            if action and action not in action_done:
                action_done.add(action)

                if not FORM_SUBMISSION:
                    logger.warning("Form submission is turned off. Gathering tokens from basic requests / responses...")
                    if response is None:
                        response = requestMaker(url)
                    if response:
                        token_analyzer.detectTokens(response, passive=True)

                else:
                    logger.debug("Preparing form inputs for submission...")
                    result = parser.prepareFormInputs(form)

                    # --- Benchmark Phase ---
                    phase_header(logger, "Benchmark")
                    logger.log(PROGRESS, "Establishing success baseline for %s", action)

                    samples = []
                    for _ in range(3):
                        sample_params, sample_session = refresh_token_pair(url, result)
                        sess = sample_session if sample_session is not None else SESSION
                        if action_method.upper() == "GET":
                            r = requestMaker(action, method=action_method, params=sample_params, session=sess)
                        else:
                            r = requestMaker(action, method=action_method, data=sample_params, session=sess)
                        if r is None:
                            break
                        samples.append(r)

                    if len(samples) < 2:
                        logger.critical("Benchmark requests failed. Aborting form: %s", url)
                        continue

                    logger.log(PROGRESS, "  %d baseline samples | status_code=%s | body_len=%s",
                               len(samples),
                               "/".join(str(r.status_code) for r in samples),
                               "/".join(str(len(r.text or "")) for r in samples))
                    logger.debug("[Benchmark] Baseline sample statuses=%s lengths=%s for %s",
                                 [r.status_code for r in samples],
                                 [len(r.text or "") for r in samples], action)
                    diff = DiffEngine()
                    base_benchmark = diff.prepareBenchmarkResponse(
                        response_bodies=[r.text for r in samples],
                        statuses=[r.status_code for r in samples],
                        headers=[dict(r.headers) for r in samples],
                    )
                    logger.log(PROGRESS, "  Stable template: %d token(s) | similarity_threshold=%.1f%%",
                               len(base_benchmark.base_benchmark), base_benchmark.similarity_threshold)
                    logger.debug("[Benchmark] Consolidated status=%s, template tokens=%d for %s",
                                 base_benchmark.status_code, len(base_benchmark.base_benchmark), action)

                    token_validated = _probe_token_validated(
                        url, action, action_method, result, diff, base_benchmark
                    )
                    if token_validated is True:
                        logger.log(PROGRESS, "  Forged-token probe: REJECTED (response diverged from baseline)")
                    elif token_validated is False:
                        logger.log(PROGRESS, "  Forged-token probe: ACCEPTED (response matched baseline — token not enforced)")
                    else:
                        logger.log(PROGRESS, "  Forged-token probe: N/A (no token field to corrupt)")
                    logger.debug("[Benchmark] Forged-token probe verdict for %s: token_validated=%s "
                                 "(True=rejected/validated, False=accepted, None=could-not-probe).",
                                 action, token_validated)

                    get_matches = False
                    neutral_session = requests.Session()
                    neutral = requestMaker(action, method="GET", session=neutral_session)
                    if neutral is not None:
                        get_matches = diff.benchmarkPassed(base_benchmark, neutral.text, neutral.status_code)
                        get_ratio = diff.performBenchmark(base_benchmark, neutral.text)
                        logger.log(PROGRESS, "  Plain-GET probe: status=%d body_similarity=%.1f%% → %s baseline",
                                   neutral.status_code, get_ratio,
                                   "matches" if get_matches else "differs from")
                        logger.debug("[Benchmark] Plain-GET probe for %s: GET status=%s len=%d | matches baseline=%s",
                                     action, neutral.status_code, len(neutral.text or ""), get_matches)
                    else:
                        logger.log(PROGRESS, "  Plain-GET probe: request failed (assuming differs from baseline)")
                        logger.debug("[Benchmark] Plain-GET probe failed for %s; assuming GET differs from baseline.", action)

                    base_benchmark.discriminative = (token_validated is True) or (not get_matches)
                    t2_reliable = not get_matches

                    if base_benchmark.discriminative:
                        logger.log(PROGRESS, "  Verdict: DISCRIMINATIVE (forged_rejected=%s, get_differs=%s)",
                                   token_validated is True, not get_matches)
                    else:
                        logger.log(PROGRESS, "  Verdict: NON-DISCRIMINATIVE (forged_rejected=%s, get_differs=%s) — skipping diff-based tests",
                                   token_validated is True, not get_matches)
                        logger.warning("[Benchmark] Non-discriminative response for %s: a forged token and a plain GET both match the success baseline, so a successful submission cannot be told apart from a page load. Skipping body-diff-based bypass tests.", action)

                    if not t2_reliable and base_benchmark.discriminative:
                        logger.log(PROGRESS, "  Note: T2 skipped (plain GET ≥ threshold, method-switch indistinguishable)")

                    bypasses_found = set()
                    token_present = False
                    csrf_finding_indices: list[int] = []

                    if TOKEN_CHECKS:
                        token_vuln_start = len(VULN_RECORDS)
                        token_present = any(
                            token_analyzer.detectTokens(s, sent_params=result, sent_method=action_method)
                            for s in samples
                        )

                        if token_present:
                            logger.log(PROGRESS, "Anti-CSRF token detected in form submission.")

                            if base_benchmark.discriminative:
                                # --- Token Tamper Tests Phase ---
                                phase_header(logger, "Token Tamper Tests")
                                passed_tests = token_analyzer.performTokenTamperTests(
                                    url=action,
                                    method=action_method,
                                    params=result,
                                    base_benchmark=base_benchmark,
                                    run_method_switch=t2_reliable,
                                )
                                bypasses_found.update(passed_tests)

                                # --- Method Override Tests Phase ---
                                phase_header(logger, "Content-Type Bypass")
                                with test_progress(logger, "M4", "Content-Type bypass") as tp_result:
                                    if _bypass_content_type(action, base_benchmark, action_method, result):
                                        bypasses_found.add("M4")
                                        tp_result["status"] = "VULNERABLE"
                                    else:
                                        tp_result["status"] = "failed"
                            else:
                                logger.warning("Skipping token tamper tests: benchmark is non-discriminative.")

                        else:
                            logger.warning("No Anti-CSRF tokens detected in response.")
                            if _is_login_form(form):
                                VulnLogger(url, "Login form lacks CSRF token. Attacker can force the victim to authenticate into an attacker-controlled account (login CSRF).", test_id="D2")
                                bypasses_found.add("D2")
                            else:
                                VulnLogger(url, "No anti-CSRF token present. Endpoint is vulnerable to request forgery.", test_id="D1")
                                bypasses_found.add("D1")
                        csrf_finding_indices.extend(range(token_vuln_start, len(VULN_RECORDS)))

                    if COOKIE_BASED:
                        # --- Cookie Tests Phase ---
                        phase_header(logger, "Cookie Tests")
                        cookie_analyzer = CookieAnalyzer()
                        is_vulnerable = cookie_analyzer.performSameSiteTests(url)

                        if is_vulnerable:
                            logger.warning("[C2] No cookies with SameSite attribute detected.")
                            VulnLogger(url, "No cookies with SameSite attribute detected.", test_id="C2")

                    _token_bypass_ids = {"T2", "T3", "T4", "T5", "T6", "T7", "T8", "M1", "M2", "M4"}
                    token_protection_effective = (
                        token_present
                        and base_benchmark.discriminative
                        and not (bypasses_found & _token_bypass_ids)
                    )
                    run_header_tests = base_benchmark.discriminative and not token_protection_effective

                    if REFERER_ORIGIN_CHECKS and run_header_tests:
                        # --- Referer Tests Phase ---
                        phase_header(logger, "Referer Tests")
                        with test_progress(logger, "R0", "Referer validation check") as tp_r0:
                            referer_not_validated = referee.checkRefererValidation(action, base_benchmark, action_method, result)
                            if referer_not_validated:
                                tp_r0["status"] = "VULNERABLE (not validated)"
                            else:
                                tp_r0["status"] = "validated"
                        if not referer_not_validated:
                            referee.performRefererBypassChecks(action, base_benchmark, action_method, result)

                        # --- Origin Tests Phase ---
                        phase_header(logger, "Origin Tests")
                        origame.performOriginBypassChecks(action, base_benchmark, action_method, result)
                    elif token_protection_effective:
                        phase_header(logger, "Referer/Origin Tests")
                        reason = "forged-token probe" if token_validated is True else "T-series tamper tests (no bypass found)"
                        logger.log(PROGRESS, "Skipping: token protection confirmed by %s.", reason)

                    # --- Encoding Tests Phase ---
                    phase_header(logger, "Encoding Tests")
                    encoding_detector = Encoding()
                    with test_progress(logger, "E1", "Token encoding analysis") as tp_result:
                        detected = encoding_detector.performTokenEncodingChecks()
                        if detected:
                            tp_result["status"] = "WEAK ENCODING"
                            logger.warning("[E1] Token detected as string-encoded / weak hashes and potentially decryptable.")
                            VulnLogger(url, "Anti-CSRF token uses a weak/structured hash encoding and may be predictable or decryptable.", test_id="E1")
                        else:
                            tp_result["status"] = "not encoded"
                            NovulLogger(url, "Anti-CSRF token is not string-encoded.", test_id="E1")

                    # Browser-dependent tests
                    if config.BROWSER_ENABLED:
                        phase_header(logger, "Browser Tests")
                        from xsrfprobe.core.main import get_browser_session
                        from xsrfprobe.modules.Browser import BrowserCSRFTests

                        browser = get_browser_session()
                        if browser:
                            bt = BrowserCSRFTests(browser)
                            bt.runAllBrowserTests(action, base_benchmark, action_method, result)

                    # PoC generation — only if an exploitable bypass was found
                    if config.POC_GENERATION and bypasses_found:
                        from xsrfprobe.modules.Generator import PoCGenerator
                        poc_gen = PoCGenerator()
                        poc_map = poc_gen.generate_all_variants(action, action_method, result, bypasses_found, action_enctype)

                        for idx in csrf_finding_indices:
                            rec = VULN_RECORDS[idx]
                            rec["details"] = {
                                "action": action,
                                "method": action_method.upper(),
                            }
                            rec["poc_paths"] = poc_map.get(rec.get("test_id", ""), [])

                        if config.AUTO_VALIDATE_POC and config.BROWSER_ENABLED:
                            from xsrfprobe.core.main import get_browser_session
                            from xsrfprobe.modules.Browser import BrowserCSRFTests

                            all_poc_paths = {p for paths in poc_map.values() for p in paths}
                            browser = get_browser_session()
                            if browser:
                                bt = BrowserCSRFTests(browser)
                                for poc_path in all_poc_paths:
                                    bt.autoValidatePoC(poc_path, action, base_benchmark)

        except Exception as e:
            logger.error("Error while processing form: %s", e)
