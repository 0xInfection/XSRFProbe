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
from xsrfprobe.core.logger import NovulLogger, VulnLogger
from xsrfprobe.modules.Origin import OriginAnalyser
from xsrfprobe.modules.Cookie import CookieAnalyzer
from xsrfprobe.modules.Referer import RefererAnalyser
from xsrfprobe.modules.Encoding import Encoding
from xsrfprobe.modules.Parser import FormParser
from xsrfprobe.modules.Token import TokenAnalyser

from xsrfprobe.files import config
from xsrfprobe.files.config import REFERER_ORIGIN_CHECKS, FORM_SUBMISSION, COOKIE_BASED, TOKEN_CHECKS
from xsrfprobe.files.discovered import FORMS_TESTED, VULN_RECORDS, POC_RECORDS

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
    for form in parser.getAllForms():
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

                    # Establish the benchmark from 3 successful samples. The
                    # token+cookie pair is refreshed before each so every sample
                    # is a valid submission — single-use tokens would otherwise
                    # make later samples fail and poison the baseline. Per-sample
                    # token differences are removed by the volatility mask.
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

                    logger.debug("Benchmarking %d form submission responses...", len(samples))
                    logger.debug("[Benchmark] Baseline sample statuses=%s lengths=%s for %s",
                                 [r.status_code for r in samples],
                                 [len(r.text or "") for r in samples], action)
                    diff = DiffEngine()
                    base_benchmark = diff.prepareBenchmarkResponse(
                        response_bodies=[r.text for r in samples],
                        statuses=[r.status_code for r in samples],
                        headers=[dict(r.headers) for r in samples],
                    )
                    logger.debug("[Benchmark] Consolidated status=%s, template tokens=%d for %s",
                                 base_benchmark.status_code, len(base_benchmark.base_benchmark), action)

                    # Discriminative-power guard via a forged-token rejection
                    # control: submit once with a corrupted token and see whether
                    # the server rejects it (response differs from the success
                    # baseline). If it does, the endpoint clearly distinguishes
                    # accepted vs rejected requests and body-diff tests are
                    # reliable. This is sturdier than a plain-GET comparison,
                    # which mislabels endpoints whose "success" baseline is itself
                    # a re-rendered form (e.g. a login that failed on empty creds).
                    token_validated = _probe_token_validated(
                        url, action, action_method, result, diff, base_benchmark
                    )
                    logger.debug("[Benchmark] Forged-token probe verdict for %s: token_validated=%s "
                                 "(True=rejected/validated, False=accepted, None=could-not-probe).",
                                 action, token_validated)
                    base_benchmark.discriminative = True
                    if token_validated is not True:
                        # Either no token to forge, or the forged token was
                        # accepted. Fall back to a plain GET to decide whether the
                        # endpoint is genuinely non-discriminative (a page load
                        # looks like success). Use a pristine session — requestMaker
                        # re-pins user-supplied cookies — so the same clean cookie
                        # context as the baseline submissions is used (no stale
                        # SESSION cookies that could desync the comparison).
                        neutral_session = requests.Session()
                        neutral = requestMaker(action, method="GET", session=neutral_session)
                        if neutral is not None:
                            get_matches = diff.benchmarkPassed(base_benchmark, neutral.text, neutral.status_code)
                            logger.debug("[Benchmark] GET-fallback for %s: GET status=%s len=%d | matches baseline=%s",
                                         action, neutral.status_code, len(neutral.text or ""), get_matches)
                            if get_matches:
                                logger.warning("[Benchmark] Non-discriminative response for %s: cannot distinguish a successful submission from a normal page load. Skipping body-diff-based bypass tests.", action)
                                base_benchmark.discriminative = False
                        else:
                            logger.debug("[Benchmark] GET-fallback request failed for %s; keeping discriminative=True.", action)

                    bypasses_found = set()
                    token_present = False
                    # Indices of the findings the generated PoCs actually
                    # demonstrate (token-tamper / D1 / D2 / M4). SameSite,
                    # Referer and Origin findings are deliberately NOT included:
                    # we don't generate dedicated PoCs for them, so stamping the
                    # token PoCs and bypass set onto them would be misleading.
                    csrf_finding_indices: list[int] = []

                    if TOKEN_CHECKS:
                        token_vuln_start = len(VULN_RECORDS)
                        # Detect tokens by inspecting the parameters WE submitted
                        # (authoritative, redirect-proof) plus the response side
                        # (cookies / headers) of each sample.
                        token_present = any(
                            token_analyzer.detectTokens(s, sent_params=result, sent_method=action_method)
                            for s in samples
                        )

                        if token_present:
                            logger.info("Anti-CSRF tokens detected in response.")

                            # Tamper tests rely on response diffing, so only run
                            # them when the benchmark can actually distinguish
                            # success from failure.
                            if base_benchmark.discriminative:
                                passed_tests = token_analyzer.performTokenTamperTests(
                                    url=action,
                                    method=action_method,
                                    params=result,
                                    base_benchmark=base_benchmark
                                )
                                bypasses_found.update(passed_tests)

                                # M4 (Content-Type) is also a token-bypass — it
                                # tests whether an alternate Content-Type makes
                                # the server skip token validation — so it runs
                                # here, dependent on a token being present.
                                if _bypass_content_type(action, base_benchmark, action_method, result):
                                    bypasses_found.add("M4")
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
                        cookie_analyzer = CookieAnalyzer()
                        is_vulnerable = cookie_analyzer.performSameSiteTests(url)

                        if is_vulnerable:
                            logger.warning("[C2] No cookies with SameSite attribute detected.")
                            VulnLogger(url, "No cookies with SameSite attribute detected.", test_id="C2")

                    # Referer/Origin tests validate a *different* protection and
                    # keep a valid token, so they are only meaningful when there
                    # is no EFFECTIVE token protection. When a valid token is
                    # required and not bypassable, an unvalidated Referer/Origin
                    # is moot and would only yield false positives.
                    _token_bypass_ids = {"T2", "T3", "T4", "T5", "T6", "T7", "T8", "M1", "M2", "M4"}
                    token_protection_effective = (
                        token_present
                        and token_validated is True
                        and not (bypasses_found & _token_bypass_ids)
                    )
                    run_header_tests = base_benchmark.discriminative and not token_protection_effective
                    if token_protection_effective:
                        logger.info("Skipping Referer/Origin tests: endpoint is protected by a validated token.")

                    if REFERER_ORIGIN_CHECKS and run_header_tests:
                        logger.info("Checking Referer header validation in form submissions...")
                        referer_not_validated = referee.checkRefererValidation(action, base_benchmark, action_method, result)
                        if not referer_not_validated:
                            referee.performRefererBypassChecks(action, base_benchmark, action_method, result)

                        origame.performOriginBypassChecks(action, base_benchmark, action_method, result)

                    encoding_detector = Encoding()
                    detected = encoding_detector.performTokenEncodingChecks()
                    if detected:
                        logger.warning("[E1] Token detected as string-encoded / weak hashes and potentially decryptable.")
                        VulnLogger(url, "Anti-CSRF token uses a weak/structured hash encoding and may be predictable or decryptable.", test_id="E1")
                    else:
                        logger.info("Token is not string-encoded.")
                        NovulLogger(url, "Anti-CSRF token is not string-encoded.", test_id="E1")

                    # Browser-dependent tests
                    if config.BROWSER_ENABLED:
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
                        poc_paths = poc_gen.generate_all_variants(action, action_method, result, bypasses_found, action_enctype)

                        # PoCs live in a single root-level report section, grouped
                        # per form/action rather than duplicated on every finding.
                        if poc_paths:
                            POC_RECORDS.append({
                                "action": action,
                                "method": action_method.upper(),
                                "bypasses": sorted(bypasses_found),
                                "paths": list(poc_paths),
                            })

                        # Tag the token/D1/D2/M4 findings with their action context.
                        # The form-level bypass set lives once in the root "pocs"
                        # section, so it isn't duplicated on every finding here.
                        for idx in csrf_finding_indices:
                            VULN_RECORDS[idx]["details"] = {
                                "action": action,
                                "method": action_method.upper(),
                            }

                        if config.AUTO_VALIDATE_POC and config.BROWSER_ENABLED:
                            from xsrfprobe.core.main import get_browser_session
                            from xsrfprobe.modules.Browser import BrowserCSRFTests

                            browser = get_browser_session()
                            if browser:
                                bt = BrowserCSRFTests(browser)
                                for poc_path in poc_paths:
                                    bt.autoValidatePoC(poc_path, action, base_benchmark)

        except Exception as e:
            logger.error("Error while processing form: %s", e)
