import os
import sys
import logging
import time
import warnings

from xsrfprobe.core.options import options
from xsrfprobe.core.inputin import inputProcessor
from xsrfprobe.core.utils import calcLogLevel
from xsrfprobe.core.handler import noCrawlProcessor
from xsrfprobe.core.logger import CustomFormatter, CustomLogger, ProgressAwareHandler, PROGRESS, phaseHeader
from xsrfprobe.core.schema import ScanReport, Finding, UrlFindings, Strength, UrlStrengths
from xsrfprobe.files.severity import get_severity, get_severity_enum, get_exploitability
from xsrfprobe.files import config
from xsrfprobe.files import discovered

from xsrfprobe.modules.Crawler import Crawler
from xsrfprobe.modules.Analysis import Analysis

warnings.filterwarnings("ignore")

_browser_session = None


def _init_browser(target_url: str = ""):
    """Initialize headless Firefox if --browser is enabled, then seed cookies."""
    global _browser_session
    if not config.BROWSER_ENABLED:
        return None

    from xsrfprobe.core.browser import BrowserSession
    from xsrfprobe.core.request import SESSION

    bs = BrowserSession(
        headless=True,
        geckodriver_path=config.GECKODRIVER_PATH,
        timeout=config.BROWSER_TIMEOUT,
    )
    if bs.start():
        _browser_session = bs
        if target_url:
            bs.sync_all_cookies(SESSION, target_url)
        return bs
    else:
        logging.getLogger("Engine").error("Failed to start browser. Browser tests disabled.")
        config.BROWSER_ENABLED = False
        return None


def _shutdown_browser():
    global _browser_session
    if _browser_session:
        _browser_session.quit()
        _browser_session = None


def get_browser_session():
    return _browser_session


def _generate_json_report(target_url: str, duration: float):
    """Generate a JSON report from discovered data."""
    logger = logging.getLogger("Engine")

    # Group findings under their URL: [{url, findings: [{test_id, description,
    # severity, details, poc_paths}, ...]}], deduped by (url, description).
    vuln_groups: "dict[str, list[Finding]]" = {}
    _seen_vulns = set()
    for rec in discovered.VULN_RECORDS:
        rec_url = rec.get("url") or target_url
        description = rec.get("vuln", "")
        key = (rec_url, description)
        if key in _seen_vulns:
            continue
        _seen_vulns.add(key)

        test_id = rec.get("test_id", "")
        details = dict(rec.get("details") or {})
        details.pop("test_id", None)
        content = (rec.get("content") or "").strip()
        if content:
            details.setdefault("evidence", content)
        exploitability = get_exploitability(test_id)
        if exploitability:
            details.setdefault("exploitability", exploitability)

        vuln_groups.setdefault(rec_url, []).append(Finding(
            test_id=test_id,
            description=description,
            severity=get_severity_enum(test_id),
            details=details,
            poc_paths=list(rec.get("poc_paths") or []),
        ))

    vulns = [UrlFindings(url=u, findings=f) for u, f in vuln_groups.items()]

    # Group strengths under their URL, deduped by (url, description).
    strength_groups: "dict[str, list[Strength]]" = {}
    _seen_strengths = set()
    for rec in discovered.STRENGTH_RECORDS:
        rec_url = rec.get("url") or target_url
        description = rec.get("strength", "")
        key = (rec_url, description)
        if key in _seen_strengths:
            continue
        _seen_strengths.add(key)
        strength_groups.setdefault(rec_url, []).append(Strength(
            test_id=rec.get("test_id", ""),
            description=description,
        ))
    strengths = [UrlStrengths(url=u, strengths=s) for u, s in strength_groups.items()]

    # Surface every token observed during the run: the active findings plus the
    # passively harvested samples, deduped by (name, value, discovery_part).
    tokens_discovered = []
    _seen_tokens = set()
    for tok in list(discovered.ANTI_CSRF_TOKENS) + list(discovered.TOKEN_SAMPLES):
        key = (tok.name, tok.token, tok.discovery_part)
        if key in _seen_tokens:
            continue
        _seen_tokens.add(key)
        tokens_discovered.append(tok)

    report = ScanReport(
        target_url=target_url,
        scan_duration_seconds=round(duration, 2),
        urls_scanned=len(discovered.INTERNAL_URLS),
        forms_tested=sum(len(v) for v in discovered.FORMS_TESTED.values()),
        vulnerabilities=vulns,
        tokens_discovered=tokens_discovered,
        strengths=strengths,
        scan_errors=list(dict.fromkeys(discovered.SCAN_ERRORS)),
    )

    report_path = os.path.join(config.OUTPUT_DIR, "report.json")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        logger.log(PROGRESS, "JSON report saved: %s", report_path)
    except Exception as e:
        logger.error("Failed to save JSON report: %s", e)


def _wrap(text: str, width: int) -> list[str]:
    """Word-wrap *text* to *width* columns, preserving existing line breaks."""
    if width <= 0:
        return [text]
    lines: list[str] = []
    for paragraph in text.split("\n"):
        while len(paragraph) > width:
            brk = paragraph.rfind(" ", 0, width)
            if brk <= 0:
                brk = width
            lines.append(paragraph[:brk])
            paragraph = paragraph[brk:].lstrip()
        lines.append(paragraph)
    return lines


def _print_strength_tables(logger, s_rows: list[dict], budget: int):
    """Render strengths as per-endpoint ASCII tables."""
    s_by_url: dict[str, list[dict]] = {}
    for rec in s_rows:
        s_by_url.setdefault(rec.get("url", "?"), []).append(rec)

    s_headers = ("ID", "Strength")
    s_id_w = max(len(s_headers[0]), max(
        (len(r.get("test_id", "")) for r in s_rows), default=2))
    s_str_w = budget - s_id_w
    s_col_w = [s_id_w, s_str_w]

    def _s_sep(left, mid, right, fill="─"):
        return left + mid.join(fill * (cw + 2) for cw in s_col_w) + right

    def _s_row(cells):
        wrapped = [_wrap(c, s_col_w[i]) for i, c in enumerate(cells)]
        height = max(len(wl) for wl in wrapped)
        out = []
        for li in range(height):
            parts = []
            for i, wl in enumerate(wrapped):
                text = wl[li] if li < len(wl) else ""
                parts.append(f" {text:<{s_col_w[i]}} ")
            out.append("│" + "│".join(parts) + "│")
        return "\n".join(out)

    w = sys.stdout.write
    w("\n")
    w(f"  Strengths ({len(s_rows)}):\n")
    for s_url, s_findings in s_by_url.items():
        w("\n")
        w(f"  {s_url}\n")
        w(f"  {_s_sep('┌', '┬', '┐')}\n")
        w(f"  {_s_row(s_headers)}\n")
        w(f"  {_s_sep('├', '┼', '┤', '═')}\n")
        for idx, sr in enumerate(s_findings):
            tid = sr.get("test_id", "")
            desc = sr.get("strength", "")
            for line in _s_row((tid, desc)).split("\n"):
                w(f"  {line}\n")
            if idx < len(s_findings) - 1:
                w(f"  {_s_sep('├', '┼', '┤')}\n")
        w(f"  {_s_sep('└', '┴', '┘')}\n")
        sys.stdout.flush()
    sys.stdout.write("\n")


def _print_scan_errors():
    """Print any errors collected during the scan (request failures, etc.),
    deduped and order-preserving. No-op when there were none."""
    seen = set()
    unique = []
    for e in discovered.SCAN_ERRORS:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    if not unique:
        return
    w = sys.stdout.write
    w("\n")
    w(f"  Scan errors ({len(unique)}):\n")
    for e in unique:
        w(f"    - {e}\n")
    w("\n")


def _print_summary(logger, duration: float):
    """Print a final summary table of findings and PoCs."""
    phaseHeader(logger, "Summary")

    forms_tested = sum(len(v) for v in discovered.FORMS_TESTED.values())
    urls_scanned = len(discovered.INTERNAL_URLS) or 1
    w = sys.stdout.write
    w(f"  Target: {config.SITE_URL}\n")
    w(f"  URLs scanned: {urls_scanned} | Forms tested: {forms_tested} | Duration: {duration:.2f}s\n")

    # Table budget: fixed 120-char max, minus 2-char indent and column chrome
    table_max = 120
    budget = table_max - 2 - 10  # 10 = 4 pipes + 3*2 padding for 3-col table

    # Dedupe vulns by (url, description)
    seen = set()
    vulns: list[dict] = []
    for rec in discovered.VULN_RECORDS:
        key = (rec.get("url", ""), rec.get("vuln", ""))
        if key in seen:
            continue
        seen.add(key)
        vulns.append(rec)

    # Dedupe strengths by (url, description)
    seen_s = set()
    s_rows: list[dict] = []
    for rec in discovered.STRENGTH_RECORDS:
        key = (rec.get("url", ""), rec.get("strength", ""))
        if key in seen_s:
            continue
        seen_s.add(key)
        s_rows.append(rec)

    if not vulns:
        w("\n")
        w("  No vulnerabilities discovered.\n")
        if s_rows:
            _print_strength_tables(logger, s_rows, budget)
        _print_scan_errors()
        return

    # Group findings by endpoint URL
    by_url: dict[str, list[dict]] = {}
    for rec in vulns:
        by_url.setdefault(rec.get("url", "?"), []).append(rec)

    w("\n")
    w(f"  Vulnerabilities ({len(vulns)}):\n")

    headers = ("Sev", "ID", "Vulnerability", "PoC")
    # 4-col table chrome = 5 pipes + 4*2 padding = 13
    vuln_budget = table_max - 2 - 13
    sev_w = max(len(headers[0]), max(
        (len(get_severity(r.get("test_id", ""))) for r in vulns), default=3))
    id_w = max(len(headers[1]), max(
        (len(r.get("test_id", "")) for r in vulns), default=2))
    remaining = vuln_budget - sev_w - id_w
    poc_w = max(len(headers[3]), len("Generated"))
    vuln_w = max(len(headers[2]), remaining - poc_w)
    col_w = [sev_w, id_w, vuln_w, poc_w]

    def _sep(left, mid, right, fill="─"):
        return left + mid.join(fill * (w + 2) for w in col_w) + right

    def _row(cells):
        wrapped = [_wrap(c, col_w[i]) for i, c in enumerate(cells)]
        height = max(len(w) for w in wrapped)
        out = []
        for line_idx in range(height):
            parts = []
            for i, w in enumerate(wrapped):
                text = w[line_idx] if line_idx < len(w) else ""
                parts.append(f" {text:<{col_w[i]}} ")
            out.append("│" + "│".join(parts) + "│")
        return "\n".join(out)

    for url, findings in by_url.items():
        w("\n")
        w(f"  {url}\n")
        w(f"  {_sep('┌', '┬', '┐')}\n")
        w(f"  {_row(headers)}\n")
        w(f"  {_sep('├', '┼', '┤', '═')}\n")
        for idx, f in enumerate(findings):
            tid = f.get("test_id", "")
            sev = get_severity(tid)
            desc = f.get("vuln", "")
            pocs = f.get("poc_paths") or []
            poc_str = "Generated" if pocs else "-"
            for line in _row((sev, tid, desc, poc_str)).split("\n"):
                w(f"  {line}\n")
            if idx < len(findings) - 1:
                w(f"  {_sep('├', '┼', '┤')}\n")
        w(f"  {_sep('└', '┴', '┘')}\n")
        sys.stdout.flush()

    if s_rows:
        _print_strength_tables(logger, s_rows, budget)

    # Proof of Concepts section
    all_pocs: list[str] = []
    for rec in vulns:
        for p in (rec.get("poc_paths") or []):
            if p not in all_pocs:
                all_pocs.append(p)
    if all_pocs:
        w("\n")
        w(f"  Proof of Concepts ({len(all_pocs)}):\n")
        for poc in all_pocs:
            w(f"    - {poc}\n")
        w("\n")

    _print_scan_errors()


def Engine():
    args = options()

    formatter = CustomFormatter()
    logging.root.setLevel(calcLogLevel(args))
    logging.setLoggerClass(CustomLogger)

    console_handler = ProgressAwareHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logging.root.addHandler(console_handler)

    error_handler = logging.FileHandler("errors.log", mode="a")
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(formatter)
    logging.root.addHandler(error_handler)

    logger = logging.getLogger("Engine")

    logger.log(PROGRESS, "Booting up XSRFProbe engine...")

    timestart = time.time()
    web, endpoint = inputProcessor()
    logger.debug(f"Successfully processed the input: {web} and {endpoint}")

    _init_browser(web)

    try:
        if config.CRAWL_SITE:
            logging.log(PROGRESS, "Initializing crawling and scanning...")
            crawler = Crawler(web)

            while crawler.has_urls_to_visit():
                url = crawler.__next__()
                logging.log(PROGRESS, "Testing: %s", url)

                soup = crawler.process()
                if not soup:
                    continue

                noCrawlProcessor(url, soup)

        else:
            logging.log(PROGRESS, "Initializing endpoint testing...")
            noCrawlProcessor(web)

        logging.log(PROGRESS, "Scan completed.")

        if config.SCAN_ANALYSIS:
            Analysis()

    except KeyboardInterrupt:
        logging.warning("User interrupted the process.")
        if config.SCAN_ANALYSIS:
            Analysis()

    finally:
        _shutdown_browser()
        timend = time.time()
        duration = timend - timestart

        _print_summary(logger, duration)

        if config.JSON_OUTPUT and config.OUTPUT_DIR:
            _generate_json_report(config.SITE_URL, duration)

        logging.log(PROGRESS, "Shutting down XSRFProbe.")
