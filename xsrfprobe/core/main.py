import os
import sys
import logging
import time
import warnings

from xsrfprobe.core.options import options
from xsrfprobe.core.inputin import inputProcessor
from xsrfprobe.core.utils import calcLogLevel
from xsrfprobe.core.handler import noCrawlProcessor
from xsrfprobe.core.logger import CustomFormatter, CustomLogger
from xsrfprobe.core.schema import ScanReport, VulnerabilityResult
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


def _handle_update():
    """Pull the latest version from git."""
    logger = logging.getLogger("Engine")
    logger.info("Checking for updates...")
    try:
        import subprocess
        result = subprocess.run(
            ["git", "pull", "origin", "master"],
            capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__))
        )
        logger.info(result.stdout.strip())
        if result.returncode != 0:
            logger.error("Update failed: %s", result.stderr.strip())
    except Exception as e:
        logger.error("Update error: %s", e)


def _generate_json_report(target_url: str, duration: float):
    """Generate a JSON report from discovered data."""
    logger = logging.getLogger("Engine")

    vulns = []
    for vuln_msg in discovered.VULN_LIST:
        vulns.append(VulnerabilityResult(
            url=target_url,
            vuln_type="csrf",
            description=str(vuln_msg),
        ))

    report = ScanReport(
        target_url=target_url,
        scan_duration_seconds=round(duration, 2),
        urls_scanned=len(discovered.INTERNAL_URLS),
        forms_tested=sum(len(v) for v in discovered.FORMS_TESTED.values()),
        vulnerabilities=vulns,
        tokens_discovered=discovered.ANTI_CSRF_TOKENS,
        strengths=discovered.STRENGTH_LIST,
    )

    report_path = os.path.join(config.OUTPUT_DIR, "report.json")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        logger.info("JSON report saved: %s", report_path)
    except Exception as e:
        logger.error("Failed to save JSON report: %s", e)


def Engine():
    args = options()

    formatter = CustomFormatter()
    logging.root.setLevel(calcLogLevel(args))
    logging.setLoggerClass(CustomLogger)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logging.root.addHandler(console_handler)

    error_handler = logging.FileHandler("errors.log", mode="a")
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(formatter)
    logging.root.addHandler(error_handler)

    logger = logging.getLogger("Engine")

    if args.update:
        _handle_update()
        return

    logger.info("Booting up XSRFProbe engine...")

    timestart = time.time()
    web, endpoint = inputProcessor()
    logger.debug(f"Successfully processed the input: {web} and {endpoint}")

    _init_browser(web)

    try:
        if config.CRAWL_SITE:
            logging.info("Initializing crawling and scanning...")
            crawler = Crawler(web)

            while crawler.has_urls_to_visit():
                url = crawler.__next__()
                logging.info(f"Testing: {url}")

                soup = crawler.process(url)
                if not soup:
                    continue

                noCrawlProcessor(url, soup)

        else:
            logging.info("Initializing endpoint testing...")
            noCrawlProcessor(web)

        logging.info("Scan completed.")

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

        if config.JSON_OUTPUT and config.OUTPUT_DIR:
            _generate_json_report(config.SITE_URL, duration)

        logging.info(f"Time taken: {duration:.2f} seconds.")
        logging.info("Shutting down XSRFProbe.")
