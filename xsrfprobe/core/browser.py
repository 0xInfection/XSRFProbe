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

logger = logging.getLogger("BrowserSession")


class BrowserSession:
    """Wraps a headless Firefox instance via Selenium for browser-dependent CSRF tests."""

    def __init__(self, headless: bool = True, geckodriver_path: str = "", timeout: int = 30):
        self.headless = headless
        self.geckodriver_path = geckodriver_path
        self.timeout = timeout
        self.driver = None

    def start(self) -> bool:
        """Launch headless Firefox. Returns True on success."""
        try:
            from selenium import webdriver
            from selenium.webdriver.firefox.options import Options
            from selenium.webdriver.firefox.service import Service
        except ImportError:
            logger.error("Selenium is not installed. Run: pip install selenium")
            return False

        options = Options()
        if self.headless:
            options.add_argument("--headless")

        options.set_preference("network.cookie.sameSite.laxByDefault", True)
        options.set_preference("network.cookie.sameSite.noneRequiresSecure", True)
        options.set_preference("dom.disable_open_during_load", False)
        options.set_preference("security.mixed_content.block_active_content", False)
        options.set_preference("privacy.trackingprotection.enabled", False)

        try:
            service_kwargs = {}
            if self.geckodriver_path:
                service_kwargs["executable_path"] = self.geckodriver_path

            service = Service(**service_kwargs)
            self.driver = webdriver.Firefox(service=service, options=options)
            self.driver.set_page_load_timeout(self.timeout)
            logger.info("Headless Firefox browser started successfully.")
            return True

        except Exception as e:
            logger.error("Failed to start Firefox: %s", e)
            logger.error("Make sure geckodriver is installed and in PATH.")
            return False

    def set_cookies(self, url: str, cookies: list[dict]) -> None:
        """Inject cookies into the browser. Must navigate to the domain first."""
        if not self.driver:
            return

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        try:
            self.driver.get(base_url)
        except Exception as e:
            logger.warning("Could not navigate to %s for cookie injection: %s", base_url, e)
            return

        for cookie in cookies:
            try:
                self.driver.add_cookie(cookie)
            except Exception as e:
                logger.debug("Failed to set cookie %s: %s", cookie.get("name"), e)

    def sync_cookies_from_config(self, url: str) -> None:
        """
        Parse user-supplied cookie strings from config.COOKIE_VALUE
        (e.g. ["PHPSESSID=abc", "_gid=xyz"]) and inject them into the browser.
        """
        from xsrfprobe.files.config import COOKIE_VALUE
        if not COOKIE_VALUE:
            return

        parsed = urlparse(url)
        cookies = []
        for raw in COOKIE_VALUE:
            raw = raw.strip()
            if "=" not in raw:
                continue
            name, value = raw.split("=", 1)
            cookies.append({
                "name": name.strip(),
                "value": value.strip(),
                "domain": parsed.hostname,
                "path": "/",
                "secure": parsed.scheme == "https",
            })

        if cookies:
            logger.info("Injecting %d user-supplied cookie(s) into browser.", len(cookies))
            self.set_cookies(url, cookies)

    def sync_cookies_from_requests(self, session: requests.Session, url: str) -> None:
        """Copy cookies from a requests.Session cookie jar into the browser."""
        cookies = []
        for cookie in session.cookies:
            cookies.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or urlparse(url).hostname,
                "path": cookie.path or "/",
                "secure": cookie.secure,
            })
        if cookies:
            logger.info("Syncing %d session cookie(s) into browser.", len(cookies))
            self.set_cookies(url, cookies)

    def sync_all_cookies(self, session: requests.Session, url: str) -> None:
        """Sync both user-supplied and session-accumulated cookies into the browser."""
        self.sync_cookies_from_config(url)
        self.sync_cookies_from_requests(session, url)

    def open_poc_file(self, poc_path: str) -> dict:
        """
        Open a local HTML PoC file in the browser.
        Returns dict with resulting state after auto-submit.
        """
        if not self.driver:
            return {"error": "Browser not started"}

        file_url = f"file://{poc_path}"
        try:
            self.driver.get(file_url)

            from selenium.webdriver.support.ui import WebDriverWait
            WebDriverWait(self.driver, self.timeout).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )

            import time
            time.sleep(2)

            return {
                "final_url": self.driver.current_url,
                "page_source": self.driver.page_source,
                "cookies": self.driver.get_cookies(),
            }

        except Exception as e:
            logger.error("Failed to open PoC file %s: %s", poc_path, e)
            return {"error": str(e)}

    def get_iframe_source(self) -> str | None:
        """Switch to the first iframe and return its page source, then switch back."""
        if not self.driver:
            return None
        try:
            iframes = self.driver.find_elements("tag name", "iframe")
            if not iframes:
                return None
            self.driver.switch_to.frame(iframes[0])
            source = self.driver.page_source
            self.driver.switch_to.default_content()
            return source
        except Exception:
            try:
                self.driver.switch_to.default_content()
            except Exception:
                pass
            return None

    def quit(self) -> None:
        """Close the browser and clean up."""
        if self.driver:
            try:
                self.driver.quit()
                logger.info("Browser session closed.")
            except Exception:
                pass
            self.driver = None
