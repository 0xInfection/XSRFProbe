import sys
import logging
import requests
from re import search, I
from urllib.parse import urlsplit

from files.config import HEADER_VALUES, USER_AGENT, COOKIE_VALUE, REFERER_URL
from files import discovered
from core.randua import RandomAgent
from core.request import requestMaker
from modules.Persistence import Persistence
from core.logger import VulnLogger, NovulLogger
from core.schema import SameSiteCookie

resps = []

class CookieAnalyzer:
    def __init__(self) -> None:
        self.user_cookie = COOKIE_VALUE

    def parseCookies(self, response: requests.Response) -> bool:
        """Parses cookies from a requests.Response object and checks for the SameSite attribute."""
        logger = logging.getLogger("CookieParser")
        found = False
        logger.debug("Parsing cookies from the response...")
        cookies = response.cookies

        for cookie in cookies:
            samesite_value = cookie._rest.get("SameSite", None)  # type: ignore
            if samesite_value:
                samesite_value = samesite_value.lower()
                if samesite_value in ["lax", "strict", "none"]:
                    logger.info(f"Found SameSite Cookie: {samesite_value.capitalize()}")
                    found = True
                else:
                    logger.warning(f"SameSite attribute has an invalid value: {samesite_value}")
            else:
                logger.debug(f"Cookie: {cookie.name}, Value: {cookie.value}, SameSite attribute not present")

        return found

    def SameSite(self, url):
        """
        This function parses and verifies the cookies with
        SameSite Flags.
        """
        logger = logging.getLogger("CookieAnalyser")
        logger.info("Analysing Cross-Origin Cookie Validation")

        foundx1, foundx2, foundx3 = False, False, False
        # Test presence of SameSite flag on cookies
        for cook in COOKIE_VALUE:
            if search("SameSite", cook, I):
                logger.info(f"SameSite Flag detected on cookie: {cook}")
                foundx1 = True

        # Step 1: Check server response with same Referer as the netloc
        logger.info("Examining server reaction to same Referer...")
        gen_headers = HEADER_VALUES.copy()
        gen_headers["User-Agent"] = USER_AGENT if USER_AGENT else RandomAgent()
        gen_headers["Referer"] = urlsplit(url).netloc

        if COOKIE_VALUE:
            gen_headers["Cookie"] = ",".join(COOKIE_VALUE)

        getreq = requestMaker(url, headers=gen_headers)  # Make the request
        HEADER_VALUES.pop("Referer", None)
        HEADER_VALUES.pop("Cookie", None)

        for h, value in getreq.headers.items():
            if "cookie" in h.lower():
                logger.info(f"Cookie Header Found: {value}")
                cookies = value.split(";")
                for cookie in cookies:
                    if search("SameSite", cookie, I):
                        logger.info("SameSite Flag detected on cookie")
                        foundx1 = 0x01
                        break

        if foundx1 == 0x01:
            logger.info("SameSite Flag Cookie Validation Present")

        # Step 2: Check response when Referer is different, without cookies
        logger.info("Examining server reaction to external Referer without cookies...")
        gen_headers = HEADER_VALUES.copy()
        gen_headers["User-Agent"] = USER_AGENT if USER_AGENT else RandomAgent()
        gen_headers["Referer"] = REFERER_URL
        getreq = Get(url, headers=gen_headers)
        HEADER_VALUES.pop("Referer", None)

        for h, value in getreq.headers.items():
            if "cookie" in h.lower():
                logger.info(f"Cookie Header Found: {value}")
                cookies = value.split(";")
                for cookie in cookies:
                    if search("SameSite", cookie, I):
                        logger.info("SameSite Flag detected on cookie")
                        foundx2 = 0x01
                        break

        # Step 3: Check response to a valid cookie from a different Referer
        logger.info("Examining server reaction to valid cookie from external Referer...")
        gen_headers = HEADER_VALUES.copy()
        gen_headers["User-Agent"] = USER_AGENT if USER_AGENT else RandomAgent()
        gen_headers["Referer"] = REFERER_URL
        if COOKIE_VALUE:
            gen_headers["Cookie"] = ",".join(COOKIE_VALUE)

        getreq = Get(url, headers=gen_headers)
        HEADER_VALUES.pop("Referer", None)

        for h, value in getreq.headers.items():
            if "cookie" in h.lower():
                logger.info(f"Cookie Header Found: {value}")
                cookies = value.split(";")
                for cookie in cookies:
                    if search("SameSite", cookie.lower(), I):
                        logger.info("SameSite Flag detected on cross-origin request")
                        foundx3 = 0x01
                        break

        if foundx1 == 0x01 and foundx3 == 0x00:
            logger.info("Endpoint NOT VULNERABLE to CSRF attacks: SameSite Flag on Cookies")
            NovulLogger(url, "SameSite Flag set on Cookies on Cross-Origin Requests.")
            if input("Continue scanning? (y/N): ").lower().startswith("n"):
                sys.exit("Shutting down...")
        elif foundx1 == 0x02 and foundx2 == 0x02 and foundx3 == 0x02:
            logger.info("Endpoint NOT VULNERABLE: No cookies set on cross-origin requests")
            NovulLogger(url, "No cookie set on Cross-Origin Requests.")
        else:
            logger.warning("Endpoint might be VULNERABLE to CSRF attacks")
            VulnLogger(url, "No Cookie Validation on Cross-Origin Requests.", str(getreq.headers))

    def Cookie(request: requests.Response):
        """
        This module checks HTTP Cookies and related security to prevent CSRF attacks.
        """
        logger = logging.getLogger("CookieChecks")
        logger.info("Starting cookie-based checks...")
        SameSite(request.url)
        Persistence(request.url, request)

    def performSameSiteTests(self, url):
        """
        This function performs SameSite cookie tests.
        """
        logger = logging.getLogger("CookieAnalyser")
        logger.info("Starting SameSite cookie tests...")
        self.SameSite(url)