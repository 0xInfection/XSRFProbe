import logging
from re import search, I
from http.cookies import SimpleCookie

from files.config import COOKIE_VALUE
from core.request import requestMaker
from core.logger import VulnLogger, NovulLogger

resps = []

class CookieAnalyzer:
    def __init__(self) -> None:
        self.user_cookie = COOKIE_VALUE

    def parseCookies(self, cookie_header: str) -> list[str]:
        """Parses cookies from a requests.Response object and checks for the SameSite attribute."""
        logger = logging.getLogger("CookieParser")
        logger.debug("Parsing cookies from the response...")
        cookiess = SimpleCookie(cookie_header)
        samesite_cookies = []
        for cookie in cookiess:
            str_cookie = cookiess[cookie].__str__().split(':', 1)[1]
            attrs = str_cookie.split(";")
            for attr in attrs:
                m_attr = attr.strip().lower()
                if m_attr.startswith("samesite"):
                    logger.info("Found SameSite attribute in cookie: %s", m_attr)
                    _, attr_value = m_attr.split("=")
                    if attr_value == "none":
                        logger.warning("Cookie %s with SameSite=None detected")
                    elif attr_value == "lax":
                        logger.warning("Cookie %s with SameSite=Lax detected")
                    elif attr_value == "strict":
                        logger.info("Cookie %s with SameSite=Strict detected")
                    samesite_cookies.append(str_cookie)

        if not samesite_cookies:
            logger.info("No SameSite cookies found in the response.")

        return samesite_cookies

    def SameSite(self, url) -> bool:
        """
        This function parses and verifies the cookies with
        SameSite Flags.
        """
        logger = logging.getLogger("CookieAnalyser")
        logger.info("Analysing Cross-Origin Cookie Validation")

        resp = requestMaker(url, method="GET")
        if resp is None:
            logger.error("No response received; the site is likely down: %s" % url)
            return False

        samesite_cookies = self.parseCookies(resp.headers.get("Set-Cookie", ""))
        if not samesite_cookies:
            return False

        for cookie in samesite_cookies:
            if search(r"SameSite=None", cookie, I):
                logger.warning("Cookie with SameSite=None detected")
                VulnLogger(url, "Cookie with SameSite=None detected")
            elif search(r"SameSite=Lax", cookie, I):
                logger.warning("Cookie with SameSite=Lax detected")
                VulnLogger(url, "Cookie with SameSite=Lax detected")
            elif search(r"SameSite=Strict", cookie, I):
                logger.info("Cookie with SameSite=Strict detected")
                NovulLogger(url, "Cookie with SameSite=Strict detected")

        return True

    def performSameSiteTests(self, url):
        """
        This function performs SameSite cookie tests.
        """
        logger = logging.getLogger("CookieAnalyser")
        logger.info("Starting SameSite cookie tests...")
        self.SameSite(url)