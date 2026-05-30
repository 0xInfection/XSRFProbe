import logging
from re import search, I
from http.cookies import SimpleCookie

from xsrfprobe.core.request import requestMaker
from xsrfprobe.core.logger import VulnLogger, NovulLogger


class CookieAnalyzer:
    def __init__(self) -> None:
        pass

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

        has_protection = False
        for cookie in samesite_cookies:
            if search(r"SameSite=None", cookie, I):
                logger.warning("Cookie with SameSite=None detected (offers no CSRF protection)")
                VulnLogger(url, "Cookie with SameSite=None detected (offers no CSRF protection)")
            elif search(r"SameSite=Lax", cookie, I):
                logger.info("Cookie with SameSite=Lax detected (blocks cross-site POST)")
                NovulLogger(url, "Cookie with SameSite=Lax detected (blocks cross-site POST)")
                has_protection = True
            elif search(r"SameSite=Strict", cookie, I):
                logger.info("Cookie with SameSite=Strict detected (blocks all cross-site requests)")
                NovulLogger(url, "Cookie with SameSite=Strict detected")
                has_protection = True

        return has_protection

    def performSameSiteTests(self, url) -> bool:
        """
        This function performs SameSite cookie tests.
        Returns True if cookies lack SameSite protections (vulnerable).
        """
        logger = logging.getLogger("CookieAnalyser")
        logger.info("Starting SameSite cookie tests...")
        return not self.SameSite(url)