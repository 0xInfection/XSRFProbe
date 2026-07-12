import logging
from http.cookies import SimpleCookie

from xsrfprobe.core.request import requestMaker
from xsrfprobe.core.logger import VulnLogger, NovulLogger, testProgress


class CookieAnalyzer:
    def __init__(self) -> None:
        pass

    def setCookieHeaders(self, resp) -> list[str]:
        """Return the individual ``Set-Cookie`` header lines from *resp*.

        ``requests`` folds duplicate response headers into a single
        comma-joined string in ``resp.headers``, which corrupts cookie parsing
        because both Expires dates and separate cookies contain commas. urllib3
        keeps every header line intact in the raw header store, so read from
        there (``getlist``/``get_all``) when available and only fall back to the
        folded value as a last resort.
        """
        raw = getattr(resp, "raw", None)
        raw_headers = getattr(raw, "headers", None)
        if raw_headers is not None:
            for accessor in ("getlist", "get_all"):
                fn = getattr(raw_headers, accessor, None)
                if fn is None:
                    continue
                try:
                    items = fn("Set-Cookie")
                except Exception:
                    items = None
                if items:
                    return list(items)

        single = resp.headers.get("Set-Cookie", "")
        return [single] if single else []

    def parseCookie(self, header_line: str) -> list[dict]:
        """
        Parse a single Set-Cookie header line into per-cookie attribute dicts using the stdlib cookie parser (robust to attribute ordering and quoting) rather than a hand-rolled split.
        """
        logger = logging.getLogger("CookieParser")
        jar = SimpleCookie()
        try:
            jar.load(header_line)
        except Exception:
            logger.info("Could not parse Set-Cookie line: %s", header_line)
            return []

        cookies = []
        for name, morsel in jar.items():
            cookies.append({
                "name": name,
                # SameSite (added to http.cookies in 3.8) is "" when absent.
                "samesite": (morsel["samesite"] or "").strip().lower(),
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
            })
        return cookies

    def analyseCookies(self, url) -> bool:
        """
        Fetch url and analyse the SameSite posture of the cookies it sets.
        """
        logger = logging.getLogger("CookieAnalyser")
        logger.info("Analysing cross-origin cookie validation for %s", url)

        resp = requestMaker(url, method="GET")
        if resp is None:
            logger.error("No response received; the site is likely down: %s", url)
            return False

        cookies = []
        for line in self.setCookieHeaders(resp):
            cookies.extend(self.parseCookie(line))

        if not cookies:
            logger.info("No cookies set on the response.")
            return False

        has_protection = False
        for c in cookies:
            name = c["name"]
            samesite = c["samesite"]

            if samesite == "none":
                logger.warning("[C1] Cookie '%s' set with SameSite=None (offers no CSRF protection).", name)
                VulnLogger(url, f"Cookie '{name}' set with SameSite=None (offers no CSRF protection).", test_id="C1")
                if not c["secure"]:
                    # SameSite=None without Secure is rejected outright by modern
                    # browsers, so the cookie is effectively unsent cross-site.
                    logger.warning("[C1] Cookie '%s' uses SameSite=None without the Secure attribute; modern browsers reject it.", name)
                    VulnLogger(url, f"Cookie '{name}' uses SameSite=None without the Secure attribute (rejected by modern browsers).", test_id="C1")
            elif samesite == "lax":
                logger.info("[C1] Cookie '%s' set with SameSite=Lax (blocks cross-site POST).", name)
                NovulLogger(url, f"Cookie '{name}' set with SameSite=Lax (blocks cross-site POST).", test_id="C1")
                has_protection = True
            elif samesite == "strict":
                logger.info("[C1] Cookie '%s' set with SameSite=Strict (blocks all cross-site requests).", name)
                NovulLogger(url, f"Cookie '{name}' set with SameSite=Strict.", test_id="C1")
                has_protection = True
            else:
                # No explicit SameSite. Modern browsers default to Lax, which
                # already blocks cross-site POST CSRF (except top-level GET and a
                # short post-set window). Legacy clients still send it cross-site,
                # so this is weaker than an explicit attribute but not fully open.
                logger.warning("[C1] Cookie '%s' has no explicit SameSite attribute (relies on the browser's Lax-by-default; not enforced on legacy clients).", name)
                NovulLogger(url, f"Cookie '{name}' has no explicit SameSite attribute (relies on the browser's Lax-by-default; not enforced on legacy clients).", test_id="C1")

        return has_protection

    def performSameSiteTests(self, url) -> bool:
        """
        Run the SameSite cookie tests.
        """
        logger = logging.getLogger("CookieAnalyser")
        with testProgress(logger, "C1", "SameSite cookie analysis") as tp_result:
            has_protection = self.analyseCookies(url)
            tp_result["status"] = "protected" if has_protection else "no SameSite"
        return not has_protection
