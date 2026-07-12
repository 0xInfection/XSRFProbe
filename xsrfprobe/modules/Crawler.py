import logging
import re
import time
import urllib.parse
from collections import deque
from bs4 import BeautifulSoup
from xsrfprobe.files import config
from xsrfprobe.files.config import EXCLUDE_DIRS
from xsrfprobe.core.request import requestMaker
from xsrfprobe.files.discovered import INTERNAL_URLS

class Crawler():
    def __init__(self, start):
        self.logger = logging.getLogger('CrawlEngine')
        self.visited: set[str] = set()
        # Deterministic FIFO BFS queue of (url, depth). A set (`queued`) tracks
        # membership so we never enqueue the same URL twice without paying the
        # O(n) scan a plain list would need.
        self.queue: "deque[tuple[str, int]]" = deque([(start, 0)])
        self.queued: set[str] = {start}
        self.uri_patterns = []
        self.current_uri = ""
        self.current_depth = 0
        # Bounds (read once at construction). 0 means "unlimited".
        self.max_urls = max(0, int(getattr(config, "CRAWL_MAX_URLS", 0) or 0))
        self.max_depth = max(0, int(getattr(config, "CRAWL_MAX_DEPTH", 0) or 0))
        self.crawl_timeout = max(0, int(getattr(config, "CRAWL_TIMEOUT", 0) or 0))
        self.start_time = time.monotonic()
        self._limit_logged = False
        parsed_start = urllib.parse.urlparse(start)
        self.target_netloc = parsed_start.netloc
        self.block_patterns = [
            r"\?date=\d{4}-\d{2}-\d{2}",
            r"javascript:void\(0\)",
            r"mailto:",
            r"tel:",
            r"#",
            r"[?&]page=\d+$",
            r"[?&]offset=\d+$",
            r"[?&]sortby=[^&]+",
            r"[?&]order=[^&]+",
            r"[?&]utm_[^&]+",
            r"[?&]ref=[^&]+",
            r"[?&]fbclid=[^&]+",
            r"[?&]gclid=[^&]+",
            r"[?&]q=[^&]+",
            r"[?&]s=[^&]+",
            r"/search\?",
            r"/logout",
            r"[?&]month=\d{4}-\d{2}",
            r"[?&]year=\d{4}",
            r"(facebook|twitter|instagram|linkedin|pinterest)\.com",
            r"/share\?",
        ]

    def __next__(self):
        self.current_uri, self.current_depth = self.queue.popleft()
        self.queued.discard(self.current_uri)
        return self.current_uri

    def _budget_exhausted(self) -> bool:
        """Whether a URL-count or time budget has been hit."""
        if self.max_urls and len(self.visited) >= self.max_urls:
            reason = f"max URLs ({self.max_urls}) reached"
        elif self.crawl_timeout and (time.monotonic() - self.start_time) >= self.crawl_timeout:
            reason = f"crawl timeout ({self.crawl_timeout}s) reached"
        else:
            return False
        if not self._limit_logged:
            self.logger.info("Crawl budget: %s; stopping crawl.", reason)
            self._limit_logged = True
        return True

    def has_urls_to_visit(self):
        if self._budget_exhausted():
            return False
        return bool(self.queue)

    def _enqueue(self, url: str, depth: int) -> None:
        """Add a URL to the BFS queue if it's new, in-budget-depth and not excluded."""
        if url in self.queued or url in self.visited:
            return
        if url in EXCLUDE_DIRS:
            return
        if self.max_depth and depth > self.max_depth:
            return
        self.queue.append((url, depth))
        self.queued.add(url)

    def process(self) -> BeautifulSoup | None:
        url = self.current_uri
        response = requestMaker(url=url)
        if response and not response.status_code >= 400:
            INTERNAL_URLS.append(url)
        # Mark visited regardless of status so a failed fetch is not retried.
        self.visited.add(url)

        if not response or "html" not in response.headers.get("Content-Type", ""):
            return None

        if response.url != url:
            url = response.url
            self.visited.add(url)

        content = response.text
        try:
            soup = BeautifulSoup(content, "html.parser")
        except Exception:
            self.logger.error(f"Error during parsing: {url}")
            return None

        child_depth = self.current_depth + 1
        for link in soup.find_all("a", href=True):
            href = str(link["href"]).strip()
            if re.match(r"javascript:|mailto:|tel:", href):
                continue

            app = urllib.parse.urljoin(url, href)

            if not self._is_in_scope(app):
                continue

            app = self._clean_path(app)
            if self._is_junk_url(app):
                continue
            uri_pattern = self._normalise_pattern(app)
            if uri_pattern not in self.uri_patterns and app != url:
                self.uri_patterns.append(uri_pattern)
                if self._enqueue_allowed(child_depth):
                    self.logger.info(f"Added to crawl queue: {app}")
                    self._enqueue(app, child_depth)

        return soup

    def _enqueue_allowed(self, depth: int) -> bool:
        """Cheap guard so we don't grow uri_patterns/log spam once bounds are hit."""
        if self.max_depth and depth > self.max_depth:
            return False
        # Once enough URLs are already discovered/visited, stop queueing more.
        if self.max_urls and (len(self.visited) + len(self.queued)) >= self.max_urls:
            return False
        return True

    def _is_in_scope(self, url: str) -> bool:
        """Check if a URL belongs to the same origin as the scan target."""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == self.target_netloc

    def _clean_path(self, url: str) -> str:
        res = urllib.parse.urlparse(url)
        path = res.path

        if "../" in path:
            while path.startswith("/../"):
                path = path[len("/../") :]

            endless_loop = 0
            while re.search(r'/\.\./', path):
                endless_loop += 1
                if endless_loop > 100:
                    self.logger.warning(f"Endless loop detected for URL: {url}. Resetting path to '/'.")
                    path = "/"
                    break
                path = re.sub(r"/[^/]*/\.\./", "/", path)

        path = re.sub(r"\./", "", path)

        app = f"{res.scheme}://{res.hostname}"
        if res.port:
            app += f":{res.port}"
        app += path
        if res.query:
            app += f"?{res.query}"
        return app

    def _is_junk_url(self, url: str) -> bool:
        """Whether a URL matches a blocklisted pattern (share links, logout,
        tracking params, infinite calendar pages, ...)."""
        return any(re.search(pattern, url) for pattern in self.block_patterns)

    def _normalise_pattern(self, url: str) -> str:
        """Collapse numeric ids / titles so paginated or per-item URLs that
        differ only by a value are treated as one crawl target (dedup key)."""
        url = re.sub(r"=[0-9]+", "=", url)
        url = re.sub(r"(title=)[^&]*", "\\1", url)
        return url
