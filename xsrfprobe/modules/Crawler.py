import logging
import re
import urllib.parse
from bs4 import BeautifulSoup
from xsrfprobe.files.config import EXCLUDE_DIRS
from xsrfprobe.core.request import requestMaker
from xsrfprobe.files.discovered import INTERNAL_URLS

class Crawler():
    def __init__(self, start):
        self.logger = logging.getLogger('CrawlEngine')
        self.visited: set[str] = set()
        self.to_visit: set[str] = {start}
        self.uri_patterns = []
        self.current_uri = ""
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
        self.current_uri = self.to_visit.pop()
        return self.current_uri

    def has_urls_to_visit(self):
        return bool(self.to_visit)

    def process(self) -> BeautifulSoup | None:
        if EXCLUDE_DIRS:
            self.to_visit = {url for url in self.to_visit if url not in EXCLUDE_DIRS}

        url = self.current_uri
        response = requestMaker(url=url)
        if response and not response.status_code >= 400:
            INTERNAL_URLS.append(url)
            self.visited.add(url)

        # once visited, remove the URL from the to_visit list
        if url in self.to_visit:
            self.to_visit.remove(url)

        if not response or "html" not in response.headers.get("Content-Type", ""):
            return None

        if response.url != url:
            url = response.url

        content = response.text
        try:
            soup = BeautifulSoup(content, "html.parser")
        except Exception:
            self.logger.error(f"Error during parsing: {url}")
            self.visited.add(url)
            if url in self.to_visit:
                self.to_visit.remove(url)
            return None

        for link in soup.find_all("a", href=True):
            href = str(link["href"]).strip()
            if re.match(r"javascript:|mailto:|tel:", href):
                continue

            app = urllib.parse.urljoin(url, href)

            if not self._is_in_scope(app):
                continue

            app = self._clean_path(app)
            uri_pattern = self._remove_junk_urls(app)
            if uri_pattern not in self.uri_patterns and app != url and app not in self.visited:
                self.logger.debug(f"Added to crawl queue: {app}")
                self.to_visit.add(app)
                self.uri_patterns.append(uri_pattern)

        self.visited.add(url)
        return soup

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

    def _remove_junk_urls(self, url: str) -> str:
        if any(re.search(pattern, url) for pattern in self.block_patterns):
            self.to_visit.discard(url)

        url = re.sub(r"=[0-9]+", "=", url)
        url = re.sub(r"(title=)[^&]*", "\\1", url)
        return url
