import logging
import re
import urllib.error
import urllib.parse
from bs4 import BeautifulSoup

from modules import Parser

from files.config import EXCLUDE_DIRS
from files.dcodelist import (
    RID_DOUBLE,
    RID_COMPILE,
    RID_SINGLE,
    NUM_COM,
    NUM_SUB,
)
from core.logger import ErrorLogger
from core.request import requestMaker
from files.discovered import INTERNAL_URLS


class Handler:
    """
    Crawler Handler to fetch URLs from an HTML page and check for CSRF vulnerabilities.
    """

    def __init__(self, start, opener):
        self.visited = []
        self.to_visit = [start]
        self.uri_patterns = []
        self.current_uri = ""
        self.opener = opener

    def __next__(self):
        self.current_uri = self.to_visit.pop(0)
        return self.current_uri

    def get_visited(self):
        return self.visited

    def get_to_visit(self):
        return self.to_visit

    def has_urls_to_visit(self):
        return bool(self.to_visit)

    def add_to_visit(self, url):
        self.to_visit.append(url)

    def process(self, root):
        if EXCLUDE_DIRS:
            self.to_visit = [url for url in self.to_visit if url not in EXCLUDE_DIRS]

        url = self.current_uri
        try:
            query = requestMaker(
                url=url,
                method="GET",
            )
            if query and not str(query.status_code).startswith("40"):
                INTERNAL_URLS.append(url)
            else:
                if url in self.to_visit:
                    self.to_visit.remove(url)
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            logging.error(f"HTTP Request Error: {e}")
            ErrorLogger(url, str(e))
            if url in self.to_visit:
                self.to_visit.remove(url)
            return None

        if not query or "html" not in query.headers.get("Content-Type", ""):
            return None

        if hasattr(query.headers, "Location"):
            url = query.headers["Location"]

        response = query.content
        try:
            soup = BeautifulSoup(response, "html.parser")
        except Exception:
            logging.error(f"BeautifulSoup Error: {url}")
            self.visited.append(url)
            if url in self.to_visit:
                self.to_visit.remove(url)
            return None

        for link in soup.find_all("a", href=True):
            app = ""
            if not re.match(r"javascript:", link["href"]) and not re.match(r"http(s?)://", link["href"]):
                app = Parser.buildUrl(url, link["href"])

            if app and re.search(root, app):
                app = self._clean_path(app)
                uri_pattern = self._remove_ids(app)
                if uri_pattern not in self.uri_patterns and app != url:
                    logging.info(f"Added: {app}")
                    self.to_visit.append(app)
                    self.uri_patterns.append(uri_pattern)

        self.visited.append(url)
        return soup

    def _clean_path(self, url):
        res = urllib.parse.urlparse(url)
        path = res.path

        if "../" in path:
            while path.startswith("/../"):
                path = path[len("/../") :]

            endless_loop = 0
            while re.search(RID_DOUBLE, path):
                endless_loop += 1
                if endless_loop > 100:
                    logging.warning(f"Endless loop detected for URL: {url}. Resetting path to '/'.")
                    path = "/"
                    break
                path = re.sub(RID_COMPILE, "/", path)

        path = re.sub(RID_SINGLE, "", path)

        app = f"{res.scheme}://{res.hostname}"
        if res.port:
            app += f":{res.port}"
        app += path
        return app

    def _remove_ids(self, url):
        url = re.sub(NUM_SUB, "=", url)
        url = re.sub(NUM_COM, "\\1", url)
        return url

    def not_exist(self, pattern):
        return pattern not in self.uri_patterns

    def add_uri_pattern(self, pattern):
        self.uri_patterns.append(pattern)

    def add_visited(self, url):
        self.visited.append(url)
