#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import logging
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from core.schema import BenchmarkResult
from files.config import SIMILARITY_THRESHOLD

class DiffEngine:
    def __init__(self):
        self.cleaner_regex = re.compile(r"\b[\da-fA-F]{8,}\b|\d+")  # Regex to remove dynamic parts
        self.logger = logging.getLogger("DiffEngine")

    def getCleanedResponse(self, html: str) -> list[str]:
        """
        Parse the HTML and extract cleaned text content without dynamic parts.
        """
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        cleaned_text = self.cleaner_regex.sub("", text)
        return cleaned_text.split()

    def diffHeaders(self, headers: tuple[dict, dict]) -> tuple[set, set, dict, set]:
        """
        Compare two sets of headers and return the common headers.
        """
        headersx, headersy = headers
        keys1 = set(headersx.keys())
        keys2 = set(headersy.keys())
        added_headers = keys2 - keys1
        removed_headers = keys1 - keys2
        common_headers = keys1 & keys2

        changed_headers = {key: (headersx[key], headersy[key]) for key in common_headers if headersx[key] != headersy[key]}
        return added_headers, removed_headers, changed_headers, common_headers

    def prepareBenchmarkResponse(self, response_bodies: tuple[str, str], statuses: tuple[int, int], headers: tuple) -> BenchmarkResult:
        """
        Compare two HTML responses and return common static parts.
        """
        responsex, responsey = response_bodies
        content1 = self.getCleanedResponse(responsex)
        content2 = self.getCleanedResponse(responsey)
        matcher = SequenceMatcher(None, content1, content2)
        common_parts = [content1[block.a:block.a + block.size] for block in matcher.get_matching_blocks() if block.size > 0]
        # we expect both the status codes of the base benchmark to be the same
        statusx, statusy = statuses
        if statusx != statusy:
            self.logger.warning("Status codes of the base benchmark responses are different. This may lead to inaccurate results.")

        headersx, headersy = headers
        diffed_headers = self.diffHeaders((headersx, headersy))
        added_headers, removed_headers, changed_headers, common_headers = diffed_headers

        return BenchmarkResult(
            base_benchmark=[item for sublist in common_parts for item in sublist],
            status_code=statusx if statusx == statusy else 0,
            headers={key: headersx[key] for key in common_headers},
        )

    def performBenchmark(self, base_benchmark: BenchmarkResult, new_html: str) -> float:
        """
        Calculate how much of the common parts match the new HTML response.
        """
        new_content = self.getCleanedResponse(new_html)
        matcher = SequenceMatcher(None, base_benchmark.base_benchmark, new_content)
        return matcher.ratio() * 100

    def benchmarkPassed(self, base_benchmark: BenchmarkResult, response_to_benchmark: str, status: int) -> bool:
        """
        Perform the benchmark and check if the new HTML response matches the threshold.
        """
        if base_benchmark.status_code != status:
            if base_benchmark.status_code == 0:
                pass
            else:
                return False

        match_ratio = self.performBenchmark(base_benchmark, response_to_benchmark)
        if match_ratio >= SIMILARITY_THRESHOLD:
            return True

        return False
