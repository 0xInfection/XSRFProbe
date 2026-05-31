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
from xsrfprobe.core.schema import BenchmarkResult
from xsrfprobe.files.config import SIMILARITY_THRESHOLD

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

    def _commonTokens(self, a: list[str], b: list[str]) -> list[str]:
        """Return the tokens of ``a`` that also appear (in order) in ``b``."""
        matcher = SequenceMatcher(None, a, b)
        common: list[str] = []
        for block in matcher.get_matching_blocks():
            if block.size:
                common.extend(a[block.a:block.a + block.size])
        return common

    def prepareBenchmarkResponse(self, response_bodies: list[str], statuses: list[int], headers: list[dict]) -> BenchmarkResult:
        """
        Build a benchmark from N baseline samples of the same request.

        The static template is the set of tokens that are stable across *all*
        samples (a volatility mask): anything that varies between otherwise
        identical requests — tokens, timestamps, nonces, counters — is dropped.
        Using >=3 samples makes the mask far less likely to retain a value that
        only coincidentally matched between two responses.
        """
        contents = [self.getCleanedResponse(b) for b in response_bodies]

        # Intersect the stable tokens across every sample.
        stable = contents[0]
        for c in contents[1:]:
            stable = self._commonTokens(stable, c)
            if not stable:
                break

        # Conservative status: only trust it when ALL samples agree, otherwise
        # mark ambiguous (0) so benchmarkPassed falls back to stricter matching.
        if len(set(statuses)) == 1:
            status_code = statuses[0]
        else:
            status_code = 0
            self.logger.warning(
                "Baseline status codes are not all equal (%s); benchmark status marked ambiguous.",
                statuses,
            )

        # Headers common to every sample.
        common_headers = set(headers[0].keys())
        for h in headers[1:]:
            common_headers &= set(h.keys())

        return BenchmarkResult(
            base_benchmark=stable,
            status_code=status_code,
            headers={key: headers[0][key] for key in common_headers},
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
        if not base_benchmark.base_benchmark:
            return False

        if base_benchmark.status_code == 0:
            self.logger.debug("Benchmark has ambiguous status (baselines differed). Requiring higher body similarity.")
            match_ratio = self.performBenchmark(base_benchmark, response_to_benchmark)
            return match_ratio >= SIMILARITY_THRESHOLD + 5

        if base_benchmark.status_code != status:
            return False

        match_ratio = self.performBenchmark(base_benchmark, response_to_benchmark)
        return match_ratio >= SIMILARITY_THRESHOLD
