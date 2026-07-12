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

# Auto-calibration bounds for the per-endpoint pass threshold (improvement #3).
# The threshold is set a small margin below how well the baseline samples match
# their own consolidated template, then clamped so it never becomes absurdly
# permissive (FLOOR) or demands an essentially byte-identical page (CEIL).
SIMILARITY_MARGIN = 5
SIMILARITY_FLOOR = 50.0
SIMILARITY_CEIL = 98.0

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

        # Auto-calibrate the pass threshold (improvement #3). Each baseline
        # sample is scored against the consolidated template; a genuine success
        # should match about as well, while a clearly different (failure) page
        # won't. We set the bar a small margin below the worst baseline self-
        # match, so a near-static page gets a strict cutoff and a dynamic one a
        # looser cutoff — instead of a single global magic number.
        if stable:
            self_scores = [
                SequenceMatcher(None, stable, c).ratio() * 100 for c in contents
            ]
            baseline_self = min(self_scores)
            calibrated = max(SIMILARITY_FLOOR,
                             min(baseline_self - SIMILARITY_MARGIN, SIMILARITY_CEIL))
            self.logger.debug(
                "Calibrated similarity threshold: %.1f (baseline self-match min=%.1f, "
                "global default=%s)", calibrated, baseline_self, SIMILARITY_THRESHOLD,
            )
        else:
            calibrated = float(SIMILARITY_THRESHOLD)

        return BenchmarkResult(
            base_benchmark=stable,
            status_code=status_code,
            headers={key: headers[0][key] for key in common_headers},
            similarity_threshold=calibrated,
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

        # Per-endpoint, auto-calibrated threshold (falls back to the global
        # default for benchmarks built before calibration existed).
        threshold = base_benchmark.similarity_threshold or float(SIMILARITY_THRESHOLD)

        if base_benchmark.status_code == 0:
            # Baselines disagreed on status — demand a stricter body match.
            self.logger.debug("Benchmark has ambiguous status (baselines differed). Requiring higher body similarity.")
            match_ratio = self.performBenchmark(base_benchmark, response_to_benchmark)
            return match_ratio >= min(threshold + 5, SIMILARITY_CEIL + 1)

        if base_benchmark.status_code != status:
            return False

        match_ratio = self.performBenchmark(base_benchmark, response_to_benchmark)
        return match_ratio >= threshold
