"""Tests for XSRFProbe --headers values containing '=' (e.g. base64 tokens)."""
import sys

from xsrfprobe.core import options as options_mod
from xsrfprobe.files import config


def test_headers_value_with_equals_sign(monkeypatch):
    """A header value containing '=' must not crash with ValueError."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["xsrfprobe", "-u", "http://example.com", "-H", "X-Token=aGVsbG8="],
    )
    saved = dict(config.HEADER_VALUES)
    try:
        args = options_mod.options()
    finally:
        config.HEADER_VALUES.clear()
        config.HEADER_VALUES.update(saved)
    assert args.headers == "X-Token=aGVsbG8="
    assert config.HEADER_VALUES.get("X-Token") == "aGVsbG8="
