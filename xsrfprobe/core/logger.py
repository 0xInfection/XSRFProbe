#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import sys
import logging
from contextlib import contextmanager
from xsrfprobe.files.discovered import (
    SCAN_ERRORS,
    VULN_LIST,
    VULN_RECORDS,
    STRENGTH_LIST,
)

PROGRESS = 25
logging.addLevelName(PROGRESS, "PROGRESS")


def _is_tty() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class CustomLogger(logging.getLoggerClass()):
    def progress(self, message, *args, **kwargs):
        if self.isEnabledFor(PROGRESS):
            self._log(PROGRESS, message, args, **kwargs)


class CustomFormatter(logging.Formatter):
    '''
    Customising my style of logging the results
    '''
    ftl_fmt  = "[-] FATAL: %(message)s"
    info_fmt = "[*] %(message)s"
    prg_fmt  = "[*] %(message)s"
    err_fmt  = "[-] ERROR: %(message)s"
    crt_fmt  = "[+] %(message)s"
    dbg_fmt  = "[~] DEBUG: %(module)s: %(message)s"
    wrg_fmt  = "[!] WARNING: %(message)s"

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%')

    def format(self, record):

        format_orig = self._style._fmt

        if record.levelno == logging.DEBUG:
            self._style._fmt = CustomFormatter.dbg_fmt

        elif record.levelno == logging.INFO:
            self._style._fmt = CustomFormatter.info_fmt

        elif record.levelno == PROGRESS:
            self._style._fmt = CustomFormatter.prg_fmt

        elif record.levelno == logging.ERROR:
            self._style._fmt = CustomFormatter.err_fmt

        elif record.levelno == logging.WARNING:
            self._style._fmt = CustomFormatter.wrg_fmt

        elif record.levelno == logging.CRITICAL:
            self._style._fmt = CustomFormatter.crt_fmt

        elif record.levelno == logging.FATAL:
            self._style._fmt = CustomFormatter.ftl_fmt

        result = logging.Formatter.format(self, record)
        self._style._fmt = format_orig

        return result


def phase_header(logger, title: str):
    """Log a phase section header at PROGRESS level."""
    import sys
    tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    if tty:
        sys.stdout.write(f"\n  --- {title} ---\n\n")
        sys.stdout.flush()
    else:
        # Non-TTY: use print to avoid the [*] prefix
        print(f"\n--- {title} ---")


@contextmanager
def test_progress(logger, test_id: str, description: str):
    """Context manager for inline test progress reporting.

    Writes an in-progress line, yields, then overwrites with result.
    Set the result via the returned dict: result['status'] = 'failed'|'passed'|etc.
    """
    result = {"status": "failed"}
    prefix = f"[{test_id}]" if test_id else ""
    label = f"{prefix} {description}"
    dots = "." * max(1, 50 - len(label))
    line_start = f"[*] {label}{dots} "

    tty = _is_tty()
    if tty:
        sys.stdout.write(line_start)
        sys.stdout.flush()

    try:
        yield result
    finally:
        status = result.get("status", "failed")
        final_line = f"{line_start}completed ({status})"
        if tty:
            sys.stdout.write(f"\r{final_line}\n")
            sys.stdout.flush()
            logger.debug("%s completed (%s)", label, status)
        else:
            logger.log(PROGRESS, "%s%s completed (%s)", label, dots, status)


def ErrorLogger(url, error):
    con = f"(i) {url} -> {error}"
    SCAN_ERRORS.append(con)


def VulnLogger(url, vuln, content="", test_id=""):
    prefix = f"[{test_id}] " if test_id else ""
    tent = f"[!] {url} -> {prefix}{vuln}\n\n{content}\n\n"
    VULN_LIST.append(tent)
    VULN_RECORDS.append({
        "url": url,
        "vuln": vuln,
        "content": content,
        "test_id": test_id,
        "details": {},
    })


def NovulLogger(url, strength, test_id=""):
    prefix = f"[{test_id}] " if test_id else ""
    tent = f"[+] {url} -> {prefix}{strength}"
    STRENGTH_LIST.append(tent)
