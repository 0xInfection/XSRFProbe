#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
from xsrfprobe.files.discovered import (
    SCAN_ERRORS,
    VULN_LIST,
    STRENGTH_LIST,
)


class CustomLogger(logging.getLoggerClass()):
    pass


class CustomFormatter(logging.Formatter):
    '''
    Customising my style of logging the results
    '''
    ftl_fmt  = "[-] FATAL: %(message)s"
    info_fmt = "[*] %(message)s"
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


def ErrorLogger(url, error):
    con = f"(i) {url} -> {error}"
    SCAN_ERRORS.append(con)


def VulnLogger(url, vuln, content=""):
    tent = f"[!] {url} -> {vuln}\n\n{content}\n\n"
    VULN_LIST.append(tent)


def NovulLogger(url, strength):
    tent = f"[+] {url} -> {strength}"
    STRENGTH_LIST.append(tent)
