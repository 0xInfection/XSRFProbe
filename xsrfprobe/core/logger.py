#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.files.config import OUTPUT_DIR
from xsrfprobe.core.verbout import verbout
from xsrfprobe.files.discovered import INTERNAL_URLS, FILES_EXEC, SCAN_ERRORS
from xsrfprobe.files.discovered import (
    VULN_LIST,
    FORMS_TESTED,
    REQUEST_TOKENS,
    STRENGTH_LIST,
)


def logger(filename, content):
    """
    This module is for logging all the stuff we found
            while crawling and scanning.
    """
    output_file = OUTPUT_DIR + filename + ".log"
    with open(output_file, "w+", encoding="utf8") as f:
        if type(content) is tuple or type(content) is list:
            for m in content:  # if it is list or tuple, it is iterable
                f.write(m + "\n")
        else:
            f.write(content)  # else we write out as it is... ;)
        f.write("\n")


def preqheaders(tup):
    """
    This module prints out the headers as received in the
                    requests normally.
    """
    verbout(colors.GR, "Receiving headers...\n")
    verbout(
        colors.GREY,
        f"  {colors.UNDERLINE}REQUEST HEADERS{colors.END}{colors.GREY}:\n",
    )
    for key, val in tup.items():
        verbout("  ", f"{colors.CYAN}{key}: {colors.ORANGE}{val}")

    verbout("", "")


def presheaders(tup):
    """
    This module prints out the headers as received in the
                    requests normally.
    """
    verbout(colors.GR, "Receiving headers...\n")
    verbout(
        colors.GREY,
        f"  {colors.UNDERLINE}RESPONSE HEADERS{colors.END}{colors.GREY}:\n",
    )
    for key, val in tup.items():
        verbout("  ", f"{colors.CYAN}{key}: {colors.ORANGE}{val}")

    verbout("", "")


def GetLogger():
    if INTERNAL_URLS:
        logger("internal-links", INTERNAL_URLS)
    if SCAN_ERRORS:
        logger("errored", SCAN_ERRORS)
    if FILES_EXEC:
        logger("files-found", FILES_EXEC)
    if REQUEST_TOKENS:
        logger("anti-csrf-tokens", REQUEST_TOKENS)
    if FORMS_TESTED:
        logger("forms-tested", FORMS_TESTED)
    if VULN_LIST:
        logger("vulnerabilities", VULN_LIST)
    if STRENGTH_LIST:
        logger("strengths", STRENGTH_LIST)


def ErrorLogger(url, error):
    con = f"(i) {url} -> {error}"
    SCAN_ERRORS.append(con)


def VulnLogger(url, vuln, content=""):
    tent = "[!] " + url + " -> " + vuln + "\n\n" + str(content) + "\n\n"
    VULN_LIST.append(tent)


def NovulLogger(url, strength):
    tent = "[+] " + url + " -> " + strength
    STRENGTH_LIST.append(tent)
