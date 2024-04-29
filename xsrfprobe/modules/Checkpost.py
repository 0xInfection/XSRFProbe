#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import time
import difflib
from urllib.parse import urlencode

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.logger import VulnLogger
from xsrfprobe.files.config import POC_GENERATION, GEN_MALICIOUS
from xsrfprobe.modules.Generator import GenNormalPoC, GenMalicious


def PostBased(url, r1, r2, r3, m_action, result, genpoc, form, m_name=""):
    """
    This method is for detecting POST-Based Request Forgeries
        on basis of fuzzy string matching and comparison
            based on Ratcliff-Obershelp Algorithm.
    """
    verbout(colors.RED, "\n +------------------------------+")
    verbout(colors.RED, " |   POST-Based Forgery Check   |")
    verbout(colors.RED, " +------------------------------+\n")
    verbout(colors.O, "Matching response query differences...")
    checkdiffx1 = difflib.ndiff(
        r1.splitlines(1), r2.splitlines(1)
    )  # check the diff noted
    checkdiffx2 = difflib.ndiff(
        r1.splitlines(1), r3.splitlines(1)
    )  # check the diff noted
    result12 = []  # an init
    verbout(colors.O, "Matching results...")
    for n in checkdiffx1:
        if re.match("\+|-", n):  # get regex matching stuff only +/-
            result12.append(n)  # append to existing list
    result13 = []  # an init
    for n in checkdiffx2:
        if re.match("\+|-", n):  # get regex matching stuff
            result13.append(n)  # append to existing list

    # This logic is based purely on the assumption on the difference of various requests
    # and response body.
    # If the number of differences of result12 are less than the number of differences
    # than result13 then we have the vulnerability. (very basic check)
    #
    # NOTE: The algorithm has lots of scopes of improvement...
    if len(result12) <= len(result13):
        print(
            colors.GREEN
            + " [+] CSRF Vulnerability Detected : "
            + colors.ORANGE
            + url
            + "!"
        )
        print(
            colors.ORANGE
            + " [!] Vulnerability Type: "
            + colors.BR
            + " POST-Based Request Forgery "
            + colors.END
        )
        VulnLogger(
            url,
            "POST-Based Request Forgery on Forms.",
            "[i] Form: "
            + form.__str__()
            + "\n[i] POST Query: "
            + result.__str__()
            + "\n",
        )
        time.sleep(0.3)
        verbout(O, "PoC of response and request...")
        if m_name:
            print(colors.RED + "\n +-----------------+")
            print(colors.RED + " |   Request PoC   |")
            print(colors.RED + " +-----------------+\n")
            print(colors.BLUE + " [+] URL : " + colors.CYAN + url)  # url part
            print(colors.CYAN + " [+] Name : " + colors.ORANGE + m_name)  # name
            if m_action.count("/") > 1:
                print(
                    colors.GREEN
                    + " [+] Action : "
                    + colors.END
                    + "/"
                    + m_action.rsplit("/", 1)[1]
                )  # action
            else:
                print(colors.GREEN + " [+] Action : " + colors.END + m_action)  # action
        else:  # if value m['name'] not there :(
            print(colors.RED + "\n +-----------------+")
            print(colors.RED + " |   Request PoC   |")
            print(colors.RED + " +-----------------+\n")
            print(colors.BLUE + " [+] URL : " + colors.CYAN + url)  # the url
            if m_action.count("/") > 1:
                print(
                    colors.GREEN
                    + " [+] Action : "
                    + colors.END
                    + "/"
                    + m_action.rsplit("/", 1)[1]
                )  # action
            else:
                print(colors.GREEN + " [+] Action : " + colors.END + m_action)  # action
        print(
            colors.ORANGE
            + " [+] POST Query : "
            + colors.GREY
            + urlencode(result).strip()
        )
        # If option --skip-poc hasn't been supplied...
        if POC_GENERATION:
            # If --malicious has been supplied
            if GEN_MALICIOUS:
                # Generates a malicious CSRF form
                GenMalicious(url, genpoc.__str__())
            else:
                # Generates a normal PoC
                GenNormalPoC(url, genpoc.__str__())
