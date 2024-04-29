#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import sys
from re import search, I

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.files.config import HEADER_VALUES, USER_AGENT, COOKIE_VALUE, REFERER_URL
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.request import Get
from xsrfprobe.core.randua import RandomAgent
from xsrfprobe.modules.Persistence import Persistence
from xsrfprobe.core.logger import VulnLogger, NovulLogger
from urllib.parse import urlsplit

resps = []


def SameSite(url):
    """
    This function parses and verifies the cookies with
                    SameSite Flags.
    """
    verbout(colors.RED, "\n +------------------------------------+")
    verbout(colors.RED, " |   Cross Origin Cookie Validation   |")
    verbout(colors.RED, " +------------------------------------+\n")
    # Some Flags we'd need later...
    foundx1 = 0x00
    foundx2 = 0x00
    foundx3 = 0x00
    # Step 1: First we check that if the server returns any
    # SameSite flag on Cookies with the same Referer as the netloc
    verbout(colors.GREY, " [+] Lets examine how server reacts to same referer...")
    gen_headers = HEADER_VALUES
    gen_headers["User-Agent"] = USER_AGENT if USER_AGENT else RandomAgent()
    verbout(colors.GR, "Setting Referer header same as host...")

    # Setting the netloc as the referer for the first check.
    gen_headers["Referer"] = urlsplit(url).netloc
    if COOKIE_VALUE:
        gen_headers["Cookie"] = ",".join(cookie for cookie in COOKIE_VALUE)

    getreq = Get(url, headers=gen_headers)  # Making the request
    map(HEADER_VALUES.pop, ["Referer", "Cookie"])
    head = getreq.headers
    for h in head:
        # if search('cookie', h, I) or search('set-cookie', h, I):
        if "Cookie".lower() in h.lower():
            verbout(colors.G, "Found cookie header value...")
            cookieval = head[h]
            verbout(
                colors.ORANGE, " [+] Cookie Received: " + colors.CYAN + str(cookieval)
            )
            m = cookieval.split(";")
            verbout(colors.GR, "Examining Cookie...")
            for q in m:
                if search("SameSite", q, I):
                    verbout(
                        colors.G,
                        "SameSite Flag " + colors.ORANGE + " detected on cookie!",
                    )
                    foundx1 = 0x01
                    q = q.split("=")[1].strip()
                    verbout(colors.C, "Cookie: " + colors.ORANGE + q)
                    break
        else:
            foundx3 = 0x02
    if foundx1 == 0x01:
        verbout(
            colors.R,
            " [+] Endpoint "
            + colors.ORANGE
            + "SameSite Flag Cookie Validation"
            + colors.END
            + " Present!",
        )

    # Step 2: Now we check security mechanisms when the Referer is
    # different, i.e. request originates from a different url other
    # than the host. (This time without the Cookie assigned)
    verbout(
        colors.GREY, " [+] Lets examine how server reacts to a fake external referer..."
    )
    gen_headers = HEADER_VALUES
    gen_headers["User-Agent"] = (
        USER_AGENT if USER_AGENT else RandomAgent()
    )  # Setting user-agents
    # Assigning a fake referer for the second check, but no cookie.
    gen_headers["Referer"] = REFERER_URL
    gen_headers.pop("Cookie", None)
    getreq = Get(url, headers=gen_headers)
    HEADER_VALUES.pop("Referer", None)
    head = getreq.headers  # Getting headers from requests
    for h in head:
        # If search('cookie', h, I) or search('set-cookie', h, I):
        if "Cookie".lower() in h.lower():
            verbout(colors.G, "Found cookie header value...")
            cookieval = head[h]
            verbout(
                colors.ORANGE, " [+] Cookie Received: " + colors.CYAN + str(cookieval)
            )
            m = cookieval.split(";")
            verbout(colors.GR, "Examining Cookie...")
            for q in m:
                if search("SameSite", q, I):
                    verbout(
                        colors.G,
                        "SameSite Flag " + colors.ORANGE + " detected on cookie!",
                    )
                    foundx2 = 0x01
                    q = q.split("=")[1].strip()
                    verbout(colors.C, "Cookie: " + colors.ORANGE + q)
                    break
        else:
            foundx3 = 0x02

    if foundx1 == 0x01:
        verbout(
            colors.R,
            " [+] Endpoint "
            + colors.ORANGE
            + "SameSite Flag Cookie Validation"
            + colors.END
            + " Present!",
        )

    # Step 3: And finally comes the most important step. Lets see how
    # the site reacts to a valid cookie (ofc supplied by the user) coming
    # from a a different site, i.e Referer set to other than host.
    # This is the most crucial part of the detection.
    #
    # TODO: Improve the logic in detection.
    verbout(
        colors.GREY,
        " [+] Lets examine how server reacts to valid cookie from a different referer...",
    )
    gen_headers = HEADER_VALUES
    gen_headers["User-Agent"] = USER_AGENT or RandomAgent()
    # Assigning a fake referer for third request, this time with cookie ;)
    gen_headers["Referer"] = REFERER_URL
    if COOKIE_VALUE:
        gen_headers["Cookie"] = ",".join(cookie for cookie in COOKIE_VALUE)

    getreq = Get(url, headers=gen_headers)
    HEADER_VALUES.pop("Referer", None)
    head = getreq.headers
    for h in head:
        # if search('cookie', h, I) or search('set-cookie', h, I):
        if "Cookie".lower() in h.lower():
            verbout(colors.G, "Found cookie header value...")
            cookieval = head[h]
            verbout(
                colors.ORANGE, " [+] Cookie Received: " + colors.CYAN + str(cookieval)
            )
            m = cookieval.split(";")
            verbout(colors.GR, "Examining Cookie...")
            for q in m:
                if search("samesite", q.lower(), I):
                    verbout(
                        colors.G,
                        "SameSite Flag "
                        + colors.ORANGE
                        + " detected on cookie on Cross Origin Request!",
                    )
                    foundx3 = 0x01
                    q = q.split("=")[1].strip()
                    verbout(colors.C, "Cookie: " + colors.ORANGE + q)
                    break
        else:
            foundx3 = 0x02

    if foundx1 == 0x01:
        verbout(
            colors.R,
            "Endpoint "
            + colors.ORANGE
            + "SameSite Flag Cookie Validation"
            + colors.END
            + " is Present!",
        )

    if (foundx1 == 0x01 and foundx3 == 0x00) and (foundx2 == 0x00 or foundx2 == 0x01):
        print(
            colors.GREEN
            + " [+] Endpoint "
            + colors.BG
            + " NOT VULNERABLE to ANY type of CSRF attacks! "
            + colors.END
        )
        print(
            colors.GREEN
            + " [+] Protection Method Detected : "
            + colors.BG
            + " SameSite Flag on Cookies "
            + colors.END
        )
        NovulLogger(url, "SameSite Flag set on Cookies on Cross-Origin Requests.")
        # If a SameSite flag is set on cookies, then the application is totally fool-proof
        # against CSRF attacks unless there is some XSS stuff on it. So for now the job of
        # this application is done. We need to confirm before we quit.
        oq = input(colors.BLUE + " [+] Continue scanning? (y/N) :> ")
        if oq.lower().startswith("n"):
            sys.exit("\n" + colors.R + "Shutting down XSRFProbe...\n")
    elif foundx1 == 0x02 and foundx2 == 0x02 and foundx3 == 0x02:
        print(
            colors.GREEN
            + " [+] Endpoint "
            + colors.BG
            + " NOT VULNERABLE "
            + colors.END
            + colors.GREEN
            + " to CSRF attacks!"
        )
        print(
            colors.GREEN
            + " [+] Type: "
            + colors.BG
            + " No Cookie Set while Cross Origin Requests "
            + colors.END
        )
        NovulLogger(url, "No cookie set on Cross-Origin Requests.")
    else:
        verbout(
            colors.R,
            "Endpoint "
            + colors.ORANGE
            + "Cross Origin Cookie Validation"
            + colors.END
            + " Not Present!",
        )
        verbout(
            colors.R,
            "Heuristic(s) reveal endpoint might be "
            + colors.BY
            + " VULNERABLE "
            + colors.END
            + " to CSRFs...",
        )
        print(
            colors.CYAN
            + " [+] Possible CSRF Vulnerability Detected : "
            + colors.GREY
            + url
        )
        print(
            colors.ORANGE
            + " [!] Possible Vulnerability Type: "
            + colors.BY
            + " No Cross Origin Cookie Validation Presence "
            + colors.END
        )
        VulnLogger(
            url,
            "No Cookie Validation on Cross-Origin Requests.",
            "[i] Headers: " + str(head),
        )


def Cookie(url, request):
    """
    This module is for checking the varied HTTP Cookies
            and the related security on them to
                    prevent CSRF attacks.
    """
    verbout(colors.GR, "Proceeding for cookie based checks...")
    SameSite(url)
    Persistence(url, request)
