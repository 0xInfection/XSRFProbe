#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import time
from datetime import datetime

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.files.config import HEADER_VALUES, COOKIE_VALUE
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.request import Get
from xsrfprobe.core.utils import checkDuplicates
from xsrfprobe.core.logger import VulnLogger, NovulLogger

# Response storing list init
resps = []


def Persistence(url, postq):
    """
    The main idea behind this is to check for Cookie
                    Persistence.
    """
    verbout(colors.RED, "\n +-----------------------------------+")
    verbout(colors.RED, " |   Cookie Persistence Validation   |")
    verbout(colors.RED, " +-----------------------------------+\n")
    # Checking if user has supplied a value.
    verbout(
        colors.GR,
        "Proceeding to test for "
        + colors.GREY
        + "Cookie Persistence"
        + colors.END
        + "...",
    )
    time.sleep(0.7)
    found = 0x00
    # Now let the real test begin...
    #
    # [Step 1]: Lets examine now whether cookies set by server are persistent or not.
    # For this we'll have to parse the cookies set by the server and check for the
    # time when the cookie expires. Lets do it!
    #
    # First its time for GET type requests. Lets prepare our request.
    # cookies = []
    verbout(
        colors.C,
        "Proceeding to test cookie persistence via "
        + colors.CYAN
        + "Prepared GET Requests"
        + colors.END
        + "...",
    )
    verbout(colors.GR, "Making the request...")
    req = Get(url, headers=HEADER_VALUES)

    if req.cookies:
        for cook in req.cookies:
            if cook.expires:
                print(
                    colors.GREEN + " [+] Persistent Cookies found in Response Headers!"
                )
                print(colors.GREY + " [+] Cookie: " + colors.CYAN + cook.__str__())
                # cookie.expires returns a timestamp value. I didn't know it. :( Spent over 2+ hours scratching my head
                # over this, until I stumbled upon a stackoverflow answer comment. So to decode this, we'd need to
                # convert it a human readable format.
                print(
                    colors.GREEN
                    + " [+] Cookie Expiry Period: "
                    + colors.ORANGE
                    + datetime.fromtimestamp(cook.expires).__str__()
                )
                found = 0x01
                VulnLogger(
                    url,
                    "Persistent Session Cookies Found.",
                    "[i] Cookie: " + req.headers.get("Set-Cookie"),
                )
            else:
                NovulLogger(url, "No Persistent Session Cookies.")

    if found == 0x00:
        verbout(
            colors.R, "No persistent session cookies identified on GET Type Requests!"
        )

    verbout(
        colors.C,
        "Proceeding to test cookie persistence on "
        + colors.CYAN
        + "POST Requests"
        + colors.END
        + "...",
    )
    # Now its time for POST Based requests.
    #
    # NOTE: As a standard method, every web application should supply a cookie upon a POST query.
    # It might or might not be in case of GET requests.
    if postq.cookies:
        for cookie in postq.cookies:
            if cookie.expires:
                print(
                    colors.GREEN + " [+] Persistent Cookies found in Response Headers!"
                )
                print(colors.GREY + " [+] Cookie: " + colors.CYAN + cookie.__str__())
                # So to decode this, we'd need to convert it a human readable format.
                print(
                    colors.GREEN
                    + " [+] Cookie Expiry Period: "
                    + colors.ORANGE
                    + datetime.fromtimestamp(cookie.expires).__str__()
                )
                found = 0x01
                VulnLogger(
                    url,
                    "Persistent Session Cookies Found.",
                    "[i] Cookie: " + req.headers.get("Set-Cookie"),
                )
                print(
                    colors.ORANGE
                    + " [!] Probable Insecure Practice: "
                    + colors.BY
                    + " Persistent Session Cookies "
                    + colors.END
                )
            else:
                NovulLogger(url, "No Persistent Cookies.")

    if found == 0x00:
        verbout(
            colors.R, "No persistent session cookies identified upon POST Requests!"
        )
        print(
            colors.ORANGE
            + " [+] Endpoint might be "
            + colors.BY
            + " NOT VULNERABLE "
            + colors.END
            + colors.ORANGE
            + " to CSRF attacks!"
        )
        print(
            colors.ORANGE
            + " [+] Detected : "
            + colors.BY
            + " No Persistent Cookies "
            + colors.END
        )

    # [Step 2]: The idea here is to try to identify cookie persistence on basis of observing
    # variations in cases of using different user-agents. For this test we have chosen 5 different
    # well used and common user-agents (as below) and then we observe the variation of set-cookie
    # header under different conditions.
    #
    # We'll test this method only when we haven't identified requests based on previous algo.
    if found != 0x01:
        verbout(
            colors.C,
            "Proceeding to test cookie persistence via "
            + colors.CYAN
            + "User-Agent Alteration"
            + colors.END
            + "...",
        )
        user_agents = {
            "Chrome on Windows 8.1": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36",
            "Safari on iOS": "Mozilla/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
            "IE6 on Windows XP": "Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
            "Opera on Windows 10": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
            "Chrome on Android": "Mozilla/5.0 (Linux; U; Android 2.3.1; en-us; MID Build/GINGERBREAD) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
        }
        verbout(colors.GR, "Setting custom generic headers...")
        gen_headers = HEADER_VALUES
        for name, agent in user_agents.items():
            verbout(colors.C, "Using User-Agent : " + colors.CYAN + name)
            verbout(colors.GR, "Value : " + colors.ORANGE + agent)
            gen_headers["User-Agent"] = agent
            if COOKIE_VALUE:
                gen_headers["Cookie"] = ",".join(cookie for cookie in COOKIE_VALUE)
            req = Get(url, headers=gen_headers)
            # We will append this to stuff only when set-cookie is being supplied.
            if req.headers.get("Set-Cookie"):
                resps.append(req.headers.get("Set-Cookie"))
        HEADER_VALUES.pop("User-Agent", None)
        HEADER_VALUES[
            "User-Agent"
        ] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36"
        if resps:
            if checkDuplicates(resps):
                verbout(
                    colors.G,
                    "Set-Cookie header does not change with varied User-Agents...",
                )
                verbout(
                    colors.ORANGE, " [+] Possible persistent session cookies found..."
                )
                print(
                    colors.RED
                    + " [+] Possible CSRF Vulnerability Detected : "
                    + colors.ORANGE
                    + url
                )
                print(
                    colors.ORANGE
                    + " [!] Probable Insecure Practice: "
                    + colors.BY
                    + " Persistent Session Cookies "
                    + colors.END
                )
                VulnLogger(
                    url,
                    "Persistent Session Cookies Found.",
                    "[i] Cookie: " + req.headers.get("Set-Cookie"),
                )
            else:
                verbout(
                    colors.G, "Set-Cookie header changes with varied User-Agents..."
                )
                verbout(colors.R, "No possible persistent session cookies found...")
                verbout(
                    colors.ORANGE,
                    " [+] Endpoint "
                    + colors.BY
                    + " PROBABLY NOT VULNERABLE "
                    + colors.END
                    + colors.ORANGE
                    + " to CSRF attacks!",
                )
                verbout(
                    colors.ORANGE,
                    " [+] Application Practice Method Detected : "
                    + colors.BY
                    + " No Persistent Cookies "
                    + colors.END,
                )
                NovulLogger(url, "No Persistent Cookies.")
        else:
            verbout(colors.R, "No cookies are being set on any requests.")
