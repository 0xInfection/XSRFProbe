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

from xsrfprobe.files.config import HEADER_VALUES, ORIGIN_URL, COOKIE_VALUE
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.request import Get
from xsrfprobe.core.logger import VulnLogger, NovulLogger


def Origin(url):
    """
    Check if the remote web application verifies the Origin before
                    processing the HTTP request.
    """
    verbout(colors.RED, "\n +-------------------------------------+")
    verbout(colors.RED, " |   Origin Based Request Validation   |")
    verbout(colors.RED, " +-------------------------------------+\n")
    # Make the request normally and get content
    verbout(colors.O, "Making request on normal basis...")
    req0x01 = Get(url)
    global HEADER_VALUES
    # Set a fake Origin along with UA (pretending to be a
    # legitimate request from a browser)
    verbout(colors.GR, "Setting generic headers...")
    gen_headers = HEADER_VALUES
    gen_headers["Origin"] = ORIGIN_URL

    # We put the cookie in request, if cookie supplied :D
    if COOKIE_VALUE:
        gen_headers["Cookie"] = ",".join(cookie for cookie in COOKIE_VALUE)

    # Make the request with different Origin header and get the content
    verbout(
        colors.O,
        "Making request with "
        + colors.CYAN
        + "Tampered Origin Header"
        + colors.END
        + "...",
    )
    req0x02 = Get(url, headers=gen_headers)
    HEADER_VALUES.pop("Origin", None)

    # Comparing the length of the requests' responses. If both content
    # lengths are same, then the site actually does not validate Origin
    # before processing the HTTP request which makes the site more
    # vulnerable to CSRF attacks.
    #
    # IMPORTANT NOTE: I'm aware that checking for the Origin header does
    # NOT protect the application against all cases of CSRF, but it's a
    # very good first step. In order to exploit a CSRF in an application
    # that protects using this method an intruder would have to identify
    # other vulnerabilities, such as XSS or open redirects, in the same
    # domain.
    #
    # TODO: This algorithm has lots of room for improvement
    if len(req0x01.content) != len(req0x02.content):
        verbout(
            colors.GREEN,
            " [+] Endoint "
            + colors.ORANGE
            + "Origin Validation"
            + colors.GREEN
            + " Present!",
        )
        print(
            colors.GREEN
            + " [-] Heuristics reveal endpoint might be "
            + colors.BG
            + " NOT VULNERABLE "
            + colors.END
            + "..."
        )
        print(
            colors.ORANGE
            + " [+] Mitigation Method: "
            + colors.BG
            + " Origin Based Request Validation "
            + colors.END
            + "\n"
        )
        NovulLogger(url, "Presence of Origin Header based request Validation.")
        return True
    else:
        verbout(
            colors.R,
            "Endpoint " + colors.RED + "Origin Validation Not Present" + colors.END,
        )
        verbout(
            colors.R,
            "Heuristics reveal endpoint might be "
            + colors.BY
            + " VULNERABLE "
            + colors.END
            + " to Origin Based CSRFs...",
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
            + " No Origin Based Request Validation "
            + colors.END
            + "\n"
        )
        VulnLogger(
            url,
            "No Origin Header based request validation presence.",
            "[i] Response Headers: " + str(req0x02.headers),
        )
        return False
