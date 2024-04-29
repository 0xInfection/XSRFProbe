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

from xsrfprobe.files.config import HEADER_VALUES, REFERER_URL, COOKIE_VALUE
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.request import Get
from xsrfprobe.core.logger import VulnLogger, NovulLogger


def Referer(url):
    """
    Check if the remote web application verifies the Referer before
                    processing the HTTP request.
    """
    verbout(colors.RED, "\n +--------------------------------------+")
    verbout(colors.RED, " |   Referer Based Request Validation   |")
    verbout(colors.RED, " +--------------------------------------+\n")
    # Make the request normally and get content
    verbout(colors.O, "Making request on normal basis...")
    req0x01 = Get(url)

    # Set normal headers...
    verbout(colors.GR, "Setting generic headers...")
    gen_headers = HEADER_VALUES

    # Set a fake Referer along with UA (pretending to be a
    # legitimate request from a browser)
    gen_headers["Referer"] = REFERER_URL

    # We put the cookie in request, if cookie supplied :D
    if COOKIE_VALUE:
        gen_headers["Cookie"] = ",".join(cookie for cookie in COOKIE_VALUE)

    # Make the request with different referer header and get the content
    verbout(
        colors.O,
        "Making request with "
        + colors.CYAN
        + "Tampered Referer Header"
        + colors.END
        + "...",
    )
    req0x02 = Get(url, headers=gen_headers)
    HEADER_VALUES.pop("Referer", None)

    # Comparing the length of the requests' responses. If both content
    # lengths are same, then the site actually does not validate referer
    # before processing the HTTP request which makes the site more
    # vulnerable to CSRF attacks.
    #
    # IMPORTANT NOTE: I'm aware that checking for the referer header does
    # NOT protect the application against all cases of CSRF, but it's a
    # very good first step. In order to exploit a CSRF in an application
    # that protects using this method an intruder would have to identify
    # other vulnerabilities, such as XSS or open redirects, in the same
    # domain.
    #
    # TODO: This algorithm has lots of room for improvement.
    if len(req0x01.content) != len(req0x02.content):
        print(
            colors.GREEN
            + " [+] Endoint "
            + colors.ORANGE
            + "Referer Validation"
            + colors.GREEN
            + " Present!"
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
            + " Referer Based Request Validation "
            + colors.END
        )
        NovulLogger(url, "Presence of Referer Header based Request Validation.")
        return True
    else:
        verbout(
            colors.R,
            "Endpoint " + colors.RED + "Referer Validation Not Present" + colors.END,
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
            + " [+] Possible Vulnerability Type: "
            + colors.BY
            + " No Referer Based Request Validation "
            + colors.END
        )
        VulnLogger(
            url,
            "No Referer Header based Request Validation presence.",
            "[i] Response Headers: " + str(req0x02.headers),
        )
        return False
