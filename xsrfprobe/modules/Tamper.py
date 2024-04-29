#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from re import search, I

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.core.request import Post
from xsrfprobe.files.config import *
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.utils import replaceStrIndex
from xsrfprobe.files.paramlist import TOKEN_ERRORS
from xsrfprobe.core.logger import VulnLogger, NovulLogger


def Tamper(url, action, req, body, query, para):
    """
    The main idea behind this is to tamper the Anti-CSRF tokens
          found and check the content length for related
                      vulnerabilities.
    """
    verbout(colors.RED, "\n +---------------------------------------+")
    verbout(colors.RED, " |   Anti-CSRF Token Tamper Validation   |")
    verbout(colors.RED, " +---------------------------------------+\n")
    # Null char flags (hex)
    flagx1, destx1 = 0x00, 0x00
    flagx2, destx2 = 0x00, 0x00
    flagx3, destx3 = 0x00, 0x00
    verbout(colors.GR, "Proceeding for CSRF attack via Anti-CSRF token tampering...")
    # First of all lets get out token from request
    if para == "":
        return True
    # Coverting the token to a raw string, cause some special
    # chars might fu*k with the operation.
    value = r"%s" % para
    copy = req

    # Alright lets start...
    # [Step 1]: First we take the token and then replace a particular character
    # at a specific position (here at 4th position) and test the response body.
    #
    # Required check for checking if string at that position isn't the
    # same char we are going to replace with.
    verbout(
        colors.GR,
        "Tampering Token by " + colors.GREY + "index replacement" + colors.END + "...",
    )
    if value[3] != "a":
        tampvalx1 = replaceStrIndex(value, 3, "a")
    else:
        tampvalx1 = replaceStrIndex(value, 3, "x")
    verbout(colors.BLUE, " [+] Original Token: " + colors.CYAN + value)
    verbout(colors.BLUE, " [+] Tampered Token: " + colors.CYAN + tampvalx1)
    # Lets build up the request...
    req[query] = tampvalx1
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :( But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # Or if the previous request has same content length as this tampered
    # request, then we have the vulnerability.
    #
    # NOTE: This algorithm has lots of room for improvement.
    if str(resp.status_code).startswith("2"):
        destx1 = 0x01
    if not any(search(s, resp.text, I) for s in TOKEN_ERRORS):
        destx2 = 0x01
    if len(body) == len(resp.text):
        destx3 = 0x01
    if (destx1 == 0x01 and destx2 == 0x01) or (destx3 == 0x01):
        verbout(
            colors.RED,
            " [-] Anti-CSRF Token tamper by "
            + colors.GREY
            + "index replacement"
            + colors.RED
            + " returns valid response!",
        )
        flagx1 = 0x01
        VulnLogger(
            url,
            "Anti-CSRF Token tamper by index replacement returns valid response.",
            "[i] POST Query: " + req.__str__(),
        )
    else:
        verbout(
            colors.RED, " [+] Token tamper in request does not return valid response!"
        )
        NovulLogger(
            url,
            "Anti-CSRF Token tamper by index replacement does not return valid response.",
        )

    # [Step 2]: Second we take the token and then remove a character
    # at a specific position and test the response body.
    verbout(
        colors.GR,
        "Tampering Token by " + colors.GREY + "index removal" + colors.END + "...",
    )
    tampvalx2 = replaceStrIndex(value, 3)
    verbout(colors.BLUE, " [+] Original Token: " + colors.CYAN + value)
    verbout(colors.BLUE, " [+] Tampered Token: " + colors.CYAN + tampvalx2)
    # Lets build up the request...
    req[query] = tampvalx2
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :( But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # NOTE: This algorithm has lots of room for improvement.
    if str(resp.status_code).startswith("2"):
        destx1 = 0x02
    if not any(search(s, resp.text, I) for s in TOKEN_ERRORS):
        destx2 = 0x02
    if len(body) == len(resp.text):
        destx3 = 0x02
    if (destx1 == 0x02 and destx2 == 0x02) or destx3 == 0x02:
        verbout(
            colors.RED,
            " [-] Anti-CSRF Token tamper by "
            + colors.GREY
            + "index removal"
            + colors.RED
            + " returns valid response!",
        )
        flagx2 = 0x01
        VulnLogger(
            url,
            "Anti-CSRF Token tamper by index removal returns valid response.",
            "[i] POST Query: " + req.__str__(),
        )
    else:
        verbout(
            colors.RED, " [+] Token tamper in request does not return valid response!"
        )
        NovulLogger(
            url,
            "Anti-CSRF Token tamper by index removal does not return valid response.",
        )

    # [Step 3]: Third we take the token and then remove the whole
    # anticsrf token and test the response body.
    verbout(
        colors.GR,
        "Tampering Token by " + colors.GREY + "Token removal" + colors.END + "...",
    )
    # Removing the anti-csrf token from request
    del req[query]
    verbout(colors.GREY, " [+] Removed token parameter from request!")
    # Lets build up the request...
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :(. But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # NOTE: This algorithm has lots of room for improvement.
    if str(resp.status_code).startswith("2"):
        destx1 = 0x03
    if not any(search(s, resp.text, I) for s in TOKEN_ERRORS):
        destx2 = 0x03
    if len(body) == len(resp.text):
        destx3 = 0x03
    if (destx1 == 0x03 and destx2 == 0x03) or destx3 == 0x03:
        verbout(
            colors.RED,
            " [-] Anti-CSRF"
            + colors.GREY
            + " Token removal"
            + colors.RED
            + " returns valid response!",
        )
        flagx3 = 0x01
        VulnLogger(
            url,
            "Anti-CSRF Token removal returns valid response.",
            "[i] POST Query: " + req.__str__(),
        )
    else:
        verbout(
            colors.RED, " [+] Token tamper in request does not return valid response!"
        )
        NovulLogger(url, "Anti-CSRF Token removal does not return valid response.")

    # If any of the forgeries worked...
    if (
        (flagx1 == 0x01 and flagx2 == 0x01)
        or (flagx1 == 0x01 and flagx3 == 0x01)
        or (flagx2 == 0x01 and flagx3 == 0x01)
    ):
        verbout(
            colors.RED,
            " [+] The tampered token value works! Endpoint "
            + colors.BR
            + " VULNERABLE to Replay Attacks "
            + colors.END
            + "!",
        )
        verbout(
            colors.ORANGE,
            " [-] The Tampered Anti-CSRF Token requested does NOT return a 40x or 50x response! ",
        )
        print(
            colors.RED
            + " [-] Endpoint "
            + colors.BR
            + " CONFIRMED VULNERABLE "
            + colors.END
            + colors.RED
            + " to Request Forgery Attacks..."
        )
        print(
            colors.ORANGE
            + " [!] Vulnerability Type: "
            + colors.BR
            + " Non-Unique Anti-CSRF Tokens in Requests "
            + colors.END
            + "\n"
        )
        VulnLogger(
            url,
            "Anti-CSRF Tokens are not Unique. Token Reuse detected.",
            "[i] Request: " + str(copy),
        )
        return True
    else:
        print(
            colors.RED
            + " [-] The Tampered Anti-CSRF Token requested returns a 40x or 50x response... "
        )
        print(
            colors.GREEN
            + " [-] Endpoint "
            + colors.BG
            + " NOT VULNERABLE "
            + colors.END
            + colors.ORANGE
            + " to CSRF Attacks..."
        )
        print(
            colors.ORANGE
            + " [!] CSRF Mitigation Method: "
            + colors.BG
            + " Unique Anti-CSRF Tokens "
            + colors.END
            + "\n"
        )
        NovulLogger(url, "Unique Anti-CSRF Tokens. No token reuse.")
        return False
