#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from re import I
from xsrfprobe.files import config

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.core.verbout import verbout
from xsrfprobe.files import discovered
from urllib.parse import urlencode, unquote
from xsrfprobe.files.paramlist import COMMON_CSRF_NAMES, COMMON_CSRF_HEADERS


def Token(req, headers):
    """
    This method checks for whether Anti-CSRF Tokens are
               present in the request.
    """
    verbout(colors.RED, "\n +---------------------------+")
    verbout(colors.RED, " |   Anti-CSRF Token Check   |")
    verbout(colors.RED, " +---------------------------+\n")
    param = ""  # Initializing param
    query = ""
    found = False
    # First lets have a look at config.py and see if its set
    if config.TOKEN_CHECKS:
        verbout(colors.O, "Parsing request for detecting anti-csrf tokens...")
        try:
            # Lets check for the request values. But before that lets encode and unquote the request :D
            con = unquote(urlencode(req)).split("&")
            for c in con:
                for name in COMMON_CSRF_NAMES:  # Iterate over the list
                    qu = c.split("=")
                    # Search if the token is there in request...
                    if name.lower() in qu[0].lower():
                        verbout(
                            colors.GREEN,
                            " [+] The form was requested with an "
                            + colors.BG
                            + " Anti-CSRF Token "
                            + colors.END
                            + colors.GREEN,
                        )
                        verbout(
                            colors.GREY,
                            " [+] Token Parameter: "
                            + colors.CYAN
                            + qu[0]
                            + "="
                            + colors.ORANGE
                            + qu[1],
                        )
                        query, param = qu[0], qu[1]
                        # We are appending the token to a variable for further analysis
                        discovered.REQUEST_TOKENS.append(param)
                        found = True
                        break  # Break execution if a Anti-CSRF token is found
            # If we haven't found the Anti-CSRF token in query, we'll search for it in headers :)
            if not found:
                for key, value in headers.items():
                    for name in COMMON_CSRF_HEADERS:  # Iterate over the list
                        # Search if the token is there in request...
                        if name.lower() in key.lower():
                            verbout(
                                colors.GREEN,
                                " [+] The form was requested with an "
                                + colors.BG
                                + " Anti-CSRF Token Header "
                                + colors.END
                                + colors.GREEN,
                            )
                            verbout(
                                colors.GREY,
                                " [+] Token Parameter: "
                                + colors.CYAN
                                + qu[0]
                                + "="
                                + colors.ORANGE
                                + qu[1],
                            )
                            query, param = key, value
                            # We are appending the token to a variable for further analysis
                            discovered.REQUEST_TOKENS.append(param)
                            break  # Break execution if a Anti-CSRF token is found
        except Exception as e:
            verbout(colors.R, "Request Parsing Exception!")
            verbout(colors.R, "Error: " + e.__str__())
        if param:
            return (query, param)
        verbout(
            colors.ORANGE,
            " [-] The form was requested "
            + colors.RED
            + " Without an Anti-CSRF Token "
            + colors.END
            + colors.ORANGE
            + "...",
        )
        print(
            colors.RED
            + " [-] Endpoint seems "
            + colors.BR
            + " VULNERABLE "
            + colors.END
            + colors.RED
            + " to "
            + colors.BR
            + " POST-Based Request Forgery "
            + colors.END
        )
        return (None, None)
