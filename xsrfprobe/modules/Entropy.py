#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import urllib.parse
from math import log

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.modules.Token import Token
from xsrfprobe.core.verbout import verbout
from xsrfprobe.files.discovered import REQUEST_TOKENS
from xsrfprobe.core.logger import VulnLogger, NovulLogger


def Entropy(req, url, headers, form, m_action, m_name=""):
    """
    This function has the work of comparing and
      calculating Shannon Entropy and related
           POST Based requests' security.
    """
    found = 0x00
    # The minimum length of a csrf token should be 6 bytes.
    min_length = 6

    # I have never seen a CSRF token longer than 256 bytes,
    # so the main concept here is doubling that and checking
    # to make sure we don't check parameters which are
    # files in multipart uploads or stuff like that.
    #
    # Multipart uploads usually have a trailing sequence of
    # characters which could be misunderstood as a CSRF token.
    # This is a very important step with respect to
    # decreasing [[ False Positives ]].
    max_length = 256 * 2

    # Shannon Entropy calculated for a particular CSRF token
    # should be at least 2.4. If the token entropy is less
    # than that, the application request can be easily
    # forged making the application vulnerable even in
    # presence of a CSRF token.
    min_entropy = 3.0

    # Check for common CSRF token names
    _q, para = Token(req, headers)
    if (para and _q) == None:
        VulnLogger(
            url,
            "Form Requested Without Anti-CSRF Token.",
            f"[i] Form Requested: {form}\n[i] Request Query: {req}",
        )
        return "", ""

    verbout(colors.RED, "\n +------------------------------+")
    verbout(colors.RED, " |   Token Strength Detection   |")
    verbout(colors.RED, " +------------------------------+\n")

    for para in REQUEST_TOKENS:
        # Coverting the token to a raw string, cause some special
        # chars might fu*k with the Shannon Entropy operation.
        value = r"%s" % para
        verbout(
            colors.CYAN,
            f" [!] Testing Anti-CSRF Token: {colors.ORANGE}{value}",
        )

        # Check length
        if len(value) <= min_length:
            print(
                f"{colors.RED} [-] CSRF Token Length less than 5 bytes. {colors.ORANGE}"
                "Token value can be guessed/bruteforced..."
            )
            print(
                f"{colors.ORANGE} [-] Endpoint likely {colors.BR} VULNERABLE {colors.END}"
                f"{colors.ORANGE} to CSRF Attacks..."
            )
            print(
                f"{colors.RED} [!] Vulnerability Type: "
                f"{colors.BR} Very Short/No Anti-CSRF Tokens {colors.END}"
            )
            VulnLogger(url, "Very Short Anti-CSRF Tokens.", f"Token: {value}")

        if len(value) >= max_length:
            print(
                colors.ORANGE
                + " [+] CSRF Token Length greater than "
                + colors.CYAN
                + "256 bytes. "
                + colors.GREEN
                + "Token value cannot be guessed/bruteforced..."
            )
            print(
                colors.GREEN
                + " [+] Endpoint likely "
                + colors.BG
                + " NOT VULNERABLE "
                + colors.END
                + colors.GREEN
                + " to CSRF Attacks..."
            )
            print(
                colors.GREEN
                + " [!] CSRF Mitigation Method: "
                + colors.BG
                + " Long Anti-CSRF Tokens "
                + colors.END
            )
            NovulLogger(url, "Long Anti-CSRF tokens with Good Strength.")
            found = 0x01

        # Checking entropy
        verbout(
            colors.O,
            "Proceeding to calculate "
            + colors.GREY
            + "Shannon Entropy"
            + colors.END
            + " of Token audited...",
        )

        entropy = calcEntropy(value)
        verbout(colors.GR, "Calculating Entropy...")
        verbout(colors.BLUE, " [+] Entropy Calculated: " + colors.CYAN + str(entropy))

        if entropy >= min_entropy:
            verbout(
                colors.ORANGE,
                " [+] Anti-CSRF Token Entropy Calculated is "
                + colors.BY
                + " GREATER than 3.0 "
                + colors.END
                + "... ",
            )
            print(
                colors.ORANGE
                + " [+] Endpoint "
                + colors.BY
                + " PROBABLY NOT VULNERABLE "
                + colors.END
                + colors.ORANGE
                + " to CSRF Attacks..."
            )
            print(
                colors.ORANGE
                + " [!] CSRF Mitigation Method: "
                + colors.BY
                + " High Entropy Anti-CSRF Tokens "
                + colors.END
            )
            NovulLogger(url, "High Entropy Anti-CSRF Tokens.")
            found = 0x01
        else:
            verbout(
                colors.RED,
                " [-] Anti-CSRF Token Entropy Calculated is "
                + colors.BY
                + " LESS than 3.0 "
                + colors.END
                + "... ",
            )
            print(
                colors.RED
                + " [-] Endpoint likely "
                + colors.BR
                + " VULNERABLE "
                + colors.END
                + colors.RED
                + " to CSRF Attacks inspite of CSRF Tokens..."
            )
            print(
                colors.RED
                + " [!] Vulnerability Type: "
                + colors.BR
                + " Low Entropy Anti-CSRF Tokens "
                + colors.END
            )
            VulnLogger(url, "Low Entropy Anti-CSRF Tokens.", "Token: " + value)

    if found == 0x00:
        if m_name:
            print(colors.RED + "\n +---------+")
            print(colors.RED + " |   PoC   |")
            print(colors.RED + " +---------+\n")
            print(colors.BLUE + " [+] URL : " + colors.CYAN + url)
            print(colors.CYAN + " [+] Name : " + colors.ORANGE + m_name)
            print(colors.GREEN + " [+] Action : " + colors.ORANGE + m_action)
        else:  # if value m_name not there :(
            print(colors.RED + "\n +---------+")
            print(colors.RED + " |   PoC   |")
            print(colors.RED + " +---------+\n")
            print(colors.BLUE + " [+] URL : " + colors.CYAN + url)
            print(colors.GREEN + " [+] Action : " + colors.ORANGE + m_action)
        # Print out the params
        print(
            colors.ORANGE + " [+] Query : " + colors.GREY + urllib.parse.urlencode(req)
        )
        print("")

    return (_q, para)  # Return the query paramter and anti-csrf token


def calcEntropy(data):
    """
    This function is used to calculate
              Shannon Entropy.
    """
    if not data:
        return 0

    entropy = 0  # init

    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * log(p_x, 2)

    return entropy
