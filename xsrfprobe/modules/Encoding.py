#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from time import sleep
from re import search

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

from xsrfprobe.core.verbout import verbout
from xsrfprobe.files.dcodelist import HASH_DB


def Encoding(val):
    """
    This function is for detecting the encoding type of
            Anti-CSRF tokens based on pre-defined
                    regular expressions.
    """
    found = 0x00
    if not val:
        return (found, None)
    verbout(colors.RED, "\n +------------------------------+")
    verbout(colors.RED, " |   Token Encoding Detection   |")
    verbout(colors.RED, " +------------------------------+\n")
    verbout(colors.GR, "Proceeding to detect encoding of Anti-CSRF Token...")
    # So the idea right here is to detect whether the Anti-CSRF tokens
    # are encoded in some form or the other.
    #
    # Often in my experience with web applications, I have found that
    # most of the Anti-CSRF tokens are encoded (mostly MD5 or SHA*).
    # In those cases, I have found that the Anti-CSRF tokens follow a
    # specific pattern. For example, every request has a specific
    # iteration number, if the previous request is 144, and MD5 encrypted
    # it turns out to be 0a09c8844ba8f0936c20bd791130d6b6, then it is
    # not at all strong, since the next request is probably 145 and can
    # be easily forged! Ofc, if there is no salt in the encryption.
    #
    # This module aims to automate and simplify the task. ;)
    for h in HASH_DB:
        txt = hashcheck(h[0], h[1], val)
        if txt is not None:
            found = 0x01
            verbout(
                colors.RED, "\n [+] Anti-CSRF Token is detected to be String Encoded!"
            )
            print(
                colors.GREEN
                + " [+] Token Encoding Detected: "
                + colors.BG
                + " "
                + txt
                + " "
                + colors.END
            )
            print(
                colors.ORANGE
                + " [-] Endpoint likely "
                + colors.BR
                + " VULNERABLE "
                + colors.END
                + colors.ORANGE
                + " to CSRF Attacks inspite of CSRF Tokens."
            )
            print(
                colors.ORANGE
                + " [!] Vulnerability Type: "
                + colors.BR
                + " String Encoded Anti-CSRF Tokens "
                + colors.END
            )
            print(
                colors.RED
                + " [-] The Tokens might be easily Decrypted and can be Forged!"
            )
            break  # Break the execution if token encoding detected
    if found == 0x00:
        print(
            colors.RED
            + "\n [-] "
            + colors.BR
            + " No Token Encoding Detected. "
            + colors.END,
            end="\n\n",
        )
    sleep(0.8)
    return (found, txt)


def hashcheck(hashtype, regexstr, data):
    try:
        print(colors.O, "Matching Encoding Type: %s" % (hashtype), end="\r", flush=True)
        sleep(0.1)
        if search(regexstr, data):
            return hashtype
    except KeyboardInterrupt:
        pass
    return None


# if __name__ == '__main__':
#   Encoding('38c4658d5308897a92cef9e113aefc3a')
