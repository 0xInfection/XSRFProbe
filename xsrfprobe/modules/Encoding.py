#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import logging
from files.discovered import ANTI_CSRF_TOKENS

from files.dcodelist import HASH_DB

class Encoding:
    def __init__(self):
        self.logger = logging.getLogger("TokenEncodingDetector")

    def detectEncoding(self, token: str) -> str | None:
        """
        This function is for detecting the encoding type of
                Anti-CSRF tokens based on pre-defined
                        regular expressions.
        """
        self.logger.info("Detecting the encoding type of the Anti-CSRF token...")
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
        for hash_type, regex in HASH_DB.items():
            if self.hashcheck(hash_type, re.compile(regex), token):
                return hash_type

    def hashcheck(self, hashtype: str, regexstr: re.Pattern, token: str) -> bool:
        self.logger.debug("Matching encoding type: %s..." % (hashtype))
        if regexstr.match(token):
            return True
        return False

    def performTokenEncodingChecks(self) -> bool:
        """
        This function performs the token encoding checks.
        """
        self.logger.info("Performing Anti-CSRF token encoding checks...")
        for token in ANTI_CSRF_TOKENS:
            encoding = self.detectEncoding(token.token)
            if encoding:
                self.logger.warning("Detected weak hash encoding type: %s on token: %s" % (encoding, token.token))
                return True
            else:
                self.logger.info("No encoding detected for the token.")

        self.logger.info("Token encoding checks completed.")
        return False
