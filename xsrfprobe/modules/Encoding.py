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
from xsrfprobe.files.discovered import ANTI_CSRF_TOKENS

from xsrfprobe.files.dcodelist import HASH_DB

class Encoding:
    # Patterns that are too broad and match any random hex token
    EXCLUDED_PATTERNS = {
        "Cisco Type 7",  # ^[a-f0-9]{4,}$ — matches almost any hex token
        "Adler32",  # ^[a-f0-9]{8}$ — 8-char hex is common in CSRF tokens
        "CRC-16-CCITT",  # ^[a-fA-F0-9]{4}$ — 4-char hex
        "CRC32 (Generic)",  # ^[a-fA-F0-9]{8}$
        "CRC-96 (ZIP)",  # ^[a-fA-F0-9]{24}$
        "MD5 (Generic)",  # A random 32-hex-char token is NOT weak
        "MD5 (ZipMonster)",  # Same as above
        "SHA-1 (Generic)",  # A random 40-hex-char token is NOT weak
        "Base64 Encoded (Generic)",  # Base64 encoding doesn't mean predictable
    }

    def __init__(self):
        self.logger = logging.getLogger("TokenEncodingDetector")

    def detectEncoding(self, token: str) -> str | None:
        """
        Detect encoding type of Anti-CSRF tokens. Only flags structured
        hash formats (with salts/prefixes) that indicate predictable generation,
        not bare hex strings which could be strong random tokens.
        """
        self.logger.info("Detecting the encoding type of the Anti-CSRF token...")
        for hash_type, regex in HASH_DB.items():
            if hash_type in self.EXCLUDED_PATTERNS:
                continue
            if self.hashcheck(hash_type, re.compile(regex), token):
                return hash_type
        return None

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
                self.logger.warning("Detected structured hash format: %s on token: %s" % (encoding, token.token))
                return True
            else:
                self.logger.info("No weak encoding pattern detected for the token.")

        self.logger.info("Token encoding checks completed.")
        return False
