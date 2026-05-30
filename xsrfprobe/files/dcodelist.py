#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Token hash encoding detection db
HASH_DB = {
    "Blowfish (Eggdrop)": r"^\+[a-zA-Z0-9\/\.]{12}$",
    "Blowfish Crypt": r"^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$",
    "DES (Unix)": r"^.{0,2}[a-zA-Z0-9\/\.]{11}$",
    "MD5 (Unix)": r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$",
    "MD5 (APR)": r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$",
    "MD5 (MyBB)": r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$",
    "MD5 (ZipMonster)": r"^[a-fA-F0-9]{32}$",
    "MD5 crypt": r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$",
    "MD5 apache crypt": r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$",
    "MD5 (Joomla)": r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$",
    "MD5 (Wordpress)": r"^\$P\$[a-zA-Z0-9\/\.]{31}$",
    "MD5 (phpBB3)": r"^\$H\$[a-zA-Z0-9\/\.]{31}$",
    "MD5 (Cisco PIX)": r"^[a-zA-Z0-9\/\.]{16}$",
    "MD5 (osCommerce)": r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$",
    "MD5 (Palshop)": r"^[a-fA-F0-9]{51}$",
    "MD5 (IP.Board)": r"^[a-fA-F0-9]{32}:.{5}$",
    "MD5 (Chap)": r"^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$",
    "Lotus Domino": r"^\(?[a-zA-Z0-9\+\/]{20}\)?$",
    "Lineage II C4": r"^0x[a-fA-F0-9]{32}$",
    "CRC-96 (ZIP)": r"^[a-fA-F0-9]{24}$",
    "NT crypt": r"^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$",
    "Cisco Type 7": r"^[a-f0-9]{4,}$",
    "Adler32": r"^[a-f0-9]{8}$",
    "CRC-16-CCITT": r"^[a-fA-F0-9]{4}$",
    "MD5 (Generic)": r"^[a-fA-F0-9]{32}$",
    "SHA-1 (Generic)": r"^[a-fA-F0-9]{40}$",
    "CRC32 (Generic)": r"^[a-fA-F0-9]{8}$",
    "Base64 Encoded (Generic)": r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
}

# Protocol Types
PROTOCOLS = r"(.*\/)[^\/]*"
