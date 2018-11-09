#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# This file contains various regex expressions for detecting the
# encoding type of strings.

# Get rid of Double ../../
RID_DOUBLE = r'/\.\./'

# Get rid of ./'s
RID_SINGLE = r'\./'

# Complier based regex
RID_COMPILE = r'/[^/]*/../'

# Number based.
NUM_SUB = r'=[0-9]+'

# Number based compile.
NUM_COM = r'(title=)[^&]*'

# Binary strings.
BINARY = r'^[01]+$'

# Decimal Strings.
DEC = r'&#.*;+'

# Protocol Types
PROTOCOLS = r'(.*\/)[^\/]*'

# Token encoding detection
token = {
        # Base64 encoded strings.
        'BASE64': r'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$',
        # SHA2 encoded strings/hashes.
        'SHA2'  : r'^([a-f0-9]{64})$',
        # SHA1 encoded strings/hashes.
        'SHA1'  : r'^([a-f0-9]{40})$',
        # MD5 encoded strings/hashes.
        'MD5'   : r'^([a-f0-9]{32})$',
        # Hex Strings.
        'HEX'   : r'^(0x|0X)?[a-fA-F0-9]+$',
        # FromChar Strings
        'FROMCHAR': r'\d*, \d*,''
        }
