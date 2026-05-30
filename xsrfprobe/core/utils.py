#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import logging
from difflib import SequenceMatcher

import xsrfprobe.files.config as config


def sameSequence(str1, str2):
    """
    This function is intended to find same sequence
                between str1 and str2.
    """
    seqMatch = SequenceMatcher(None, str1, str2)
    match = seqMatch.find_longest_match(0, len(str1), 0, len(str2))

    if match.size != 0:
        return str1[match.a : match.a + match.size]
    else:
        return ""


def byteString(s, encoding="utf8"):
    """
    Return a byte-string version of 's',
            Encoded as utf-8.
    """
    try:
        s = s.encode(encoding)
    except (UnicodeEncodeError, UnicodeDecodeError):
        s = str(s)
    return s


def calcLogLevel(args):
    '''
    Calculate logging level based on verbose options
    '''
    baseloglevel = config.DEBUG_LEVEL

    if args.verbose:
        baseloglevel = logging.INFO

    if args.debug:
        baseloglevel = logging.DEBUG

    if args.quiet:
        baseloglevel = logging.CRITICAL

    return baseloglevel
