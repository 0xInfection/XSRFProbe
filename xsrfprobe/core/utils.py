#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import difflib
import string
from difflib import SequenceMatcher
from xsrfprobe.files.config import (
    FUZZY_MATCH_LIMIT,
    TRANSLATION_TABLE
)

def sameSequence(str1,str2):
    '''
    This function is intended to find same sequence between str1 and str2.
    '''
    seqMatch = SequenceMatcher(None, str1, str2)

    # Find match of longest sub-string
    # Output will be like Match(a=0, b=0, size=5)
    match = seqMatch.find_longest_match(0, len(str1), 0, len(str2))

    # Print longest substring
    if (match.size!=0):
        return (str1[match.a: match.a + match.size])
    else:
        return ''

def replaceStrIndex(text, index=0, replacement=''):
    '''
    This method returns a tampered string by replacement
    '''
    return '%s%s%s' % (text[:index], replacement, text[index+1:])

def checkDuplicates(iterable):
    '''
    This function works as a byte sequence checker for tuples passed onto this function.
    '''
    seen = set()
    for x in iterable:
        if x in seen:
            return True
        seen.add(x)
    return False

def byteString(s, encoding='utf8'):
    """
    Return a byte-string version of 's', encoded as utf-8.
    """
    try:
        s = s.encode(encoding)
    except (UnicodeEncodeError, UnicodeDecodeError):
        s = str(s)
    return s

def subSequence(str1, str2):
    '''
    Returns whether 'str1' and 'str2' are subsequence of one another.
    '''
    j = 0    # Index of str1
    i = 0    # Index of str2

    # Traverse both str1 and str2
    # Compare current character of str2 with
    # First unmatched character of str1
    # If matched, then move ahead in str1
    m = len(str1)
    n = len(str2)
    while j<m and i<n:
        if str1[j] == str2[i]:
            j = j+1
        i = i + 1

    # If all characters of str1 matched, then j is equal to m
    return j==m

def optimalFuzzyEqual(body1, body2, limit=FUZZY_MATCH_LIMIT):
    '''
    Fuzzy matches a response body with another to look for
    similarities in responses
    '''
    if limit == 0:
        return True

    if limit == 1.0:
        return body1==body2

    if len(body1) == 0 or len(body2) == 0:
        return len(body1) == len(body2)

    if len(body2) == len(body1) and body1 == body2:
        return True

    if limit > upperBoundSimilarity(len(body1), len(body2)):
        return False

    return None

def matchFuzzyEqual(str1, str2, limit):
    '''
    Returns a fuzzy value upon comparison
    '''
    optimalres = optimalFuzzyEqual(str1, str2, limit=limit)

    if optimalres is not None:
        return optimalres

    # we cannot optimise any further
    distance = matchRelative(str1, str2)
    return distance > limit

def separatorSplit(sequence):
    '''
    Splitting primitives as per a separator
    '''
    try:
        translated_seq = string.translate(sequence, TRANSLATION_TABLE)
    except UnicodeDecodeError:
        translated_seq = string.translate(sequence.encode('utf-8'), TRANSLATION_TABLE)
    return translated_seq.split('\0')

def matchRelative(str1, str2):
    '''
    Matches relative distance between two strings
    '''
    asp = separatorSplit(str1)
    bsp = separatorSplit(str2)

    return difflib.SequenceMatcher(None, asp, bsp).quick_ratio()

def upperBoundSimilarity(len1, len2):
    # first check if len2 is larger of both
    if len2 < len1:
        len1, len2 = len2, len1

    return (2.0 * len1) / (len1 + len2)

def matchResponses(req1, req2):
    '''
    Matches cont1 and cont2 to see of they are equal or not
    '''
    if req1.status_code != req2.status_code:
        return False

    if not matchFuzzyEqual(req1.text, req2.text, FUZZY_MATCH_LIMIT):
        return False

    return True
