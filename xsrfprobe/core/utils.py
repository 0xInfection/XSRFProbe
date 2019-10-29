#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from difflib import SequenceMatcher

def sameSequence(str1,str2):
    '''
    This function is intended to find same sequence
                between str1 and str2.
    '''
    # Initialize SequenceMatcher object with
    # Input string
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
    This method returns a tampered string by
                    replacement
    '''
    return '%s%s%s' % (text[:index], replacement, text[index+1:])

def checkDuplicates(iterable):
    '''
    This function works as a byte sequence checker for
            tuples passed onto this function.
    '''
    seen = set()
    for x in iterable:
        if x in seen:
            return True
        seen.add(x)
    return False

def byteString(s, encoding='utf8'):
    """
    Return a byte-string version of 's',
            Encoded as utf-8.
    """
    try:
        s = s.encode(encoding)
    except (UnicodeEncodeError, UnicodeDecodeError):
        s = str(s)
    return s

def subSequence(str1,str2):
    '''
    Returns whether 'str1' and 'str2' are subsequence
                    of one another.
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
