#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from re import finditer
from core.colors import *
from core.verbout import verbout
from files.dcodelist import hashes

def Encoding(val):
    '''
    This function is for detecting the encoding type of
            Anti-CSRF tokens based on pre-defined
                    regular expressions.
    '''
    found = 0x00
    for h in hashes:
        txt = hashcheck(h[0], h[1], val)
        if txt is not None:
            found = 0x01
            print(color.GREEN+' [+] The Token Encoding Detected: '+color.BG+' '+hashtype+' '+color.END)
            break  # Break the execution if token encoding detected
    if found == 0x00:
        print(color.RED+' [-] No Token Encoding detected.')

def hashcheck(hashtype, regexstr, data):
    verbout(G, 'Proceeding to detect encoding of Anti-CSRF Token...')
    try:
        valid_hash = finditer(regexstr, data)
        result = [match.group(0) for match in valid_hash]
        if result:
            return hashtype
    except Exception:
        pass
    return None

