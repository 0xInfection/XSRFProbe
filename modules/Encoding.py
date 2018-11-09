#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from re import search
from core.verbout import verbout
from files.dcodelist import token

def Encoding(val):
    verbout(G, 'Proceeding to detect encoding of Anti-CSRF Token...')

def encodeDetect(val):
    '''
    The main target of this method is to detect if there is
            any encoding in the string value passed.
    '''
    value = makeAscii()

def makeAscii(value, encoding='latin-1'):
    '''
    The main target of this function is to ensure that 'value'
                has all characters in ASCII.
    '''
    if isinstance(value, (str, bytearray)):
        return s.decode(encoding, 'strict')
