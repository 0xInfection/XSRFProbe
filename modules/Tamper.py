#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from re import search, I
from core.colors import *
from core.request import Post
from files.config import *
from core.verbout import verbout
from urllib.parse import urlencode, quote

# Null char flags (hex)
flagx1 = 0x00
flagx2 = 0x00

def Tamper(url, action, req, body, query, para):
    '''
    The main idea behind this is to tamper the Anti-CSRF tokens
          found and check the content length for related
                      vulnerabilities.
    '''
    verbout(GR, 'Proceeding for CSRF attack via Anti-CSRF token tampering...')
    # First of all lets get out token from request
    if para == '':
        return True
    # Coverting the token to a raw string, cause some special
    # chars might fu*k with the Shannon Entropy operation.
    value = r'%s' % para

    # Alright lets start...
    # [Step 1]: First we take the token and then replace a char
    # at a specific position and test the response body.
    #
    # Required check for checking if string at that position isn't the
    # same char we are going to replace with.
    verbout(GR, 'Tampering Token by index replacement...')
    if value[3] != 'a':
        tampvalx1 = replaceStrIndex(value, 3, 'a')
    else:
        tampvalx1 = replaceStrIndex(value, 3, 'x')
    verbout(G, 'Tampered Token: '+color.CYAN+tampvalx1)
    # Lets build up the request...
    req[query] = tampvalx1
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :( But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # NOTE: This algorithm has lots of room for improvment.
    if not str(resp.status_code).startswith('40') or not str(resp.status_code).startswith('50'):
        flagx1 = 0x01

    # [Step 2]: Second we take the token and then remove a char
    # at a specific position and test the response body.
    #
    # Required check for checking if string at that position isn't the
    # same char we are going to replace with.
    verbout(GR, 'Tampering Token by index removal...')
    tampvalx2 = replaceStrIndex(value, 3)
    verbout(G, 'Tampered Token: '+color.CYAN+tampvalx1)
    # Lets build up the request...
    req[query] = tampvalx2
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :( But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # NOTE: This algorithm has lots of room for improvment.
    if not str(resp.status_code).startswith('40') or not str(resp.status_code).startswith('50'):
        flagx2 = 0x01

    # If any of the forgeries worked...
    if flagx1 == 0x01 or flagx2 == 0x01:
        verbout(color.GREEN,' [+] The tampered token value works!')
        verbout(color.GREEN,' [-] The Tampered Anti-CSRF Token requested does NOT return a 40x or 50x response! ')
        print(color.ORANGE+' [-] Endpoint '+color.BR+' CONFIRMED VULNERABLE '+color.END+color.ORANGE+' to Request Forgery Attacks...')
        print(color.ORANGE+' [!] Vulnerability Type: '+color.BG+' Non-Unique Anti-CSRF Tokens in Requests '+color.END)
    else:
        print(color.RED+' [-] The Tampered Anti-CSRF Token requested returns a 40x or 50x response... ')
        print(color.ORANGE+' [-] Endpoint '+color.BG+' NOT VULNERABLE '+color.END+color.ORANGE+' to CSRF Attacks...')
        print(color.ORANGE+' [!] CSRF Mitigation Method: '+color.BG+' Unique Anti-CSRF Tokens '+color.END)

def replaceStrIndex(text, index=0, replacement=''):
    ''' This method returns a tampered string by replacement '''
    return '%s%s%s' % (text[:index], replacement, text[index+1:])

