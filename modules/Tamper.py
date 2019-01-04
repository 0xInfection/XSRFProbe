#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from re import search, I
from core.colors import *
from core.request import Post
from files.config import *
from core.verbout import verbout
from core.utils import replaceStrIndex
from files.paramlist import TOKEN_ERRORS
from urllib.parse import urlencode, quote
from core.logger import VulnLogger, NovulLogger

def Tamper(url, action, req, body, query, para):
    '''
    The main idea behind this is to tamper the Anti-CSRF tokens
          found and check the content length for related
                      vulnerabilities.
    '''
    verbout(color.RED, '\n +---------------------------------------+')
    verbout(color.RED, ' |   Anti-CSRF Token Tamper Validation   |')
    verbout(color.RED, ' +---------------------------------------+\n')
    # Null char flags (hex)
    flagx1 = 0x00
    flagx2 = 0x00
    flagx3 = 0x00
    verbout(GR, 'Proceeding for CSRF attack via Anti-CSRF token tampering...')
    # First of all lets get out token from request
    if para == '':
        return True
    # Coverting the token to a raw string, cause some special
    # chars might fu*k with the operation.
    value = r'%s' % para
    copy = req

    # Alright lets start...
    # [Step 1]: First we take the token and then replace a particular character
    # at a specific position (here at 4th position) and test the response body.
    #
    # Required check for checking if string at that position isn't the
    # same char we are going to replace with.
    verbout(GR, 'Tampering Token by '+color.GREY+'index replacement'+color.END+'...')
    if value[3] != 'a':
        tampvalx1 = replaceStrIndex(value, 3, 'a')
    else:
        tampvalx1 = replaceStrIndex(value, 3, 'x')
    verbout(color.BLUE, ' [+] Original Token: '+color.CYAN+value)
    verbout(color.BLUE, ' [+] Tampered Token: '+color.CYAN+tampvalx1)
    # Lets build up the request...
    req[query] = tampvalx1
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :( But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # Or if the previous request has same content length as this tampered
    # request, then we have the vulnerability.
    #
    # NOTE: This algorithm has lots of room for improvement.
    if ((str(resp.status_code).startswith('2') and not any(search(s, resp.text, I) for s in TOKEN_ERRORS))
        or (len(body) == len(resp.text))):
        verbout(color.RED,' [-] Anti-CSRF Token tamper by '+color.GREY+'index replacement'+color.RED+' returns valid response!')
        flagx1 = 0x01
        VulnLogger(url, 'Anti-CSRF Token tamper by index replacement returns valid response.', '[i] POST Query: '+req.__str__())
    else:
        verbout(color.RED,' [+] Token tamper in request does not return valid response!')
        NovulLogger(url, 'Anti-CSRF Token tamper by index replacement does not return valid response.')

    # [Step 2]: Second we take the token and then remove a character
    # at a specific position and test the response body.
    verbout(GR, 'Tampering Token by '+color.GREY+'index removal'+color.END+'...')
    tampvalx2 = replaceStrIndex(value, 3)
    verbout(color.BLUE, ' [+] Original Token: '+color.CYAN+value)
    verbout(color.BLUE, ' [+] Tampered Token: '+color.CYAN+tampvalx2)
    # Lets build up the request...
    req[query] = tampvalx2
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :( But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # NOTE: This algorithm has lots of room for improvement.
    if ((str(resp.status_code).startswith('2') and not any(search(s, resp.text, I) for s in TOKEN_ERRORS))
        or (len(body) == len(resp.text))):
        verbout(color.RED,' [-] Anti-CSRF Token tamper by '+color.GREY+'index removal'+color.RED+' returns valid response!')
        flagx2 = 0x01
        VulnLogger(url, 'Anti-CSRF Token tamper by index removal returns valid response.', '[i] POST Query: '+req.__str__())
    else:
        verbout(color.RED,' [+] Token tamper in request does not return valid response!')
        NovulLogger(url, 'Anti-CSRF Token tamper by index removal does not return valid response.')

    # [Step 3]: Third we take the token and then remove the whole
    # anticsrf token and test the response body.
    verbout(GR, 'Tampering Token by '+color.GREY+'Token removal'+color.END+'...')
    # Removing the anti-csrf token from request
    del req[query]
    verbout(color.GREY, ' [+] Removed token parameter from request!')
    # Lets build up the request...
    resp = Post(url, action, req)

    # If there is a 40x (Not Found) or a 50x (Internal Error) error,
    # we assume that the tamper did not work :(. But if there is a 20x
    # (Accepted) or a 30x (Redirection), then we know it worked.
    #
    # NOTE: This algorithm has lots of room for improvement.
    if ((str(resp.status_code).startswith('2') and not any(search(s, resp.text, I) for s in TOKEN_ERRORS))
        or (len(body) == len(resp.text))):
        verbout(color.RED,' [-] Anti-CSRF'+color.GREY+' Token removal'+color.RED+' returns valid response!')
        flagx3 = 0x01
        VulnLogger(url, 'Anti-CSRF Token removal returns valid response.', '[i] POST Query: '+req.__str__())
    else:
        verbout(color.RED,' [+] Token tamper in request does not return valid response!')
        NovulLogger(url, 'Anti-CSRF Token removal does not return valid response.')

    # If any of the forgeries worked...
    if (flagx1 or flagx2 or flagx3) == 0x01:
        verbout(color.RED,' [+] The tampered token value works! Endpoint '+color.BR+' VULNERABLE to Replay Attacks '+color.END+'!')
        verbout(color.ORANGE,' [-] The Tampered Anti-CSRF Token requested does NOT return a 40x or 50x response! ')
        print(color.RED+' [-] Endpoint '+color.BR+' CONFIRMED VULNERABLE '+color.END+color.RED+' to Request Forgery Attacks...')
        print(color.ORANGE+' [!] Vulnerability Type: '+color.BR+' Non-Unique Anti-CSRF Tokens in Requests '+color.END+'\n')
        VulnLogger(url, 'Anti-CSRF Tokens are not Unique. Token Reuse detected.', '[i] Request: '+str(copy))
        return True
    else:
        print(color.RED+' [-] The Tampered Anti-CSRF Token requested returns a 40x or 50x response... ')
        print(color.GREEN+' [-] Endpoint '+color.BG+' NOT VULNERABLE '+color.END+color.ORANGE+' to CSRF Attacks...')
        print(color.ORANGE+' [!] CSRF Mitigation Method: '+color.BG+' Unique Anti-CSRF Tokens '+color.END+'\n')
        NovulLogger(url, 'Unique Anti-CSRF Tokens. No token reuse.')
        return False
