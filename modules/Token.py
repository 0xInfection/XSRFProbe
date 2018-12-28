#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from files import config
from re import search, I
from time import sleep
from core.colors import *
from core.verbout import verbout
from files.discovered import REQUEST_TOKENS
from urllib.parse import urlencode, unquote
from files.paramlist import COMMON_CSRF_NAMES, COMMON_CSRF_HEADERS

def Token(req, headers):
    '''
    This method checks for whether Anti-CSRF Tokens are
               present in the request.
    '''
    verbout(color.RED, '\n +---------------------------+')
    verbout(color.RED, ' |   Anti-CSRF Token Check   |')
    verbout(color.RED, ' +---------------------------+\n')
    param = ''  # Initializing param
    query = ''
    found = False
    # First lets have a look at config.py and see if its set
    if config.TOKEN_CHECKS:
        verbout(O,'Parsing request for detecting anti-csrf tokens...')
        try:
            # Lets check for the request values. But before that lets encode and unquote the request :D
            con = unquote(urlencode(req)).split('&')
            for c in con:
                for name in COMMON_CSRF_NAMES:  # Iterate over the list
                    qu = c.split('=')
                    # Search if the token is there in request...
                    if name.lower() in qu[0].lower():
                        verbout(color.GREEN, ' [+] The form was requested with an '+color.BG+' Anti-CSRF Token '+color.END+color.GREEN+'!')
                        verbout(color.GREY, ' [+] Token Parameter: '+color.CYAN+qu[0]+'='+color.ORANGE+qu[1])
                        query, param = qu[0], qu[1]
                        # We are appending the token to a variable for further analysis
                        REQUEST_TOKENS.append(param)
                        found = True
                        break  # Break execution if a Anti-CSRF token is found
            # If we haven't found the Anti-CSRF token in query, we'll search for it in headers :)
            if not found:
                for key, value in headers.items():
                    for name in COMMON_CSRF_HEADERS:  # Iterate over the list
                        # Search if the token is there in request...
                        if name.lower() in key.lower():
                            verbout(color.GREEN, ' [+] The form was requested with an '+color.BG+' Anti-CSRF Token Header '+color.END+color.GREEN+'!')
                            verbout(color.GREY, ' [+] Token Parameter: '+color.CYAN+qu[0]+'='+color.ORANGE+qu[1])
                            query, param = key, value
                            # We are appending the token to a variable for further analysis
                            REQUEST_TOKENS.append(param)
                            break  # Break execution if a Anti-CSRF token is found
        except Exception as e:
            verbout(R, 'Request Parsing Exception!')
            verbout(R, 'Error: '+e.__str__())
        if param:
            return (query, param)
        verbout(color.ORANGE,' [-] The form was requested '+color.RED+' Without an Anti-CSRF Token '+color.END+color.ORANGE+'...')
        print(color.RED+' [-] Endpoint seems '+color.BR+' VULNERABLE '+color.END+color.RED+' to '+color.BR+' POST-Based Request Forgery '+color.END)
        return (None, None)
