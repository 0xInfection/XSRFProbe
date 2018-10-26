#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/theInfectedDrake/XSRFProbe

from re import search, I
from time import sleep
from files.config import *
from core.colors import *
from core.verbout import verbout
from urllib.parse import urlencode, unquote
from files.paramlist import COMMON_CSRF_NAMES

def Token(req):
    '''
    This method checks for whether anti-csrf tokens are
               present in the request. 
    '''

    param = '' # Initializing param
    query = ''
    # First lets have a look at core/config.py and see if its set 
    if TOKEN_CHECKS:
        # Lets check for the request values. But before that lets encode and unquote the request :D
        verbout(O,'Parsing request for detecting anti-csrf tokens...')
        try:
            con = unquote(urlencode(req)).split('&')
            for c in con:
                for name in COMMON_CSRF_NAMES:
                    qu = c.split('=')
                    if qu[0].lower() == name.lower():
                        print(color.GREEN+' [+] The form was requested with a '+color.ORANGE+'Anti-CSRF Token'+color.GREEN+'...')
                        print(color.GREY+' [+] Token Parameter : '+color.CYAN+qu[0]+'='+qu[1]+' ...')
                        query, param = qu[0], qu[1]
                        sleep(0.5)
                        break
            
        except Exception as e:
            print(R+'Request Parsing Execption!')
            print(R+'Error: '+str(e))           

        if param != '':
            return param
        else:
            print(color.RED+' [-] The form was requested without a '+color.GREY+'Anti-CSRF token'+color.RED+'...')
            print(color.ORANGE+' [-] Endpoint seems vulnerable to CSRF POST-Based Attacks...')
            return ''
