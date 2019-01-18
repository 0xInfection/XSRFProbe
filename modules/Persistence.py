#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import time, os, sys
from core.colors import *
from files.config import *
from re import search, I
from core.verbout import verbout
from core.request import Get
from core.randua import RandomAgent
from datetime import datetime
from core.utils import checkDuplicates
from core.logger import VulnLogger, NovulLogger
from urllib.parse import urlencode, unquote, urlsplit
# Response storing list init
resps = []

def Persistence(url, postq):
    '''
    The main idea behind this is to check for Cookie
                    Persistence.
    '''
    verbout(color.RED, '\n +-----------------------------------+')
    verbout(color.RED, ' |   Cookie Persistence Validation   |')
    verbout(color.RED, ' +-----------------------------------+\n')
    # Checking if user has supplied a value.
    verbout(GR,'Proceeding to test for '+color.GREY+'Cookie Persistence'+color.END+'...')
    time.sleep(0.7)
    found = 0x00
    # Now let the real test begin...
    #
    # [Step 1]: Lets examine now whether cookies set by server are persistent or not.
    # For this we'll have to parse the cookies set by the server and check for the
    # time when the cookie expires. Lets do it!
    #
    # First its time for GET type requests. Lets prepare our request.
    cookies = []
    verbout(C, 'Proceeding to test cookie persistence via '+color.CYAN+'Prepared GET Requests'+color.END+'...')
    gen_headers = HEADER_VALUES
    gen_headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36'
    if COOKIE_VALUE:
        for cookie in COOKIE_VALUE:
            gen_headers['Cookie'] = cookie
    verbout(GR,'Making the request...')
    req = Get(url, headers=gen_headers)
    if req.cookies:
        for cook in req.cookies:
            if cook.expires:
                print(color.GREEN+' [+] Persistent Cookies found in Response Headers!')
                print(color.GREY+' [+] Cookie: '+color.CYAN+cook.__str__())
                # cookie.expires returns a timestamp value. I didn't know it. :( Spent over 2+ hours scratching my head
                # over this, until I stumbled upon a stackoverflow answer comment. So to decode this, we'd need to
                # convert it a human readable format.
                print(color.GREEN+' [+] Cookie Expiry Period: '+color.ORANGE+datetime.fromtimestamp(cook.expires).__str__())
                found = 0x01
                VulnLogger(url, 'Persistent Session Cookies Found.', '[i] Cookie: '+req.headers.get('Set-Cookie'))
            else:
                NovulLogger(url, 'No Persistent Session Cookies.')
    if found == 0x00:
        verbout(R, 'No persistent session cookies identified on GET Type Requests!')
    verbout(C, 'Proceeding to test cookie persistence on '+color.CYAN+'POST Requests'+color.END+'...')
    # Now its time for POST Based requests.
    #
    # NOTE: As a standard method, every web application should supply a cookie upon a POST query.
    # It might or might not be in case of GET requests.
    if postq.cookies:
        for cookie in postq.cookies:
            if cookie.expires:
                print(color.GREEN+' [+] Persistent Cookies found in Response Headers!')
                print(color.GREY+' [+] Cookie: '+color.CYAN+cookie.__str__())
                # So to decode this, we'd need to convert it a human readable format.
                print(color.GREEN+' [+] Cookie Expiry Period: '+color.ORANGE+datetime.fromtimestamp(cookie.expires).__str__())
                found = 0x01
                VulnLogger(url, 'Persistent Session Cookies Found.', '[i] Cookie: '+req.headers.get('Set-Cookie'))
                print(color.ORANGE+' [!] Probable Insecure Practice: '+color.BR+' Persistent Session Cookies '+color.END)
            else:
                NovulLogger(url, 'No Persistent Cookies.')
    if found == 0x00:
        verbout(R, 'No persistent session cookies identified upon POST Requests!')
        print(color.GREEN+' [+] Endpoint might be '+color.BG+' NOT VULNERABLE '+color.END+color.GREEN+' to CSRF attacks!')
        print(color.GREEN+' [+] Detected : '+color.BG+' No Persistent Cookies '+color.END)

    # [Step 2]: The idea here is to try to identify cookie persistence on basis of observing
    # variations in cases of using different user-agents. For this test we have chosen 5 different
    # well used and common user-agents (as below) and then we observe the variation of set-cookie
    # header under different conditions.
    #
    # We'll test this method only when we haven't identified requests based on previous algo.
    if found != 0x01:
        verbout(C, 'Proceeding to test cookie persistence via '+color.CYAN+'User-Agent Alteration'+color.END+'...')
        user_agents = {
                'Chrome on Windows 8.1' : 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36',
                'Safari on iOS'         : 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4',
                'IE6 on Windows XP'     : 'Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)',
                'Opera on Windows 10'   : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991',
                'Chrome on Android'     : 'Mozilla/5.0 (Linux; U; Android 2.3.1; en-us; MID Build/GINGERBREAD) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1'
            }
        verbout(GR,'Setting custom generic headers...')
        gen_headers = HEADER_VALUES
        for name, agent in user_agents.items():
            verbout(C,'Using User-Agent : '+color.CYAN+name)
            verbout(GR,'Value : '+color.ORANGE+agent)
            gen_headers['User-Agent'] = agent
            if COOKIE_VALUE:
                for cookie in COOKIE_VALUE:
                    gen_headers['Cookie'] = cookie
            req = Get(url, headers=gen_headers)
            # We will append this to stuff only when set-cookie is being supplied.
            if req.headers.get('Set-Cookie'):
                resps.append(req.headers.get('Set-Cookie'))
        if resps:
            if checkDuplicates(resps):
                verbout(G, 'Set-Cookie header does not change with varied User-Agents...')
                verbout(color.GREEN, ' [+] Possible persistent session cookies found...')
                print(color.RED+' [+] Possible CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
                print(color.ORANGE+' [!] Probable Insecure Practice: '+color.BY+' Persistent Session Cookies '+color.END)
                VulnLogger(url, 'Persistent Session Cookies Found.', '[i] Cookie: '+req.headers.get('Set-Cookie'))
            else:
                verbout(G,'Set-Cookie header changes with varied User-Agents...')
                verbout(R,'No possible persistent session cookies found...')
                verbout(color.GREEN, ' [+] Endpoint '+color.BG+' PROBABLY NOT VULNERABLE '+color.END+color.GREEN+' to CSRF attacks!')
                verbout(color.ORANGE, ' [+] Application Practice Method Detected : '+color.BG+' No Persistent Cookies '+color.END)
                NovulLogger(url, 'No Persistent Cookies.')
        else:
            verbout(R, 'No cookies are being set on any requests.')