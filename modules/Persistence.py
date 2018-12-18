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
from core.utils import checkDuplicates
from core.logger import VulnLogger, NovulLogger
from urllib.parse import urlencode, unquote, urlsplit
# Response storing list init
resps = []

def Persistence(url):
    '''
    The main idea behind this is to check for Cookie
       Persistence (the cookie supplied by user).
    '''
    # Checking if user has supplied a value.
    if COOKIE_VALUE:
        verbout(GR,'Proceeding to test for '+color.GREY+'Cookie Persistence'+color.END+'...')
        time.sleep(0.7)
        # So the idea is to
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
            for cookie in COOKIE_VALUE:
                gen_headers['Cookie'] = cookie
            verbout(GR,'Making the request...')
            req = Get(url, headers=gen_headers)
            resps.append(req.headers.get('Set-Cookie'))
        if checkDuplicates(resps):
            verbout(G,'Set-Cookie header does not change with varied User-Agents...')
            verbout(R,'Possible persistent session cookies found...')
            print(color.RED+ ' [+] Possible CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
            print(color.ORANGE+' [!] Probable Insecure Practise: '+color.BR+' Persistent Session Cookies '+color.END)
            VulnLogger(url, 'Persistent Session Cookies.')
        else:
            verbout(G,'Set-Cookie header changes with varied User-Agents...')
            verbout(R,'No possible persistent session cookies found...')
            print(color.GREEN+' [+] Endpoint might be '+color.BG+' NOT VULNERABLE '+color.END+color.GREEN+' to CSRF attacks!')
            print(color.GREEN+' [+] Protection Method Detected : '+color.BG+' No Persistent Cookies '+color.END)
            NovulLogger(url, 'No Persistent Cookies.')
    else:
        verbout(R,'Skipping persistence checks as no cookie value supplied...')
