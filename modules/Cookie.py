#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from core.colors import *
from files.config import *
from re import search, I
from core.randua import randua
from core.verbout import verbout
from core.request import norm_requester
from urllib.parse import urlencode, unquote

found = 0x00
resps = []


def Cookie(url):
    '''
    This module is for checking the varied HTTP Cookies
            and the related security on them to
                    prevent CSRF attacks.
    '''
    if COOKIE_BASED:
        SameSite(url)
        Persistence(url)

def Persistence(url):
    verbout(GR,'Proceeding to test for '+color.GREY+'Cookie Persistence'+color.END+'...')
    time.sleep(0.7)
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
        verbout(B,'Using User-Agent : '+C+name)
        verbout(GR,'UA Value : '+O+agent)
        gen_headers['User-Agent'] = agent
        verbout(GR,'Making the request...')
        req = norm_requester(web, headers=headers)
        resps.append(req.headers.get('Set-Cookie'))
        c+=1
    if has_duplicates(resps):
        verbout(G,'Set-Cookie header does not change with varied User-Agents...')

def SameSite(url):
    '''
    This function parses and verifies the cookies with
                    SameSite Flags.
    '''
    getreq = norm_requester(url)
    head = getreq.headers
    for h in head:
        #if search('cookie', h, I) or search('set-cookie', h, I):
        if 'Cookie'.lower() in h.lower():
            verbout(G,'Found cookie header value...')
            cookval = head[h]
            verbout(color.ORANGE+'Cookie Received: '+color.CYAN+str(coolkieval))
            m = cookieval.split(';').strip()
            verbout(GR,'Examining Cookie...')
            for q in m:
                if search('SameSite', q, I):
                    verbout(G,'SameSite Flag '+color.ORANGE+' detected on cookie!')
                    found = 0x01
                    q = q.split('=')[1]
                    verbout
                    break
        else:
            verbout(R, 'No cookie value reflection found...')

    if found = 0x01:
        print(color.GREEN+' [+] Endpoint '+color.BG+' NOT VULNERABLE '+color.END+color.GREEN+' to ANY type of CSRF attacks!')
        print(color.GREEN+' [+] Protection Method Detected : '+color.BG+' SameSite Flag on Cookies ')
    else:
        verbout(R,' [+] Endpoint '+color.ORANGE+'SameSite Flag Cookie Validation'+color.END+' Not Present!')
        verbout(R,' [!] Heuristic(s) reveal endpoint might be '+color.BR+' VULNERABLE '+color.END+' to CSRFs...')
        print(color.GREEN+ ' [+] Possible CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
        print(color.ORANGE+' [!] Possible Vulnerability Type: '+color.BR+' No SameSite Flag on Cookies '+color.END)                

def has_duplicates(iterable):
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
