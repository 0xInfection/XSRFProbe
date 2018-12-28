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
from .Persistence import Persistence
from core.logger import VulnLogger, NovulLogger
from urllib.parse import urlencode, unquote, urlsplit

resps = []

def Cookie(url, request):
    '''
    This module is for checking the varied HTTP Cookies
            and the related security on them to
                    prevent CSRF attacks.
    '''
    verbout(GR, 'Proceeding for cookie based checks...')
    SameSite(url)
    Persistence(url, request)

def SameSite(url):
    '''
    This function parses and verifies the cookies with
                    SameSite Flags.
    '''
    verbout(color.RED, '\n +------------------------------------+')
    verbout(color.RED, ' |   Cross Origin Cookie Validation   |')
    verbout(color.RED, ' +------------------------------------+\n')
    # Some Flags we'd need later...
    foundx1 = 0x00
    foundx2 = 0x00
    foundx3 = 0x00
    # Step 1: First we check that if the server returns any
    # SameSite flag on Cookies with the same Referer as the netloc
    verbout(color.GREY,' [+] Lets examine how server reacts to same referer...')
    gen_headers = HEADER_VALUES
    gen_headers['User-Agent'] = USER_AGENT or RandomAgent()
    verbout(GR,'Setting Referer header same as host...')
    # Setting the netloc as the referer for the first check.
    gen_headers['Referer'] = urlsplit(url).netloc
    if COOKIE_VALUE:
        for cook in COOKIE_VALUE:
            gen_headers['Cookie'] = cook
    getreq = Get(url, headers=gen_headers)  # Making the request
    head = getreq.headers
    for h in head:
        #if search('cookie', h, I) or search('set-cookie', h, I):
        if 'Cookie'.lower() in h.lower():
            verbout(G,'Found cookie header value...')
            cookieval = head[h]
            verbout(color.ORANGE,' [+] Cookie Received: '+color.CYAN+str(cookieval))
            m = cookieval.split(';')
            verbout(GR,'Examining Cookie...')
            for q in m:
                if search('SameSite', q, I):
                    verbout(G,'SameSite Flag '+color.ORANGE+' detected on cookie!')
                    foundx1 = 0x01
                    q = q.split('=')[1].strip()
                    verbout(C, 'Cookie: '+color.ORANGE+q)
                    break
        else:
            foundx3 = 0x02
    if foundx1 == 0x01:
        verbout(R,' [+] Endpoint '+color.ORANGE+'SameSite Flag Cookie Validation'+color.END+' Present!')

    # Step 2: Now we check security mechanisms when the Referer is
    # different, i.e. request originates from a different url other
    # than the host. (This time without the Cookie assigned)
    verbout(color.GREY,' [+] Lets examine how server reacts to a fake external referer...')
    gen_headers = HEADER_VALUES
    gen_headers['User-Agent'] = USER_AGENT or RandomAgent()  # Setting user-agents
    # Assigning a fake referer for the second check, but no cookie.
    gen_headers['Referer'] = REFERER_URL
    getreq = Get(url, headers=gen_headers)
    head = getreq.headers  # Getting headers from requests
    for h in head:
        # If search('cookie', h, I) or search('set-cookie', h, I):
        if 'Cookie'.lower() in h.lower():
            verbout(G,'Found cookie header value...')
            cookieval = head[h]
            verbout(color.ORANGE,' [+] Cookie Received: '+color.CYAN+str(cookieval))
            m = cookieval.split(';')
            verbout(GR,'Examining Cookie...')
            for q in m:
                if search('SameSite', q, I):
                    verbout(G,'SameSite Flag '+color.ORANGE+' detected on cookie!')
                    foundx2 = 0x01
                    q = q.split('=')[1].strip()
                    verbout(C, 'Cookie: '+color.ORANGE+q)
                    break
        else:
            foundx3 = 0x02

    if foundx1 == 0x01:
        verbout(R,' [+] Endpoint '+color.ORANGE+'SameSite Flag Cookie Validation'+color.END+' Present!')

    # Step 3: And finally comes the most important step. Lets see how
    # the site reacts to a valid cookie (ofc supplied by the user) coming
    # from a a different site, i.e Referer set to other than host.
    # This is the most crucial part of the detection.
    #
    # TODO: Improve the logic in detection.
    verbout(color.GREY,' [+] Lets examine how server reacts to valid cookie from a different referer...')
    gen_headers = HEADER_VALUES
    gen_headers['User-Agent'] = USER_AGENT or RandomAgent()
    # Assigning a fake referer for third request, this time with cookie ;)
    gen_headers['Referer'] = REFERER_URL
    if COOKIE_VALUE:
        for cook in COOKIE_VALUE:
            gen_headers['Cookie'] = cook
    getreq = Get(url, headers=gen_headers)
    head = getreq.headers
    for h in head:
        # if search('cookie', h, I) or search('set-cookie', h, I):
        if 'Cookie'.lower() in h.lower():
            verbout(G,'Found cookie header value...')
            cookieval = head[h]
            verbout(color.ORANGE,' [+] Cookie Received: '+color.CYAN+str(cookieval))
            m = cookieval.split(';')
            verbout(GR,'Examining Cookie...')
            for q in m:
                if search('samesite', q.lower(), I):
                    verbout(G,'SameSite Flag '+color.ORANGE+' detected on cookie on Cross Origin Request!')
                    foundx3 = 0x01
                    q = q.split('=')[1].strip()
                    verbout(C, 'Cookie: '+color.ORANGE+q)
                    break
        else:
            foundx3 = 0x02

    if foundx1 == 0x01:
        verbout(R,'Endpoint '+color.ORANGE+'SameSite Flag Cookie Validation'+color.END+' is Present!')

    if (foundx1 == 0x01 and foundx3 == 0x00) and (foundx2 == 0x00 or foundx2 == 0x01):
        print(color.GREEN+' [+] Endpoint '+color.BG+' NOT VULNERABLE to ANY type of CSRF attacks! '+color.END)
        print(color.GREEN+' [+] Protection Method Detected : '+color.BG+' SameSite Flag on Cookies '+color.END)
        NovulLogger(url, 'SameSite Flag set on Cookies on Cross-Origin Requests.')
        # If a SameSite flag is set on cookies, then the application is totally fool-proof
        # against CSRF attacks unless there is some XSS stuff on it. So for now the job of
        # this application is done. We need to confirm before we quit.
        oq = input(color.BLUE+' [+] Continue scanning? (y/N) :> ')
        if oq.lower().startswith('n'):
            sys.exit('\n'+R+'Shutting down XSRFProbe...\n')
    elif foundx1 == 0x02 and foundx2 == 0x02 and foundx3 == 0x02:
        print(color.GREEN+' [+] Endpoint '+color.BG+' NOT VULNERABLE '+color.END+color.GREEN+' to CSRF attacks!')
        print(color.GREEN+' [+] Type: '+color.BG+' No Cookie Set while Cross Origin Requests '+color.END)
        NovulLogger(url, 'No cookie set on Cross-Origin Requests.')
    else:
        verbout(R,'Endpoint '+color.ORANGE+'Cross Origin Cookie Validation'+color.END+' Not Present!')
        verbout(R,'Heuristic(s) reveal endpoint might be '+color.BY+' VULNERABLE '+color.END+' to CSRFs...')
        print(color.GREEN+ ' [+] Possible CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
        print(color.ORANGE+' [!] Possible Vulnerability Type: '+color.BY+' No Cross Origin Cookie Validation Presence '+color.END)
        VulnLogger(url, 'No Cookie Validation on Cross-Origin Requests.', '[i] Headers: '+str(head))
