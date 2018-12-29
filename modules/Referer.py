#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import requests
from core.colors import *
from files.config import *
from core.verbout import verbout
from core.request import Get
from core.logger import VulnLogger, NovulLogger

def Referer(url):
    """
    Check if the remote web application verifies the Referer before
                    processing the HTTP request.
    """
    verbout(color.RED, '\n +--------------------------------------+')
    verbout(color.RED, ' |   Referer Based Request Validation   |')
    verbout(color.RED, ' +--------------------------------------+\n')
    # Make the request normally and get content
    verbout(O,'Making request on normal basis...')
    req0x01 = Get(url)

    # Set normal headers...
    verbout(GR,'Setting generic headers...')
    gen_headers = HEADER_VALUES

    # Set a fake Referer along with UA (pretending to be a
    # legitimate request from a browser)
    gen_headers['Referer'] = REFERER_URL

    # We put the cookie in request, if cookie supplied :D
    if COOKIE_VALUE:
        for cookie in COOKIE_VALUE:
            gen_headers['Cookie'] = cookie

    # Make the request with different referer header and get the content
    verbout(O,'Making request with '+color.CYAN+'Tampered Referer Header'+color.END+'...')
    req0x02 = Get(url, headers=gen_headers)

    # Comparing the length of the requests' responses. If both content
    # lengths are same, then the site actually does not validate referer
    # before processing the HTTP request which makes the site more
    # vulnerable to CSRF attacks.
    #
    # IMPORTANT NOTE: I'm aware that checking for the referer header does
    # NOT protect the application against all cases of CSRF, but it's a
    # very good first step. In order to exploit a CSRF in an application
    # that protects using this method an intruder would have to identify
    # other vulnerabilities, such as XSS or open redirects, in the same
    # domain.
    #
    # TODO: This algorithm has lots of room for improvement.
    if len(req0x01.content) != len(req0x02.content):
        print(color.GREEN+' [+] Endoint '+color.ORANGE+'Referer Validation'+color.GREEN+' Present!')
        print(color.GREEN+' [-] Heuristics reveal endpoint might be '+color.BG+' NOT VULNERABLE '+color.END+'...')
        print(color.ORANGE+' [+] Mitigation Method: '+color.BG+' Referer Based Request Validation '+color.END)
        NovulLogger(url, 'Presence of Referer Header based Request Validation.')
        return True
    else:
        verbout(R,'Endpoint '+color.RED+'Referer Validation Not Present'+color.END+'!')
        verbout(R,'Heuristics reveal endpoint might be '+color.BY+' VULNERABLE '+color.END+' to Origin Based CSRFs...')
        print(color.CYAN+ ' [+] Possible CSRF Vulnerability Detected : '+color.GREY+url+'!')
        print(color.ORANGE+' [+] Possible Vulnerability Type: '+color.BY+' No Referer Based Request Validation '+color.END)
        VulnLogger(url, 'No Referer Header based Request Validation presence.', '[i] Response Headers: '+str(req0x02.headers))
        return False
