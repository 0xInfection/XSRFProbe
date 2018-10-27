#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import requests
from core.colors import *
from core.verbout import verbout
from files.config import REFERER_URL as fake_referer

def Referer(url):
    """
    Check if the remote web application verifies the Referer before
                    processing the HTTP request.
    """

    # Make the request normally and get content
    verbout(O,'Making request on normal basis...')
    req0x01 = requests.get(url, verify=True).text
    
    # Set a fake referer along with UA (pretending to be a 
    # legitimate request from a browser)
    verbout(GR,'Setting generic headers...')
    gen_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201',
                'Referer': fake_referer,
                'Connection': 'close'
            }
    # Make the request with different referer header and get the content
    verbout(O,'Making request with tampered headers...')
    req0x02 = requests.get(url, headers=gen_headers, verify=True).text
    
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
    # TODO: This algorithm has lots of room for improvement
    if len(req0x01) != len(req0x02):
        return True
    else:
        return False
