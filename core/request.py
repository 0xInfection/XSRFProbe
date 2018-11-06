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
from files.config import *
from core.verbout import verbout
from core.logger import pheaders
from core.randua import RandomAgent
import urllib.request, urllib.parse, urllib.error # import ends

headers = HEADER_VALUES # set the headers

# Set Cookie
if COOKIE_VALUE:
    for cookie in COOKIE_VALUE:
        headers['Cookie'] = cookie
        
# Set User-Agent
if USER_AGENT_RANDOM:
    headers['User-Agent'] = RandomAgent()
else:
    headers['User-Agent'] = USER_AGENT


def Post(referer,action,form):
    '''
    The main use of this function is as a
            Form Requester [POST].
    '''
    headers['Referer'] = referer # set referer
    verbout(GR, 'Requesting the form...')
    data = urllib.parse.urlencode(form) # encode stuff to make callable
    try:
        request = urllib.request.Request(action, data)
        if USER_AGENT:
            request.add_header('User-Agent', USER_AGENT)
        else:
            request.add_header('User-Agent', RandomAgent())
        if COOKIE:
            request.add_header('User-Agent', COOKIE_VALUE)
        request.add_header('Referer', referer)
        response = urllib.request.urlopen(request, timeout=TIMEOUT_VALUE)
        return response.read() # read data content

    except urllib.error.HTTPError: # if error
        verbout(R,"HTTP Error 1 : "+action)
        return

    except ValueError: # again if valuerror
        verbout(R,"Value Error : "+action)
        return

    except:
        return '' # if at all nothing happens :(
        
def Get(url, headers=headers):
    '''
    The main use of this function is as a 
            Url Requester [GET].
    '''
    # We do not verify thr request while GET requests
    verbout(GR, 'Processing the GET Request...')
    req = requests.get(url, headers=headers, timeout=TIMEOUT_VALUE, verify=False)
    pheaders(req.headers)
    return req
