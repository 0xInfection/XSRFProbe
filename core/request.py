#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import requests, time
from core.colors import *
from files.config import *
from core.verbout import verbout
from core.logger import pheaders
from core.randua import RandomAgent
from urllib.parse import urljoin  # import ends

headers = HEADER_VALUES  # set the headers

# Set Cookie
if COOKIE_VALUE:
    for cookie in COOKIE_VALUE:
        headers['Cookie'] = cookie

# Set User-Agent
if USER_AGENT_RANDOM:
    headers['User-Agent'] = RandomAgent()
else:
    headers['User-Agent'] = USER_AGENT


def Post(url, action, data):
    '''
    The main use of this function is as a
           Form Requester [POST].
    '''
    time.sleep(DELAY_VALUE)  # If delay param has been supplied
    verbout(GR, 'Processing the POST Request...')
    main_url = urljoin(url, action)  # encode stuff to make callable
    try:
        # Make the POST Request.
        response = requests.post(main_url, headers=headers, data=data, timeout=TIMEOUT_VALUE)
        return response  # read data content

    except requests.exceptions:  # if error
        verbout(R,"HTTP Error : "+action)
        return

    except ValueError:  # again if valuerror
        verbout(R,"Value Error : "+action)
        return

    except:
        return ''  # if at all nothing happens :(

def Get(url, headers=headers):
    '''
    The main use of this function is as a
            Url Requester [GET].
    '''
    # We do not verify thr request while GET requests
    verbout(GR, 'Processing the GET Request...')
    time.sleep(DELAY_VALUE)  # We make requests after the time delay
    req = requests.get(url, headers=headers, timeout=TIMEOUT_VALUE, verify=False)
    pheaders(req.headers)
    return req
