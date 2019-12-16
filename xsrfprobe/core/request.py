#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import requests, time
from urllib.parse import urljoin
from xsrfprobe.core.colors import *
from xsrfprobe.files.config import *
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.randua import RandomAgent
from xsrfprobe.files.discovered import FILES_EXEC
from xsrfprobe.core.logger import presheaders, preqheaders, ErrorLogger  # import ends

headers = HEADER_VALUES  # set the headers

# Set Cookie
if COOKIE_VALUE:
    headers['Cookie'] = ','.join(cookie for cookie in COOKIE_VALUE)

# Set User-Agent
if USER_AGENT_RANDOM:
    headers['User-Agent'] = RandomAgent()
if USER_AGENT:
    headers['User-Agent'] = USER_AGENT

def Post(url, action, data):
    '''
    The main use of this function is as a
           Form Requester [POST].
    '''
    global headers, TIMEOUT_VALUE, VERIFY_CERT
    time.sleep(DELAY_VALUE)  # If delay param has been supplied
    verbout(GR, 'Preparing the request...')
    if DISPLAY_HEADERS:
        preqheaders(headers)
    verbout(GR, 'Processing the '+color.GREY+'POST'+color.END+' Request...')
    main_url = urljoin(url, action)  # join url and action
    try:
        # Make the POST Request.
        response = requests.post(main_url, headers=headers, data=data,
                            timeout=TIMEOUT_VALUE, verify=VERIFY_CERT)
        if DISPLAY_HEADERS:
            presheaders(response.headers)
        return response  # read data content
    except requests.exceptions.HTTPError as e:  # if error
        verbout(R, "HTTP Error : "+main_url)
        ErrorLogger(main_url, e.__str__())
        return None
    except requests.exceptions.ConnectionError as e:
        verbout(R, 'Connection Aborted : '+main_url)
        ErrorLogger(main_url, e.__str__())
        return None
    except requests.exceptions.ReadTimeout as e:
        verbout(R, 'Exception at: '+color.GREY+url)
        verbout(R, 'Error: Read Timeout. Consider increasing the timeout value via --timeout.')
        ErrorLogger(url, e.__str__())
        return None
    except ValueError as e:  # again if valuerror
        verbout(R, "Value Error : "+main_url)
        ErrorLogger(main_url, e.__str__())
        return None
    except Exception as e:
        verbout(R, "Exception Caught: "+e.__str__())
        ErrorLogger(main_url, e.__str__())
        return None  # if at all nothing happens :(

def Get(url, headers=headers):
    '''
    The main use of this function is as a
            Url Requester [GET].
    '''
    global TIMEOUT_VALUE, VERIFY_CERT
    # We do not verify the request while GET requests
    time.sleep(DELAY_VALUE)  # We make requests after the time delay
    # Making sure the url is not a file
    if url.split('.')[-1].lower() in (FILE_EXTENSIONS or EXECUTABLES):
        FILES_EXEC.append(url)
        verbout(G, 'Found File: '+color.BLUE+url)
        return None
    try:
        verbout(GR, 'Preparing the request...')
        if DISPLAY_HEADERS:
            preqheaders(headers)
        verbout(GR, 'Processing the '+color.GREY+'GET'+color.END+' Request...')
        req = requests.get(url, headers=headers, timeout=TIMEOUT_VALUE,
                                    stream=False, verify=VERIFY_CERT)
        # Displaying headers if DISPLAY_HEADERS is 'True'
        if DISPLAY_HEADERS:
            presheaders(req.headers)
        # Return the object
        return req
    except requests.exceptions.MissingSchema as e:
        verbout(R, 'Exception at: '+color.GREY+url)
        verbout(R, 'Error: Invalid URL Format')
        ErrorLogger(url, e.__str__())
        return None
    except requests.exceptions.ReadTimeout as e:
        verbout(R, 'Exception at: '+color.GREY+url)
        verbout(R, 'Error: Read Timeout. Consider increasing the timeout value via --timeout.')
        ErrorLogger(url, e.__str__())
        return None
    except requests.exceptions.HTTPError as e:  # if error
        verbout(R, "HTTP Error Encountered : "+url)
        ErrorLogger(url, e.__str__())
        return None
    except requests.exceptions.ConnectionError as e:
        verbout(R, 'Connection Aborted : '+url)
        ErrorLogger(url, e.__str__())
        return None
    except Exception as e:
        verbout(R, "Exception Caught: "+e.__str__())
        ErrorLogger(url, e.__str__())
        return None
