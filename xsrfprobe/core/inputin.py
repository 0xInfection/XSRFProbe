#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection (@_tID)
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

import requests, re
from urllib.parse import urlparse
from xsrfprobe.core.colors import *
from xsrfprobe.core.verbout import verbout
from xsrfprobe.files.dcodelist import IP
from xsrfprobe.core.logger import ErrorLogger
from xsrfprobe.files.config import (
    SITE_URL, 
    CRAWL_SITE,
    VERIFY_CERT
)

def inputin():
    '''
    This module actually parses the url passed by the user.
    '''
    if SITE_URL:
        web = SITE_URL  # If already assigned
    if not web.endswith('/'):
        web = web + '/'
    if 'http' not in web:  # add protocol to site
        web = 'http://' + web
    try:
        web0 = urlparse(web).netloc
    except Exception:
        web0 = re.search(IP, web).group(0)
    try:
        print(O+'Testing site '+color.CYAN+web0+color.END+' status...')
        requests.get(web)  # test whether site is up or not
        print(color.GREEN+' [+] Site seems to be up!'+color.END)
    except requests.exceptions.RequestException:  # if site is down
        print(R+'Site seems to be down...')
        quit()
    # We'll test for endpoint only when the --crawl isn't supplied.
    if not CRAWL_SITE:
        try:
            print(O+'Testing '+color.CYAN+web.split('//')[1].split('/', 1)[1]+color.END+' endpoint status...')
            requests.get(web, verify=VERIFY_CERT)
            print(color.GREEN+' [+] Endpoint seems to be up!'+color.END)
        except requests.exceptions.RequestException as e:
            verbout(R, 'Endpoint error: '+web.split('//')[1].split('/', 1)[1])
            ErrorLogger(web0, e.__str__())
            quit()
        except Exception as e:
            verbout(R, "Exception Caught: "+e.__str__())
            ErrorLogger(web0, e.__str__())
            quit()
    if not web0.endswith('/'):
        web0 = web0 + '/'
    if web.split('//')[1] == web0:
        return web, ''
    return (web, web0)
