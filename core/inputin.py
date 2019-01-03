#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection (@_tID)
#This module requires XSRF-Probe
#https://github.com/0xInfection/XSRF-Probe

import socket, requests
from tld import get_fld
from core.colors import *
from core.verbout import verbout
from files.config import SITE_URL, CRAWL_SITE

def inputin():
    '''
    This module actually parses the url passed by the user.
    '''
    if SITE_URL:
        web = SITE_URL # If already assigned
    if 'http' not in web: # add protocol to site
        web = 'http://' + web
    if not web.endswith('/'):
        web = web + '/'
    web0 = get_fld(web)
    try:
        print(O+'Testing site '+color.GREY+web0+color.END+' status...')
        socket.gethostbyname(web0) # test whether site is up or not
        print(color.GREEN+' [+] Site seems to be up!'+color.END)
    except socket.gaierror: # if site is down
        print(R+'Site seems to be down...')
        quit()
    # We'll test for endpoint only when the --crawl isn't supplied.
    if not CRAWL_SITE:
        try:
            print(O+'Testing '+color.CYAN+web.split('//')[1].split('/', 1)[1]+color.END+' endpoint status...')
            requests.get(web)
            print(color.GREEN+' [+] Endpoint seems to be up!'+color.END)
        except requests.exceptions.MissingSchema as e:
            verbout(R, 'Exception at: '+color.GREY+url)
            verbout(R, 'Error: Invalid URL Format')
            ErrorLogger(url, e.__str__())
            quit()
        except requests.exceptions.HTTPError as e:  # if error
            verbout(R, "HTTP Error : "+url)
            ErrorLogger(url, e.__str__())
            quit()
        except requests.exceptions.ConnectionError as e:
            verbout(R, 'Connection Aborted : '+url)
            ErrorLogger(url, e.__str__())
            quit()
        except Exception as e:
            verbout(R, "Exception Caught: "+e.__str__())
            ErrorLogger(url, e.__str__())
            quit()  # if at all nothing happens :(
    if not web0.endswith('/'):
        web0 = web0 + '/'
    if web.split('//')[1] == web0:
        return web, ''
    return (web, web0)
