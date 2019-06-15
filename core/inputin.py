#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection (@_tID)
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

from core.colors import *
import socket, requests, tld, re
from core.verbout import verbout
from files.dcodelist import IP
from .logger import ErrorLogger
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
    try:
        web0 = tld.get_fld(web)
    except tld.exceptions.TldDomainNotFound:
        web0 = re.search(IP, web).group(0)
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
            verbout(R, 'Exception at: '+color.GREY+web0)
            verbout(R, 'Error: Invalid URL Format')
            ErrorLogger(web0, e.__str__())
            quit()
        except requests.exceptions.HTTPError as e:
            verbout(R, "HTTP Error: "+web0)
            ErrorLogger(web0, e.__str__())
            quit()
        except requests.exceptions.ConnectionError as e:
            verbout(R, 'Connection Aborted: '+web0)
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
