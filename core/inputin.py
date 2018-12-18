#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection (@_tID)
#This module requires XSRF-Probe
#https://github.com/0xInfection/XSRF-Probe

import sys, socket
from tld import get_fld
from core.colors import *
from files.config import SITE_URL

def inputin():

    if SITE_URL:
        web = SITE_URL # If already assigned

    if 'http' not in web: # add protocol to site
        web = 'http://' + web

    web0 = get_fld(web)
    try:
        print(O+'Testing site status...')
        socket.gethostbyname(web0) # test whether site is up or not
        print(color.GREEN+' [+] Site seems to be up!'+color.END)
    except socket.gaierror: # if site is down
        print(R+'Site seems to be down...')
        sys.exit(0)
    if not web0.endswith('/'):
        web0 = web0 + '/'
    if web.split('//')[1] == web0:
        return web, ''
    return (web, web0)
