#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection (@_tID)
#This module requires XSRF-Probe
#https://github.com/0xInfection/XSRF-Probe

import sys
import socket
from core.colors import *
from files.config import *

def inputin():

    if SITE_URL != '':
        web = SITE_URL # If already assigned
    else:
        web = input(color.CYAN+' [$] Enter target address :> '+color.END) # take input

    if 'http' not in web: # add protocol to site
        web = 'http://' + web

    web0 = web.split('//')[1]
    try:
        print(O+'Testing site status...')
        socket.gethostbyname(web0) # test whether site is up or not
        print(color.GREEN+' [+] Site seems to be up!'+color.END)

    except socket.gaierror: # if site is down
        print(R+'Site seems to be down...')
        sys.exit(0)

    if COOKIE_VALUE:
        cook = COOKIE_VALUE
        
    if web.endswith('/'): # check
        return web, cook
    else:
        web = web + '/' # make sure the site address ends with '/'
        return web, cook
