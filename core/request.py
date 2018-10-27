#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

import urllib.request, urllib.parse, urllib.error
from core.impo import *
from core.colors import * # import ends

def request(referer,action,form,opener,cookie):

    data = urllib.parse.urlencode(form) # encode stuff to make callable
    if cookie != '': # if user input has cookie
        headers = {
                'User-Agent' : 'Mozilla/5.0 (Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
                'Cookie' : cookie,
                'Referer' : referer
                } # headers set
    else: # if cookie value not set
        headers = {
                'User-Agent' : 'Mozilla/5.0 (Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
                'Referer' : referer
                } # headers set
    try:
        return opener.open(action,data).read() # read data content

    except urllib.error.HTTPError: # if error
        print(R+"HTTP Error 1 : "+action) # ah shit -_-
        return

    except ValueError: # again if valuerror
        print(R+"Value Error : "+action) # another one -_-
        return

    except:
        return '' # if at all nothing happens :(
