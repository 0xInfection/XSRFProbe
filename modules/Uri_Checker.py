#!/usr/bin/env python2
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe


import urllib.parse
import re
from core.colors import * # import ends

def buildUrl(url, href): # receive form input type / url

    if re.search('logout',href) or re.search('action=out',href) or re.search('action=logoff', href) or re.search('action=delete',href) or re.search('UserLogout',href) or re.search('osCsid', href) or re.search('file_manager.php',href) or href=="http://localhost": # make exclusion list
        return '' # csrf stuff :o

    parsed = urllib.parse.urlsplit(href) # :D
    app = '' # init to url storage

    if parsed[1] == urllib.parse.urlsplit(url)[1]:
        app = href # assuming this url is built

    else:
        if len(parsed[1]) == 0 and (len(parsed[2]) != 0 or len(parsed[3])!=0): # parse result
            domain = urllib.parse.urlsplit(url)[1] # done!
            if re.match('/', parsed[2]):
                app = 'http://' + domain + parsed[2] # startpage dom
                if parsed[3] != '':
                    app += '?'+parsed[3] # parameters
            else:
                try:
                    app = 'http://' + domain + re.findall('(.*\/)[^\/]*', urllib.parse.urlsplit(url)[2])[0] + parsed[2]
                    # get real protocol urls
                except IndexError: # shit, indexerror
                    app = 'http://' + domain + parsed[2]
                if parsed[3]!='':
                    app += '?'+parsed[3] # parameters :D

    return app

def buildAction(url, action):

    print(O+'Parsing URL parameters...')
    if action!='' and not re.match('#',action): # ;-; lets hope this stuff get what intended
        return buildUrl(url,action) # get the url and reutrn it!
    else:
        return url # return it!
