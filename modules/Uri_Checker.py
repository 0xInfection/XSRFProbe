#!/usr/bin/env python2
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe


import re
from urllib.parse import urlsplit # import ends

def buildUrl(url, href): # receive form input type / url

    exclusions = 'logout action=out action=logoff action=delete UserLogout osCsid file_manager.php'
    if href == "http://localhost" or any(s in href for s in exclusions.split()):
        return '' # csrf stuff :o

    url_parts = urlsplit(url) # --> SplitResult(scheme, netloc, path, query, fragment)
    href_parts = urlsplit(href)
    app = '' # init to url storage

    if href_parts.netloc == url_parts.netloc:
        app = href # assuming this url is built

    else:
        if len(href_parts.netloc) == 0 and (len(href_parts.path) != 0 or len(href_parts.query) != 0): # parse result
            domain = url_parts.netloc # done!
            if href_parts.path.startswith('/'):
                app = 'http://' + domain + href_parts.path # startpage dom
            else:
                try:
                    app = 'http://' + domain + re.findall('(.*\/)[^\/]*', url_parts.path)[0] + href_parts.path
                    # get real protocol urls
                except IndexError:
                    app = 'http://' + domain + href_parts.path
            if href_parts.query:
                app += '?' + href_parts.query # parameters :D

    return app

def buildAction(url, action):

    print(O+'Parsing URL parameters...')
    if action and not action.startswith('#'): # ;-; lets hope this stuff get what intended
        return buildUrl(url, action) # get the url and reutrn it!
    else:
        return url # return it!
