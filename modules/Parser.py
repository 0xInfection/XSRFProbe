#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: 0xInfection
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

import re
from urllib.parse import urlsplit
from core.verbout import verbout
from files.dcodelist import PROTOCOLS
from files.paramlist import EXCLUSIONS_LIST
from core.colors import *  # import ends

def buildUrl(url, href):  # receive form input type / url
    '''
    This function is for building a proper URL based
                on comparison to 'href'.
    '''
    # Making an exclusion list, so as to stop detection of Self-CSRF (Logout-CSRF)
    #
    # This is yet another step is reducing false positives [[ significantly ]].
    # Self-CSRF/Logout Based CSRFs are not really of any value and are deemed
    # of as low quality CSRF (bugs).
    #
    # TODO: Add more to EXCLUSIONS_LIST.
    if href == "http://localhost" or any((re.search(s, href, re.IGNORECASE)) for s in EXCLUSIONS_LIST):
        return ''

    url_parts = urlsplit(url)  # SplitResult(scheme, netloc, path, query, fragment)
    href_parts = urlsplit(href)
    app = ''  # Init to the Url that will be built

    # If Url and Destination have the same domain...
    if href_parts.netloc == url_parts.netloc:
        app = href  # Assigning the main netloc

    else:  # If the destination Url doesn't have a domain
        if len(href_parts.netloc) == 0 and (len(href_parts.path) != 0 or len(href_parts.query) != 0):
            domain = url_parts.netloc  # Assigning the main domain
            if href_parts.path.startswith('/'):  # If the href starts with a '/', it is an internal Url
                app = 'http://' + domain + href_parts.path  # Startpage
            else:
                try:
                    app = 'http://' + domain + re.findall(PROTOCOLS, url_parts.path)[0] + href_parts.path
                    # Get real protocol urls
                except IndexError:
                    app = 'http://' + domain + href_parts.path
            if href_parts.query:  # Checking if any queries were there...
                app += '?' + href_parts.query  # Adding the query paramaters to Url
    # Return '' for invalid url, url otherwise
    return app

def buildAction(url, action):
    '''
    The main function of this is to create an action Url based
                on Current Location and Destination.
    '''
    verbout(O,'Parsing URL parameters...')
    if action and not action.startswith('#'):  # make sure it is not a fragment (eg. http://site.tld/index.php#search)
        return buildUrl(url, action)  # get the url and reutrn it!
    return url  # return the url itself if buildAction didn't identify the action
