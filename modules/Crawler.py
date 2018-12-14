#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: 0xInfection
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

import re, sys
from . import Parser
import urllib.error
from core.colors import *
from files.config import *
from files.dcodelist import *
from bs4 import BeautifulSoup
from core.request import Get
from core.verbout import verbout
from core.logger import ErrorLogger
from files.discovered import INTERNAL_URLS

class Handler():  # Main Crawler Handler
    '''
    This is a crawler that is used to fetch all the Urls
        associated to the HTML page, and susequently
            crawl them and build checks for CSRFs.
    '''
    def __init__(self, start, opener):
        self.visited = []  # Visited stuff
        self.toVisit = []  # To visit
        self.uriPatterns = []  # Patterns to follow
        self.currentURI = ''  # What is it now?
        self.opener = opener  # Init build_opener
        self.toVisit.append(start)  # Lets add up urls

    def __next__(self):
        self.currentURI = self.toVisit[0]  # To visit
        self.toVisit.remove(self.currentURI)  # After its done
        return self.currentURI

    def getVisited(self):
        return self.visited

    def getToVisit(self):
        return self.toVisit

    def noinit(self):
        if self.toVisit:  # Incase there are urls left
            return True  # +1
        return False  # -1

    def addToVisit(self, Parser):
        self.toVisit.append(Parser)  # Add what we have got

    def process(self, root):
        # Our first task is to remove urls that aren't to be scanned and have been
        # passed via the --exclude parameter.
        if EXCLUDE_DIRS:
            for link in EXCLUDE_DIRS:
                self.toVisit.remove(link)
        url = self.currentURI  # Main Url (Current)
        try:
            query = Get(url)  # Open it (to check if it exists)
            if query != None and not str(query.status_code).startswith('40'):  # Avoiding 40x errors
                INTERNAL_URLS.append(url)  # We append it to the list of valid urls
            else:
                if url in self.toVisit:
                    self.toVisit.remove(url)

        except (urllib.error.HTTPError, urllib.error.URLError) as msg:  # Incase there isan exception connecting to Url
            verbout(R, 'HTTP Request Error: '+msg.__str__())
            ErrorLogger(url, msg.__str__())
            if url in self.toVisit:
                self.toVisit.remove(url)  # Remove non-existent / errored urls
            return None

        # Making sure the content type is in HTML format, so that BeautifulSoup
        # can parse it...
        if not query or not re.search('html', query.headers['Content-Type']):
            return None

        # Just in case there is a redirection, we are supposed to follow it :D
        verbout(GR, 'Making request to new location...')
        if hasattr(query.headers, 'Location'):
            url = query.headers['Location']
        verbout(O,'Reading response...')
        response = query.content  # Read the response contents

        try:
            verbout(O, 'Trying to parse response...')
            soup = BeautifulSoup(response)  # Parser init

        except HTMLParser.HTMLParseError:
            verbout(R, 'BeautifulSoup Error: '+url)
            self.visited.append(url)
            if url in self.toVisit:
                self.toVisit.remove(url)
            return None

        for m in soup.findAll('a', href=True):  # find out all href^?://*
            app = ''
            # Making sure that href is not a function or doesn't begin with http://
            if not re.match(r'javascript:', m['href']) or re.match('http://', m['href']):
                app = Parser.buildUrl(url, m['href'])

            # If we get a valid link
            if app!='' and re.search(root, app):
                # Getting rid of Urls starting with '../../../..'
                while re.search(RID_DOUBLE, app):
                    p = re.compile(RID_COMPILE)
                    app = p.sub('/', app)
                # Getting rid of Urls starting with './'
                p = re.compile(RID_SINGLE)
                app = p.sub('', app)

                # Add new link to the queue only if its pattern has not been added yet
                uriPattern=removeIDs(app)  # remove IDs
                if self.notExist(uriPattern) and app != url:
                    verbout(G, 'Added :> ' +color.BLUE+ app)  # display what we have got!
                    self.toVisit.append(app)  # add up urls to visit
                    self.uriPatterns.append(uriPattern)

        self.visited.append(url)  # add urls visited
        return soup  # go back!

    def getUriPatterns(self):  # get uri patterns
        return self.uriPatterns

    def notExist(self, test):  # 404 stuffs
        if (test not in self.uriPatterns):  # if non-existent
            return 1
        return 0  # else existent

    def addUriPatterns(self, Parser):  # append patterns to follow
        self.uriPatterns.append(Parser)

    def addVisited(self, Parser):  # visited stuffs added
        self.visited.append(Parser)

def removeIDs(Parser):
    '''
    This function removes the Numbers from the Urls
                    which are built.
    '''
    p = re.compile(NUM_SUB)
    Parser = p.sub('=', Parser)
    p = re.compile(NUM_COM)
    Parser = p.sub('\\1', Parser)
    return Parser
