#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: 0xInfection
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

import re, html.parser
import urllib.error
from bs4 import BeautifulSoup
from xsrfprobe.modules import Parser
from xsrfprobe.core.colors import *
from xsrfprobe.files.config import *
from xsrfprobe.files.dcodelist import *
from xsrfprobe.core.request import Get
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.logger import ErrorLogger
from xsrfprobe.files.discovered import INTERNAL_URLS

class Handler:  # Main Crawler Handler
    '''
    This is a crawler that is used to fetch all the Urls
        associated to the HTML page, and susequently
            crawl them and build checks for CSRFs.
    '''
    def __init__(self, start, opener):
        self.visited = list()
        self.toVisit = list()
        self.uriPatterns = list()
        self.currentURI = ''
        self.opener = opener
        self.toVisit.append(start)

    def __next__(self):
        self.currentURI = self.toVisit[0]
        self.toVisit.remove(self.currentURI)
        return self.currentURI

    def getVisited(self):
        return self.visited

    def getToVisit(self):
        return self.toVisit

    def noinit(self):
        if self.toVisit:
            return True
        return False

    def addToVisit(self, Parser):
        self.toVisit.append(Parser)

    def process(self, root):
        # Our first task is to remove urls that aren't to be scanned and have been
        # passed via the --exclude parameter.
        if EXCLUDE_DIRS:
            for link in EXCLUDE_DIRS:
                self.visited.append(link)

        url = self.currentURI
        try:
            query = Get(url)
            if query != None and not str(query.status_code).startswith('40'):
                INTERNAL_URLS.append(url)
            else:
                if url in self.toVisit:
                    self.toVisit.remove(url)

        except (urllib.error.HTTPError, urllib.error.URLError) as msg:
            verbout(R, 'HTTP Request Error: '+msg.__str__())
            ErrorLogger(url, msg.__str__())
            if url in self.toVisit:
                self.toVisit.remove(url)
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
        response = query.content

        try:
            verbout(O, 'Trying to parse response...')
            soup = BeautifulSoup(response)

        except html.parser.HTMLParseError:
            verbout(R, 'BeautifulSoup Error: '+url)
            self.visited.append(url)
            if url in self.toVisit:
                self.toVisit.remove(url)
            return None

        for m in soup.findAll('a', href=True):
            app = ''
            # Making sure that href is not a function or doesn't begin with http://
            if not re.match(r'javascript:', m['href']) or re.match('http://', m['href']):
                app = Parser.buildUrl(url, m['href'])

            # If we get a valid link
            if app != '' and re.search(root, app):
                # Getting rid of Urls starting with './'
                p = re.compile(RID_SINGLE)
                app = p.sub('', app)

                # Add new link to the queue only if its pattern has not been added yet
                uriPattern=removeIDs(app)
                if self.notExist(uriPattern) and app != url:
                    if app not in EXCLUDE_DIRS:
                        verbout(G, 'Added :> ' +color.BLUE+ app)
                        self.toVisit.append(app)
                        self.uriPatterns.append(uriPattern)
                    else:
                        verbout(O, 'Skipping due to exclusion:', app)

        self.visited.append(url)
        return soup

    def getUriPatterns(self):
        return self.uriPatterns

    def notExist(self, test):
        if (test not in self.uriPatterns):
            return 1
        return 0

    def addUriPatterns(self, Parser):
        self.uriPatterns.append(Parser)

    def addVisited(self, Parser):
        self.visited.append(Parser)

def removeIDs(Parser):
    '''
    This function removes the IDs from the Urls which are built.
    '''
    p = re.compile(NUM_SUB)
    Parser = p.sub('=', Parser)
    p = re.compile(NUM_COM)
    Parser = p.sub('\\1', Parser)
    return Parser
