#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe

import re
from . import Parser
from core.colors import *
from bs4 import BeautifulSoup 
from core.verbout import verbout
import urllib.request, urllib.error, urllib.parse

class Crawler_Handler(): # Main Crawler Handler
    '''
    This is a crawler that is used to fetch all the Urls
        associated to the HTML page, and susequently
            crawl them and build checks for CSRFs.
    '''
    def __init__(self, start,opener):
        self.visited = [] # Visited stuff
        self.toVisit = [] # To visit
        self.uriPatterns = [] # Patterns to follow
        self.currentURI = ''; # What is it now?
        self.opener = opener; # Init build_opener
        self.toVisit.append(start) # Lets add up urls

    def __next__(self):
        self.currentURI = self.toVisit[0] # To visit
        self.toVisit.remove(self.currentURI) # After its done
        return self.currentURI

    def getVisited(self):
        return self.visited

    def getToVisit(self):
        return self.toVisit

    def noinit(self):
        if len(self.toVisit) > 0: # Incase there are urls left
            return True # +1
        else:
            return False # -1

    def addToVisit(self,Parser):
        self.toVisit.append(Parser) # Add what we have got

    def process(self, root):
        url = self.currentURI # Whats up?

        try:
            query = self.opener.open(url) # open it (to check if it exists)

        except urllib.error.HTTPError as msg:
            verbout(R,'Request Error: '+msg.__str__())
            if url in self.toVisit:
                self.toVisit.remove(url) # Remove non-existent / errored urls
            return

        # making sure the content type is in HTML format, so that BeautifulSoup 
        # can parse it...
        if not re.search('html',query.info()['Content-Type']):
            return

        # Just in case there is a redirection, we are supposed to follow it :D
        verbout(GR,'Making request to new location...')
        if hasattr(query.info(),'Location'):
            url=query.info()['Location']
        verbout(O,'Reading response...')
        response = query.read() # Read the response contents

        try:
            verbout(O,'Trying to parse response...')
            soup = BeautifulSoup(response) # Parser init

        except HTMLParser.HTMLParseError:
            verbout(R,'BeautifulSoup Error: '+url)
            self.visited.append(url)

            if url in self.toVisit:
                self.toVisit.remove(url)
            return

        for m in soup.findAll('a',href=True): # find out all href^?://*

            app = ''
            # Making sure that href is not a function or doesn't begin with http://
            if not re.match(r'javascript:',m['href']) or re.match('http://',m['href']):
                app = Parser.buildUrl(url,m['href'])

            # If we get a valid link
            if app!='' and re.search(root, app):
                # Getting rid of Urls starting with '../../../..'
                while re.search(r'/\.\./',app):
                    p = re.compile('/[^/]*/../')
                    app = p.sub('/',app)
                # Getting rid of Urls starting with './'
                p = re.compile('\./') # 
                app = p.sub('',app)

                # Add new link to the queue only if its pattern has not been added yet
                uriPattern=removeIDs(app) # remove IDs
                if self.notExist(uriPattern) and app!=url:
                    verbout(G,'Added :> ' +color.BLUE+ app) # display what we have got!
                    self.toVisit.append(app) # add up urls to visit
                    self.uriPatterns.append(uriPattern)

        self.visited.append(url) # add urls visited
        return soup # go back!

    def getUriPatterns(self): # get uri patterns
        return self.uriPatterns

    def notExist(self, test): # 404 stuffs
        if (test not in self.uriPatterns): # if non-existent
            return 1
        return 0 # else existent

    def addUriPatterns(self,Parser): # append patterns to follow
        self.uriPatterns.append(Parser)

    def addVisited(self,Parser): # visited stuffs added
        self.visited.append(Parser)

def removeIDs(Parser):
    '''
    This function removes the Numbers from the Urls 
                    which are built.
    '''
    p = re.compile('=[0-9]+')
    Parser = p.sub('=',Parser)
    p = re.compile('(title=)[^&]*')
    Parser = p.sub('\\1',Parser)
    return Parser
