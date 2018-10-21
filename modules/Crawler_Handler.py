#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe

import re
import urllib.request, urllib.error, urllib.parse
from . import Uri_Checker
from core.colors import *
from bs4 import BeautifulSoup # imports done

class Crawler_Handler(): # main crawler handler

    def __init__(self, start,opener):

        self.visited = [] # init to visited stuff
        self.toVisit = [] # to visit
        self.uriPatterns = [] # patterns to follow
        self.currentURI = ''; # what is it now?
        self.opener = opener; # init opener
        self.toVisit.append(start) # lets add up urls

    def __next__(self):
        self.currentURI = self.toVisit[0] # to visit
        self.toVisit.remove(self.currentURI) # after its done
        return self.currentURI

    def getVisited(self):
        return self.visited # get it back

    def getToVisit(self):
        return self.toVisit # get it back again

    def noinit(self):
        if len(self.toVisit) > 0: # incase there are urls left
            return True # +1
        else:
            return False # -1

    def addToVisit(self,Uri_Checker):
        self.toVisit.append(Uri_Checker) # add what we have got

    def process(self, root):
        url = self.currentURI # whats up?

        try:
            query = self.opener.open(url) # open it

        except urllib.error.HTTPError as msg:
            print(R+'Request Error: '+msg.__str__()) # error!
            if url in self.toVisit:
                self.toVisit.remove(url) # remove non-existent
            return

        if not re.search('html',query.info()['Content-Type']): # if content-type mentioned
            return

        print(GR+'Making request to new location...')
        if hasattr(query.info(),'Location'): # get query for new loc
            url=query.info()['Location']
        print(O+'Reading response...') # read it
        response = query.read()

        try:
            print(O+'Trying to parse response...')
            soup = BeautifulSoup(response) # parser init

        except HTMLParser.HTMLParseError:
            print(R+'BeautifulSoup Error: '+url) # shit, error!
            self.visited.append(url)

            if url in self.toVisit: # nah ;-;
                self.toVisit.remove(url)
            return

        for m in soup.findAll('a',href=True): # find out all href^?://*

            app = ''
            if not re.match(r'javascript:',m['href']) or re.match('http://',m['href']): # crawl for stuff
                app = Uri_Checker.buildUrl(url,m['href'])

            if app!='' and re.search(root, app):
                while re.search(r'/\.\./',app): # untill all stuffs found...
                    p = re.compile('/[^/]*/../')
                    app = p.sub('/',app)
                p = re.compile('\./') # regex stuff to load
                app = p.sub('',app)

                uriPattern=removeIDs(app) # remove IDs
                if self.notExist(uriPattern) and app!=url:
                    print(G+'Added :> ' +color.BOLD+ app) # display what we have got!
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

    def addUriPatterns(self,Uri_Checker): # append patterns to follow
        self.uriPatterns.append(Uri_Checker)

    def addVisited(self,Uri_Checker): # visited stuffs added
        self.visited.append(Uri_Checker)

def removeIDs(Uri_Checker):

    p = re.compile('=[0-9]+') # regex stuff
    Uri_Checker = p.sub('=',Uri_Checker) # get stuff done
    p = re.compile('(title=)[^&]*') # whats the title u told?
    Uri_Checker = p.sub('\\1',Uri_Checker)
    return Uri_Checker
