#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Standard Package imports
import os
import re
import time
import warnings
import difflib
import urllib.error
import http.cookiejar
from bs4 import BeautifulSoup
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor

# Imports from core
from core.options import *
from core.colors import *
from core.inputin import inputin
from core.request import Get, Post
from core.verbout import verbout
from core.forms import form10, form20
from core.banner import banner, banabout

# Imports from files
from files.config import *

# Imports from modules
from modules import Debugger
from modules import Parser
from modules import Crawler
from modules.Origin import Origin
from modules.Cookie import Cookie
from modules.Tamper import Tamper
from modules.Entropy import Entropy
from modules.Referer import Referer
from modules.Encoding import Encoding
from modules.Analysis import Analysis
# Import Ends

# First rule, remove the warnings!
warnings.filterwarnings('ignore')

def Engine():  # lets begin it!

    os.system('clear')  # Clear shit from terminal :p
    banner()  # Print the banner
    banabout()  # The second banner
    web = inputin()  # Take the input
    form1 = form10()  # Get the form 1 ready
    form2 = form20()  # Get the form 2 ready

    # For the cookies that we encounter during requests...
    Cookie0 = http.cookiejar.CookieJar()  # First as User1
    Cookie1 = http.cookiejar.CookieJar()  # Then as User2
    resp1 = build_opener(HTTPCookieProcessor(Cookie0))  # Process cookies and do stuff
    resp2 = build_opener(HTTPCookieProcessor(Cookie1))  # Process cookies and do stuff

    actionDone = []  # init to the done stuff

    csrf = ''  # no token initialise / invalid token
    ref_detect = 0x00  # Null Char
    ori_detect = 0x00
    init1 = web  # get the starting page
    form = Debugger.Form_Debugger()  # init to the form parser+token generator

    bs1=BeautifulSoup(form1).findAll('form',action=True)[0]  # make sure the stuff works properly
    bs2=BeautifulSoup(form2).findAll('form',action=True)[0]  # same as above

    action = init1  # First init

    resp1.open(action)  # Makes request as User2
    resp2.open(action)  # Make request as User1

    verbout(GR, "Initializing crawling and scanning...")
    crawler = Crawler.Handler(init1, resp1)  # Init to the Crawler handler

    try:
        while crawler.noinit():  # Until 0 urls left
            url = next(crawler)  # Go for next!

            print(C+'Crawling :> ' +color.CYAN+ url)  # Display what url its crawling

            try:
                soup = crawler.process(web)  # Start the parser
                if not soup:
                    continue;  # Making sure not to end the program yet...
                i = 0  # Set count = 0
                if REFERER_ORIGIN_CHECKS:
                    # Referer Based Checks if True...
                    verbout(O, 'Checking endpoint request validation via '+color.GREY+'Referer'+color.END+' Checks...')
                    if Referer(url):
                        ref_detect = 0x01
                    verbout(O, 'Confirming the vulnerability...')

                    # We have finished with Referer Based Checks, lets go for Origin Based Ones...
                    verbout(O, 'Confirming endpoint request validation via '+color.GREY+'Origin'+color.END+' Checks...')
                    if Origin(url):
                        ori_detect = 0x01

                if COOKIE_BASED:
                    Cookie(url)

                # Now lets get the forms...
                verbout(O, 'Retrieving all forms on ' +color.GREY+url+color.END+'...')
                for m in Debugger.getAllForms(soup):  # iterating over all forms extracted
                    action = Parser.buildAction(url,m['action'])  # get all forms which have 'action' attribute
                    if not action in actionDone and action!='':  # if url returned is not a null value nor duplicate...
                        # If form submission is kept to True
                        if FORM_SUBMISSION:
                            try:
                                result = form.prepareFormInputs(m)  # prepare inputs
                                r1 = Post(url, action, result).text  # make request with token values generated as user1
                                result = form.prepareFormInputs(m)  # prepare the input types
                                r2 = Post(url, action, result).text  # again make request with token values generated as user2
                                # Go for token based entropy checks...
                                try:
                                    if m['name']:
                                        query, token = Entropy(result, url, m['action'], m['name'])
                                except KeyError:
                                    query, token = Entropy(result, url, m['action'])
                                # Go for token parameter tamper checks.
                                if (query and token):
                                    Tamper(url, action, result, r2, query, token)
                                o2 = resp2.open(url).read()  # make request as user2
                                try:
                                    form2 = Debugger.getAllForms(BeautifulSoup(o2))[i]  # user2 gets his form
                                except IndexError:
                                    verbout(R, 'Form Error')
                                    continue;  # making sure program won't end here (dirty fix :( )
                                verbout(GR, 'Preparing form inputs...')
                                contents2 = form.prepareFormInputs(form2)  # prepare for form 2 as user2
                                r3 = Post(url,action,contents2).text  # make request as user3 with user2's form
                                try:
                                    checkdiff = difflib.ndiff(r1.splitlines(1),r2.splitlines(1))  # check the diff noted
                                    checkdiff0 = difflib.ndiff(r1.splitlines(1),r3.splitlines(1))  # check the diff noted
                                    result12 = []  # an init
                                    for n in checkdiff:
                                        if re.match('\+|-',n):  # get regex matching stuff
                                            result12.append(n)  # append to existing list
                                    result13 = []  # an init
                                    for n in checkdiff0:
                                        if re.match('\+|-',n):  # get regex matching stuff
                                            result13.append(n)  # append to existing list
                                    # This logic is based purely on the assumption on the difference of requests and
                                    # response body.
                                    # If the number of differences of result12 are less than the number of differences
                                    # than result13 then we have the vulnerability.
                                    #
                                    # NOTE: The alogrithm has lots of scopes of improvements
                                    if len(result12)<=len(result13):
                                        print(color.GREEN+ ' [+] CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
                                        print(color.ORANGE+' [!] Vulnerability Type: '+color.BR+' POST-Based Request Forgery '+color.END)
                                        time.sleep(0.3)
                                        print(O+'PoC of response and request...')
                                        try:  # yet we give out what we found
                                            if m['name']:
                                                print(color.RED+'\n +---------+')
                                                print(color.RED+' |   PoC   |')
                                                print(color.RED+' +---------+\n')
                                                print(color.BLUE+' [+] URL : ' +color.CYAN+url)  # url part
                                                print(color.CYAN+' [+] Name : ' +color.ORANGE+m['name'])  # name
                                                print(color.GREEN+' [+] Action : ' +color.END+m['action'])  # action
                                        except KeyError:# if value m['name'] not there :(
                                            print(color.RED+'\n +---------+')
                                            print(color.RED+' |   PoC   |')
                                            print(color.RED+' +---------+\n')
                                            print(color.BLUE+' [+] URL : ' +color.CYAN+url)  # the url
                                            print(color.GREEN+' [+] Action : ' +color.END+ m['action'])  # action

                                        print(color.ORANGE+' [+] Query : '+color.GREY+ urlencode(result).strip())
                                        print('')                                        # print out the params + url

                                except KeyboardInterrupt:  # incase user wants to exit (while form processing)
                                    verbout(R, 'User Interrupt!')
                                    print(R+'Aborted!')  # say goodbye
                                    quit()

                                except KeyboardInterrupt:  # other exceptions ;-; can be ignored
                                    pass

                            except urllib.error.HTTPError as msg:  # if runtime exception...
                                verbout(R, 'Exception : '+msg.__str__())  # again exception :(

                    actionDone.append(action)  # add the stuff done
                    i+=1  # ctr++

            except urllib.error.URLError:  # if again...
                verbout(R, 'Exception at : '+url)  # again exception -_-
                time.sleep(0.4)
                verbout(O, 'Moving on...')
                continue;  # make sure it doesn't stop

        print('\n'+G+"Scan completed!"+'\n')
        Analysis()  # For Post Scan Analysis

    except urllib.error.HTTPError as e:  # 403 not authenticated
        if str(e.code) == '403':
            verbout(R, 'HTTP Authentication Error!')
            verbout(R, 'Error Code : ' +O+ str(e.code))
            quit()

    except KeyboardInterrupt:  # incase user wants to exit ;-; (while crawling)
        verbout(R, 'User Interrupt!')
        Analysis()  # For Post scan Analysis
        print(R+'Aborted!')  # say goodbye
        quit()
