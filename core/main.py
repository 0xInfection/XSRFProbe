#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Standard Package imports
import os
import re
import time
import warnings
import difflib
import http.cookiejar
from bs4 import BeautifulSoup
try:
    from urllib.parse import urlencode
    from urllib.error import HTTPError, URLError
    from urllib.request import build_opener, HTTPCookieProcessor
except ImportError:  # Throws exception in Case of Python2
    print("\033[1;91m [-] \033[1;93mXSRFProbe\033[0m isn't compatible with Python 2.x versions.\n\033[1;91m [-] \033[0mUse Python 3.x to run \033[1;93mXSRFProbe.")
    quit()
try:
    import requests, stringdist, bs4
except ImportError:
    print(' [-] Required dependencies are not installed.\n [-] Run \033[1;93mpip3 install -r requirements.txt\033[0m to fix it.')

# Imports from core
from core.options import *
from core.colors import *
from core.inputin import inputin
from core.request import Get, Post
from core.verbout import verbout
from core.prettify import formPrettify
from core.banner import banner, banabout
from core.forms import testFormx1, testFormx2
from core.logger import ErrorLogger, GetLogger
from core.logger import VulnLogger, NovulLogger

# Imports from files
from files.config import *
from files.discovered import FORMS_TESTED

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
from modules.Checkpost import PostBased
# Import Ends

# First rule, remove the warnings!
warnings.filterwarnings('ignore')

def Engine():  # lets begin it!

    os.system('clear')  # Clear shit from terminal :p
    banner()  # Print the banner
    banabout()  # The second banner
    web, fld = inputin()  # Take the input
    form1 = testFormx1()  # Get the form 1 ready
    form2 = testFormx2()  # Get the form 2 ready
    # For the cookies that we encounter during requests...
    Cookie0 = http.cookiejar.CookieJar()  # First as User1
    Cookie1 = http.cookiejar.CookieJar()  # Then as User2
    resp1 = build_opener(HTTPCookieProcessor(Cookie0))  # Process cookies
    resp2 = build_opener(HTTPCookieProcessor(Cookie1))  # Process cookies
    actionDone = []  # init to the done stuff
    csrf = ''  # no token initialise / invalid token
    ref_detect = 0x00  # Null Char Flag
    ori_detect = 0x00  # Null Char Flags
    form = Debugger.Form_Debugger()  # init to the form parser+token generator
    bs1 = BeautifulSoup(form1).findAll('form', action=True)[0]  # make sure the stuff works properly
    bs2 = BeautifulSoup(form2).findAll('form', action=True)[0]  # same as above
    init1 = web  # First init
    resp1.open(init1)  # Makes request as User2
    resp2.open(init1)  # Make request as User1

    # Now there are 2 different modes of scanning and crawling here.
    # 1st -> Testing a single endpoint without the --crawl flag.
    # 2nd -> Testing all endpoints with the --crawl flag.
    try:
        # Implementing the first mode. [NO CRAWL]
        if not CRAWL_SITE:
            url = web
            response = Get(url).text
            try:
                verbout(O,'Trying to parse response...')
                soup = BeautifulSoup(response)  # Parser init
            except HTMLParser.HTMLParseError:
                verbout(R,'BeautifulSoup Error: '+url)
            i = 0 # Init user number
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
            # Now lets get the forms...
            verbout(O, 'Retrieving all forms on ' +color.GREY+url+color.END+'...')
            for m in Debugger.getAllForms(soup):  # iterating over all forms extracted
                verbout(O,'Testing form:\n'+color.CYAN)
                formPrettify(m.prettify())
                verbout('', '')
                FORMS_TESTED.append('(i) '+url+':\n\n'+m.prettify()+'\n')
                try:
                    if m['action']:
                        pass
                except KeyError:
                    m['action'] = '/' + url.rsplit('/', 1)[1]
                    ErrorLogger(url, 'No standard form "action".')
                action = Parser.buildAction(url, m['action'])  # get all forms which have 'action' attribute
                if not action in actionDone and action!='':  # if url returned is not a null value nor duplicate...
                    # If form submission is kept to True
                    if FORM_SUBMISSION:
                        try:
                            # NOTE: Slow connections may cause read timeouts which may result in AttributeError
                            # So the idea here is tp make requests pretending to be 3 different users.
                            # Now a series of requests will be targeted against the site with different
                            # identities. Refer to XSRFProbe wiki for more info.
                            #
                            # NOTE: Slow connections may cause read timeouts which may result in AttributeError
                            result, genpoc = form.prepareFormInputs(m)  # prepare inputs as user 1
                            r1 = Post(url, action, result)  # make request with token values generated as user1
                            result, genpoc = form.prepareFormInputs(m)  # prepare inputs as user 2
                            r2 = Post(url, action, result)  # again make request with token values generated as user2
                            # Go for cookie based checks
                            if COOKIE_BASED:
                                Cookie(url, r1)
                            # Go for token based entropy checks...
                            try:
                                if m['name']:
                                    query, token = Entropy(result, url, r1.headers, m.prettify(), m['action'], m['name'])
                            except KeyError:
                                query, token = Entropy(result, url, r1.headers, m.prettify(), m['action'])
                            # Now its time to detect the encoding type (if any) of the Anti-CSRF token.
                            fnd, detct = Encoding(token)
                            if fnd == 0x01 and detct:
                                VulnLogger(url, 'Token is a string encoded value which can be probably decrypted.', '[i] Encoding: '+detct)
                            else:
                                NovulLogger(url, 'Anti-CSRF token is not a string encoded value.')
                            # Go for token parameter tamper checks.
                            if (query and token):
                                txor = Tamper(url, action, result, r2.text, query, token)
                            o2 = resp2.open(url).read()  # make request as user2
                            try:
                                form2 = Debugger.getAllForms(BeautifulSoup(o2))[i]  # user2 gets his form
                            except IndexError:
                                verbout(R, 'Form Index Error')
                                ErrorLogger(url, 'Form Index Error.')
                                continue  # Making sure program won't end here (dirty fix :( )
                            verbout(GR, 'Preparing form inputs...')
                            contents2, genpoc = form.prepareFormInputs(form2)  # prepare for form 3 as user3
                            r3 = Post(url, action, contents2)  # make request as user3 with user3's form
                            if (POST_BASED) and ((not query) or (txor)):
                                try:
                                    if m['name']:
                                        PostBased(url, r1.text, r2.text, r3.text, m['action'], result, genpoc, m.prettify(), m['name'])
                                except KeyError:
                                    PostBased(url, r1.text, r2.text, r3.text, m['action'], result, genpoc, m.prettify())
                            else:
                                print(color.GREEN+' [+] The form was requested with a Anti-CSRF token.')
                                print(color.GREEN+' [+] Endpoint '+color.BG+' NOT VULNERABLE '+color.END+color.GREEN+' to POST-Based CSRF Attacks!')
                                NovulLogger(url, 'Not vulnerable to POST-Based CSRF Attacks.')
                        except HTTPError as msg:  # if runtime exception...
                            verbout(R, 'Exception : '+msg.__str__())  # again exception :(
                            ErrorLogger(url, msg)
                actionDone.append(action)  # add the stuff done
                i+=1  # Increase user iteration
        else:
            # Implementing the 2nd mode [CRAWLING AND SCANNING].
            verbout(GR, "Initializing crawling and scanning...")
            crawler = Crawler.Handler(init1, resp1)  # Init to the Crawler handler
            while crawler.noinit():  # Until 0 urls left
                url = next(crawler)  # Go for next!
                print(C+'Testing :> '+color.CYAN+url)  # Display what url its crawling
                try:
                    soup = crawler.process(fld)  # Start the parser
                    if not soup:
                        continue  # Making sure not to end the program yet...
                    i = 0  # Set count = 0 (user number 0, which will be subsequently incremented)
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
                    # Now lets get the forms...
                    verbout(O, 'Retrieving all forms on ' +color.GREY+url+color.END+'...')
                    for m in Debugger.getAllForms(soup):  # iterating over all forms extracted
                        FORMS_TESTED.append('(i) '+url+':\n\n'+m.prettify()+'\n')
                        try:
                            if m['action']:
                                pass
                        except KeyError:
                            m['action'] = '/' + url.rsplit('/', 1)[1]
                            ErrorLogger(url, 'No standard "action" attribute.')
                        action = Parser.buildAction(url, m['action'])  # get all forms which have 'action' attribute
                        if not action in actionDone and action != '':  # if url returned is not a null value nor duplicate...
                            # If form submission is kept to True
                            if FORM_SUBMISSION:
                                try:
                                    result, genpoc = form.prepareFormInputs(m)  # prepare inputs as user 1
                                    r1 = Post(url, action, result)  # make request with token values generated as user1
                                    result, genpoc = form.prepareFormInputs(m)  # prepare inputs as user 2
                                    r2 = Post(url, action, result)  # again make request with token values generated as user2
                                    if COOKIE_BASED:
                                        Cookie(url, r1)
                                    # Go for token based entropy checks...
                                    try:
                                        if m['name']:
                                            query, token = Entropy(result, url, r1.headers, m.prettify(), m['action'], m['name'])
                                    except KeyError:
                                        query, token = Entropy(result, url, r1.headers, m.prettify(), m['action'])
                                        ErrorLogger(url, 'No standard form "name".')
                                    # Now its time to detect the encoding type (if any) of the Anti-CSRF token.
                                    fnd, detct = Encoding(token)
                                    if fnd == 0x01 and detct:
                                        VulnLogger(url, 'String encoded token value. Token might be decrypted.', '[i] Encoding: '+detct)
                                    else:
                                        NovulLogger(url, 'Anti-CSRF token is not a string encoded value.')
                                    # Go for token parameter tamper checks.
                                    if (query and token):
                                        txor = Tamper(url, action, result, r2.text, query, token)
                                    o2 = resp2.open(url).read()  # make request as user2
                                    try:
                                        form2 = Debugger.getAllForms(BeautifulSoup(o2))[i]  # user2 gets his form
                                    except IndexError:
                                        verbout(R, 'Form Index Error')
                                        ErrorLogger(url, 'Form Index Error.')
                                        continue  # making sure program won't end here (dirty fix :( )
                                    verbout(GR, 'Preparing form inputs...')
                                    contents2, genpoc = form.prepareFormInputs(form2)  # prepare for form 3 as user3
                                    r3 = Post(url, action, contents2)  # make request as user3 with user3's form
                                    if (POST_BASED) and ((query == '') or (txor == True)):
                                        try:
                                            if m['name']:
                                                PostBased(url, r1.text, r2.text, r3.text, m['action'], result, genpoc, m.prettify(), m['name'])
                                        except KeyError:
                                            PostBased(url, r1.text, r2.text, r3.text, m['action'], result, genpoc, m.prettify())
                                    else:
                                        print(color.GREEN+' [+] The form was requested with a Anti-CSRF token.')
                                        print(color.GREEN+' [+] Endpoint '+color.BG+' NOT VULNERABLE '+color.END+color.GREEN+' to P0ST-Based CSRF Attacks!')
                                        NovulLogger(url, 'Not vulnerable to POST-Based CSRF Attacks.')
                                except HTTPError as msg:  # if runtime exception...
                                    verbout(color.RED, ' [-] Exception : '+color.END+msg.__str__())  # again exception :(
                                    ErrorLogger(url, msg)
                        actionDone.append(action)  # add the stuff done
                        i+=1  # Increase user iteration
                except URLError as e:  # if again...
                    verbout(R, 'Exception at : '+url)  # again exception -_-
                    time.sleep(0.4)
                    verbout(O, 'Moving on...')
                    ErrorLogger(url, e)
                    continue  # make sure it doesn't stop at exceptions
                # This error usually happens when some sites are protected by some load balancer
                # example Cloudflare. These domains return a 403 forbidden response in various
                # contexts. For example when making reverse DNS queries.
                except HTTPError as e:
                    if str(e.code) == '403':
                        verbout(R, 'HTTP Authentication Error!')
                        verbout(R, 'Error Code : ' +O+ str(e.code))
                        ErrorLogger(url, e)
                        quit()
        GetLogger()  # The scanning has finished, so now we can log out all the links ;)
        print('\n'+G+"Scan completed!"+'\n')
        Analysis()  # For Post Scan Analysis
    except KeyboardInterrupt as e:  # Incase user wants to exit :') (while crawling)
        verbout(R, 'User Interrupt!')
        time.sleep(1.5)
        Analysis()  # For Post scan Analysis
        print(R+'Aborted!')  # say goodbye
        ErrorLogger('KeyBoard Interrupt', 'Aborted')
        GetLogger()  # The scanning has interrupted, so now we can log out all the links ;)
        quit()
    except Exception as e:
        verbout(R, e.__str__())
        ErrorLogger(url, e)
