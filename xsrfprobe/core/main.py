#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Standard Package imports
import ssl
import time
import warnings
import http.cookiejar
from bs4 import BeautifulSoup
try:
    from urllib.error import HTTPError, URLError
    from urllib.request import build_opener, HTTPCookieProcessor
except ImportError:
    print("[-] XSRFProbe isn't compatible with Python 2.x versions.\n [-] Use Python 3.x to run XSRFProbe.")
    quit()

# Imports from core
from xsrfprobe.core.options import *
from xsrfprobe.core.colors import *
from xsrfprobe.core.inputin import inputin
from xsrfprobe.core.request import Get, Post
from xsrfprobe.core.verbout import verbout
from xsrfprobe.core.prettify import formPrettify
from xsrfprobe.core.logger import ErrorLogger, GetLogger
from xsrfprobe.core.logger import VulnLogger, NovulLogger

# Imports from files
from xsrfprobe.files.config import *
from xsrfprobe.files.discovered import FORMS_TESTED

# Imports from modules
from xsrfprobe.modules import Debugger
from xsrfprobe.modules import Parser
from xsrfprobe.modules import Crawler
from xsrfprobe.modules.Origin import Origin
from xsrfprobe.modules.Cookie import Cookie
from xsrfprobe.modules.Tamper import Tamper
from xsrfprobe.modules.Entropy import Entropy
from xsrfprobe.modules.Referer import Referer
from xsrfprobe.modules.Encoding import Encoding
from xsrfprobe.modules.Analysis import Analysis
from xsrfprobe.modules.Checkpost import PostBased
# Import Ends

# First rule, remove the warnings!
warnings.filterwarnings('ignore')

def Engine():
    web, fld = inputin()
    Cookie0 = http.cookiejar.CookieJar()
    Cookie1 = http.cookiejar.CookieJar()
    if not VERIFY_CERT:
        context=ssl._create_unverified_context()
        sslHandler = urllib.request.HTTPSHandler(context=context)
        resp1 = build_opener(HTTPCookieProcessor(Cookie0), sslHandler)
        resp2 = build_opener(HTTPCookieProcessor(Cookie1), sslHandler)
    else:
        resp1 = build_opener(HTTPCookieProcessor(Cookie0))
        resp2 = build_opener(HTTPCookieProcessor(Cookie1))
    actionDone = list()
    ori_detect = 0x00
    ref_detect = 0x00
    hdrs = [('Cookie', ','.join(cookie for cookie in COOKIE_VALUE))]
    [hdrs.append((k, v)) for k, v in HEADER_VALUES.items()]
    resp1.addheaders = resp2.addheaders = hdrs
    resp1.open(web)  # Makes request as User2
    resp2.open(web)  # Make request as User1

    # Now there are 2 different modes of scanning and crawling here.
    # 1st -> Testing a single endpoint without the --crawl flag.
    # 2nd -> Testing all endpoints with the --crawl flag.
    try:
        # Implementing the first mode. [NO CRAWL]
        if not CRAWL_SITE:
            url = web
            try:
                response = Get(url).text
                verbout(O, 'Trying to parse response...')
                soup = BeautifulSoup(response)
            except AttributeError:
                verbout(R, 'No response received, site probably down: '+url)
            i = 0
            if REFERER_ORIGIN_CHECKS:
                verbout(O, 'Checking endpoint request validation via '+color.GREY+'Referer'+color.END+' Checks...')
                if Referer(url):
                    ref_detect = 0x01
                verbout(O, 'Confirming the vulnerability...')

                verbout(O, 'Confirming endpoint request validation via '+color.GREY+'Origin'+color.END+' Checks...')
                if Origin(url):
                    ori_detect = 0x01

            if ori_detect == 0x01 and ref_detect == 0x01:
                verbout(G, 'Passive checks confirm '+color.BOLD+'presence of appropriate CSRF protection.'+color.END)

            verbout(O, 'Proceeding to active enumeration phase...')
            verbout(O, 'Retrieving all forms on ' +color.GREY+url+color.END+'...')
            for m in Debugger.getAllForms(soup):
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
                action = Parser.buildAction(url, m['action'])

                if not action in actionDone and action != '':
                    if FORM_SUBMISSION:
                        try:
                            # NOTE: Slow connections may cause read timeouts which may result in AttributeError
                            # So the idea here is to make requests pretending to be 3 different users.
                            # Now a series of requests will be targeted against the site with different
                            # identities. Refer to XSRFProbe wiki for more info.
                            #
                            # NOTE: Slow connections may cause read timeouts which may result in AttributeError
                            result, genpoc = Debugger.prepareFormInputs(m)  # prepare inputs as user 1
                            r1 = Post(url, action, result)  # make request with token values generated as user1
                            result, genpoc = Debugger.prepareFormInputs(m)  # prepare inputs as user 2
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
                            o2 = Get(url).text  # make request as user2
                            try:
                                bform = Debugger.getAllForms(BeautifulSoup(o2))[i]  # user2 gets his form
                            except IndexError:
                                verbout(R, 'Form Index Error')
                                ErrorLogger(url, 'Form Index Error.')
                                continue  # Making sure program won't end here (dirty fix :( )
                            verbout(GR, 'Preparing form inputs...')
                            contents2, genpoc = Debugger.prepareFormInputs(bform)  # prepare for form 3 as user3
                            r3 = Post(url, action, contents2)  # make request as user3 with user3's form
                            if (POST_BASED) and ((not query) or (txor)):
                                try:
                                    if m['name']:
                                        PostBased(url, r1.text, r2.text, r3.text, action, result, genpoc, m.prettify(), m['name'])
                                except KeyError:
                                    PostBased(url, r1.text, r2.text, r3.text, action, result, genpoc, m.prettify())
                            else:
                                print(color.GREEN+' [+] The form was requested with a Anti-CSRF token.')
                                print(color.GREEN+' [+] Endpoint '+color.BG+' NOT VULNERABLE '+color.END+color.GREEN+' to POST-Based CSRF Attacks!')
                                NovulLogger(url, 'Not vulnerable to POST-Based CSRF Attacks.')
                        except HTTPError as msg:
                            verbout(R, 'Exception : '+msg.__str__())
                            ErrorLogger(url, msg)
                    actionDone.append(action)
                    i+=1
        else:
            # Implementing the 2nd mode [CRAWLING AND SCANNING].
            verbout(GR, "Initializing crawling and scanning...")
            crawler = Crawler.Handler(web, resp1)  # Init to the Crawler handler
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
                    verbout(O, 'Retrieving all forms on ' +color.GREY+url+color.END+'...')
                    for m in Debugger.getAllForms(soup):
                        FORMS_TESTED.append('(i) '+url+':\n\n'+m.prettify()+'\n')
                        try:
                            if m['action']:
                                pass
                        except KeyError:
                            m['action'] = '/' + url.rsplit('/', 1)[1]
                            ErrorLogger(url, 'No standard "action" attribute.')
                        action = Parser.buildAction(url, m['action'])
                        if not action in actionDone and action != '':

                            if FORM_SUBMISSION:
                                try:
                                    result, genpoc = Debugger.prepareFormInputs(m)
                                    r1 = Post(url, action, result)
                                    result, genpoc = Debugger.prepareFormInputs(m)
                                    r2 = Post(url, action, result)
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

                                    if (query and token):
                                        txor = Tamper(url, action, result, r2.text, query, token)
                                    o2 = Get(url).text
                                    try:
                                        bform = Debugger.getAllForms(BeautifulSoup(o2))[i]
                                    except IndexError:
                                        verbout(R, 'Form Index Error')
                                        ErrorLogger(url, 'Form Index Error.')
                                        continue
                                    verbout(GR, 'Preparing form inputs...')
                                    contents2, genpoc = Debugger.prepareFormInputs(bform)
                                    r3 = Post(url, action, contents2)
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
                                except HTTPError as msg:
                                    verbout(color.RED, ' [-] Exception : '+color.END+msg.__str__())
                                    ErrorLogger(url, msg)
                            actionDone.append(action)
                            i+=1
                except HTTPError as e:
                    if str(e.code) == '403':
                        verbout(R, 'HTTP Authentication Error!')
                        verbout(R, 'Error Code : ' +O+ str(e.code))
                        ErrorLogger(url, e)
                        quit()
                except URLError as e:
                    verbout(R, 'Exception at : '+url)
                    time.sleep(0.4)
                    verbout(O, 'Moving on...')
                    ErrorLogger(url, e)
                    continue
        GetLogger()
        print('\n'+G+"Scan completed!"+'\n')
        Analysis()
    except KeyboardInterrupt as e:
        verbout(R, 'User Interrupt!')
        time.sleep(1.5)
        Analysis()
        print(R+'Aborted!')
        ErrorLogger('KeyBoard Interrupt', 'Aborted')
        GetLogger()
        sys.exit(1)
    #except Exception as e:
        print('\n'+R+'Encountered an error. \n')
        print(R+'Please view the error log files to view what went wrong.')
        verbout(R, e.__str__())
        ErrorLogger(url, e)
        GetLogger()
