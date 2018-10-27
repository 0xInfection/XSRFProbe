#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from core.impo import *
from files.config import *
from core.verbout import *
from core.globalvars import *
from modules.Crawler import *
from modules.Debugger import *
from modules.Parser import * # get imports
from modules.Entropy import *
from modules.Referer import *

def xsrf_main(): # lets begin it!

    os.system('clear') # clear shit from terminal :p
    banner() # print the banner
    banabout() # the second banner
    web, cookie = inputin() # take the input
    form1 = form10() # get the form 1 ready
    form2 = form20() # get the form 2 ready

    Cookie0 = http.cookiejar.CookieJar() # cookies ummm...
    Cookie1 = http.cookiejar.CookieJar() # another one :o
    resp1 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(Cookie0)) # process cookies and do stuff
    resp2 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(Cookie1))  # process cookies and do stuff

    actionDone = [] # init to the done stuff

    csrf='' # no token initialise / invalid token
    init1 = web # get the starting page
    form = Form_Debugger() # init to the form parser+token generator

    bs1=BeautifulSoup(form1).findAll('form',action=True)[0] # make sure the stuff works properly
    bs2=BeautifulSoup(form2).findAll('form',action=True)[0] # same as above

    action = init1 # lets start the stuff

    resp1.open(action) # make thre req ;)
    resp2.open(action) # go for the second one

    verbout(GR, "Initializing crawling and scanning...")
    crawler = Crawler_Handler(init1,resp1) # pass onto the crawler

    try:

        while crawler.noinit(): # until 0 urls left
            url = next(crawler) # go for next!

            verbout(C, 'Crawling :> ' +color.CYAN+ url) # display what url its crawling

            try:
                soup = crawler.process(web) # start the parser
                if not soup:
                    continue; # making sure not to end the program yet...
                i = 0 # set count = 0
                if Referer(url):
                    print(color.GREEN+' [+] Endoint '+color.ORANGE+'Referer Validation'+color.GREEN+' Present!')
                    print(color.GREEN+' [-] Heuristics reveal endpoint might NOT be vulnerable...')
                else:
                    print(color.RED+' [+] Endpoint '+color.ORANGE+'Referer Validation'+color.RED+' Not Present!')
                    print(color.RED+' [-] Heuristics reveal endpoint might be VULNERABLE to Referer Based CSRFs...')
                
                verbout(O, 'Retrieving all forms on ' +color.GREY+url+color.END+'...')
                for m in getAllForms(soup): # iterating over all forms extracted
                    action = Parser.buildAction(url,m['action']) # get all forms which have 'action' attribute
                    if not action in actionDone and action!='': # if url returned is not a null value nor duplicate...
                        if FORM_SUBMISSION:
                            try:
                                result = form.prepareFormInputs(m) # prepare inputs
                                r1 = request(url, action, result, resp1, cookie) # make request with token values generated as user1
                                result = form.prepareFormInputs(m) # prepare the input types
                                r2 = request(url, action, result, resp2, cookie) # again make request with token values generated as user2

                                if Entropy(result): #  yep we got the vuln for sure!
                                    if re.search(csrf, r2): 
                                        print(color.GREEN+ ' [+] CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
                                        print(color.ORANGE+' [!] Vulnerability Type: '+color.CYAN+'Very Weak/No Anti-CSRF Token...')
                                        try:
                                            if m['name']: # print it out fancy:p
                                                print(color.RED+'\n +---------+')
                                                print(color.RED+' |   PoC   |')
                                                print(color.RED+' +---------+\n')
                                                print(color.BLUE+' [+] URL : ' +color.CYAN+url)
                                                print(color.CYAN+' [+] Name : ' +color.ORANGE+m['name'])
                                                print(color.GREEN+' [+] Action : ' +color.ORANGE+m['action'])

                                        except KeyError: # if value m['name'] not there :(

                                            print(color.RED+'\n +---------+')
                                            print(color.RED+' |   PoC   |')
                                            print(color.RED+' +---------+\n')
                                            print(color.BLUE+' [+] URL : ' +color.CYAN+url)
                                            print(color.GREEN+' [+] Action : ' +color.ORANGE+m['action'])

                                        print(color.ORANGE+' [+] Query : '+color.GREY+urllib.parse.urlencode(result))
                                        print('')                               # print out the params + url

                                    continue;

                                o2 = resp2.open(url).read() # make request as user2

                                try:
                                    form2 = getAllForms(BeautifulSoup(o2))[i] # user2 gets his form

                                except IndexError:
                                    verbout(R, 'Form Error') 
                                    continue; # making sure program won't end here (dirty fix :( )

                                verbout(GR, 'Preparing form inputs...')
                                contents2 = form.prepareFormInputs(form2) # prepare for form 2
                                r3 = request(url,action,contents2,resp2, cookie) # make request as user3

                                try:
                                    checkdiff = difflib.ndiff(r1.splitlines(1),r2.splitlines(1)) # check the diff noted
                                    checkdiff0 = difflib.ndiff(r1.splitlines(1),r3.splitlines(1)) # check the diff noted

                                    result12 = [] # an init
                                    for n in checkdiff:
                                        if re.match('\+|-',n): # get regex matching stuff
                                            result12.append(n) # append to existing list

                                    result13 = [] # an init
                                    for n in checkdiff0:
                                        if re.match('\+|-',n): # get regex matching stuff
                                            result13.append(n) # append to existing list
                                    
                                    # This logic is based purely on the assumption on the difference of requests and
                                    # response body (thats why we're using difflib).
                                    #
                                    # If the number of differences of result12 are less than the number of differences
                                    # than result13
                                    if len(result12)<=len(result13):
                                        print(color.GREEN+ ' [+] CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
                                        print(color.ORANGE+' [!] Vulnerability Type: '+color.CYAN+' POST-Based Request Forgery...')
                                        time.sleep(0.3)
                                        print(O+'PoC of response and request...')
                                        try: # yet we give out what we found
                                            if m['name']: 
                                                print(color.RED+'\n +---------+')
                                                print(color.RED+' |   PoC   |')
                                                print(color.RED+' +---------+\n')
                                                print(color.BLUE+' [+] URL : ' +color.CYAN+url) # url part
                                                print(color.CYAN+' [+] Name : ' +color.ORANGE+m['name']) # name
                                                print(color.GREEN+' [+] Action : ' +color.END+m['action']) # action

                                        except KeyError:# if value m['name'] not there :(

                                            print(color.RED+'\n +---------+')
                                            print(color.RED+' |   PoC   |')
                                            print(color.RED+' +---------+\n')
                                            print(color.BLUE+' [+] URL : ' +color.CYAN+url) # the url
                                            print(color.GREEN+' [+] Action : ' +color.END+ m['action']) # action

                                        print(color.ORANGE+' [+] Query : '+color.GREY+ urllib.parse.urlencode(result).strip())
                                        print('')                                       # print out the params + url

                                except KeyboardInterrupt: # incase user wants to exit (while form processing)
                                    verbout(R, 'User Interrupt!')
                                    print(R+'Aborted!') # say goodbye
                                    sys.exit(1)

                                except KeyboardInterrupt: # other exceptions ;-; can be ignored
                                    pass

                            except urllib.error.HTTPError as msg: # if runtime exception...
                                verbout(R, 'Exception : '+msg.__str__()) # again exception :(

                    actionDone.append(action) # add the stuff done
                    i+=1 # ctr++

            except urllib.error.URLError: # if again...
                verbout(R, 'Exception at : '+url) # again exception -_-
                time.sleep(0.4)
                verbout(O, 'Moving on...')
                continue; # make sure it doesn't stop

        verbout('\n'+G,"Scan completed!"+'\n')

    except urllib.error.HTTPError as e: # 403 not authenticated
        if str(e.code) == '403':
            verbout(R, 'HTTP Authentication Error!')
            verbout(R, 'Error Code : ' +O+ str(e.code))
            pass

    except KeyboardInterrupt: # incase user wants to exit ;-; (while crawling)
        verbout(R, 'User Interrupt!')
        print(R+'Aborted!') # say goodbye
        sys.exit(1)
