#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import time
import difflib
from core.colors import *
from core.verbout import verbout
from urllib.parse import urlencode
from core.logger import VulnLogger
from files.config import POC_GENERATION, GEN_MALICIOUS
from modules.Generator import GenNormalPoC, GenMalicious

def PostBased(url, r1, r2, r3, m_action, result, genpoc, form, m_name=''):
    '''
    This method is for detecting POST-Based Request Forgeries
        on basis of fuzzy string matching and comparison
            based on Ratcliff-Obershelp Algorithm.
    '''
    verbout(color.RED, '\n +------------------------------+')
    verbout(color.RED, ' |   POST-Based Forgery Check   |')
    verbout(color.RED, ' +------------------------------+\n')
    verbout(O, 'Matching response query differences...')
    checkdiffx1 = difflib.ndiff(r1.splitlines(1), r2.splitlines(1))  # check the diff noted
    checkdiffx2 = difflib.ndiff(r1.splitlines(1), r3.splitlines(1))  # check the diff noted
    result12 = []  # an init
    verbout(O, 'Matching results...')
    for n in checkdiffx1:
        if re.match('\+|-', n):  # get regex matching stuff only +/-
            result12.append(n)  # append to existing list
    result13 = []  # an init
    for n in checkdiffx2:
        if re.match('\+|-', n):  # get regex matching stuff
            result13.append(n)  # append to existing list
    # Make sure m_action has a / before it. (legitimate action).
    if not m_action.startswith('/'):
        m_action = '/' + m_action

    # This logic is based purely on the assumption on the difference of various requests
    # and response body.
    # If the number of differences of result12 are less than the number of differences
    # than result13 then we have the vulnerability. (very basic check)
    #
    # NOTE: The algorithm has lots of scopes of improvement...
    if len(result12) <= len(result13):
        print(color.GREEN+ ' [+] CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
        print(color.ORANGE+' [!] Vulnerability Type: '+color.BR+' POST-Based Request Forgery '+color.END)
        VulnLogger(url, 'POST-Based Request Forgery on Forms.', '[i] Form: '+form.__str__()+'\n[i] POST Query: '+result.__str__()+'\n')
        time.sleep(0.3)
        verbout(O, 'PoC of response and request...')
        if m_name:
            print(color.RED+'\n +-----------------+')
            print(color.RED+' |   Request PoC   |')
            print(color.RED+' +-----------------+\n')
            print(color.BLUE+' [+] URL : ' +color.CYAN+url)  # url part
            print(color.CYAN+' [+] Name : ' +color.ORANGE+m_name)  # name
            if m_action.count('/') > 1:
                print(color.GREEN+' [+] Action : ' +color.END+'/'+m_action.rsplit('/', 1)[1])  # action
            else:
                print(color.GREEN+' [+] Action : ' +color.END+m_action)  # action
        else:  # if value m['name'] not there :(
            print(color.RED+'\n +-----------------+')
            print(color.RED+' |   Request PoC   |')
            print(color.RED+' +-----------------+\n')
            print(color.BLUE+' [+] URL : ' +color.CYAN+url)  # the url
            if m_action.count('/') > 1:
                print(color.GREEN+' [+] Action : ' +color.END+'/'+m_action.rsplit('/', 1)[1])  # action
            else:
                print(color.GREEN+' [+] Action : ' +color.END+m_action)  # action
        print(color.ORANGE+' [+] POST Query : '+color.GREY+ urlencode(result).strip())
        # If option --skip-poc hasn't been supplied...
        if POC_GENERATION:
            # If --malicious has been supplied
            if GEN_MALICIOUS:
                # Generates a malicious CSRF form
                GenMalicious(url, genpoc.__str__())
            else:
                # Generates a normal PoC
                GenNormalPoC(url, genpoc.__str__())
