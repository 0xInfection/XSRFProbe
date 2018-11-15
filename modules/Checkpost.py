#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import time
import difflib
from core.colors import *
from urllib.parse import urlencode

def PostBased(url, r1, r2, r3, m_action, result, m_name=''):
    try:
        checkdiffx1 = difflib.ndiff(r1.splitlines(1),r2.splitlines(1))  # check the diff noted
        checkdiffx2 = difflib.ndiff(r1.splitlines(1),r3.splitlines(1))  # check the diff noted
        result12 = []  # an init
        for n in checkdiffx1:
            if re.match('\+|-',n):  # get regex matching stuff
                result12.append(n)  # append to existing list
        result13 = []  # an init
        for n in checkdiffx2:
            if re.match('\+|-',n):  # get regex matching stuff
                result13.append(n)  # append to existing list
        # This logic is based purely on the assumption on the difference of requests and
        # response body.
        # If the number of differences of result12 are less than the number of differences
        # than result13 then we have the vulnerability. (very basic check)
        #
        # NOTE: The alogrithm has lots of scopes of improvements
        if len(result12)<=len(result13):
            print(color.GREEN+ ' [+] CSRF Vulnerability Detected : '+color.ORANGE+url+'!')
            print(color.ORANGE+' [!] Vulnerability Type: '+color.BR+' POST-Based Request Forgery '+color.END)
            time.sleep(0.3)
            print(O+'PoC of response and request...')
            try:  # yet we give out what we found
                if m_name:
                    print(color.RED+'\n +---------+')
                    print(color.RED+' |   PoC   |')
                    print(color.RED+' +---------+\n')
                    print(color.BLUE+' [+] URL : ' +color.CYAN+url)  # url part
                    print(color.CYAN+' [+] Name : ' +color.ORANGE+m_name)  # name
                    print(color.GREEN+' [+] Action : ' +color.END+m_action)  # action
            except KeyError:# if value m['name'] not there :(
                print(color.RED+'\n +---------+')
                print(color.RED+' |   PoC   |')
                print(color.RED+' +---------+\n')
                print(color.BLUE+' [+] URL : ' +color.CYAN+url)  # the url
                print(color.GREEN+' [+] Action : ' +color.END+ m_action)  # action

            print(color.ORANGE+' [+] Query : '+color.GREY+ urlencode(result).strip())
            print('')                                        # print out the params + url
