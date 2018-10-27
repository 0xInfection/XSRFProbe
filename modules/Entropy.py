#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import time
import urllib.parse
from math import log
from core.colors import *
from .Token import Token
from core.verbout import verbout

def Entropy(req):
    """
    This function has the work of comparing and 
      calculating Shannon Entropy and related
           POST Based requests' security. 
        
    """
    
    # The minimum length of a csrf token should be 5 bytes. 
    min_length = 5
    
    # I have never seen a CSRF token longer than 256 bytes,
    # so the main concept here is doubling that and checking 
    # to make sure we don't check parameters which are
    # files in multipart uploads or stuff like that.
    max_length = 256*2
    
    # Shannon Entropy calculated for a particular CSRF token 
    # should be at least 2.4. If the token entropy is less 
    # than that, the application request can be easily 
    # forged making the application vulnerable even in
    # presence of a CSRF token.  
    min_entropy = 2.4 

    # Check for common CSRF token names
    para = Token(req)
    if para == '':
        return True
        
    value = urllib.parse.quote(str(para), safe='')
    
    # Check length
    if len(value) <= min_length:
        print(color.RED+' [-] CSRF Token Length less than 5 bytes. '+color.ORANGE+'Token value can be guessed/bruteforced...')
        print(color.ORANGE+' [-] Application likely '+color.RED+'VULNERABLE'+color.ORANGE+' to CSRF Attacks...')

    if len(value) > max_length:
        # Multipart uploads usually have a trailing sequence of 
        # characters which could be misunderstood as a CSRF token.
        # This is a very important step with respect to 
        # decreasing [[ False Positives ]].
        print(color.GREEN+' [+] CSRF Token Length greater than 256 bytes. '+color.ORANGE+'Token value cannot be guessed/bruteforced...')
        print(color.ORANGE+' [+] Application likely '+color.GREEN+'NOT VULNERABLE'+color.ORANGE+' to CSRF Attacks...')
    
    # Calculate entropy
    verbout(O, 'Proceeding to calculate '+color.GREY+'Shannon Entropy'+color.END+' of Token audited...')
    entropy = shannon_entropy(value)
    verbout(GR, 'Calculating Entropy...')
    if entropy >= min_entropy:
        print(color.GREEN+' [-] Anti-CSRF Token Entropy Calculated is '+color.ORANGE+'GREATER than 2.4... ')
        print(color.ORANGE+' [-] Application '+color.GREEN+'NOT VULNERABLE'+color.ORANGE+' to CSRF Attacks...')
        time.sleep(0.5)
        print(color.GREEN+' [+] The Application implements Token Based Checks for preventing CSRF Attacks...')
        return False
    else:
        print(color.RED+' [-] Anti-CSRF Token Entropy Calculated is '+color.ORANGE+'less than 2.4... ')
        print(color.ORANGE+' [-] Application likely '+color.GREEN+'VULNERABLE'+color.ORANGE+' to CSRF Attacks inspite of CSRF Tokens...')
        return True

def shannon_entropy(data):
    """
    This function is used to calculate
            Shannon Entropy.
    """
    if not data:
        return 0

    entropy = 0 # init

    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x * log(p_x, 2)

    return entropy
    
def smart_string(s, encoding='utf8'):
    """
    Return a byte-string version of 's', 
            Encoded as utf-8.
    """
    try:
        s = s.encode(encoding)
    except UnicodeEncodeError:
        s = str(s)
    return s

