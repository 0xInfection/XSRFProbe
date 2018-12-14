#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import os
from core.colors import *
from files.config import *
from core.verbout import verbout

def logger(filename, content):
    '''
    This module is for logging all the stuff we found
            while crawling and scanning.
    '''
    output_file = OUTPUT_DIR + filename + '.log'
    with open(output_file, 'w+', encoding='utf8') as f:
        if type(content) is tuple or type(content) is list:
            for m in content:  # if it is list or tuple, it is iterable
                f.write(m+'\n')
        else:
            f.write(content)  # else we write out as it is... ;)
        f.write('\n')

def pheaders(tup):
    '''
    This module prints out the headers as received in the
                    requests normally.
    '''
    verbout(GR, 'Receiving headers...\n')
    verbout(color.GREY,'  '+color.UNDERLINE+'HEADERS'+color.END+color.GREY+':'+'\n')
    for key, val in tup.items():
        verbout('  ',color.CYAN+key+': '+color.ORANGE+val)
    verbout('','')

def LinkLogger():
    from files.discovered import INTERNAL_URLS
    logger('internal-links', INTERNAL_URLS)

def ErrorLogger(url, error):
    content = '(i) 'url+' -> '+error
    logger('errors', content)
