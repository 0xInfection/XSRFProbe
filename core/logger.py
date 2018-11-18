#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
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
    output_file = OUTPUT_DIR + filename + '.txt'
    with open(output_file, 'w+', encoding='utf8') as f:
        for m in content:
            f.write(m+'\n')
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
