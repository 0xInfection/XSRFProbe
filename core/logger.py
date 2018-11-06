#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import os
from files.config import *

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
        
