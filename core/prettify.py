#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
from core.colors import *

def formPrettify(response):
    '''
    The main aim for this is to beautify the forms
        that will be displayed on the terminal.
    '''
    highlighted = []
    response = response.splitlines()
    try:
        for newLine in response:
            line = newLine
            # Find starting tags
            pattern = re.findall(r"""(<+\w+>)""", line)
            for grp in pattern:
                starttag = ''.join(grp)
                if starttag:
                    line = line.replace(starttag, color.BLUE + starttag + color.END)
            # Find attributes
            pattern = re.findall(r'''(\s\w+=)''', line)
            for grp in pattern:
                stu = ''.join(grp)
                if stu:
                    line = line.replace(stu, color.CYAN + stu + color.END)
            # Find ending tags
            pattern = re.findall(r'''(</.*>)''', line)
            for grp in pattern:
                endtag = ''.join(grp)
                if endtag:
                    line = line.replace(endtag, color.CYAN + endtag + color.END)
            if line != newLine:
                highlighted.append(line)
            else:
                highlighted.append(color.GREY+newLine)
    except MemoryError:
        pass
    for h in highlighted:
        print('  '+h)
