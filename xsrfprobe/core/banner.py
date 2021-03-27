#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection
#This module requires XSRF-Probe
#https://github.com/0xInfection/XSRF-Probe

# Just for some fancy benner to appear at beginning

import time
from xsrfprobe import __version__
from xsrfprobe.core.colors import *

def banner():
    '''
    Sweet ass banner
    '''
    print('''
  %s%sParasite%s - %sThe Next-Gen Recon Framework
              %sVersion : v%s%s
''' % (color.BOLD, color.CYAN, color.GREY, color.BLUE, color.RED, __version__, color.END))

