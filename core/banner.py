#!/usr/bin/env python3
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: 0xInfection
#This module requires XSRF-Probe
#https://github.com/0xInfection/XSRF-Probe

# Just for some fancy benner to appear at beginning

from core.colors import *
import time

def banner():

    print('\n\n')
    time.sleep(0.05)
    print(color.ORANGE+'     _____       _____       _____      _____       _____                                    ')
    time.sleep(0.05)
    print(color.RED+'  __'+color.ORANGE+'|'+color.RED+'__ '+color.ORANGE+'  |_  '+color.RED+'__'+color.ORANGE+'|'+color.RED+'___ '+color.ORANGE+' |_  '+color.RED+'__'+color.ORANGE+'|'+color.RED+'___  '+color.ORANGE+'|_  '+color.RED+'_'+color.ORANGE+'|'+color.RED+'____ '+color.ORANGE+'|_'+color.RED+'   _'+color.ORANGE+'|'+color.RED+'____ '+color.ORANGE+'|_ '+color.RED+' _____   _____  ______  ______  ')
    time.sleep(0.05)
    print(color.RED+" \  `  /    "+color.ORANGE+'|'+color.RED+'|   ___|   '+color.ORANGE+'|'+color.RED+'|  _  _|   '+color.ORANGE+'|'+color.RED+'|   ___|  '+color.ORANGE+'| '+color.RED+'|   _  |  '+color.ORANGE+"|"+color.RED+"|  _ ,' /     \|  _   )|   ___| ")
    time.sleep(0.05)
    print(color.RED+'  >   <     '+color.ORANGE+'|'+color.RED+' `-.`-.    '+color.ORANGE+'|'+color.RED+'|     \    '+color.ORANGE+'|'+color.RED+'|   ___|  '+color.ORANGE+'|'+color.RED+' |    __|  '+color.ORANGE+'|'+color.RED+'|     \ |  -  || |_  { |   ___| ')
    time.sleep(0.05)
    print(color.RED+' /__/__\   '+color.ORANGE+'_|'+color.RED+'|______|  '+color.ORANGE+'_|'+color.RED+'|__|\__\ '+color.ORANGE+' _|'+color.RED+'|___|   '+color.ORANGE+' _|'+color.RED+' |___|   '+color.ORANGE+' _|'+color.RED+'|__|\__\\\_____/|______)|______| ')
    time.sleep(0.05)
    print(color.ORANGE+'    |_____|     |_____|     |_____|    |_____|     |_____| \n\n')
    time.sleep(0.05)

def banabout(): # some fancy banner stuff :p

    print(color.BLUE+'   [---]            '+color.GREY+'XSRF Probe,'+color.RED+' A'+color.ORANGE+' Cross Site Request Forgery '+color.RED+'Audit Toolkit          '+color.BLUE+'[---]')
    time.sleep(0.1)
    print(color.BLUE+'   [---]                                                                            [---]')
    time.sleep(0.1)
    print(color.BLUE+'   [---]   '+color.PURPLE+'                  '+color.GREEN+'~  Author : '+color.CYAN+'The Infected Drake  ~                 '+color.BLUE+'     [---]')
    time.sleep(0.1)
    print(color.BLUE+'   [---]   '+color.CYAN+'                    ~  github.com / '+color.GREY+'0xInfection  ~                     '+color.BLUE+'  [---]')
    time.sleep(0.1)
    print(color.BLUE+'   [---]                                                                            [---]')
    time.sleep(0.1)
    print(color.BLUE+'   [---]   '+color.ORANGE+'                       ~  Version '+color.RED+open('files/VersionNum').read().strip()+color.ORANGE+'  ~                       '+color.BLUE+'  [---]\n')
    time.sleep(0.1)
