#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

import time
from core.colors import *

def banabout(): # some fancy banner stuff :p

    print(color.BLUE+'   [---]           '+color.GREY+'XSRF Probe |'+color.RED+' A'+color.ORANGE+' Cross Site Request Forgery '+color.RED+'Audit Toolkit          '+color.BLUE+'[---]')
    time.sleep(0.2)
    print(color.BLUE+'   [---]                                                                            [---]')
    time.sleep(0.2)
    print(color.BLUE+'   [---]   '+color.PURPLE+'                  '+color.GREEN+'~  Author : '+color.CYAN+'The Infected Drake  ~                 '+color.BLUE+'     [---]')
    time.sleep(0.2)
    print(color.BLUE+'   [---]   '+color.CYAN+'                    ~  github.com / '+color.GREY+'0xInfection  ~                     '+color.BLUE+'  [---]')
    time.sleep(0.2)
    print(color.BLUE+'   [---]                                                                            [---]')
    time.sleep(0.2)
    print(color.BLUE+'   [---]   '+color.ORANGE+'                          ~  Version '+color.RED+'v1.1.0'+color.ORANGE+'  ~                         '+color.BLUE+'  [---]\n')
    time.sleep(0.2)

# Custom help message if -h/--help is supplied :D
def msg():
    print('''
    \033[1;91mXSRFProbe\033[0m, \033[1;97mA Cross Site Request Forgery Audit Toolkit\033[0m
    
usage: xsrfprobe.py [-h] [-u ROOT_URL] [-c COOK] [-o OUTPUT] [-d DELAY] [-q]
                    [--user-agent USER_AGENT] [--headers] [--exclude EXCLUDE]
                    [--timeout TIMEOUT] [--max-chars MAXCHARS] [--update]
                    [--random-agent] [--version]

Required Arguments:
  -u ROOT_URL, --url ROOT_URL   Main URL to test.

Optional Arguments:
  -h, --help                    Show this help message and exit.
  -c COOKIE, --cookie COOKIE    Cookie value to be requested with each successive request.
                                If there are multiple cookies, separate them with commas.
                                For example: `-c PHPSESSID=i837c5n83u4, _gid=jdhfbuysf`
  -o OUTPUT, --output OUTPUT    Output directory where files to be stored. Default is the
                                `files` folder where all files generated will be stored.
  -d DELAY, --delay DELAY       Time delay between requests in seconds. Default is zero.
  --user-agent USER_AGENT       Custom user-agent to be used. Only one user-agent can
                                be specified.
  -q, --quiet                   Set the DEBUG mode to quiet. Report only when vulnerabilities
                                are found. Minimal output will be printed on screen. 
  --headers HEADERS             Comma separated list of custom headers you'd want to use.
                                For example: ``--headers Accept=text/php, DNT=1``.
  --exclude EXCLUDE             Comma separated list of paths or directories to be excluded 
                                which are not in scope. These paths won't be scanned. 
                                For example: `--exclude somepage/, sensitive-dir/, dontscan/`
  --timeout TIMEOUT             HTTP request timeout value in seconds. The entered value must
                                be in floating point decimal. Example: ``--timeout 10.0`` 
  --max-chars MAXCHARS          Maximum allowed character length for the custom token value to
                                be generated. For example: `--max-chars 5`. Default value is 6.
  --random-agent                Use random user-agents for requests.
  --update                      Update XSRFProbe to latest version on GitHub via git.
  --version                     Display the version of XSRFProbe and exit.
''')

