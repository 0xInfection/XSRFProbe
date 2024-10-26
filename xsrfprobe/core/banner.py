#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRF-Probe
# https://github.com/0xInfection/XSRF-Probe

# Just for some fancy benner to appear at beginning
from xsrfprobe import __version__

def banner():
    """Display the program banner"""
    print("\n\n")
    print(r'''
                     ________                    ______
____  __________________  __/_______________________  /______
__  |/_/_  ___/_  ___/_  /_ ___  __ \_  ___/  __ \_  __ \  _ \
__>  < _(__  )_  /   _  __/ __  /_/ /  /   / /_/ /  /_/ /  __/
/_/|_| /____/ /_/    /_/    _  .___//_/    \____//_.___/\___/
                            /_/

                                   ~  0xInfection | %s

''' % __version__)