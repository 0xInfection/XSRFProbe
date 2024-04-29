#!/usr/bin/env python3
# coding: utf-8

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRF-Probe
# https://github.com/0xInfection/XSRF-Probe

# Just for some fancy benner to appear at beginning

import time
from xsrfprobe import __version__
from xsrfprobe.core.colors import *

SLEEP_TIME = 0

def banner():
    """Display the program banner"""
    print("\n\n")
    time.sleep(SLEEP_TIME)
    print(
        color.ORANGE
        + "     _____       _____       _____      _____       _____                                    "
    )
    time.sleep(SLEEP_TIME)
    print(
        color.RED
        + "  __"
        + color.ORANGE
        + "|"
        + color.RED
        + "__ "
        + color.ORANGE
        + "  |_  "
        + color.RED
        + "__"
        + color.ORANGE
        + "|"
        + color.RED
        + "___ "
        + color.ORANGE
        + " |_  "
        + color.RED
        + "__"
        + color.ORANGE
        + "|"
        + color.RED
        + "___  "
        + color.ORANGE
        + "|_  "
        + color.RED
        + "_"
        + color.ORANGE
        + "|"
        + color.RED
        + "____ "
        + color.ORANGE
        + "|_"
        + color.RED
        + "   _"
        + color.ORANGE
        + "|"
        + color.RED
        + "____ "
        + color.ORANGE
        + "|_ "
        + color.RED
        + " _____   _____  ______  ______  "
    )
    time.sleep(SLEEP_TIME)
    print(
        color.RED
        + " \  `  /    "
        + color.ORANGE
        + "|"
        + color.RED
        + "|   ___|   "
        + color.ORANGE
        + "|"
        + color.RED
        + "|  _  _|   "
        + color.ORANGE
        + "|"
        + color.RED
        + "|   ___|  "
        + color.ORANGE
        + "| "
        + color.RED
        + "|   _  |  "
        + color.ORANGE
        + "|"
        + color.RED
        + "|  _ ,' /     \|  _   )|   ___| "
    )
    time.sleep(SLEEP_TIME)
    print(
        color.RED
        + "  >   <     "
        + color.ORANGE
        + "|"
        + color.RED
        + " `-.`-.    "
        + color.ORANGE
        + "|"
        + color.RED
        + "|     \    "
        + color.ORANGE
        + "|"
        + color.RED
        + "|   ___|  "
        + color.ORANGE
        + "|"
        + color.RED
        + " |    __|  "
        + color.ORANGE
        + "|"
        + color.RED
        + "|     \ |  -  || |_  { |   ___| "
    )
    time.sleep(SLEEP_TIME)
    print(
        color.RED
        + " /__/__\   "
        + color.ORANGE
        + "_|"
        + color.RED
        + "|______|  "
        + color.ORANGE
        + "_|"
        + color.RED
        + "|__|\__\ "
        + color.ORANGE
        + " _|"
        + color.RED
        + "|___|   "
        + color.ORANGE
        + " _|"
        + color.RED
        + " |___|   "
        + color.ORANGE
        + " _|"
        + color.RED
        + "|__|\__\\\_____/|______)|______| "
    )
    time.sleep(SLEEP_TIME)
    print(
        color.ORANGE + "    |_____|     |_____|     |_____|    |_____|     |_____| \n\n"
    )
    time.sleep(SLEEP_TIME)


def banabout():  # some fancy banner stuff :p
    print(
        color.BLUE
        + "   [---]            "
        + color.GREY
        + "XSRFProbe,"
        + color.RED
        + " A"
        + color.ORANGE
        + " Cross Site Request Forgery "
        + color.RED
        + "Audit Toolkit          "
        + color.BLUE
        + "[---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        color.BLUE
        + "   [---]                                                                           [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        color.BLUE
        + "   [---]   "
        + color.PURPLE
        + "                    "
        + color.GREEN
        + "~  Author : "
        + color.CYAN
        + "Pinaki Mondal  ~                   "
        + color.BLUE
        + "     [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        color.BLUE
        + "   [---]   "
        + color.CYAN
        + "                   ~  github.com / "
        + color.GREY
        + "0xInfection  ~                     "
        + color.BLUE
        + "  [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        color.BLUE
        + "   [---]                                                                           [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        color.BLUE
        + "   [---]  "
        + color.ORANGE
        + "                         ~  Version "
        + color.RED
        + __version__
        + color.ORANGE
        + "  ~                           "
        + color.BLUE
        + "  [---]\n"
    )
    time.sleep(SLEEP_TIME)
