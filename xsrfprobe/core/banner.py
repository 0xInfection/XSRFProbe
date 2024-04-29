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
import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()

SLEEP_TIME = 0


def banner():
    """Display the program banner"""
    print("\n\n")
    time.sleep(SLEEP_TIME)
    print(
        colors.ORANGE
        + "     _____       _____       _____      _____       _____                                    "
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.RED
        + "  __"
        + colors.ORANGE
        + "|"
        + colors.RED
        + "__ "
        + colors.ORANGE
        + "  |_  "
        + colors.RED
        + "__"
        + colors.ORANGE
        + "|"
        + colors.RED
        + "___ "
        + colors.ORANGE
        + " |_  "
        + colors.RED
        + "__"
        + colors.ORANGE
        + "|"
        + colors.RED
        + "___  "
        + colors.ORANGE
        + "|_  "
        + colors.RED
        + "_"
        + colors.ORANGE
        + "|"
        + colors.RED
        + "____ "
        + colors.ORANGE
        + "|_"
        + colors.RED
        + "   _"
        + colors.ORANGE
        + "|"
        + colors.RED
        + "____ "
        + colors.ORANGE
        + "|_ "
        + colors.RED
        + " _____   _____  ______  ______  "
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.RED
        + " \  `  /    "
        + colors.ORANGE
        + "|"
        + colors.RED
        + "|   ___|   "
        + colors.ORANGE
        + "|"
        + colors.RED
        + "|  _  _|   "
        + colors.ORANGE
        + "|"
        + colors.RED
        + "|   ___|  "
        + colors.ORANGE
        + "| "
        + colors.RED
        + "|   _  |  "
        + colors.ORANGE
        + "|"
        + colors.RED
        + "|  _ ,' /     \|  _   )|   ___| "
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.RED
        + "  >   <     "
        + colors.ORANGE
        + "|"
        + colors.RED
        + " `-.`-.    "
        + colors.ORANGE
        + "|"
        + colors.RED
        + "|     \    "
        + colors.ORANGE
        + "|"
        + colors.RED
        + "|   ___|  "
        + colors.ORANGE
        + "|"
        + colors.RED
        + " |    __|  "
        + colors.ORANGE
        + "|"
        + colors.RED
        + "|     \ |  -  || |_  { |   ___| "
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.RED
        + " /__/__\   "
        + colors.ORANGE
        + "_|"
        + colors.RED
        + "|______|  "
        + colors.ORANGE
        + "_|"
        + colors.RED
        + "|__|\__\ "
        + colors.ORANGE
        + " _|"
        + colors.RED
        + "|___|   "
        + colors.ORANGE
        + " _|"
        + colors.RED
        + " |___|   "
        + colors.ORANGE
        + " _|"
        + colors.RED
        + "|__|\__\\\_____/|______)|______| "
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.ORANGE
        + "    |_____|     |_____|     |_____|    |_____|     |_____| \n\n"
    )
    time.sleep(SLEEP_TIME)


def banabout():  # some fancy banner stuff :p
    print(
        colors.BLUE
        + "   [---]            "
        + colors.GREY
        + "XSRFProbe,"
        + colors.RED
        + " A"
        + colors.ORANGE
        + " Cross Site Request Forgery "
        + colors.RED
        + "Audit Toolkit          "
        + colors.BLUE
        + "[---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.BLUE
        + "   [---]                                                                           [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.BLUE
        + "   [---]   "
        + colors.PURPLE
        + "                    "
        + colors.GREEN
        + "~  Author : "
        + colors.CYAN
        + "Pinaki Mondal  ~                   "
        + colors.BLUE
        + "     [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.BLUE
        + "   [---]   "
        + colors.CYAN
        + "                   ~  github.com / "
        + colors.GREY
        + "0xInfection  ~                     "
        + colors.BLUE
        + "  [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.BLUE
        + "   [---]                                                                           [---]"
    )
    time.sleep(SLEEP_TIME)
    print(
        colors.BLUE
        + "   [---]  "
        + colors.ORANGE
        + "                         ~  Version "
        + colors.RED
        + __version__
        + colors.ORANGE
        + "  ~                           "
        + colors.BLUE
        + "  [---]\n"
    )
    time.sleep(SLEEP_TIME)
