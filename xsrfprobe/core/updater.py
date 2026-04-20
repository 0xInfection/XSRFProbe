#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import os
import sys
import requests
from xsrfprobe.core import __version__


def updater():
    """
    Function to update XSRFProbe seamlessly.
    """
    print("Checking for updates...")
    vno = requests.get(
        "https://raw.githubusercontent.com/0xInfection/XSRFProbe/master/xsrfprobe/files/VersionNum",
        timeout=1,
    ).text.strip()

    print("[+] Version on GitHub:", vno)
    print("[+] Version installed locally:", __version__)
    if vno != __version__:
        print("[!] A new version of XSRFProbe is available!")
        print("[*] Updating XSRFProbe via PIP...")
        choice = input("Would you like to update? [Y/n] :> ").lower()
        if choice != "n":
            print("Updating...")
            os.system("python3 -m pip install --upgrade xsrfprobe")
            print("Update successful!")
    else:
        print("XSRFProbe is up to date!")

    sys.exit(0)
