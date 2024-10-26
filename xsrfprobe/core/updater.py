#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import os
from requests import get
from xsrfprobe import __version__

import core.colors

colors = core.colors.color()


def updater():
    """
    Function to update XSRFProbe seamlessly.
    """
    print("Checking for updates...")
    vno = get(
        "https://raw.githubusercontent.com/0xInfection/XSRFProbe/master/xsrfprobe/files/VersionNum",
        timeout=1,
    ).text

    print("Version on GitHub: " + vno.strip())
    print("Version You Have : " + __version__)
    if vno != __version__:
        print("A new version of XSRFProbe is available!")
        current_path = os.getcwd().split("/")  # if you know it, you know it
        folder = current_path[-1]  # current directory name
        path = "/".join(current_path)  # current directory path
        choice = input("Would you like to update? [Y/n] :> ").lower()
        if choice != "n":
            print("Updating ..")
            os.system(
                "git clone --quiet https://github.com/0xInfection/XSRFProbe %s"
                % (folder)
            )
            os.system(
                "cp -r %s/%s/* %s && rm -r %s/%s/ 2>/dev/null"
                % (path, folder, path, path, folder)
            )
            print("Update successful!")
    else:
        print("XSRFProbe is up to date!")
    quit()
