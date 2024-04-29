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

import xsrfprobe.core.colors

colors = xsrfprobe.core.colors.color()


def updater():
    """
    Function to update XSRFProbe seamlessly.
    """
    print(colors.GR + "Checking for updates...")
    vno = get(
        "https://raw.githubusercontent.com/0xInfection/XSRFProbe/master/xsrfprobe/files/VersionNum",
        timeout=1,
    ).text

    print(colors.GR + "Version on GitHub: " + colors.CYAN + vno.strip())
    print(colors.GR + "Version You Have : " + colors.CYAN + __version__)
    if vno != __version__:
        print(colors.G + "A new version of XSRFProbe is available!")
        current_path = os.getcwd().split("/")  # if you know it, you know it
        folder = current_path[-1]  # current directory name
        path = "/".join(current_path)  # current directory path
        choice = input(colors.O + "Would you like to update? [Y/n] :> ").lower()
        if choice != "n":
            print(colors.GR + "Updating XSRFProbe...")
            os.system(
                "git clone --quiet https://github.com/0xInfection/XSRFProbe %s"
                % (folder)
            )
            os.system(
                "cp -r %s/%s/* %s && rm -r %s/%s/ 2>/dev/null"
                % (path, folder, path, path, folder)
            )
            print(colors.G + "Update successful!")
    else:
        print(colors.G + "XSRFProbe is up to date!")
    quit()
