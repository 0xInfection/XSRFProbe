#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import os


class color:
    END = (
        BOLD
    ) = (
        RED
    ) = GREEN = ORANGE = BLUE = PURPLE = UNDERLINE = CYAN = GREY = BR = BG = BY = ""

    # no color values
    O = " [!] "
    R = " [-] "
    GR = " [*] "
    G = " [+] "
    C = " [+] "

    def __init__(self) -> None:
        # Put it here so that it is called after options is called
        from xsrfprobe.files.config import NO_COLORS

        if os.name == "nt" or os.name == "mac" or NO_COLORS:
            return

        self.END = "\033[0m"  # normal
        self.BOLD = "\033[1m"  # bold
        self.RED = "\033[1;91m"  # red
        self.GREEN = "\033[1;92m"  # green
        self.ORANGE = "\033[1;93m"  # orange
        self.BLUE = "\033[1;94m"  # blue
        self.PURPLE = "\033[1;95m"  # purple
        self.UNDERLINE = "\033[4m"  # underline
        self.CYAN = "\033[1;96m"  # cyan
        self.GREY = "\033[1;97m"  # gray
        self.BR = "\033[1;97;41m"  # background red
        self.BG = "\033[1;97;42m"  # background green
        self.BY = "\033[1;97;43m"  # background yellow
        self.O = "\033[1m \033[93m[!]\033[0m "  # information
        self.R = "\033[1m \033[91m[-]\033[0m "  # something's not right
        self.GR = "\033[1m \033[97m[*]\033[0m "  # processing
        self.G = "\033[1m \033[92m[+]\033[0m "  # yay!
        self.C = "\033[1m \033[96m[+]\033[0m "  # crawling...
