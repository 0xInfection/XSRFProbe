#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re


def formPrettify(response):
    """
    Beautify HTML forms for terminal display.
    """
    highlighted = []
    response = response.splitlines()
    for line in response:
        highlighted.append(line)
    for h in highlighted:
        print("  " + h)


def indentPrettify(soup, indent=2):
    pretty_soup = str()
    previous_indent = 0
    for line in soup.prettify().split("\n"):
        current_indent = str(line).find("<")
        if current_indent == -1 or current_indent > previous_indent + 2:
            current_indent = previous_indent + 1
        previous_indent = current_indent
        pretty_soup += writeOut(line, current_indent, indent)
    return pretty_soup


def writeOut(line, current_indent, desired_indent):
    new_line = ""
    spaces_to_add = (current_indent * desired_indent) - current_indent
    if spaces_to_add > 0:
        for i in range(spaces_to_add):
            new_line += " "
    new_line += str(line) + "\n"
    return new_line
