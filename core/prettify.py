#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
from core.colors import *

def formPrettify(response):
    '''
    The main aim for this is to beautify the forms
        that will be displayed on the terminal.
    '''
    highlighted = []
    response = response.splitlines()
    for newLine in response:
        line = newLine
        # Find starting tags
        pattern = re.findall(r"""(<+\w+>)""", line)
        for grp in pattern:
            starttag = ''.join(grp)
            if starttag:
                line = line.replace(starttag, color.BLUE + starttag + color.END)
        # Find attributes
        pattern = re.findall(r'''(\s\w+=)''', line)
        for grp in pattern:
            stu = ''.join(grp)
            if stu:
                line = line.replace(stu, color.CYAN + stu + color.END)
        # Find ending tags
        pattern = re.findall(r'''(</.*>)''', line)
        for grp in pattern:
            endtag = ''.join(grp)
            if endtag:
                line = line.replace(endtag, color.CYAN + endtag + color.END)
        if line != newLine:
            highlighted.append(line)
        else:
            highlighted.append(color.GREY+newLine)
    for h in highlighted:
        print('  '+h)

def indentPrettify(soup, indent=2):
    # where desired_indent is number of spaces as an int()
	pretty_soup = str()
	previous_indent = 0
	# iterate over each line of a prettified soup
	for line in soup.prettify().split("\n"):
	    # returns the index for the opening html tag '<'
		current_indent = str(line).find("<")
		# which is also represents the number of spaces in the lines indentation
		if current_indent == -1 or current_indent > previous_indent + 2:
			current_indent = previous_indent + 1
			# str.find() will equal -1 when no '<' is found. This means the line is some kind
			# of text or script instead of an HTML element and should be treated as a child
			# of the previous line. also, current_indent should never be more than previous + 1.
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
