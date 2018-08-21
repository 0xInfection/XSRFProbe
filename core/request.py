#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

# Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe

import urllib
from impo import *
from core.colors import * # import ends

def request(referer,action,form,opener,cookie):

	data = urllib.urlencode(form) # encode stuff to make callable
	if cookie != '': # if user input has cookie
		headers = {
			'User-Agent' : 'Mozilla/5.0 (Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
			'Set-Cookie' : cookie, 
			'Referer' : referer
			} # headers set
	else: # if not
		headers = {
			'User-Agent' : 'Mozilla/5.0 (Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
			'Referer' : referer
			} # headers set
	try:
		return opener.open(action,data).read() # read data content

	except urllib2.HTTPError: # if error
		print R+"HTTP Error 1 : "+action # ah shit -_-
		return

	except ValueError: # again if valuerror
		print R+"Value Error : "+action # another one -_-
		return

	except:
		return '' # if at all nothing happens

