#!/usr/bin/env python2
#coding: utf-8

#-:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
#-:-:-:-:-:-:-::-:-:#

#Author: the-Infected-Drake (@_tID)
#This module requires XSRF-Probe
#https://github.com/the-Infected-Drake/XSRF-Probe

from __future__ import print_function
import sys
import socket
from core.colors import *

def inputin():

	web = raw_input(color.CYAN+' [$] Enter target address :> '+color.END) # take input

	if 'http' not in web: # add protocol to site
		web = 'http://' + web

	web0 = web.split('//')[1]
	try:
		print(O+'Testing site status...')
		socket.gethostbyname(web0) # test whether site is up or not
		print(color.GREEN+' [+] Site seems to be up!'+color.END)

	except socket.gaierror: # if site is down
		print(R+'Site seems to be down...')
		sys.exit(0)

	cook = raw_input(color.RED+' [$] Got any cookies? '+color.ORANGE+'[Enter for None]'+color.RED+' :> '+color.END)
	if web.endswith('/'): # check
		return web, cook
	else:
		web = web + '/' # make sure the site address ends with '/'
		return web, cook
