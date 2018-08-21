#!/usr/bin/env python2
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe

import re
import string 
import Uri_Checker
from core.colors import * 
from random import Random # import ends

class Form_Debugger():

	def prepareFormInputs(self, form):
		print O+'Crafting inputs as form type...'
		print GR+'Parsing final inputs...'
		input = {} # :D

		print O+'Processing'+color.BOLD+' <input type="hidden" name="...' # get hidden input types
		for m in form.findAll('input',{'name' : True,'type' : 'hidden'}):
			if re.search(' value=',m.__str__()):
				value=m['value'].encode('utf8') # make sure no encoding errors there
			else:
				value=randString()
			input[m['name']] = value # assign passed on value

		print O+'Processing '+color.BOLD+'<input type="test" name="...' # get name type inputs
		for m in form.findAll('input',{'name' : True,'type' : 'text'}):
			if re.search(' value=',m.__str__()):
				value=m['value'].encode('utf8') # make sure no encoding errors there
			else:
				value=randString()
			input[m['name']] = value # assign passed on value

		print O+'Processing'+color.BOLD+' <input type="password" name="...' # get password inputs
		for m in form.findAll('input',{'name' : True,'type' : 'password'}):
			if re.search(' value=',m.__str__()):
				value=m['value'].encode('utf8') # make sure no encoding errors there
			else:
				value=randString()
			input[m['name']] = value # assign passed on value

		print O+'Processing '+color.BOLD+'<input type="submit" name="...' # get submit buttons :D
		for m in form.findAll('input',{'name' : True,'type' : 'submit'}):
			if re.search(' value=',m.__str__()):
				value=m['value'].encode('utf8') # make sure no encoding errors there
			else:
				value=randString()
			input[m['name']] = value # assign passed on value

		print O+'Processing'+color.BOLD+' <input type="checkbox" name="...' # get checkbox type inputs
		for m in form.findAll('input',{'name' : True,'type' : 'checkbox'}):
			if re.search(' value=',m.__str__()):
				value=m['value'].encode('utf8') # make sure no encoding errors there
			else:
				value=randString() # assign passed on value
			input[m['name']] = value # assign discovered value

		print O+'Processing'+color.BOLD+' <input type="radio" name="...' # get radio buttons :D
		listRadio = []
		for m in form.findAll('input',{'name' : True,'type' : 'radio'}):
			if (not m['name'] in listRadio) and re.search(' value=',m.__str__()):
				listRadio.append(m['name'])
				input[m['name']] = value.encode('utf8') # make sure no encoding errors there

		print O+'Processing'+color.BOLD+' <textarea name="...' # get textarea input types
		for m in form.findAll('textarea',{'name' : True}):
			if len(m.contents)==0:
				m.contents.append(randString()) # get random strings
			input[m['name']] = m.contents[0].encode('utf8') # make sure no encoding errors there

		print O+'Processing'+color.BOLD+' <select name="...' # selection type inputs
		for m in form.findAll('select',{'name' : True}):
			if len(m.findAll('option',value=True))>0:
				name = m['name'] # assign passed on value
				input[name] = m.findAll('option',value=True)[0]['value'].encode('utf8') # make sure no encoding errors there

		return input

def randString(): # generate random strings
	print GR+'Compiling strings...'
	return ''.join( Random().sample(string.letters, 6)) # any 6 chars
		
def getAllForms(soup): # get all forms (form based csrf)
	return soup.findAll('form',action=True,method=re.compile("post", re.IGNORECASE)) # duh...

