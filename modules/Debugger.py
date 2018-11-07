#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import re
import string
from core.colors import *
from random import Random
from files.config import *
from core.verbout import verbout 

class Form_Debugger():

    def prepareFormInputs(self, form):
        '''
        This method parses specific form types and generates tokens based 
                        on their input types.
        '''
        verbout(O,'Crafting inputs as form type...')
        verbout(GR,'Parsing final inputs...')
        input = {}

        verbout(O,'Processing '+color.BOLD+'<input type="text" name="...')  # get name type inputs
        for m in form.findAll('input',{'name' : True,'type' : 'text'}):
            if re.search(' value=', str(m), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()
            input[m['name']] = value  # assign passed on value

        verbout(O,'Processing'+color.BOLD+' <input type="password" name="...')  # get password inputs
        for m in form.findAll('input',{'name' : True,'type' : 'password'}):
            if re.search(' value=', str(m), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()
            input[m['name']] = value  # assign passed on value

        verbout(O,'Processing'+color.BOLD+' <input type="hidden" name="...')  # get hidden input types
        for m in form.findAll('input',{'name' : True,'type' : 'hidden'}):
            if re.search(' value=', str(m), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()
            input[m['name']] = value  # assign passed on value

        verbout(O,'Processing '+color.BOLD+'<input type="submit" name="...')  # get submit buttons :D
        for m in form.findAll('input',{'name' : True,'type' : 'submit'}):
            if re.search(' value=', str(m), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()
            input[m['name']] = value  # assign passed on value

        verbout(O,'Processing'+color.BOLD+' <input type="checkbox" name="...')  # get checkbox type inputs
        for m in form.findAll('input',{'name' : True,'type' : 'checkbox'}):
            if re.search(' value=', str(m), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()  # assign passed on value
            input[m['name']] = value  # assign discovered value

        verbout(O,'Processing'+color.BOLD+' <input type="radio" name="...')  # get radio buttons :D
        listRadio = []
        for m in form.findAll('input',{'name' : True,'type' : 'radio'}):
            if (not m['name'] in listRadio) and re.search(' value=', str(m), re.IGNORECASE):   # Ignore case while searching for a match
                listRadio.append(m['name'])
                input[m['name']] = value.encode('utf8')  # make sure no encoding errors there

        verbout(O,'Processing'+color.BOLD+' <textarea name="...')  # get textarea input types
        for m in form.findAll('textarea',{'name' : True}):
            if len(m.contents)==0:
                m.contents.append(randString())  # get random strings
            input[m['name']] = m.contents[0].encode('utf8')  # make sure no encoding errors there

        verbout(O,'Processing'+color.BOLD+' <select name="...')  # selection type inputs
        for m in form.findAll('select',{'name' : True}):
            if len(m.findAll('option',value=True))>0:
                name = m['name']  # assign passed on value
                input[name] = m.findAll('option',value=True)[0]['value'].encode('utf8')  # find forms fields based on value

        return input  # Return the form input types

def randString():  # generate random strings
    verbout(GR,'Compiling strings...')
    return ''.join( Random().sample(string.ascii_letters, TOKEN_GENERATION_LENGTH))  # any 6 chars

def getAllForms(soup):  # get all forms
    return soup.findAll('form',action=True,method=re.compile("post", re.IGNORECASE))  # duh...
