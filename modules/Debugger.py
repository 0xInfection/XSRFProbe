#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
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
        This method parses form types and generates strings based
                        on their input types.
        '''
        verbout(O,'Crafting inputs as form type...')
        cr_input = {}
        totcr = []

        verbout(GR, 'Processing '+color.BOLD+'<input type="text" name="...')  # get name type inputs
        for m in form.findAll('input', {'name' : True, 'type' : 'text'}):
            if re.search('value=', str(m).strip(), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()
            cr_input[m['name']] = value  # assign passed on value
            cr0 = {}
            cr0['type'] = 'text'
            cr0['name'] = m['name']
            cr0['label'] = m['name'].title()
            cr0['value'] = ''
            totcr.append(cr0)

        verbout(GR, 'Processing'+color.BOLD+' <input type="password" name="...')  # get password inputs
        for m in form.findAll('input', {'name' : True, 'type' : 'password'}):
            if re.search('value=', str(m).strip(), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()
            cr_input[m['name']] = value  # assign passed on value
            cr1={}
            cr1['type'] = 'password'
            cr1['name'] = m['name']
            cr1['label'] = 'Password'
            cr1['value'] = ''
            totcr.append(cr1)

        try:
            verbout(GR, 'Processing'+color.BOLD+' <input type="hidden" name="...')  # get hidden input types
            for m in form.findAll('input', {'name' : True, 'type' : 'hidden'}):
                if re.search('value=', m.__str__(), re.IGNORECASE):   # Ignore case while searching for a match
                    value=m['value']  # make sure no encoding errors there
                else:
                    value=randString()
                cr_input[m['name']] = value  # assign passed on value
                cr2={}
                cr2['type'] = 'hidden'
                cr2['name'] = m['name']
                cr2['label'] = ''  # Nothing since its a hidden field
                cr2['value'] = value
                totcr.append(cr2)
        except KeyboardInterrupt:
            cr2['value'] = ''

        verbout(GR, 'Processing '+color.BOLD+'<input type="submit" name="...')  # get submit buttons :D
        for m in form.findAll('input', {'name' : True, 'type' : 'submit'}):
            if re.search('value=', str(m).strip(), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()
            cr_input[m['name']] = value  # assign passed on value

        verbout(GR, 'Processing'+color.BOLD+' <input type="checkbox" name="...')  # get checkbox type inputs
        for m in form.findAll('input', {'name' : True, 'type' : 'checkbox'}):
            if re.search('value=', m.__str__(), re.IGNORECASE):   # Ignore case while searching for a match
                value=m['value'].encode('utf8')  # make sure no encoding errors there
            else:
                value=randString()  # assign passed on value
            cr_input[m['name']] = value  # assign discovered value
            cr3={}
            cr3['type'] = 'checkbox'
            cr3['name'] = m['name']
            cr3['label'] = m['name'].title()
            cr3['value'] = ''
            totcr.append(cr3)

        verbout(GR, 'Processing'+color.BOLD+' <input type="radio" name="...')  # get radio buttons :D
        listRadio = []
        for m in form.findAll('input', {'name' : True,'type' : 'radio'}):
            if (not m['name'] in listRadio) and re.search('value=', str(m).strip(), re.IGNORECASE):   # Ignore case while searching for a match
                listRadio.append(m['name'])
                cr_input[m['name']] = value.encode('utf8')  # make sure no encoding errors there
                cr4={}
                cr4['type'] = 'radio'
                cr4['name'] = m['name']
                cr4['label'] = m['name'].title()
                cr4['value'] = ''
                totcr.append(cr4)

        verbout(GR, 'Processing'+color.BOLD+' <textarea name="...')  # get textarea input types
        for m in form.findAll('textarea', {'name' : True}):
            if len(m.contents)==0:
                m.contents.append(randString())  # get random strings
            cr_input[m['name']] = m.contents[0].encode('utf8')  # make sure no encoding errors there
            cr5={}
            cr5['type'] = 'text'
            cr5['name'] = m['name']
            cr5['label'] = m['name'].title()
            cr5['value'] = ''
            totcr.append(cr5)

        verbout(GR, 'Processing'+color.BOLD+' <select name="...')  # selection type inputs
        for m in form.findAll('select', {'name' : True}):
            if m.findAll('option', value=True):
                name = m['name']  # assign passed on value
                cr_input[name] = m.findAll('option',value=True)[0]['value'].encode('utf8')  # find forms fields based on value

        verbout(GR,'Parsing final inputs...')
        return (cr_input, totcr)  # Return the form input types

def randString():  # generate random strings
    verbout(GR,'Compiling strings...')
    return ''.join(Random().sample(string.ascii_letters, TOKEN_GENERATION_LENGTH))  # any chars to be generated as form field inputs

def getAllForms(soup):  # get all forms
    return soup.findAll('form', method=re.compile("post", re.IGNORECASE))  # get forms with post method only
