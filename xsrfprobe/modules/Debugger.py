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
from xsrfprobe.core.colors import *
from random import Random
from xsrfprobe.files.config import *
from xsrfprobe.core.verbout import verbout

def prepareFormInputs(form):
    '''
    This method parses form types and generates strings based
                    on their input types.
    '''
    verbout(O, 'Crafting inputs as form type...')
    cr_input = dict()
    totcr = list()

    verbout(GR, 'Processing '+color.BOLD+'<input type="text" name="...')
    for m in form.findAll('input', {'name': True, 'type': 'text'}):
        value = TEXT_VALUE
        if m.get('value'):
            value = m['value']
        cr_input[m['name']] = value
        cr0 = dict()
        cr0['type'] = 'text'
        cr0['name'] = m['name']
        cr0['label'] = m['name'].title()
        cr0['value'] = ''
        totcr.append(cr0)

    verbout(GR, 'Processing'+color.BOLD+' <input type="email" name="...')
    for m in form.findAll('input', {'name': True, 'type': 'email'}):
        value = EMAIL_VALUE
        if m.get('value'):
            value = m['value']
        cr_input[m['name']] = value
        cr1 = dict()
        cr1['type'] = 'email'
        cr1['name'] = m['name']
        cr1['label'] = 'Email'
        cr1['value'] = ''
        totcr.append(cr1)

    verbout(GR, 'Processing'+color.BOLD+' <input type="password" name="...')
    for m in form.findAll('input', {'name': True, 'type': 'password'}):
        value = randString()
        if m.get('value'):
            value = m['value']
        cr_input[m['name']] = value
        cr2 = dict()
        cr2['type'] = 'password'
        cr2['name'] = m['name']
        cr2['label'] = 'Password'
        cr2['value'] = ''
        totcr.append(cr2)

    verbout(GR, 'Processing'+color.BOLD+' <input type="hidden" name="...')
    for m in form.findAll('input', {'name': True, 'type': 'hidden'}):
        if m.get('value'):
            value = m['value']
        else:
            value = TEXT_VALUE
        cr_input[m['name']] = value
        cr3 = dict()
        cr3['type'] = 'hidden'
        cr3['name'] = m['name']
        cr3['label'] = ''
        cr3['value'] = value
        totcr.append(cr3)

    verbout(GR, 'Processing '+color.BOLD+'<input type="submit" name="...')
    for m in form.findAll('input', {'name': True, 'type': 'submit'}):
        if m.get('value'):
            value = m['value']
        else:
            value = 'Submit'
        cr_input[m['name']] = value

    verbout(GR, 'Processing'+color.BOLD+' <input type="checkbox" name="...')
    for m in form.findAll('input', {'name': True, 'type': 'checkbox'}):
        if m.get('value'):
            value = m['value']
        else:
            value = randString()
        cr_input[m['name']] = value
        cr4 = dict()
        cr4['type'] = 'checkbox'
        cr4['name'] = m['name']
        cr4['label'] = m['name'].title()
        cr4['value'] = ''
        totcr.append(cr4)

    verbout(GR, 'Processing'+color.BOLD+' <input type="radio" name="...')
    listRadio = list()
    for m in form.findAll('input', {'name': True, 'type': 'radio'}):
        if (not m['name'] in listRadio) and m.get('value') != "":
            listRadio.append(m['name'])
            value = m.get('value')
            cr_input[m['name']] = value
            cr5 = dict()
            cr5['type'] = 'radio'
            cr5['name'] = m['name']
            cr5['label'] = m['name'].title()
            cr5['value'] = ''
            totcr.append(cr5)

    verbout(GR, 'Processing'+color.BOLD+' <textarea name="...')
    for m in form.findAll('textarea', {'name': True}):
        if len(m.contents) == 0:
            m.contents.append(randString())
        cr_input[m['name']] = m.contents[0].encode('utf8')
        cr6 = dict()
        cr6['type'] = 'text'
        cr6['name'] = m['name']
        cr6['label'] = m['name'].title()
        cr6['value'] = ''
        totcr.append(cr6)

    verbout(GR, 'Processing'+color.BOLD+' <select name="...')
    for m in form.findAll('select', {'name': True}):
        if m.findAll('option', value=True):
            name = m['name']
            cr_input[name] = m.findAll('option', value=True)[0]['value'].encode('utf8')

    verbout(GR,'Parsing final inputs...')
    return cr_input, totcr

def randString():
    verbout(GR,'Compiling strings...')
    return ''.join(Random().sample(string.ascii_letters, TOKEN_GENERATION_LENGTH))

def getAllForms(soup):
    return soup.findAll('form', method=re.compile("post", re.IGNORECASE))