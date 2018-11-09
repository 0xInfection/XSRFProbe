#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: @_tID
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

import

def Decoder(val):
    verbout(GR,'Decoding the token...')

def SHA2(string, base):
    html = urlopen("http://md5decrypt.net/Api/api.php?hash="+string+"&hash_type=sha256&email=deanna_abshire@proxymail.eu&code=1152464b80a61728")
    string = html.read()
    string = ensure_str(string)
    if len(string) > 0:
        if string in decoded:
            Quit()
        print(g + ' Cracked SHA2 Hash: %s' % string)
        decoded.append(string)
        decode(base, 'sha2')
        Quit()
    else:
        print('\033[1;31m[-]\033[1;m Its a SHA2 Hash but I failed to crack it.')
        Quit()

def SHA1(string, base):
    data = urlencode({"auth":"8272hgt", "hash":string, "string":"","Submit":"Submit"})
    html = urlopen("http://hashcrack.com/index.php" , data)
    find = html.read()
    match = search (r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
    if match:
        string = match.group().split('hervorheb2>')[1][:-18]
        string = ensure_str(string)
        if string in decoded:
            Quit()
        print(g + ' Cracked SHA1 : %s' % string)
        decoded.append(string)
        decode(base, 'sha1')
        Quit()
    else:
        print('\033[1;31m[-]\033[1;m Its a SHA1 Hash but I failed to crack it.')
        Quit()

def MD5(string, base):
    url = "http://www.nitrxgen.net/md5db/" + string
    string = urlopen(url).read()
    string = ensure_str(string)
    if len(string) > 0:
        if string in decoded:
            Quit()
        print(g + ' Cracked MD5 Hash : %s' % string)
        decoded.append(string)
        decode(base, 'md5')
        Quit()
    else:
        print('\033[1;31m[-]\033[1;m Its a MD5 Hash but I failed to crack it.')
        Quit()

def fromchar(string, base):
        string = string.lower()
        string = string.strip('string.fromcharcode(').strip(')').strip(' ')
        jv_list = string.split(',')
        decoded = []
        for i in jv_list:
            i = i.replace(' ', '').replace('97', 'a').replace('98', 'b').replace('99', 'c').replace('100', 'd').replace('101', 'e').replace('102', 'f').replace('103', 'g').replace('104', 'h').replace('105', 'i').replace('106', 'j').replace('107', 'k').replace('108', 'l').replace('109', 'm').replace('110', 'n').replace('111', 'o').replace('112', 'p').replace('113', 'q').replace('114', 'r').replace('115', 's').replace('116', 't').replace('117', 'u').replace('118', 'v').replace('119', 'w').replace('120', 'x').replace('121', 'y').replace('122', 'z').replace('48', '0').replace('49', '1').replace('50', '2').replace('51', '3').replace('52', '4').replace('53', '5').replace('54', '6').replace('55', '7').replace('56', '8').replace('57', '9').replace('33', '!').replace('64', '@').replace('35', '#').replace('36', '$').replace('37', '%').replace('94', '^').replace('38', '&').replace('42', '*').replace('40', '(').replace('41', ')').replace('45', '-').replace('61', '=').replace('95', '_').replace('43', '+').replace('91', '[').replace('93', ']').replace('92', '\\').replace('59', ';').replace('39', '\'').replace('44', ',').replace('46', '.').replace('47', '/').replace('123', '{').replace('125', '}').replace('124', '|').replace('58', ':').replace('34', '"').replace('60', '<').replace('62', '>').replace('63', '?').replace('32', ' ').replace(',', '').replace('65', 'A').replace('66', 'B').replace('67', 'C').replace('68', 'D').replace('69', 'E').replace('70', 'F').replace('71', 'G').replace('72', 'H').replace('73', 'I').replace('74', 'J').replace('75', 'K').replace('76', 'L').replace('77', 'M').replace('78', 'N').replace('79', 'O').replace('80', 'P').replace('81', 'Q').replace('82', 'R').replace('83', 'S').replace('84', 'T').replace('85', 'U').replace('86', 'V').replace('87', 'W').replace('88', 'X').replace('89', 'Y').replace('90', 'Z').replace('32', ' ')
            decoded.append(i)
        string = ''.join(decoded)
        string = ensure_str(string)
        if string in decoded:
            Quit()
        print(g + ' Decoded from FromChar : %s' % (string))
        decoded.append(string)
        decode(string, 'none')
        decode(base, 'jv_char')
        Quit()
