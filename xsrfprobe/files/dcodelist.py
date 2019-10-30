#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# This file contains various regex expressions for detecting the
# encoding type of strings.

# Token hash encoding detection db, thanks to a book, Python for Penetation Testers, LOL!
HASH_DB = (
            ("Blowfish (Eggdrop)", r"^\+[a-zA-Z0-9\/\.]{12}$"),
            ("Blowfish (OpenBSD)", r"^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),
            ("Blowfish Crypt", r"^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("DES (Unix)", r"^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
            ("MD5 (Unix)", r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
            ("MD5 (APR)", r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
            ("MD5 (MyBB)", r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
            ("MD5 (ZipMonster)", r"^[a-fA-F0-9]{32}$"),
            ("MD5 crypt", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("MD5 apache crypt", r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("MD5 (Joomla)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
            ("MD5 (Wordpress)", r"^\$P\$[a-zA-Z0-9\/\.]{31}$"),
            ("MD5 (phpBB3)", r"^\$H\$[a-zA-Z0-9\/\.]{31}$"),
            ("MD5 (Cisco PIX)", r"^[a-zA-Z0-9\/\.]{16}$"),
            ("MD5 (osCommerce)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
            ("MD5 (Palshop)", r"^[a-fA-F0-9]{51}$"),
            ("MD5 (IP.Board)", r"^[a-fA-F0-9]{32}:.{5}$"),
            ("MD5 (Chap)", r"^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
            ("Juniper Netscreen/SSG (ScreenOS)", r"^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),
            ("Fortigate (FortiOS)", r"^[a-fA-F0-9]{47}$"),
            ("Minecraft (Authme)", r"^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
            ("Lotus Domino", r"^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
            ("Lineage II C4", r"^0x[a-fA-F0-9]{32}$"),
            ("CRC-96 (ZIP)", r"^[a-fA-F0-9]{24}$"),
            ("NT crypt", r"^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("Skein-1024", r"^[a-fA-F0-9]{256}$"),
            ("RIPEMD-320", r"^[A-Fa-f0-9]{80}$"),
            ("EPi hash", r"^0x[A-F0-9]{60}$"),
            ("EPiServer 6.x < v4", r"^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$"),
            ("EPiServer 6.x >= v4", r"^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$"),
            ("Cisco IOS SHA256", r"^[a-zA-Z0-9]{43}$"),
            ("oRACLE 11g/12c", r"^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$"),
            ("SHA-1 (Django)", r"^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
            ("SHA-1 crypt", r"^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("SHA-1 (Hex)", r"^[a-fA-F0-9]{40}$"),
            ("SHA-1 (LDAP) Base64", r"^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
            ("SHA-1 (LDAP) Base64 + salt", r"^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),
            ("SHA-512 (Drupal)", r"^\$S\$[a-zA-Z0-9\/\.]{52}$"),
            ("SHA-512 crypt", r"^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("SHA-256 (Django)", r"^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
            ("SHA-256 crypt", r"^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
            ("SHA-384 (Django)", r"^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
            ("SHA-256 (Unix)", r"^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
            ("SHA-512 (Unix)", r"^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
            ("SHA-384", r"^[a-fA-F0-9]{96}$"),
            ("SHA-512", r"^[a-fA-F0-9]{128}$"),
            ("SipHash", r"^[a-f0-9]{16}:2:4:[a-f0-9]{32}$"),
            ("SSHA-1", r"^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
            ("SSHA-1 (Base64)", r"^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
            ("SSHA-512 (Base64)", r"^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
            ("Oracle 11g", r"^S:[A-Z0-9]{60}$"),
            ("SMF >= v1.1", r"^[a-fA-F0-9]{40}:[0-9]{8}&"),
            ("MySQL 5.x", r"^\*[a-f0-9]{40}$"),
            ("MySQL 3.x", r"^[a-fA-F0-9]{16}$"),
            ("OSX v10.7", r"^[a-fA-F0-9]{136}$"),
            ("OSX v10.8", r"^\$ml\$[a-fA-F0-9$]{199}$"),
            ("SAM (LM_Hash:NT_Hash)", r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
            ("MSSQL (2000)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
            ("Cisco Type 7", r"^[a-f0-9]{4,}$"),
            ("Snefru-256", r"^(\\$snefru\\$)?[a-f0-9]{64}$"),
            ("MSSQL (2005)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
            ("MSSQL (2012)", r"^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
            ("TIGER-160 (HMAC)", r"^[a-f0-9]{40}$"),
            ("SHA-256", r"^[a-fA-F0-9]{64}$"),
            ("SHA-1 (Oracle)", r"^[a-fA-F0-9]{48}$"),
            ("SHA-224", r"^[a-fA-F0-9]{56}$"),
            ("Adler32", r"^[a-f0-9]{8}$"),
            ("CRC-16-CCITT", r"^[a-fA-F0-9]{4}$"),
            ("NTLM", r"^[0-9A-Fa-f]{32}$"),
        )

# IP Regex
IP = r'((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]{0,1})\.){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]{0,1})'

# Get rid of Double ../../
RID_DOUBLE = r'/\.\./'

# Get rid of ./'s
RID_SINGLE = r'\./'

# Complier based regex
RID_COMPILE = r'/[^/]*/../'

# Number based.
NUM_SUB = r'=[0-9]+'

# Number based compile.
NUM_COM = r'(title=)[^&]*'

# Binary strings.
BINARY = r'^[01]+$'

# Decimal Strings.
DEC = r'&#.*;+'

# Protocol Types
PROTOCOLS = r'(.*\/)[^\/]*'