#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/0xInfection/XSRFProbe

# import stuffs
import sys
import os
import re
import time
import warnings
import difflib
import requests
import http.cookiejar
import urllib.request
import urllib.parse
import urllib.error
from bs4 import BeautifulSoup
from core.options import *
from core.verbout import *
from core.formtype01 import *
from core.formtype02 import *
from core.inputin import *
from core.banner import *
from core.banabout import *
from core.request import *
from core.colors import *
from core.xsrf_main import *
from files.config import *
from modules.Token import *
from modules.Referer import *
from modules.Crawler import *
from modules.Debugger import *
from modules.Parser import *
from modules.Entropy import *
from modules.Cookie import *
