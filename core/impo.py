#!/usr/bin/env python3
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe

# import stuffs
import sys
import os
import re
import time
import warnings
import difflib
try:
    import urllib.parse
except ImportError:
    import urllib.parse as urlparse
import requests
import http.cookiejar
import urllib.request, urllib.parse, urllib.error
from bs4 import BeautifulSoup
warnings.filterwarnings('ignore')
from core.formtype01 import *
from core.formtype02 import *
from core.inputin import *
from core.banner import *
from core.banabout import *
from core.request import *
from core.colors import *
from core.globalvars import *
from core.xsrf_main import *
from modules.Crawler_Handler import *
from modules.Form_Debugger import *
from modules.Uri_Checker import *
