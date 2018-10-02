#!/usr/bin/env python2
#-*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
#-:-:-:-:-:-:-:-:-:#

#Author: @_tID
#This module requires XSRFProbe
#https://github.com/theInfectedDrake/XSRFProbe

from __future__ import print_function
from core.impo import *
from core.globalvars import *
from modules.Crawler_Handler import *
from modules.Form_Debugger import *
from modules.Uri_Checker import * # get imports

def xsrf_main(): # lets begin it!

	os.system('clear') # clear shit from terminal :p
	banner() # print the banner
	banabout() # the second banner
	web, cookie = inputin() # take the input
	form1 = form10() # get the form 1 ready
	form2 = form20() # get the form 2 ready

	Cookie0 = cookielib.CookieJar() # cookies ummm...
	Cookie1 = cookielib.CookieJar() # another one :o
	resp1 = urllib2.build_opener(urllib2.HTTPCookieProcessor(Cookie0)) # process cookies and do stuff
	resp2 = urllib2.build_opener(urllib2.HTTPCookieProcessor(Cookie1))  # process cookies and do stuff

	actionDone = [] # init to the done stuff

	csrf='' # no token initialise
	init1 = web # get the starting page
	form = Form_Debugger() # get the parser

	bs1=BeautifulSoup(form1).findAll('form',action=True)[0] # make sure the stuff works properly
	bs2=BeautifulSoup(form2).findAll('form',action=True)[0] # same as above

	action = init1 # lets start the stuff

	resp1.open(action) # make thre req ;)
	resp2.open(action) # go for the second one

	crawler = Crawler_Handler(init1,resp1) # pass onto the crawler
	print(GR+"Initializing crawling and scanning...")

	try:

		while crawler.noinit(): # if 0 init
		    url = crawler.next() # go for next!

		    print(C+'Crawling :> ' +color.BOLD+ url) # display what url its crawling
			
		    try:
			soup=crawler.process(web) # start the parser
			if not soup:
				continue; # don't end the program yet...
			i=0 # count = 0
			print(O+'Retrieving all forms on ' +color.BOLD+ url+color.END+'...')
			for m in getAllForms(soup): # iterating over all forms got
				action = Uri_Checker.buildAction(url,m['action']) # see what it takes
				if not action in actionDone and action!='': # not a null value / neither duplicate...
					try:
						result = form.prepareFormInputs(m) # prepare inputs
						r1 = request(url, action, result, resp1, cookie) # comparable request
						result = form.prepareFormInputs(m) # prepare the input types
						r2 = request(url, action, result, resp2, cookie) # request the form

						if(len(csrf)>0):
							if not re.search(csrf, r2): # yep we got the vuln!
								print(color.GREEN+ ' [+] CSRF vulnerability Detected : '+color.ORANGE+url+'!\n')
								try:
								    if m['name']: # print it out fancy:p
									print(color.RED+'\n +---------+')
									print(color.RED+' |   PoC   |')
									print(color.RED+' +---------+\n')
									print(color.BLUE+' [+] URL : ' +color.CYAN+url)
									print(color.CYAN+' [+] Name : ' +color.ORANGE+m['name'])
									print(color.GREEN+' [+] Action : ' +color.ORANGE+m['action'])

								except KeyError: # if value m['name'] not there :(

									print(color.RED+'\n +---------+')
									print(color.RED+' |   PoC   |')
									print(color.RED+' +---------+\n')
									print(color.BLUE+' [+] URL : ' +color.CYAN+url)
									print(color.GREEN+' [+] Action : ' +color.ORANGE+m['action'])

								print(color.ORANGE+' [+] Code : '+color.END+urllib.urlencode(result))
								print('')				# print out the params + url

							continue;

						o2 = resp2.open(url).read() # open and read the response

						try:
							form2 = getAllForms(BeautifulSoup(o2))[i] # com'on lets get it

						except IndexError:
							print(R+'Form Error') # ah shit -_-
							continue; # program won't end here

						print(GR+'Preparing form inputs...')
						contents2 = form.prepareFormInputs(form2) # prepare for form 2
						r3 = request(url,action,contents2,resp2, cookie) # make request

						try:
							checkdiff = difflib.ndiff(r1.splitlines(1),r2.splitlines(1)) # check the diff noted
							checkdiff0 = difflib.ndiff(r1.splitlines(1),r3.splitlines(1)) # check the diff noted

							result12 = [] # an init
							for n in checkdiff:
								if re.match('\+|-',n): # get regex matching stuff
									result12.append(n) # append to existing list

							result13 = [] # an init
							for n in checkdiff0:
								if re.match('\+|-',n): # get regex matching stuff
									result13.append(n) # append to existing list

							if len(result12)<=len(result13): # incase we dont have a csrf
								print(R+ 'No CSRF Detected At : '+color.BOLD+url+'...')
								time.sleep(0.3)
								print(O+'PoC of response and request...')
								try: # yet we give out what we found
								    if m['name']: # print it out
									print(color.RED+'\n +---------+')
									print(color.RED+' |   PoC   |')
									print(color.RED+' +---------+\n')
									print(color.BLUE+' [+] URL : ' +color.CYAN+url) # url part
									print(color.CYAN+' [+] Name : ' +color.ORANGE+m['name']) # name
									print(color.GREEN+' [+] Action : ' +color.END+m['action']) # action

								except KeyError:# if value m['name'] not there :(

									print(color.RED+'\n +---------+')
									print(color.RED+' |   PoC   |')
									print(color.RED+' +---------+\n')
									print(color.BLUE+' [+] URL : ' +color.CYAN+url) # the url 
									print(color.GREEN+' [+] Action : ' +color.END+ m['action']) # action

								print(color.ORANGE+' [+] Code : '+color.END+ urllib.urlencode(result).strip())
								print('') 					# print out the params + url

						except KeyboardInterrupt: # incase user wants to exit (while form processing)
							print(R+'User Interrupt!')
							print(R+'Aborted!') # say goodbye
							sys.exit(1)

						except: # other exceptions ;-; can be ignored
							pass

					except urllib2.HTTPError, msg: # if runtime exception...
						print(R+'Exception : '+msg.__str__()) # again exception :(

				actionDone.append(action) # add the stuff done
				i+=1 # ctr++

		    except urllib2.URLError: # if again...
		    	print(R+'Exception at : '+url) # again exception -_-
		    	time.sleep(0.4)
		    	print(O+'Moving on...')
		    	continue; # make sure it doesn't stop

		print(G+"Scan completed!")

	except urllib2.HTTPError as e: # 403 not authenticated
	    if str(e.code) == '403':
		print(R+'HTTP Authentication Error!')
		print(R+'Error Code : ' +O+ str(e.code))
		pass

	except KeyboardInterrupt: # incase user wants to exit ;-; (while crawling)
		print(R+'User Interrupt!')
		print(R+'Aborted!') # say goodbye
		sys.exit(1)

