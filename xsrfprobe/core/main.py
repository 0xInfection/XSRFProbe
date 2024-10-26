#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-:-:-:#
#    XSRFProbe     #
# -:-:-:-:-:-:-:-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

# Standard Package imports
import os
import time
import requests
import warnings
from bs4 import BeautifulSoup

# This needs to be first, so that the options are loaded, as well as things like
#  colors are disabled
import files.config as config

# Imports from core
from files.discovered import FORMS_TESTED

from core.verbout import verbout
from core.inputin import inputin
from core.prettify import formPrettify
from core.logger import ErrorLogger, GetLogger
from core.logger import VulnLogger, NovulLogger

# Imports from files
from files.config import (
    COOKIE_VALUE,
    HEADER_VALUES,
    CRAWL_SITE,
    REFERER_ORIGIN_CHECKS,
    FORM_SUBMISSION,
    COOKIE_BASED,
    POST_BASED,
)

# Imports from modules
from modules import Debugger
from modules import Parser
from modules import Crawler
from modules.Origin import Origin
from modules.Cookie import Cookie
from modules.Tamper import Tamper
from modules.Entropy import Entropy
from modules.Referer import Referer
from modules.Encoding import Encoding
from modules.Analysis import Analysis
from modules.Checkpost import PostBased

# Import Ends

# First rule, remove the warnings!
warnings.filterwarnings("ignore")


def Engine():  # lets begin it!
    web, fld = inputin()  # Take the input
    session1 = requests.Session()  # First as User1
    session2 = requests.Session()  # Then as User2

    actionDone = []  # init to whatever was done
    csrf = ""  # no token initialised / invalid token
    ref_detect = 0x00
    ori_detect = 0x00
    form = Debugger.Form_Debugger()  # init to the form parser+token generator
    bs1 = BeautifulSoup(form1).findAll("form", action=True)[
        0
    ]  # make sure the stuff works properly
    bs2 = BeautifulSoup(form2).findAll("form", action=True)[0]  # same as above
    init1 = web  # First init
    hdrs = [("Cookie", ",".join(cookie for cookie in COOKIE_VALUE))]
    [hdrs.append((k, v)) for k, v in HEADER_VALUES.items()]
    resp1.addheaders = resp2.addheaders = hdrs
    resp1.open(init1)  # Makes request as User2
    resp2.open(init1)  # Make request as User1

    # Now there are 2 different modes of scanning and crawling here.
    # 1st -> Testing a single endpoint without the --crawl flag.
    # 2nd -> Testing all endpoints with the --crawl flag.
    try:
        # Implementing the first mode. [NO CRAWL]
        if not CRAWL_SITE:
            url = web
            try:
                response = Get(url).text
                verbout(colors.O, "Trying to parse response...")
                soup = BeautifulSoup(response)  # Parser init
            except AttributeError:
                verbout(colors.R, "No response received, site probably down: " + url)
            i = 0  # Init user number
            if REFERER_ORIGIN_CHECKS:
                # Referer Based Checks if True...
                verbout(
                    colors.O,
                    "Checking endpoint request validation via "
                    + colors.GREY
                    + "Referer"
                    + colors.END
                    + " Checks...",
                )

                if Referer(url):
                    ref_detect = 0x01

                verbout(colors.O, "Confirming the vulnerability...")
                # We have finished with Referer Based Checks, lets go for Origin Based Ones...
                verbout(
                    colors.O,
                    "Confirming endpoint request validation via "
                    f"{colors.GREY}Origin{colors.END} Checks...",
                )

                if Origin(url):
                    ori_detect = 0x01

            # Now lets get the forms...
            verbout(
                colors.O,
                f"Retrieving all forms on {colors.GREY}{url}{colors.END}...",
            )

            for m in Debugger.getAllForms(soup):  # iterating over all forms extracted
                verbout(colors.O, "Testing form:\n" + colors.CYAN)
                formPrettify(m.prettify())
                verbout("", "")
                FORMS_TESTED.append("(i) " + url + ":\n\n" + m.prettify() + "\n")
                try:
                    if m["action"]:
                        pass
                except KeyError:
                    m["action"] = "/" + url.rsplit("/", 1)[1]
                    ErrorLogger(url, 'No standard form "action".')
                action = Parser.buildAction(
                    url, m["action"]
                )  # get all forms which have 'action' attribute
                if (
                    not action in actionDone and action != ""
                ):  # if url returned is not a null value nor duplicate...
                    # If form submission is kept to True
                    if FORM_SUBMISSION:
                        try:
                            # NOTE: Slow connections may cause read timeouts which may result in AttributeError
                            # So the idea here is tp make requests pretending to be 3 different users.
                            # Now a series of requests will be targeted against the site with different
                            # identities. Refer to XSRFProbe wiki for more info.
                            #
                            # NOTE: Slow connections may cause read timeouts which may result in AttributeError
                            result, genpoc = form.prepareFormInputs(
                                m
                            )  # prepare inputs as user 1

                            r1 = Post(
                                url, action, result
                            )  # make request with token values generated as user1

                            result, genpoc = form.prepareFormInputs(
                                m
                            )  # prepare inputs as user 2

                            r2 = Post(
                                url, action, result
                            )  # again make request with token values generated as user2

                            # Go for cookie based checks
                            if COOKIE_BASED:
                                Cookie(url, r1)

                            # Go for token based entropy checks...
                            try:
                                if m["name"]:
                                    query, token = Entropy(
                                        result,
                                        url,
                                        r1.headers,
                                        m.prettify(),
                                        m["action"],
                                        m["name"],
                                    )
                            except KeyError:
                                query, token = Entropy(
                                    result, url, r1.headers, m.prettify(), m["action"]
                                )

                            # Now its time to detect the encoding type (if any) of the Anti-CSRF token.
                            fnd, detct = Encoding(token)

                            if fnd == 0x01 and detct:
                                VulnLogger(
                                    url,
                                    "Token is a string encoded value which can be probably decrypted.",
                                    "[i] Encoding: " + detct,
                                )
                            else:
                                NovulLogger(
                                    url,
                                    "Anti-CSRF token is not a string encoded value.",
                                )

                            # Go for token parameter tamper checks.
                            if query and token:
                                txor = Tamper(
                                    url, action, result, r2.text, query, token
                                )

                            o2 = Get(url).text  # make request as user2
                            try:
                                form2 = Debugger.getAllForms(BeautifulSoup(o2))[
                                    i
                                ]  # user2 gets his form
                            except IndexError:
                                verbout(colors.R, "Form Index Error")
                                ErrorLogger(url, "Form Index Error.")
                                continue  # Making sure program won't end here (dirty fix :( )

                            verbout(colors.GR, "Preparing form inputs...")
                            contents2, genpoc = form.prepareFormInputs(
                                form2
                            )  # prepare for form 3 as user3
                            r3 = Post(
                                url, action, contents2
                            )  # make request as user3 with user3's form
                            if (POST_BASED) and ((not query) or (txor)):
                                try:
                                    if m["name"]:
                                        PostBased(
                                            url,
                                            r1.text,
                                            r2.text,
                                            r3.text,
                                            action,
                                            result,
                                            genpoc,
                                            m.prettify(),
                                            m["name"],
                                        )
                                except KeyError:
                                    PostBased(
                                        url,
                                        r1.text,
                                        r2.text,
                                        r3.text,
                                        action,
                                        result,
                                        genpoc,
                                        m.prettify(),
                                    )
                            else:
                                print(
                                    f"{colors.GREEN} [+] The form was requested "
                                    "with a Anti-CSRF token."
                                )
                                print(
                                    f"{colors.GREEN} [+] Endpoint {colors.BG} "
                                    f"NOT VULNERABLE {colors.END}{colors.GREEN} to "
                                    "POST-Based CSRF Attacks!"
                                )

                                NovulLogger(
                                    url, "Not vulnerable to POST-Based CSRF Attacks."
                                )
                        except HTTPError as msg:  # if runtime exception...
                            verbout(
                                colors.R, "Exception : " + msg.__str__()
                            )  # again exception :(
                            ErrorLogger(url, msg)
                actionDone.append(action)  # add the stuff done
                i += 1  # Increase user iteration
        else:
            # Implementing the 2nd mode [CRAWLING AND SCANNING].
            verbout(colors.GR, "Initializing crawling and scanning...")
            crawler = Crawler.Handler(init1, resp1)  # Init to the Crawler handler
            while crawler.noinit():  # Until 0 urls left
                url = next(crawler)  # Go for next!
                print(
                    f"{colors.C}Testing :> {colors.CYAN}{url}"
                )  # Display what url its crawling

                try:
                    soup = crawler.process(fld)  # Start the parser
                    if not soup:
                        continue  # Making sure not to end the program yet..

                    i = 0  # Set count = 0 (user number 0, which will be subsequently incremented)
                    if REFERER_ORIGIN_CHECKS:
                        # Referer Based Checks if True...
                        verbout(
                            colors.O,
                            "Checking endpoint request validation via "
                            + colors.GREY
                            + "Referer"
                            + colors.END
                            + " Checks...",
                        )

                        if Referer(url):
                            ref_detect = 0x01

                        verbout(colors.O, "Confirming the vulnerability...")
                        # We have finished with Referer Based Checks, lets go for Origin Based Ones...
                        verbout(
                            colors.O,
                            "Confirming endpoint request validation via "
                            f"{colors.GREY}Origin{colors.END} Checks...",
                        )
                        if Origin(url):
                            ori_detect = 0x01
                    # Now lets get the forms...
                    verbout(
                        colors.O,
                        f"Retrieving all forms on {colors.GREY}{url}{colors.END}...",
                    )

                    for m in Debugger.getAllForms(
                        soup
                    ):  # iterating over all forms extracted
                        FORMS_TESTED.append(f"(i) {url}:\n\n{m.prettify()}\n")

                        try:
                            if m["action"]:
                                pass
                        except KeyError:
                            m["action"] = "/" + url.rsplit("/", 1)[1]
                            ErrorLogger(url, 'No standard "action" attribute.')

                        action = Parser.buildAction(
                            url, m["action"]
                        )  # get all forms which have 'action' attribute
                        if (
                            action not in actionDone and action != ""
                        ):  # if url returned is not a null value nor duplicate...
                            # If form submission is kept to True
                            if FORM_SUBMISSION:
                                try:
                                    result, genpoc = form.prepareFormInputs(
                                        m
                                    )  # prepare inputs as user 1

                                    r1 = Post(
                                        url, action, result
                                    )  # make request with token values generated as user1

                                    result, genpoc = form.prepareFormInputs(
                                        m
                                    )  # prepare inputs as user 2

                                    r2 = Post(
                                        url, action, result
                                    )  # again make request with token values generated as user2

                                    if COOKIE_BASED:
                                        Cookie(url, r1)

                                    # Go for token based entropy checks...
                                    try:
                                        if m["name"]:
                                            query, token = Entropy(
                                                result,
                                                url,
                                                r1.headers,
                                                m.prettify(),
                                                m["action"],
                                                m["name"],
                                            )
                                    except KeyError:
                                        query, token = Entropy(
                                            result,
                                            url,
                                            r1.headers,
                                            m.prettify(),
                                            m["action"],
                                        )
                                        ErrorLogger(url, 'No standard form "name".')

                                    # Now its time to detect the encoding type (if any) of the Anti-CSRF token.
                                    fnd, detct = Encoding(token)

                                    if fnd == 0x01 and detct:
                                        VulnLogger(
                                            url,
                                            "String encoded token value. Token might be decrypted.",
                                            "[i] Encoding: " + detct,
                                        )
                                    else:
                                        NovulLogger(
                                            url,
                                            "Anti-CSRF token is not a string encoded value.",
                                        )

                                    # Go for token parameter tamper checks.
                                    if query and token:
                                        txor = Tamper(
                                            url, action, result, r2.text, query, token
                                        )

                                    o2 = Get(url).text  # make request as user2
                                    try:
                                        form2 = Debugger.getAllForms(BeautifulSoup(o2))[
                                            i
                                        ]  # user2 gets his form
                                    except IndexError:
                                        verbout(colors.R, "Form Index Error")
                                        ErrorLogger(url, "Form Index Error.")
                                        continue  # making sure program won't end here (dirty fix :( )

                                    verbout(colors.GR, "Preparing form inputs...")

                                    contents2, genpoc = form.prepareFormInputs(
                                        form2
                                    )  # prepare for form 3 as user3

                                    r3 = Post(
                                        url, action, contents2
                                    )  # make request as user3 with user3's form

                                    if (POST_BASED) and ((query == "") or txor):
                                        try:
                                            if m["name"]:
                                                PostBased(
                                                    url,
                                                    r1.text,
                                                    r2.text,
                                                    r3.text,
                                                    m["action"],
                                                    result,
                                                    genpoc,
                                                    m.prettify(),
                                                    m["name"],
                                                )
                                        except KeyError:
                                            PostBased(
                                                url,
                                                r1.text,
                                                r2.text,
                                                r3.text,
                                                m["action"],
                                                result,
                                                genpoc,
                                                m.prettify(),
                                            )
                                    else:
                                        print(
                                            f"{colors.GREEN} [+] The form was requested with a Anti-CSRF token."
                                        )
                                        print(
                                            colors.GREEN
                                            + " [+] Endpoint "
                                            + colors.BG
                                            + " NOT VULNERABLE "
                                            + colors.END
                                            + colors.GREEN
                                            + " to P0ST-Based CSRF Attacks!"
                                        )
                                        NovulLogger(
                                            url,
                                            "Not vulnerable to POST-Based CSRF Attacks.",
                                        )
                                except HTTPError as msg:  # if runtime exception...
                                    verbout(
                                        colors.RED,
                                        " [-] Exception : "
                                        + colors.END
                                        + msg.__str__(),
                                    )  # again exception :(
                                    ErrorLogger(url, msg)

                        actionDone.append(action)  # add the stuff done
                        i += 1  # Increase user iteration

                # This error usually happens when some sites are protected by some load balancer
                # example Cloudflare. These domains return a 403 forbidden response in various
                # contexts. For example when making reverse DNS queries.
                except HTTPError as e:
                    if str(e.code) == "403":
                        verbout(colors.R, "HTTP Authentication Error!")
                        verbout(colors.R, "Error Code : " + str(e.code))
                        ErrorLogger(url, e)
                        quit()
                except URLError as e:  # if again...
                    verbout(colors.R, "Exception at : " + url)  # again exception -_-
                    time.sleep(0.4)
                    verbout(colors.O, "Moving on...")
                    ErrorLogger(url, e)
                    continue  # make sure it doesn't stop at exceptions

        GetLogger()  # The scanning has finished, so now we can log out all the links ;)
        print(f"\n{colors.G}Scan done\n")
        Analysis()  # For Post Scan Analysis
    except KeyboardInterrupt as e:  # Incase user wants to exit :') (while crawling)
        verbout(colors.R, "User Interrupt!")
        time.sleep(1.5)
        Analysis()  # For Post scan Analysis
        print("Aborted!")  # say goodbye
        ErrorLogger("KeyBoard Interrupt", "Aborted")
    except Exception as e:
        print("\n" + "Encountered an error. \n")
        print("Please view the error log files to view what went wrong.")
        verbout(colors.R, e.__str__())
        ErrorLogger(url, e)
    finally:
        GetLogger()
