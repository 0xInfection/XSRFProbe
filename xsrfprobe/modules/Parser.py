#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Tag

from xsrfprobe.files.dcodelist import PROTOCOLS
from xsrfprobe.files.paramlist import EXCLUSIONS_LIST
from xsrfprobe.files.config import INPUT_TYPES_DEAULTS, TEXT_VALUE


class FormParser:
    def __init__(self, soup: BeautifulSoup) -> None:
        self.soup = soup
        self.logger = logging.getLogger("FormParser")
        self.crafted_inputs = {}

    def getAllForms(self) -> list[Tag]:
        """
        Extracts all forms with method='POST' from the given BeautifulSoup object.
        """
        self.logger.info("Extracting all forms with method='POST'...")
        return self.soup.findAll("form")  # type: ignore

    def checkBadInputs(self, form: Tag) -> bool:
        """
        Checks if the form has any inputs that are not of type 'submit'.
        """
        self.logger.debug("Checking for bad inputs in form...")
        if form.find("input", {"type": "image"}):
            self.logger.warning("Form contains an input of type 'image'. Skipping...")
            return True

        return False

    def extractFormAction(self, form: Tag) -> str:
        """
        Extracts the action attribute from the form tag.
        """
        action = form.get("action")
        if action:
            self.logger.debug(f"Extracted form action: {action}")
            return action  # type: ignore

        self.logger.debug("No action attribute found in form. Trying to extract from <input> attributes...")
        submit = form.find("input", {"type": "submit"})
        if submit:
            action = submit.get("formaction")  # type: ignore
            if action:
                self.logger.debug(f"Extracted form action from <input>: {action}")
                return action  # type: ignore

        self.logger.warning("No action attribute found in form. Trying to extract from <button> attributes...")
        button = form.find("button", {"type": "submit"})
        if button:
            action = button.get("formaction")  # type: ignore
            if action:
                self.logger.debug(f"Extracted form action from <button>: {action}")
                return action  # type: ignore

        return ""

    def extractFormMethod(self, form: Tag) -> str:
        """
        Extracts the method attribute from the form tag.
        """
        method = form.get("method")
        if method:
            self.logger.debug(f"Extracted form method: {method}")
            return method.upper()  # type: ignore

        # extract from button
        button = form.find("button", {"type": "submit"})
        if button:
            method = button.get("formmethod")  # type: ignore
            if method:
                self.logger.debug(f"Extracted form method from <button>: {method}")
                return method.upper()  # type: ignore

        #extract from input type submit
        submit = form.find("input", {"type": "submit"})
        if submit:
            method = submit.get("formmethod")  # type: ignore
            if method:
                self.logger.debug(f"Extracted form method from <input>: {method}")
                return method.upper()  # type: ignore

        self.logger.debug("No method attribute found in form. Defaulting to 'GET'.")
        return "GET"

    def extractFormEnctype(self, form: Tag) -> str:
        """
        Extracts the enctype attribute from the form tag.
        Defaults to 'application/x-www-form-urlencoded' if not specified.
        """
        enctype = form.get("enctype", "").strip().lower()  # type: ignore
        if enctype in ("multipart/form-data", "text/plain", "application/x-www-form-urlencoded"):
            self.logger.debug(f"Extracted form enctype: {enctype}")
            return enctype
        return "application/x-www-form-urlencoded"

    def processInput(self, input_tag: Tag, input_type: str) -> None:
        """
        Helper function to process input tags and generate corresponding strings based on their input types.
        """
        self.logger.debug(f"Processing input tag: {input_tag} with type: {input_type}")
        value = input_tag.get("value", INPUT_TYPES_DEAULTS.get(input_type, TEXT_VALUE))
        self.logger.debug(f"Using default value for input type '{input_type}': {value}")
        self.crafted_inputs[input_tag["name"]] = value

    def prepareFormInputs(self, form: Tag) -> dict:
        """
        Parses form inputs and returns a dict of {name: value} for submission.
        """
        self.crafted_inputs = {}
        self.logger.debug("Crafting inputs based on form types...")

        # Process all input tags
        self.logger.debug("Processing <input> elements...")
        for input_tag in form.findAll("input", {"name": True}):  # type: ignore
            input_type = input_tag.get("type", "text").lower()
            self.processInput(input_tag, input_type)

        # Process <textarea>
        self.logger.debug("Processing <textarea name='...'>")
        for textarea in form.findAll("textarea", {"name": True}):  # type: ignore
            value = textarea.string or textarea.get("value", TEXT_VALUE)
            self.crafted_inputs[textarea["name"]] = value

        # Process <select>
        self.logger.info("Processing <select name='...'>")
        for select in form.findAll("select", {"name": True}):  # type: ignore
            options = select.findAll("option", value=True)
            value = options[0]["value"] if options else ""
            self.crafted_inputs[select["name"]] = value

        self.logger.info("Finished parsing form inputs.")
        return self.crafted_inputs

    def buildUrl(self, base_url: str, action_uri: str) -> str | None:
        """
        Build a proper URL based on the provided base URL and action_uri.

        Excludes URLs that match the EXCLUSIONS_LIST to prevent detecting self-CSRF (e.g., Logout-CSRF).

        Args:
            base_url (str): The base URL to build upon.
            action_uri (str): The action_uri to resolve against the base URL.

        Returns:
            str or None: A fully resolved URL or None if excluded or invalid.
        """
        # Exclude self-CSRF/Logout-CSRF URLs
        if action_uri == "http://localhost" or any(re.search(pattern, action_uri, re.IGNORECASE) for pattern in EXCLUSIONS_LIST):
            return None

        base_parts = urlparse(base_url)  # Split base URL into components
        port_part = f":{base_parts.port}" if base_parts.port else ""

        action_uri_parts = urlparse(action_uri)  # Split action_uri into components

        # If action_uri has the same domain as the base URL, return action_uri as-is
        if action_uri_parts.netloc == base_parts.netloc:
            return action_uri

        # If action_uri lacks a netloc but has a path or query, resolve it relative to the base URL
        if not action_uri_parts.netloc and (action_uri_parts.path or action_uri_parts.query):
            domain = base_parts.hostname
            scheme = base_parts.scheme

            if action_uri_parts.path.startswith("/"):
                # Internal URL starting from root
                resolved_url = f"{scheme}://{domain}{port_part}{action_uri_parts.path}"
            else:
                # Internal relative URL
                try:
                    path_prefix = re.findall(PROTOCOLS, base_parts.path)[0]
                    resolved_url = f"{scheme}://{domain}{port_part}{path_prefix}{action_uri_parts.path}"
                except IndexError:
                    resolved_url = f"{scheme}://{domain}{port_part}{action_uri_parts.path}"

            # Append query parameters if present
            if action_uri_parts.query:
                resolved_url += f"?{action_uri_parts.query}"

            self.logger.debug(f"Built final action URL: {resolved_url}")
            return resolved_url

        # Return None for invalid or unresolvable hrefs
        return None

    def buildAction(self, base_url: str, action: str) -> str | None:
        """
        Create an action URL based on the current location and destination action.

        Args:
            base_url (str): The base URL to build upon.
            action (str): The action (e.g., a form action or link destination).

        Returns:
            str: The fully resolved action URL or the base URL if no valid action is found.
        """
        self.logger.info("Parsing URL parameters...")
        if action and not action.startswith("#"):
            return self.buildUrl(base_url, action)

        return base_url
