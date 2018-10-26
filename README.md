<p align="middle"><img src='https://i.imgur.com/b7SnRvX.png' /></p>  

# XSRF Probe [![python](https://img.shields.io/badge/Python-3.x-green.svg?style=style=flat-square)](https://docs.python.org/3/download.html) [![license](https://img.shields.io/badge/License-GPLv3-orange.svg?style=style=flat-square)](https://github.com/theinfecteddrake/XSRFProbe/blob/master/LICENSE) [![version](https://img.shields.io/badge/Version-v1.0-blue.svg?style=style=flat-square)](https://github.com/theinfecteddrake/XSRFProbe/blob/master/README.md#version) [![Build Status](https://travis-ci.org/theInfectedDrake/XSRFProbe.svg?branch=master)](https://travis-ci.org/theInfectedDrake/XSRFProbe)

XSRF Probe is an advanced Cross Site Request Forgery Audit Toolkit equipped with Powerful Crawling and Intelligent Token Generation Capabilities.

> XSRFProbe is undergoing [major code changes and core refactors](https://github.com/theInfectedDrake/XSRFProbe/projects/1) at present. So consider avoiding making pull requests and raising issues temporarily until I publish the next release.

<img src="https://i.imgur.com/HTz6EDY.png" />

### Some Features:

- [x] Has a powerful crawler which features continuous crawling and scanning.
- [x] XSRFProbe has absolute support for POST based CSRF Vulnerabilities.
- [x] Out of the box support for custom cookie values and generic headers.
- [x] Can intelligently generate crafted tokens for different types of parameters.
- [x] Can effectively crawl and hunt out hidden parameters `(without bruteforce)`.
- [x] Submits forms in the normal values as well as with crafted token.
- [x] Rare chances of false positives occuring during scan.
- [x] Follows a redirect when there is a 302 response.
- [x] Generates PoCs for both exploitable and non-exploitable CSRFs.
- [x] Has a user-friendly interaction environment.
- [x] Everything is automated on demand.

### The Workflow:

The typical workflow of this scanner is :-

- Spiders the target website to find all pages.
- Finds all types of forms present on the each page.
- Hunts out hidden as well as visible parameter values.
- Identifies every parameter type by identifying a normal request.
- Submits each form with normal tokens & parameter values.
- Generates random token strings and sets parameter values accordingly.
- Submits each form with the crafted tokens.
- Finds out if the tokens are sufficiently protected.
- Generates custom proof of concepts after each successful request and subsequent discovery.

<img src="https://i.imgur.com/a2va9wh.gif" />

### Warnings:

Do not use this tool on a live site!

It is because this tool is designed to perform all kinds of form submissions automatically which can sabotage the site. Sometimes you may screw up the database and most probably perform a DoS on the site as well.

Test on a disposable test site!

### Drawbacks:
The scanner has the following drawbacks presently:

- Normally the scanner assumes that every form has a hidden/visible parameter and token field.
- Changing or removing that token field usually causes a 403 Forbidden response.
- Spidering is restricted to domains of startpages (so doesn't work with all domains). :(

### Requirements:

- requests
- bs4
- lxml

### Usage:

➲ Clone the repo locally and navigate to the directory.
```
git clone https://github.com/theInfectedDrake/XSRFProbe.git
cd XSRFProbe
```
➲ Install the dependencies.
> __NOTE:__ You will need to default your Python version to 3.x for running this tool.
```
pip3 install -r requirements.txt
```
➲ Launch the script.
```
python3 xsrfprobe.py
```
➲ Enter the website target.
```
http://examplesite.com
```
➲ Let the scanner load up.

➲ Keep track of PoCs which may appear (if a bug exists).

### Version:
```
v1.1.0
```
> The latest release includes support for only Python 3.x and removes support for Python 2.x versions ([you know why](https://pythonclock.org/)). Some new methods for detecting CSRF are under development.

### Disclaimer:
Usage of XSRFProbe for testing websites without prior mutual consistency can be considered as an illegal activity. It is the final user's responsibility to obey all applicable local, state and federal laws. The author assumes no liability and is not exclusively responsible for any misuse or damage caused by this program.

### To Do's:
- Associate multithreading for the better.
- Include methods for detecting blind CSRF. 

Thats it folks! Thank you...

> Copyright © [The Infected Drake](https://www.twitter.com/infecteddrake)

