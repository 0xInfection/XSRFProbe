<h1 align="center">
  <br>
  <a href="https://github.com/0xinfection"><img src="https://i.imgur.com/9R5cXB6.png" alt="XSRFProbe"></a>
</h1>

<p align="center">  
  <a href="https://docs.python.org/3/download.html">
    <img src="https://img.shields.io/badge/Python-3.x-green.svg">
  </a>
  <a href="https://github.com/0xinfection/XSRFProbe/releases">
    <img src="https://img.shields.io/badge/Version-v2.0.0%20(stable)-blue.svg">
  </a>
  <a href="https://github.com/0xinfection/XSRFProbe/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/License-GPLv3-orange.svg">
  </a> 
  <a href="https://travis-ci.org/0xInfection/XSRFProbe">
    <img src="https://camo.githubusercontent.com/e748965ef2afbc44d14cf41001c0c29b9f685965/68747470733a2f2f696d672e736869656c64732e696f2f7472617669732f63636c617573732f54656e2d6c696e65732d6f722d6c6573732f6d61737465722e7376673f6c6f676f3d747261766973">
  </a>
</p>

### About XSRFProbe
__XSRFProbe__ is an advanced [Cross Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) (CSRF/XSRF) Audit and Exploitation Toolkit. Equipped with a Powerful Crawling Engine and Numerous Systematic Checks, it is now able to detect most cases of CSRF vulnerabilities, their related bypasses and futher generate (maliciously) exploitable proof of concepts with each found vulnerability. For more info on how XSRFProbe works, see [XSRFProbe Internals](https://github.com/0xInfection/XSRFProbe/wiki#xsrfprobe-internals) on [wiki](https://github.com/0xInfection/XSRFProbe/wiki/). This release is a stable release.

<img src="https://i.imgur.com/xTrfWSt.gif" alt="xsrf-logo">
<p align="center">
  <a href="https://github.com/0xinfection/xsrfprobe/wiki">Wiki</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/Getting-Started">Getting Started</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/General-Usage">General Usage</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/Advanced-Usage">Advanced Usage</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/XSRFProbe-Internals">XSRFProbe Internals</a> •
  <a href="https://github.com/0xinfection/xsrfprobe#gallery">Gallery</a>
</p>

### Some Features:

- [x] Has a powerful crawler which features continuous crawling and scanning.
- [x] Performs [several types of checks](https://github.com/0xInfection/XSRFProbe/wiki/XSRFProbe-Internals#types-of-checks) before declaring an endpoint as vulnerable.
- [x] Can detect several types of Anti-CSRF tokens in POST requests.
- [x] Out of the box support for custom cookie values and generic headers.
- [x] Accurate [Token-Strength Detection](https://github.com/0xInfection/XSRFProbe/wiki/XSRFProbe-Internals#token-randomness-calculation) and [Analysis](https://github.com/0xInfection/XSRFProbe/wiki/XSRFProbe-Internals#post-scan-token-analysis) using various algorithms.
- [x] Can generate both normal as well as maliciously exploitable CSRF PoCs.
- [x] Follows a redirect when there is a 30x response.
- [x] Well [documented code](https://github.com/0xInfection/XSRFProbe/tree/master?files=1) and [highly generalised automated workflow](https://github.com/0xInfection/XSRFProbe/wiki#xsrfprobe-internals).
- [x] The user is in [control of everything](https://github.com/0xInfection/XSRFProbe/wiki/Advanced-Usage#xsrfprobe-configuration-variables) whatever the scanner does.
- [x] Has a user-friendly interaction environment with full verbose support.
- [x] Detailed logging system of errors, vulnerabilities, tokens and other stuffs.

### Gallery:
Lets see some real-world scenarios of XSRFProbe in action:

<img src="https://i.imgur.com/AAE1HrE.gif" width=50% /><img src="https://i.imgur.com/TJt103P.gif" width=50% />
<img src="https://i.imgur.com/yzyvXHX.gif" />
<img src="https://i.imgur.com/MhTucgI.gif" width=50% /><img src="https://i.imgur.com/gcfZ9zQ.gif" width=50% />

### Version and License:
XSRFProbe v2 release is a stable release and is licensed under the [GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html).

### Warnings:

Do not use this tool on a live site!

It is because this tool is designed to perform all kinds of form submissions automatically which can sabotage the site. Sometimes you may screw up the database and most probably perform a DoS on the site as well.

Test on a disposable/dummy setup/site!

### Disclaimer:
Usage of XSRFProbe for testing websites without prior mutual consistency can be considered as an illegal activity. It is the final user's responsibility to obey all applicable local, state and federal laws. The author assumes no liability and is not exclusively responsible for any misuse or damage caused by this program.

### Author's Words:
This project is based __entirely upon my own research and my own experience with web applications__ on Cross-Site Request Forgery attacks. Useful [pull requests](https://github.com/0xInfection/XSRFProbe/wiki/Contributing), [ideas and issues](https://github.com/0xInfection/XSRFProbe/wiki/Contributing) are highly welcome. If you wish to see what how XSRFProbe is being developed, check out the [Development Board](https://github.com/0xInfection/XSRFProbe/projects/1). 

Thats it folks. Thank you...

> Copyright © [__Infected Drake__](https://www.twitter.com/0xInfection)
