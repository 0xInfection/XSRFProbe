<h1 align="center">
  <br>
  <a href="https://github.com/0xinfection/xsrfprobe"><img src="https://i.ibb.co/rQzpKk6/circle-cropped.png" alt="xsrfprobe"/></a>
  <br>
  <br>
  XSRFProbe
</h1>
<h4 align="center">The Prime Cross Site Request Forgery Audit & Exploitation Toolkit.</h4>
<p align="center">
  <a href="https://docs.python.org/3/download.html">
    <img src="https://img.shields.io/badge/Python-3.11+-green.svg">
  </a>
  <a href="https://github.com/0xinfection/XSRFProbe/releases">
    <img src="https://img.shields.io/badge/Version-v3.0.0%20(stable)-blue.svg">
  </a>
  <a href="https://github.com/0xinfection/XSRFProbe/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/License-GPLv3-orange.svg">
  </a>
</p>

### About:
__XSRFProbe__ is an advanced [Cross Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) (CSRF/XSRF) Audit and Exploitation Toolkit. Equipped with a powerful crawling engine and numerous systematic checks, it is able to detect most cases of CSRF vulnerabilities, their related bypasses and futher generate (maliciously) exploitable proof of concepts with each found vulnerability. For more info on how XSRFProbe works, see [XSRFProbe Internals](https://github.com/0xInfection/XSRFProbe/wiki#xsrfprobe-internals) on [wiki](https://github.com/0xInfection/XSRFProbe/wiki/).

<img src="https://i.imgur.com/xTrfWSt.gif" alt="xsrf-logo">
<p align="center">
  <a href="https://github.com/0xinfection/xsrfprobe/wiki">XSRFProbe Wiki</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/Getting-Started">Getting Started</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/General-Usage">General Usage</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/Advanced-Usage">Advanced Usage</a> •
  <a href="https://github.com/0xinfection/xsrfprobe/wiki/XSRFProbe-Internals">XSRFProbe Internals</a> •
  <a href="https://github.com/0xinfection/xsrfprobe#gallery">Gallery</a>
</p>

### Some Features:

- [x] Runs a full battery of [systematic checks](https://github.com/0xInfection/XSRFProbe/wiki/XSRFProbe-Internals#types-of-checks) — backed by a response diffing/benchmark engine — before declaring an endpoint vulnerable.
- [x] Detects and actively tampers with many Anti-CSRF token implementations: request-method switch, token removal, empty/duplicated values, non-session-bound tokens, double-submit cookies and custom-header tokens.
- [x] Probes Referer and Origin validation with real-world bypasses (header removal, regex/subdomain tricks, `Origin: null`) as well as method-override and Content-Type bypasses.
- [x] Analyses SameSite cookie protections, with optional subdomain enumeration (via crt.sh) for sibling-domain bypass testing.
- [x] Works with a powerful crawler featuring deterministic, bounded crawling and scanning (configurable via `--max-urls`, `--max-depth` and `--crawl-timeout`).
- [x] Optional headless Firefox (Selenium) integration for browser-dependent tests and auto-validation of generated PoCs.
- [x] Accurate [Token-Strength Detection](https://github.com/0xInfection/XSRFProbe/wiki/XSRFProbe-Internals#token-randomness-calculation) and [Analysis](https://github.com/0xInfection/XSRFProbe/wiki/XSRFProbe-Internals#post-scan-token-analysis) using entropy and encoding checks.
- [x] Can generate both normal as well as maliciously exploitable CSRF proof of concepts.
- [x] Out of the box support for custom cookie values, generic headers and a JSON report — each finding carries a severity rating and an exploitability precondition.
- [x] The user is in [control of everything](https://github.com/0xInfection/XSRFProbe/wiki/Advanced-Usage#xsrfprobe-configuration-variables) whatever the scanner does.
- [x] User-friendly interaction environment with full verbose support and detailed logging of errors, vulnerabilities and tokens.

### Vulnerability Tests & IDs:

Every check XSRFProbe runs has a unique identifier. The ID is shown in the console output (e.g. `[T6] VULNERABLE: ...`) and stored as the `test_id` field of each finding in the JSON report (alongside its `severity` and, where relevant, an `exploitability` note under `details`), so each finding maps back to the exact test that produced it.

| ID | Category | Check |
|----|----------|-------|
| `D1` | Token presence | No anti-CSRF token present (generic request forgery) |
| `D2` | Token presence | Login form lacks CSRF token (login CSRF) |
| `T2` | Token tampering | Validation tied to request method (GET ↔ POST switch) |
| `T3` | Token tampering | Token can be omitted entirely |
| `T4` | Token tampering | Token not tied to the user session (cross-session replay) |
| `T5` | Token tampering | Token tied to a non-session cookie (e.g. `csrfKey`) |
| `T6` | Token tampering | Naive double-submit cookie (cookie == body, no binding) |
| `T7` | Token tampering | Empty token value accepted |
| `T8` | Token tampering | Custom-header token can be omitted or forged |
| `M1` | Method / Content-Type | HTTP method override via `_method` parameter |
| `M2` | Method / Content-Type | HTTP method override via `X-HTTP-Method-Override` header |
| `M4` | Method / Content-Type | Validation bypass via alternate `Content-Type` |
| `R0` | Referer | Referer header not validated on form submission |
| `R1` | Referer | Referer validation bypassed by omitting the header |
| `R2a` | Referer | Referer regex bypass — target as attacker subdomain |
| `R2b` | Referer | Referer regex bypass — target in query string |
| `R2c` | Referer | Referer regex bypass — target in path |
| `O1` | Origin | Origin validation bypassed with `Origin: null` |
| `O2` | Origin | Origin validation bypassed with a subdomain trick |
| `O3` | Origin | Origin validation bypassed by omitting the header |
| `S2` | SameSite (browser) | `SameSite=Strict` bypass via client-side redirect gadget |
| `S3` | SameSite (browser) | `SameSite=Strict` bypass via XSS on a sibling subdomain |
| `S4` | SameSite (browser) | `SameSite=Lax` bypass via cookie-refresh / OAuth flow |
| `C1` | Cookie posture | Cookie `SameSite` attribute analysis (`None`/`Lax`/`Strict`) |
| `C2` | Cookie posture | No `SameSite` attribute set on cookies |
| `E1` | Token strength | Token uses a weak/structured hash encoding |
| `A1` | Token strength | Post-scan token predictability / forgeability analysis |

> `S*` checks require the optional headless-browser integration (`--browser`). `T*`/`M*`/`R*`/`O*` are HTTP-level checks gated by the response diffing/benchmark engine.

### Gallery:
Lets see some real-world scenarios of XSRFProbe in action:

<img src="https://i.imgur.com/AAE1HrE.gif" width=50% /><img src="https://i.imgur.com/TJt103P.gif" width=50% />
<img src="https://i.imgur.com/yzyvXHX.gif" />
<img src="https://i.imgur.com/MhTucgI.gif" width=50% /><img src="https://i.imgur.com/gcfZ9zQ.gif" width=50% />

### Usage:
> For the full usage info, please take a look at the wiki's &mdash; [General Usage](https://github.com/0xinfection/xsrfprobe/wiki/general-usage) and [Advanced Usage](https://github.com/0xinfection/xsrfprobe/wiki/advanced-usage).

#### Installing via Pypi:
XSRFProbe can be easily installed via a single command:
```
pip install xsrfprobe
```

#### Installing manually:
- For the basics, the first step is to install the tool:
```
pip install .
```
- Now, the tool can be fired up via:
```
xsrfprobe --help
```
- The browser-dependent tests (`--browser`, `--auto-validate-poc`) additionally require [geckodriver](https://github.com/mozilla/geckodriver/releases) to be available in your `PATH` (or pointed to via `--geckodriver-path`).
- After testing XSRFProbe on a site, an output folder is created in your present working directory as `xsrfprobe-output`. Under this folder you can view the detailed logs and information collected during the scans (pass `--json` for a machine-readable report).

### Version and License:
XSRFProbe is currently `v3.0.0` and the work is licensed under the [GNU General Public License (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.en.html).

### Warnings:

Do not use this tool on a live site!

It is because this tool is designed to perform all kinds of form submissions automatically which can sabotage the site. Sometimes you may screw up the database and most probably perform a DoS on the site as well.

Test on a disposable/dummy setup/site!

### Disclaimer:
Usage of XSRFProbe for testing websites without prior mutual consistency can be considered as an illegal activity. It is the final user's responsibility to obey all applicable local, state and federal laws. The author assumes no liability and is not exclusively responsible for any misuse or damage caused by this program.

### Author's Words:
This project is based __entirely upon my own research and my own experience with web applications__ on Cross-Site Request Forgery attacks. You can try going through the source code which is highly documented to help you understand how this toolkit was built. Useful [pull requests](https://github.com/0xInfection/XSRFProbe/wiki/Contributing), [ideas and issues](https://github.com/0xInfection/XSRFProbe/wiki/Reporting-Bugs#before-submitting) are highly welcome. If you wish to see what how XSRFProbe is being developed, check out the [Development Board](https://github.com/0xInfection/XSRFProbe/projects/1).

> Copyright &copy; [@0xInfection](https://www.twitter.com/0xInfection)
