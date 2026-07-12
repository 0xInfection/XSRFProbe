#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# -:-:-:-:-:-:-::-:-:#
#    XSRF Probe     #
# -:-:-:-:-:-:-::-:-:#

# Author: 0xInfection
# This module requires XSRFProbe
# https://github.com/0xInfection/XSRFProbe

from xsrfprobe.core.schema import SeverityEnum

# test_id -> SeverityEnum. Anything not listed falls back to MEDIUM.
SEVERITY: "dict[str, SeverityEnum]" = {
    # Missing / broken token defences — directly forgeable.
    "D1": SeverityEnum.HIGH,   # No anti-CSRF token at all
    "D2": SeverityEnum.MEDIUM, # Login CSRF (no session context yet)
    "T2": SeverityEnum.HIGH,   # Token bypassed via HTTP method switch
    "T3": SeverityEnum.HIGH,   # Token can be omitted entirely
    "T4": SeverityEnum.HIGH,   # Token not tied to the user session
    "T7": SeverityEnum.HIGH,   # Empty token value accepted
    "T8": SeverityEnum.HIGH,   # Header token can be omitted / forged
    "M1": SeverityEnum.HIGH,   # _method override bypass
    "M2": SeverityEnum.HIGH,   # Method-override header bypass (CORS-gated)
    "M4": SeverityEnum.HIGH,   # Content-Type change bypass
    "A1": SeverityEnum.HIGH,   # Predictable / low-entropy token

    # Exploitable only under an additional attacker precondition.
    "T5": SeverityEnum.MEDIUM, # Token tied to a non-session cookie
    "T6": SeverityEnum.MEDIUM, # Naive double-submit cookie
    "S2": SeverityEnum.MEDIUM, # SameSite=Strict redirect-gadget bypass
    "S3": SeverityEnum.MEDIUM, # SameSite=Strict via sibling-subdomain XSS
    "S4": SeverityEnum.MEDIUM, # SameSite=Lax refresh bypass

    # Origin / Referer defences (weaker controls than tokens).
    "O1": SeverityEnum.MEDIUM, # Origin: null accepted
    "O2": SeverityEnum.MEDIUM, # Origin subdomain trick
    "O3": SeverityEnum.MEDIUM, # Origin header omission accepted
    "R1": SeverityEnum.MEDIUM, # Referer omission accepted
    "R2a": SeverityEnum.MEDIUM,
    "R2b": SeverityEnum.MEDIUM,
    "R2c": SeverityEnum.MEDIUM,
    "R0": SeverityEnum.LOW,    # Referer simply not validated (weak control)

    # Weak encoding / cookie hygiene — informational-to-low.
    "E1": SeverityEnum.MEDIUM, # Weak/structured token encoding
    "C1": SeverityEnum.LOW,    # SameSite cookie attribute weakness
    "C2": SeverityEnum.LOW,    # No SameSite attribute anywhere
}

# test_id -> short precondition string. Absent/empty means "no special
# precondition beyond a victim visiting an attacker page".
_LAX_DEFAULT_NOTE = (
    "Modern browsers default cookies to SameSite=Lax, which already blocks "
    "cross-site POSTs; primarily exploitable via top-level GET side effects, "
    "cookies explicitly set to SameSite=None, or non-browser/legacy clients."
)
_COOKIE_WRITE_NOTE = (
    "Requires the attacker to write the CSRF cookie (subdomain cookie-tossing, "
    "a cookie-injection gadget, or an HTTP MITM); not exploitable from an "
    "unrelated cross-site origin alone."
)
_REFERER_ONLY_NOTE = (
    "Only exploitable where Referer validation is the sole CSRF defence."
)

EXPLOITABILITY: "dict[str, str]" = {
    "D1": _LAX_DEFAULT_NOTE,
    "D2": _LAX_DEFAULT_NOTE,
    "C2": _LAX_DEFAULT_NOTE,
    "C1": (
        "SameSite only governs cross-site requests; it does not protect "
        "same-site requests or top-level navigations."
    ),
    "T5": _COOKIE_WRITE_NOTE,
    "T6": _COOKIE_WRITE_NOTE,
    "M2": (
        "Requires permissive CORS that lets the custom header be sent "
        "cross-site with credentials."
    ),
    "R0": _REFERER_ONLY_NOTE,
    "R1": _REFERER_ONLY_NOTE,
    "R2a": _REFERER_ONLY_NOTE + " Attacker must control a matching Referer.",
    "R2b": _REFERER_ONLY_NOTE + " Attacker must control a matching Referer.",
    "R2c": _REFERER_ONLY_NOTE + " Attacker must control a matching Referer.",
}


def get_severity_enum(test_id: str) -> SeverityEnum:
    return SEVERITY.get(test_id or "", SeverityEnum.MEDIUM)


def get_severity(test_id: str) -> str:
    return get_severity_enum(test_id).value.upper()


def get_exploitability(test_id: str) -> str:
    return EXPLOITABILITY.get(test_id or "", "")
