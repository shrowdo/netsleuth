"""
Guess vendor / netmiko device type and neighbour role from CDP, LLDP or
"show version" text.
"""

import re

# Evaluated in order; first match wins.
_PLATFORM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ArubaOS-CX|AOS-CX|\b[A-Z]{2}\.10\.\d{2}", re.I), "aruba_aoscx"),
    (re.compile(r"ProCurve|\b[A-Z]{1,2}\.1[56]\.\d{2}\.\d{4}|Image stamp.*/code/build", re.I), "hp_procurve"),
    (re.compile(r"NX-OS|Nexus", re.I), "cisco_nxos"),
    (re.compile(r"IOS[- ]XR", re.I), "cisco_xr"),
    (re.compile(r"IOS[- ]XE", re.I), "cisco_xe"),
    (re.compile(r"Cisco IOS|cisco WS-C|cisco C9|cisco C1000|cisco IE-|Catalyst", re.I), "cisco_ios"),
    (re.compile(r"Arista", re.I), "arista_eos"),
    (re.compile(r"JUNOS|Juniper", re.I), "juniper_junos"),
    (re.compile(r"Comware|H3C", re.I), "hp_comware"),
    (re.compile(r"Huawei|Versatile Routing Platform", re.I), "huawei"),
    (re.compile(r"ExtremeXOS", re.I), "extreme_exos"),
    (re.compile(r"Dell EMC Networking OS10|OS10 Enterprise", re.I), "dell_os10"),
]


def classify_platform(text: str) -> str:
    """Return a netmiko device type for *text*, or "" if it can't be identified."""
    if not text:
        return ""
    for pattern, device_type in _PLATFORM_PATTERNS:
        if pattern.search(text):
            return device_type
    return ""


_AP_PLATFORM_RE = re.compile(r"\bAIR-|access point|\bAP\d|Aruba AP|UniFi AP|\bU6-|\bUAP", re.I)
_PHONE_PLATFORM_RE = re.compile(r"\bphone\b|\bSEP[0-9A-F]{12}\b|Polycom|Yealink|Avaya", re.I)


def _lldp_letters(caps: str) -> set[str]:
    """Parse LLDP single-letter capability codes like "B,T" or "B, R"."""
    tokens = [t.strip() for t in re.split(r"[,\s]+", caps) if t.strip()]
    if tokens and all(len(t) == 1 and t.isalpha() for t in tokens):
        return {t.upper() for t in tokens}
    return set()


def neighbor_role(capabilities: str, platform: str = "", hostname: str = "") -> str:
    """
    Classify a CDP/LLDP neighbour as "switch", "endpoint" or "unknown".

    Phones and access points advertise bridge capability, so they're checked
    first. Only switches are crawled; endpoints stay in the graph as leaves so
    an unmanaged device seen on two switch ports still shows up as a loop.
    """
    caps = capabilities or ""
    letters = _lldp_letters(caps)
    words = caps.lower()
    plat = f"{platform} {hostname}"

    if (
        "T" in letters or "phone" in words or "telephone" in words
        or _PHONE_PLATFORM_RE.search(plat)
    ):
        return "endpoint"
    if (
        "W" in letters or "trans-bridge" in words or "wlan" in words
        or "access-point" in words or _AP_PLATFORM_RE.search(plat)
    ):
        return "endpoint"
    if "B" in letters or "switch" in words or "bridge" in words:
        return "switch"
    if letters or words.strip():
        # Router-only, host/station-only, etc.
        return "endpoint"
    if classify_platform(platform):
        return "switch"
    return "unknown"
