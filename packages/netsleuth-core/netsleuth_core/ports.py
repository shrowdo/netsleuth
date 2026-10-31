# Longest prefixes first so "Twe" wins over "Tw" and "Fi" doesn't shadow "Fo"/"Fa".
_PORT_PREFIXES: list[tuple[str, str]] = [
    ("Twe", "TwentyFiveGigE"),
    ("Gi",  "GigabitEthernet"),
    ("Fa",  "FastEthernet"),
    ("Te",  "TenGigabitEthernet"),
    ("Tw",  "TwoGigabitEthernet"),
    ("Fi",  "FiveGigabitEthernet"),
    ("Hu",  "HundredGigE"),
    ("Fo",  "FortyGigabitEthernet"),
    ("Eth", "Ethernet"),
    ("Et",  "Ethernet"),
    ("Po",  "Port-channel"),
    ("Se",  "Serial"),
    ("Lo",  "Loopback"),
]


def expand_port(abbrev: str) -> str:
    """Expand a Cisco abbreviated interface name to its full form."""
    for short, long_ in _PORT_PREFIXES:
        if abbrev.startswith(short) and not abbrev[len(short):len(short) + 1].isalpha():
            return long_ + abbrev[len(short):]
    return abbrev


def canonical_port(port: str) -> str:
    """Normalise an interface name so the same port compares equal however it was written."""
    if not port:
        return ""
    value = port.strip().rstrip(".,;:")
    value = expand_port(value)
    return value.lower().replace(" ", "")
