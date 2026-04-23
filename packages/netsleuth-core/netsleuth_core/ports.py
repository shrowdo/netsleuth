_PORT_PREFIXES: list[tuple[str, str]] = [
    ("Gi",  "GigabitEthernet"),
    ("Fa",  "FastEthernet"),
    ("Te",  "TenGigabitEthernet"),
    ("Tw",  "TwoGigabitEthernet"),
    ("Hu",  "HundredGigE"),
    ("Fo",  "FortyGigabitEthernet"),
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
