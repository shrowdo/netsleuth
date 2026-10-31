"""
Inbound broadcast/multicast rates per port: the quickest way to find where a
broadcast storm is entering the network.

Cisco/Arista/NX-OS and AOS-CX expose cumulative counters, so two samples are
taken a few seconds apart and turned into packets/sec. HP ProCurve reports a
rate directly.
"""

import re

from netsleuth_core.ports import canonical_port, expand_port


def _int(token: str) -> int | None:
    token = token.replace(",", "")
    return int(token) if token.isdigit() else None


def parse_cisco_counters(output: str) -> dict[str, int]:
    """
    "show interfaces counters" (IOS / Arista) or "show interface counters"
    (NX-OS). Returns {canonical_port: InMcastPkts + InBcastPkts}.
    """
    totals: dict[str, int] = {}
    columns: list[str] = []
    for line in output.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] == "Port" or tokens[0] == "Interface":
            columns = tokens if any(t in ("InMcastPkts", "InBcastPkts") for t in tokens) else []
            continue
        if not columns or set(line.strip()) <= set("- "):
            continue
        wanted = [i for i, c in enumerate(columns) if c in ("InMcastPkts", "InBcastPkts")]
        if len(tokens) != len(columns):
            continue
        values = [_int(tokens[i]) for i in wanted]
        if any(v is None for v in values):
            continue
        port = canonical_port(tokens[0])
        totals[port] = totals.get(port, 0) + sum(values)
    return totals


def parse_procurve_rates(output: str) -> dict[str, float]:
    """
    AOS-S "show interfaces <ports>" detail. Uses the
    "B/Mcast Rx (Pkts/sec)" rate, a 5 minute weighted average.
    """
    rates: dict[str, float] = {}
    for block in re.split(r"(?=Port Counters for port)", output, flags=re.I):
        port_m = re.search(r"Port Counters for port\s+(\S+)", block, re.I)
        rate_m = re.search(r"B/Mcast Rx\s*\(Pkts/sec\)\s*:\s*([\d,]+)", block, re.I)
        if port_m and rate_m:
            rates[canonical_port(port_m.group(1))] = float(rate_m.group(1).replace(",", ""))
    return rates


def parse_procurve_port_list(output: str) -> list[str]:
    """Ports that are up, from AOS-S "show interfaces brief"."""
    ports = []
    for line in output.splitlines():
        m = re.match(r"^\s*(\S+)\s+(?:\S+\s+)?\|\s+(?:Yes|No)\s+(?:Yes|No)\s+Up(?!\w)", line)
        if m:
            ports.append(m.group(1))
    return ports


def parse_aoscx_counters(output: str) -> dict[str, int]:
    """AOS-CX "show interface": RX broadcast + multicast packets per port."""
    totals: dict[str, int] = {}
    for block in re.split(r"(?=^Interface\s+\S+\s+is\s)", output, flags=re.M):
        port_m = re.match(r"Interface\s+(\S+)\s+is\s", block)
        if not port_m:
            continue
        total = 0
        found = False
        for kind in ("Broadcast", "Multicast"):
            m = re.search(rf"^\s*{kind}\s+([\d,]+)", block, re.M)
            if m:
                found = True
                total += int(m.group(1).replace(",", ""))
        if found:
            totals[canonical_port(port_m.group(1))] = total
    return totals


def rates_from_samples(first: dict[str, int], second: dict[str, int], elapsed: float) -> dict[str, float]:
    if elapsed <= 0:
        return {}
    rates = {}
    for port, end in second.items():
        start = first.get(port)
        if start is None or end < start:
            continue  # new port or counter cleared/wrapped
        rates[port] = (end - start) / elapsed
    return rates


def display_port(port: str) -> str:
    """Turn a canonical port back into something readable ("gigabitethernet1/0/1" -> "Gi1/0/1")."""
    from netsleuth_core.ports import _PORT_PREFIXES

    for short, long_ in _PORT_PREFIXES:
        if port.startswith(long_.lower()):
            return short + port[len(long_):]
    return port[:1].upper() + port[1:] if port[:1].isalpha() and not port[:3] == "lag" else port


__all__ = [
    "parse_cisco_counters", "parse_procurve_rates", "parse_procurve_port_list",
    "parse_aoscx_counters", "rates_from_samples", "display_port", "expand_port",
]
