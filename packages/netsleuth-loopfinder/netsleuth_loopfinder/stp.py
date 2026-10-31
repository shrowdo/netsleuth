"""
Parse spanning-tree state, link aggregation membership and topology-change
history from switch output.
"""

import re

from netsleuth_core.ports import canonical_port, expand_port

# Raw state token -> normalised state. Discarding/broken ports don't forward.
_STATE_MAP = {
    "fwd": "FWD", "forwarding": "FWD",
    "blk": "BLK", "blocking": "BLK", "discarding": "BLK", "bkn": "BLK", "broken": "BLK",
    "lis": "LIS", "listening": "LIS",
    "lrn": "LRN", "learning": "LRN",
    "dis": "DIS", "disabled": "DIS", "down": "DIS",
}

# Matches a port row in any vendor's "show spanning-tree" table, whatever
# column the state is in. Cisco IOS:  "Gi1/0/1   Desg FWD 4  128.1  P2p"
# ProCurve: "49  SFP+SR  2000  128  Alternate  Blocking  001b3f-5c2e00"
# AOS-CX:   "1/1/49  Root  Forwarding  20000  128  P2P  0"
_ROW_RE = re.compile(
    r"^\s*(?P<port>[A-Za-z]*[\w/.:-]*\d[\w/.:-]*)\s+.*?"
    r"(?<![\w-])(?P<state>FWD|BLK|BKN\*?|LIS|LRN|Forwarding|Blocking|Discarding|Broken|Listening|Learning)(?![\w-])",
    re.IGNORECASE | re.MULTILINE,
)

_HUAWEI_ROW_RE = re.compile(
    r"^\s*\d+\s+(?P<port>\S+)\s+\S+\s+(?P<state>FORWARDING|DISCARDING|LEARNING|BLOCKING)\b",
    re.IGNORECASE | re.MULTILINE,
)

_STP_OFF_RE = re.compile(
    r"No spanning tree instance|spanning[- ]tree is disabled|"
    r"STP Enabled\s*:\s*No|Spanning Tree (?:Status|Enabled)\s*:\s*(?:Disabled|No)|"
    r"Protocol Status\s*:\s*Disabled|STP is disabled|spanning tree protocol is disabled",
    re.IGNORECASE,
)

_SKIP_PORT_TOKENS = {"port", "interface", "vlan", "mst", "cist", "instance", "root", "bridge"}


def _merge(states: set[str]) -> str:
    """Merge one port's states across VLANs/instances."""
    if not states:
        return ""
    if states == {"BLK"}:
        return "BLK"
    if "BLK" in states:
        return "PART"  # blocked in some VLANs, forwarding in others
    if "FWD" in states:
        return "FWD"
    return sorted(states)[0]


def parse_stp(output: str, device_type: str = "") -> tuple[dict[str, str], str]:
    """
    Return ({canonical_port: state}, mode) where mode is "enabled",
    "disabled" or "unknown".
    """
    if not output or not output.strip():
        return {}, "unknown"
    if _STP_OFF_RE.search(output):
        return {}, "disabled"

    pattern = _HUAWEI_ROW_RE if device_type.startswith("huawei") else _ROW_RE
    seen: dict[str, set[str]] = {}
    for m in pattern.finditer(output):
        port = m.group("port")
        if port.lower() in _SKIP_PORT_TOKENS or port.lower().startswith("vlan"):
            continue
        state = _STATE_MAP.get(m.group("state").lower().rstrip("*"), m.group("state").upper())
        seen.setdefault(canonical_port(port), set()).add(state)

    ports = {p: _merge(s) for p, s in seen.items()}
    return ports, ("enabled" if ports else "unknown")


# ---------------------------------------------------------------------------
# Topology changes ("who keeps flapping STP?")
# ---------------------------------------------------------------------------

def _age_seconds(text: str) -> int | None:
    """Convert Cisco "00:00:03", "1d02h", "2w3d" style ages to seconds."""
    text = text.strip()
    m = re.fullmatch(r"(\d+):(\d+):(\d+)", text)
    if m:
        h, mi, s = map(int, m.groups())
        return h * 3600 + mi * 60 + s
    total = 0
    found = False
    for value, unit in re.findall(r"(\d+)([wdhms])", text):
        found = True
        total += int(value) * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
    return total if found else None


def parse_cisco_tcn(output: str) -> list[dict]:
    """
    Parse "show spanning-tree detail" for each instance's topology-change
    count, how long ago the last one happened and which port it came from.
    Following "from_port" switch by switch leads to the source of the churn.
    """
    results = []
    blocks = re.split(r"(?=^\s*(?:VLAN|MST|Instance)\S*\s+is executing)", output, flags=re.M | re.I)
    for block in blocks:
        inst_m = re.match(r"\s*(\S+)\s+is executing", block, re.I)
        count_m = re.search(r"Number of topology changes\s+(\d+)\s+last change occurred\s+(\S+)\s+ago", block, re.I)
        if not (inst_m and count_m):
            continue
        from_m = re.search(r"last change occurred\s+\S+\s+ago\s*\n?\s*from\s+(\S+)", block, re.I)
        results.append({
            "instance": inst_m.group(1),
            "count": int(count_m.group(1)),
            "age_s": _age_seconds(count_m.group(2)),
            "from_port": expand_port(from_m.group(1)) if from_m else "",
        })
    return results


def parse_procurve_tcn(output: str) -> list[dict]:
    """AOS-S / AOS-CX "show spanning-tree" topology change counters."""
    count_m = re.search(r"Topology Change Count\s*:\s*(\d+)", output, re.I)
    if not count_m:
        return []
    age_m = re.search(r"Time Since Last Change\s*:\s*([^\n]+)", output, re.I)
    age = None
    if age_m:
        raw = age_m.group(1).strip().lower()
        num = re.match(r"(\d+)\s*(sec|min|hour|day)", raw)
        if num:
            mult = {"sec": 1, "min": 60, "hour": 3600, "day": 86400}[num.group(2)]
            age = int(num.group(1)) * mult
        else:
            age = _age_seconds(raw)
    return [{"instance": "CST", "count": int(count_m.group(1)), "age_s": age, "from_port": ""}]


# ---------------------------------------------------------------------------
# Link aggregation
# ---------------------------------------------------------------------------

_MEMBER_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z\-]*\d[\w/.:]*)\((\w+\+?)\)")


def parse_cisco_lags(output: str) -> dict[str, str]:
    """
    Cisco "show etherchannel summary", NX-OS / Arista "show port-channel
    summary". Returns {canonical_member: "Po1"}.
    """
    lags: dict[str, str] = {}
    current = ""
    for line in output.splitlines():
        tokens = _MEMBER_TOKEN_RE.findall(line)
        if not tokens:
            continue
        names = [t[0] for t in tokens]
        if re.match(r"^\s*\d+\s+", line) and names[0].lower().startswith("po"):
            current = names[0]
            members = names[1:]
        elif line.startswith((" ", "\t")) and current:
            members = names
        else:
            continue
        for member in members:
            if member.upper().startswith("LACP") or member.lower().startswith("po"):
                continue
            lags[canonical_port(member)] = current
    return lags


def parse_procurve_trunks(output: str) -> dict[str, str]:
    """AOS-S "show trunks": "  49  | ...  | Trk1   LACP"."""
    lags: dict[str, str] = {}
    for m in re.finditer(r"^\s*(\S+)\s+\|.*\|\s*((?:Trk|Dyn)\d+)\b", output, re.M):
        lags[canonical_port(m.group(1))] = m.group(2)
    return lags


def parse_aoscx_lags(output: str) -> dict[str, str]:
    """AOS-CX "show lacp interfaces" / "show lag": "1/1/49  lag1 ..."."""
    lags: dict[str, str] = {}
    for m in re.finditer(r"^\s*(\d+/\d+/\d+)\s+(lag\d+)\b", output, re.M | re.I):
        lags[canonical_port(m.group(1))] = m.group(2)
    # "show lag" detail form: "Aggregate lag1 ... Interfaces : 1/1/49 1/1/50"
    for block in re.split(r"(?=^\s*Aggregate\s+lag\d+)", output, flags=re.M | re.I):
        name_m = re.match(r"\s*Aggregate\s+(lag\d+)", block, re.I)
        members_m = re.search(r"(?:Interfaces|Aggregated-interfaces)\s*:\s*([^\n]+)", block, re.I)
        if name_m and members_m:
            for port in re.findall(r"\d+/\d+/\d+", members_m.group(1)):
                lags[canonical_port(port)] = name_m.group(1)
    return lags


# ---------------------------------------------------------------------------
# Loop evaluation helpers
# ---------------------------------------------------------------------------

def port_state(stp: dict[str, str], stp_mode: str, port: str) -> str:
    """STP state for *port* ("" if unknown). With STP off every port forwards."""
    if stp_mode == "disabled":
        return "FWD"
    if not port:
        return ""
    return stp.get(canonical_port(port), "")
