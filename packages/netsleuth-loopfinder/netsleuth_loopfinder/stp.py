"""
Collect STP port states from switches to check if loops are already being blocked.
"""

import re
from netsleuth_core.ssh import connect


# Maps raw STP state tokens to normalised abbreviations.
_STATE_MAP = {
    "forwarding": "FWD",
    "fwd":        "FWD",
    "blocking":   "BLK",
    "blk":        "BLK",
    "listening":  "LIS",
    "lis":        "LIS",
    "learning":   "LRN",
    "lrn":        "LRN",
    "disabled":   "DIS",
    "dis":        "DIS",
}

# Cisco IOS "show spanning-tree" output has lines like:
#   Gi0/1             128.1    P2p      Desg FWD
#   Gi0/2             128.2    P2p      Root BLK
# The port name can be abbreviated (Gi, Fa, Te, …) or full.
_PORT_LINE_RE = re.compile(
    r"^(?P<port>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<state>FWD|BLK|LIS|LRN|DIS|"
    r"Forwarding|Blocking|Listening|Learning|Disabled)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Fallback pattern for "Port X (GigabitEthernetY) of VLAN... is Forwarding"
_VERBOSE_LINE_RE = re.compile(
    r"Port\s+\S+\s+\((?P<port>\S+)\).*?is\s+(?P<state>Forwarding|Blocking|Listening|Learning|Disabled)",
    re.IGNORECASE,
)

# Cisco IOS abbreviation prefix expansion table (longest-match first).
_PORT_PREFIXES = [
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


def _expand_port(abbrev: str) -> str:
    """Expand a Cisco abbreviated interface name to its full form."""
    for short, long_ in _PORT_PREFIXES:
        if abbrev.startswith(short) and not abbrev[len(short):len(short)+1].isalpha():
            return long_ + abbrev[len(short):]
    return abbrev


def _parse_stp_output(output: str) -> dict[str, str]:
    """
    Parse ``show spanning-tree`` output and return {full_port_name: state_abbrev}.
    """
    ports: dict[str, str] = {}

    for m in _PORT_LINE_RE.finditer(output):
        port = _expand_port(m.group("port"))
        state = _STATE_MAP.get(m.group("state").lower(), m.group("state").upper())
        ports[port] = state

    # If the tabular pattern found nothing, try the verbose pattern.
    if not ports:
        for m in _VERBOSE_LINE_RE.finditer(output):
            port = _expand_port(m.group("port"))
            state = _STATE_MAP.get(m.group("state").lower(), m.group("state").upper())
            ports[port] = state

    return ports


def get_stp_status(devices: dict, creds: dict) -> dict[str, dict[str, str]]:
    """
    SSH into each device and collect per-port STP state.

    Returns:
        {hostname: {full_port_name: state_abbrev}}
        e.g. {"SW1": {"GigabitEthernet0/1": "FWD", "GigabitEthernet0/2": "BLK"}}
    """
    from rich.console import Console
    console = Console()

    result: dict[str, dict[str, str]] = {}

    for hostname, device in devices.items():
        try:
            console.print(f"[cyan]STP: connecting to {hostname} ({device.ip})…[/cyan]")
            conn = connect(
                ip=device.ip,
                username=creds["username"],
                password=creds["password"],
                device_type=creds["device_type"],
                port=creds.get("port", 22),
                key_file=creds.get("key_file"),
            )
            output = conn.send_command("show spanning-tree")
            conn.disconnect()

            ports = _parse_stp_output(output)
            result[hostname] = ports
            console.print(f"[green]  STP data collected: {len(ports)} port(s)[/green]")
        except Exception as exc:
            console.print(f"[red]  STP collection failed for {hostname}: {exc}[/red]")
            result[hostname] = {}

    return result


def get_stp_status_mock(devices: dict) -> dict[str, dict[str, str]]:
    """
    Return synthetic STP data suitable for mock/demo runs.

    Strategy: for each device the first neighbor port is set to BLK so that
    at least one loop will appear as "handled by STP" in the demo output.
    All remaining ports are set to FWD.
    """
    result: dict[str, dict[str, str]] = {}
    first_device = True

    for hostname, device in devices.items():
        ports: dict[str, str] = {}
        first_port = True

        for neighbor in device.neighbors:
            port_name = neighbor.local_port or f"GigabitEthernet0/{len(ports)}"
            if first_device and first_port:
                ports[port_name] = "BLK"
                first_port = False
            else:
                ports[port_name] = "FWD"

        result[hostname] = ports
        first_device = False

    return result


def check_loops_stp_status(loops: list, loop_edges: list, stp_data: dict) -> list[dict]:
    """
    For each loop determine whether any edge port is in Blocking state.

    Args:
        loops:      List of cycles (each a list of hostnames) from find_loops().
        loop_edges: Parallel list of edge-lists returned by get_loop_edges() for
                    each cycle.  Each entry is a list of dicts with keys
                    "from", "to", "local_port", "remote_port".
        stp_data:   {hostname: {port: state}} from get_stp_status[_mock]().

    Returns:
        List of dicts, one per loop:
        {
            "loop_index":     int,   # 1-based
            "blocked":        bool,
            "blocking_port":  str,   # empty string when not blocked
            "blocking_device": str,  # empty string when not blocked
        }
    """
    results = []

    for i, edges in enumerate(loop_edges, start=1):
        blocked = False
        blocking_port = ""
        blocking_device = ""

        for edge in edges:
            device_name = edge["from"]
            local_port = edge["local_port"]

            device_stp = stp_data.get(device_name, {})
            state = device_stp.get(local_port, "")

            if state == "BLK":
                blocked = True
                blocking_port = local_port
                blocking_device = device_name
                break

        results.append({
            "loop_index": i,
            "blocked": blocked,
            "blocking_port": blocking_port,
            "blocking_device": blocking_device,
        })

    return results
