"""
SSH into switches and discover topology via CDP/LLDP neighbor data.
"""

import re
import time
from netmiko import NetmikoTimeoutException, NetmikoAuthenticationException

# When a user types a vendor shorthand (e.g. "aruba"), try these in order.
_DEVICE_TYPE_ALIASES: dict[str, list[str]] = {
    "aruba":   ["aruba_aoscx", "aruba_procurve", "aruba_osswitch", "aruba_os"],
    "hp":      ["hp_procurve", "hp_comware"],
    "juniper": ["juniper_junos", "juniper"],
    "huawei":  ["huawei_vrp", "huawei_vrpv8", "huawei"],
    "extreme": ["extreme_exos", "extreme_nos", "extreme_vsp"],
}
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from netsleuth_core.models import Neighbor, Device
from netsleuth_core.ssh import connect, get_hostname, detect_device_type

console = Console()

# Port abbreviation expansion table (mirrors stp.py _PORT_PREFIXES).
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
        if abbrev.startswith(short) and not abbrev[len(short):len(short) + 1].isalpha():
            return long_ + abbrev[len(short):]
    return abbrev


def get_cdp_neighbors(conn) -> list[Neighbor]:
    output = conn.send_command("show cdp neighbors detail")
    neighbors = []
    blocks = re.split(r"-{3,}", output)
    for block in blocks:
        hostname_match = re.search(r"Device ID:\s*(\S+)", block)
        local_port_match = re.search(r"Interface:\s*(\S+),", block)
        remote_port_match = re.search(r"Outgoing Port(?:ID)?:\s*(\S+)", block, re.IGNORECASE)
        ip_match = re.search(r"IP[Vv]?[46]?\s+[Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)", block)

        if hostname_match and local_port_match:
            # Strip trailing '~' appended by some IOS versions (truncation marker).
            raw_hostname = hostname_match.group(1).rstrip("~")
            # Strip parenthetical suffix e.g. "SW1(Serial0)" -> "SW1".
            raw_hostname = re.sub(r"\(.*?\)$", "", raw_hostname)
            hostname = raw_hostname.split(".")[0]  # strip domain

            local_port = _expand_port(local_port_match.group(1))
            remote_port = _expand_port(remote_port_match.group(1)) if remote_port_match else ""

            # IPv4 first; fall back to IPv6 for topology-edge preservation.
            if ip_match:
                ip = ip_match.group(1)
            else:
                ipv6_match = re.search(r"IPv6\s+[Aa]ddress:\s*([\da-fA-F:]+)", block)
                ip = ipv6_match.group(1) if ipv6_match else ""

            neighbors.append(Neighbor(
                hostname=hostname,
                local_port=local_port,
                remote_port=remote_port,
                ip=ip,
            ))
    return neighbors


def get_lldp_neighbors(conn) -> list[Neighbor]:
    output = conn.send_command("show lldp neighbors detail")
    neighbors = []
    blocks = re.split(r"-{3,}|={3,}", output)
    for block in blocks:
        # Case-insensitive to catch Juniper "System name:" as well as "System Name:".
        hostname_match = re.search(r"System [Nn]ame:\s*(\S+)", block, re.IGNORECASE)
        # Arista EOS fallback: use Chassis ID as system name.
        if not hostname_match:
            hostname_match = re.search(r"Chassis ID:\s*(\S+)", block)

        local_port_match = re.search(r"Local Port(?:ID)?:\s*(\S+)", block, re.IGNORECASE)
        # HP ProCurve uses "PortId:" (no space).
        if not local_port_match:
            local_port_match = re.search(r"PortId:\s*(\S+)", block, re.IGNORECASE)

        remote_port_match = re.search(r"Port ID:\s*(\S+)", block)
        # Fallback: use Port Description if Port ID is absent.
        if not remote_port_match:
            remote_port_match = re.search(r"Port Description:\s*(\S+)", block)

        # Tighten management IP search to 300 chars after "Management Address".
        ip_match = re.search(r"Management Address.{0,300}?(\d+\.\d+\.\d+\.\d+)", block, re.DOTALL)

        if hostname_match and local_port_match:
            neighbors.append(Neighbor(
                hostname=hostname_match.group(1).split(".")[0],
                local_port=local_port_match.group(1),
                remote_port=remote_port_match.group(1) if remote_port_match else "",
                ip=ip_match.group(1) if ip_match else "",
            ))
    return neighbors


def _aoscx_neighbor_ip(conn, local_port: str) -> str:
    """Get management IP for a single AOS-CX LLDP neighbor via per-port detail."""
    try:
        out = conn.send_command(f"show lldp neighbor-info {local_port}")
        m = re.search(r"Neighbor Management-Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def get_lldp_neighbors_aoscx(conn) -> list[Neighbor]:
    """
    Parse 'show lldp neighbor-info' for Aruba AOS-CX switches.
    The output is a fixed-width table; management IPs require a per-port lookup.
    """
    output = conn.send_command("show lldp neighbor-info")
    neighbors = []
    lines = output.splitlines()

    # Find header line to get column positions
    header_idx = next(
        (i for i, l in enumerate(lines) if "LOCAL-PORT" in l and "SYS-NAME" in l), None
    )
    if header_idx is None:
        return neighbors

    header = lines[header_idx]
    try:
        col_local   = header.index("LOCAL-PORT")
        col_chassis = header.index("CHASSIS-ID")
        col_port_id = header.index("PORT-ID")
        # PORT-DESC column is absent on some AOS-CX firmware versions.
        try:
            col_portd = header.index("PORT-DESC")
        except ValueError:
            col_portd = len(header)
        col_ttl     = header.index("TTL")
        col_name    = header.index("SYS-NAME")
    except ValueError:
        return neighbors

    for line in lines[header_idx + 2:]:   # skip header + dashes
        if not line.strip() or line.startswith("-"):
            continue
        local_port = line[col_local:col_chassis].strip()
        port_id    = line[col_port_id:col_portd].strip()
        sys_name   = line[col_name:].strip()
        if not local_port or not sys_name:
            continue
        ip = _aoscx_neighbor_ip(conn, local_port)
        neighbors.append(Neighbor(
            hostname=sys_name,
            local_port=local_port,
            remote_port=port_id,
            ip=ip,
        ))
    return neighbors


def get_lldp_neighbors_huawei(conn) -> list[Neighbor]:
    """
    Parse ``display lldp neighbor detail`` output from Huawei VRP devices.
    Returns [] on any failure so discovery can continue.
    """
    try:
        output = conn.send_command("display lldp neighbor detail")
        neighbors = []
        # Blocks are separated by lines of dashes
        blocks = re.split(r"-{3,}", output)
        for block in blocks:
            hostname_match = re.search(r"System name:\s*(\S+)", block, re.IGNORECASE)
            local_port_match = re.search(r"Port name:\s*(\S+)", block, re.IGNORECASE)
            remote_port_match = re.search(r"Neighbor port ID:\s*(\S+)", block, re.IGNORECASE)
            ip_match = re.search(r"Management address:\s*(\d+\.\d+\.\d+\.\d+)", block, re.IGNORECASE)

            if hostname_match and local_port_match:
                neighbors.append(Neighbor(
                    hostname=hostname_match.group(1).split(".")[0],
                    local_port=local_port_match.group(1),
                    remote_port=remote_port_match.group(1) if remote_port_match else "",
                    ip=ip_match.group(1) if ip_match else "",
                ))
        return neighbors
    except Exception:
        return []


def _get_neighbors(conn) -> list[Neighbor]:
    """
    Dispatch to the right neighbor-discovery function based on ``conn.device_type``.
    """
    device_type: str = getattr(conn, "device_type", "") or ""

    # Huawei VRP
    if any(dt in device_type for dt in ("huawei_vrp", "huawei_vrpv8")):
        return get_lldp_neighbors_huawei(conn)

    # Aruba AOS-CX — dedicated parser, fall back to generic LLDP
    if "aruba_aoscx" in device_type:
        neighbors = get_lldp_neighbors_aoscx(conn)
        if not neighbors:
            neighbors = get_lldp_neighbors(conn)
        return neighbors

    # Cisco variants, Arista EOS, Juniper JunOS, HP ProCurve / Aruba —
    # try CDP first, then fall back to generic LLDP
    if any(dt in device_type for dt in (
        "cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr",
        "arista_eos", "juniper_junos", "hp_procurve",
        "aruba_procurve", "aruba_osswitch",
    )):
        try:
            neighbors = get_cdp_neighbors(conn)
            if not neighbors:
                neighbors = get_lldp_neighbors(conn)
            return neighbors
        except Exception:
            return get_lldp_neighbors(conn)

    # All other vendors — generic LLDP only
    try:
        return get_lldp_neighbors(conn)
    except Exception:
        return []


def _try_connect(ip: str, device_type: str, creds_sets: list[dict]):
    """
    Attempt SSH connection using each credential set in order.

    Tries each set sequentially; moves to the next only on
    NetmikoAuthenticationException.  Timeouts and other errors are re-raised
    immediately.  Returns ``(connection, used_fallback)`` on the first success,
    or re-raises the last authentication exception if all sets are exhausted.
    """
    last_exc = None
    for idx, creds in enumerate(creds_sets):
        try:
            conn = connect(
                ip=ip,
                username=creds["username"],
                password=creds["password"],
                device_type=device_type,
                port=creds.get("port", 22),
                key_file=creds.get("key_file"),
            )
            return conn, idx > 0
        except NetmikoAuthenticationException as exc:
            last_exc = exc
    raise last_exc


def discover(
    seed_ip: str,
    creds: dict,
    max_depth: int = None,
    use_hint_for_all: bool = False,
    extra_creds: list[dict] = None,
    timeout_seconds: int = None,
    on_device_found: callable = None,
    on_device_failed: callable = None,
) -> dict[str, Device]:
    """
    Recursively discover the network topology starting from seed_ip.
    Returns a dict of hostname -> Device.

    Args:
        seed_ip:          IP of the first switch to connect to.
        creds:            Dict with username, password, device_type, port, key_file.
        max_depth:        Maximum hop depth (None = unlimited).
        use_hint_for_all: When True, use creds["device_type"] for every device.
                          When False (default), auto-detect the type for every
                          neighbor IP that is discovered during crawl.
        extra_creds:      Optional list of partial credential dicts to try after
                          the primary creds when an auth failure occurs.  Each
                          entry may contain ``username``, ``password``, or both;
                          missing keys fall back to the primary creds values.
        timeout_seconds:  If set, stop processing new devices from the queue
                          after this many seconds have elapsed.  A yellow
                          warning is printed and the while-loop exits early.
                          The stub-entry second pass still runs afterwards.
        on_device_found:  Optional callable(hostname, ip, neighbor_count) invoked
                          after each device is successfully connected and its
                          neighbors retrieved.  Default None (no-op).
        on_device_failed: Optional callable(ip, ip) invoked when a device
                          connection fails.  Default None (no-op).
    """
    visited_ips: set[str] = set()
    devices: dict[str, Device] = {}
    # Queue entries: (ip, depth, device_type_or_None)
    # device_type_or_None is None for neighbors that need auto-detection.
    queue: list[tuple[str, int, str | None]] = [(seed_ip, 0, creds["device_type"])]
    # Cache auto-detected types so we don't probe the same IP twice.
    detected_types: dict[str, str] = {}

    # Build the ordered list of credential dicts to try for every connection.
    # The primary set is always first; extra_creds entries fill in missing keys
    # from the primary set so each dict is self-contained.
    _base = {
        "username": creds["username"],
        "password": creds["password"],
        "port": creds.get("port", 22),
        "key_file": creds.get("key_file"),
    }
    creds_sets: list[dict] = [_base]
    if extra_creds:
        for ec in extra_creds:
            merged = dict(_base)
            merged.update({k: v for k, v in ec.items() if v is not None})
            creds_sets.append(merged)

    start_time = time.monotonic() if timeout_seconds is not None else None

    with Progress(
        SpinnerColumn(spinner_name="line"),
        TextColumn("{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Starting discovery...", total=None)

        while queue:
            ip, depth, queued_type = queue.pop(0)
            if ip in visited_ips:
                continue
            if max_depth is not None and depth > max_depth:
                continue
            visited_ips.add(ip)

            # Resolve device type for this IP.
            if queued_type is not None:
                device_type_to_use = queued_type
            elif ip in detected_types:
                device_type_to_use = detected_types[ip]
            else:
                progress.update(task, description=f"Detecting device type for {ip}...")
                dtype = detect_device_type(
                    ip=ip,
                    port=creds.get("port", 22),
                    username=creds["username"],
                    password=creds["password"],
                    key_file=creds.get("key_file"),
                )
                detected_types[ip] = dtype
                device_type_to_use = dtype
                progress.console.print(f"[dim]  Auto-detected {ip} → {dtype}[/dim]")

            progress.update(task, description=f"Connecting to {ip}...")

            try:
                conn, used_fallback = _try_connect(ip, device_type_to_use, creds_sets)
                if used_fallback:
                    progress.console.print(f"[dim]  Used fallback credentials for {ip}[/dim]")

                hostname = get_hostname(conn)
                progress.console.print(f"[green]  Connected: {hostname}[/green]")

                neighbors = _get_neighbors(conn)

                conn.disconnect()

                device = Device(hostname=hostname, ip=ip, neighbors=neighbors)
                devices[hostname] = device

                if on_device_found is not None:
                    on_device_found(hostname, ip, len(neighbors))

                for neighbor in neighbors:
                    if neighbor.ip and neighbor.ip not in visited_ips:
                        neighbor_type = creds["device_type"] if use_hint_for_all else None
                        queue.append((neighbor.ip, depth + 1, neighbor_type))

            except NetmikoAuthenticationException:
                progress.console.print(f"[red]  Auth failed for {ip} (all credential sets exhausted)[/red]")
                if on_device_failed is not None:
                    on_device_failed(ip, ip)
            except NetmikoTimeoutException:
                progress.console.print(f"[yellow]  Timeout connecting to {ip}[/yellow]")
                if on_device_failed is not None:
                    on_device_failed(ip, ip)
            except Exception as e:
                progress.console.print(f"[red]  Error on {ip}: {e}[/red]")
                if on_device_failed is not None:
                    on_device_failed(ip, ip)

            # Discovery timeout check — runs after every device attempt.
            if start_time is not None and (time.monotonic() - start_time) > timeout_seconds:
                progress.console.print(
                    f"[yellow]  Discovery timeout ({timeout_seconds}s) reached — "
                    f"stopping early ({len(queue)} device(s) remaining in queue)[/yellow]"
                )
                break

        # Second pass: add stub entries for any neighbor referenced by a
        # reachable device that we never successfully connected to.  These
        # stubs keep the edge in the graph so loops through unreachable
        # switches are not silently dropped.
        queued_ips = {entry[0] for entry in queue}
        for device in list(devices.values()):
            for neighbor in device.neighbors:
                if neighbor.hostname and neighbor.hostname not in devices:
                    if not neighbor.ip or neighbor.ip not in queued_ips:
                        devices[neighbor.hostname] = Device(
                            hostname=neighbor.hostname,
                            ip=neighbor.ip,
                            neighbors=[],
                            reachable=False,
                        )

    return devices
