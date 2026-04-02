"""
SSH into switches and discover topology via CDP/LLDP neighbor data.
"""

import re
from dataclasses import dataclass, field
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko.exceptions import NetmikoBaseException

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

console = Console()


@dataclass
class Neighbor:
    hostname: str
    local_port: str
    remote_port: str
    ip: str = ""


@dataclass
class Device:
    hostname: str
    ip: str
    neighbors: list[Neighbor] = field(default_factory=list)


def connect(ip: str, username: str, password: str, device_type: str, port: int = 22, key_file: str = None) -> object:
    candidates = _DEVICE_TYPE_ALIASES.get(device_type.lower(), [device_type])

    last_err = None
    for dtype in candidates:
        params = {
            "device_type": dtype,
            "host": ip,
            "username": username,
            "password": password,
            "port": port,
        }
        if key_file:
            params["use_keys"] = True
            params["key_file"] = key_file
        try:
            conn = ConnectHandler(**params)
            if len(candidates) > 1:
                console.print(f"[dim]  Auto-detected device type: {dtype}[/dim]")
            return conn
        except (ValueError, NetmikoBaseException) as e:
            last_err = e
            continue

    raise last_err


def get_hostname(conn) -> str:
    output = conn.send_command("show version | include hostname|uptime")
    match = re.search(r"(\S+)\s+uptime", output)
    if match:
        return match.group(1)
    # fallback: use the prompt
    return conn.find_prompt().strip("#>")


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
            neighbors.append(Neighbor(
                hostname=hostname_match.group(1).split(".")[0],  # strip domain
                local_port=local_port_match.group(1),
                remote_port=remote_port_match.group(1) if remote_port_match else "",
                ip=ip_match.group(1) if ip_match else "",
            ))
    return neighbors


def get_lldp_neighbors(conn) -> list[Neighbor]:
    output = conn.send_command("show lldp neighbors detail")
    neighbors = []
    blocks = re.split(r"-{3,}|={3,}", output)
    for block in blocks:
        hostname_match = re.search(r"System Name:\s*(\S+)", block)
        local_port_match = re.search(r"Local Port(?:ID)?:\s*(\S+)", block, re.IGNORECASE)
        remote_port_match = re.search(r"Port ID:\s*(\S+)", block)
        ip_match = re.search(r"Management Address.*?(\d+\.\d+\.\d+\.\d+)", block, re.DOTALL)
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
        m = re.search(r"Management Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", out)
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
        col_portd   = header.index("PORT-DESC")
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


def discover(seed_ip: str, creds: dict, max_depth: int = None) -> dict[str, Device]:
    """
    Recursively discover the network topology starting from seed_ip.
    Returns a dict of hostname -> Device.
    """
    visited_ips = set()
    devices: dict[str, Device] = {}
    queue = [(seed_ip, 0)]

    with Progress(
        SpinnerColumn(spinner_name="line"),
        TextColumn("{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Starting discovery...", total=None)

        while queue:
            ip, depth = queue.pop(0)
            if ip in visited_ips:
                continue
            if max_depth is not None and depth > max_depth:
                continue
            visited_ips.add(ip)

            progress.update(task, description=f"Connecting to {ip}...")

            try:
                conn = connect(
                    ip=ip,
                    username=creds["username"],
                    password=creds["password"],
                    device_type=creds["device_type"],
                    port=creds.get("port", 22),
                    key_file=creds.get("key_file"),
                )
                hostname = get_hostname(conn)
                progress.console.print(f"[green]  Connected: {hostname}[/green]")

                # Use device-specific neighbor discovery
                device_type = getattr(conn, "device_type", "")
                if "aoscx" in device_type:
                    neighbors = get_lldp_neighbors_aoscx(conn)
                else:
                    # Try CDP first, fall back to generic LLDP
                    try:
                        neighbors = get_cdp_neighbors(conn)
                        if not neighbors:
                            neighbors = get_lldp_neighbors(conn)
                    except Exception:
                        neighbors = get_lldp_neighbors(conn)

                conn.disconnect()

                device = Device(hostname=hostname, ip=ip, neighbors=neighbors)
                devices[hostname] = device

                for neighbor in neighbors:
                    if neighbor.ip and neighbor.ip not in visited_ips:
                        queue.append((neighbor.ip, depth + 1))

            except NetmikoAuthenticationException:
                progress.console.print(f"[red]  Auth failed for {ip}[/red]")
            except NetmikoTimeoutException:
                progress.console.print(f"[yellow]  Timeout connecting to {ip}[/yellow]")
            except Exception as e:
                progress.console.print(f"[red]  Error on {ip}: {e}[/red]")

    return devices
