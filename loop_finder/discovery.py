"""
SSH into switches and discover topology via CDP/LLDP neighbor data.
"""

import re
from dataclasses import dataclass, field
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
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
    params = {
        "device_type": device_type,
        "host": ip,
        "username": username,
        "password": password,
        "port": port,
    }
    if key_file:
        params["use_keys"] = True
        params["key_file"] = key_file
    return ConnectHandler(**params)


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


def discover(seed_ip: str, creds: dict, max_depth: int = None) -> dict[str, Device]:
    """
    Recursively discover the network topology starting from seed_ip.
    Returns a dict of hostname -> Device.
    """
    visited_ips = set()
    devices: dict[str, Device] = {}
    queue = [(seed_ip, 0)]

    with Progress(
        SpinnerColumn(),
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

                # Try CDP first, fall back to LLDP
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
