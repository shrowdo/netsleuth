"""
Network auto-discovery helpers for the loop-finder CLI.

Provides:
  get_local_subnets()          — find local IPv4 /24 subnets
  scan_subnet_for_ssh()        — TCP-probe every host in a subnet for port 22
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


def get_local_subnets() -> list[str]:
    """
    Return a list of CIDR strings representing local IPv4 subnets.

    Strategy (best-effort, graceful degradation):
    1. Try ``netifaces`` for per-interface addresses + netmasks.
    2. Fall back to ``socket.gethostbyname(socket.gethostname())`` with an
       assumed /24 prefix.

    Loopback (127.x.x.x) and link-local (169.254.x.x) addresses are excluded.
    """
    subnets: list[str] = []

    # --- attempt 1: netifaces ---
    try:
        import netifaces  # type: ignore

        AF_INET = netifaces.AF_INET
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(AF_INET, [])
            for entry in addrs:
                addr_str = entry.get("addr", "")
                netmask = entry.get("netmask", "255.255.255.0")
                if not addr_str:
                    continue
                try:
                    ip = ipaddress.IPv4Address(addr_str)
                    if ip.is_loopback or ip.is_link_local:
                        continue
                    network = ipaddress.IPv4Network(
                        f"{addr_str}/{netmask}", strict=False
                    )
                    cidr = str(network)
                    if cidr not in subnets:
                        subnets.append(cidr)
                except (ValueError, ipaddress.AddressValueError):
                    continue
    except ImportError:
        pass  # netifaces not installed — fall through

    if subnets:
        return subnets

    # --- attempt 2: socket.gethostbyname fallback ---
    try:
        hostname = socket.gethostname()
        primary_ip = socket.gethostbyname(hostname)
        ip = ipaddress.IPv4Address(primary_ip)
        if not ip.is_loopback and not ip.is_link_local:
            network = ipaddress.IPv4Network(f"{primary_ip}/24", strict=False)
            subnets.append(str(network))
    except Exception:
        pass

    return subnets


def scan_subnet_for_ssh(
    subnet: str,
    port: int = 22,
    timeout: float = 0.5,
    max_workers: int = 50,
) -> list[str]:
    """
    Probe every usable host in *subnet* for an open SSH port.

    Uses a thread pool for concurrent TCP connections so that a /24 scan
    completes in a few seconds even on a slow LAN.

    Args:
        subnet:      CIDR string, e.g. ``"192.168.1.0/24"``.
        port:        TCP port to probe (default 22).
        timeout:     Per-host connection timeout in seconds (default 0.5).
        max_workers: Thread-pool size (default 50).

    Returns:
        Sorted list of IP address strings that accepted a TCP connection.
    """
    try:
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn

        _console = Console()
    except ImportError:  # pragma: no cover
        _console = None  # type: ignore

    network = ipaddress.IPv4Network(subnet, strict=False)
    # Exclude network address and broadcast address
    hosts = list(network.hosts())

    found: list[str] = []

    def _probe(ip_str: str) -> Optional[str]:
        try:
            with socket.create_connection((ip_str, port), timeout=timeout):
                return ip_str
        except OSError:
            return None

    if _console is not None:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=_console,
            transient=True,
        )
        progress.start()
        task = progress.add_task(
            f"Scanning {subnet} for SSH hosts...", total=len(hosts)
        )
    else:
        progress = None  # type: ignore
        task = None

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_probe, str(h)): h for h in hosts}
            for future in as_completed(futures):
                if progress is not None:
                    progress.advance(task)
                result = future.result()
                if result is not None:
                    found.append(result)
    finally:
        if progress is not None:
            progress.stop()

    # Sort numerically by packed IP address
    found.sort(key=lambda ip: ipaddress.IPv4Address(ip))
    return found
