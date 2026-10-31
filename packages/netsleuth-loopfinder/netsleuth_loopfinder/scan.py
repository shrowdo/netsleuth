"""
Local network helpers for picking a seed switch.

  get_local_subnets()     - this machine's IPv4 subnets (real netmasks where possible)
  scan_subnet_for_ssh()   - find hosts with SSH open, optionally with their SSH banner
"""

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Never sweep more than this many addresses per subnet.
MAX_PREFIX = 22


def _windows_subnets() -> list[tuple[str, str]]:
    """(ip, netmask) pairs from ipconfig, including adapters without a gateway."""
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except Exception:
        return []
    pairs = []
    ip = None
    for line in out.splitlines():
        m = re.search(r"IPv4 Address[ .]*:\s*([\d.]+)", line)
        if m:
            ip = m.group(1)
            continue
        m = re.search(r"Subnet Mask[ .]*:\s*([\d.]+)", line)
        if m and ip:
            pairs.append((ip, m.group(1)))
            ip = None
    return pairs


def _generic_addresses() -> list[tuple[str, str]]:
    pairs = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            pairs.append((info[4][0], "255.255.255.0"))
    except OSError:
        pass
    # The address used for the default route, even when DNS for our own hostname is broken.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            pairs.append((s.getsockname()[0], "255.255.255.0"))
    except OSError:
        pass
    return pairs


def get_local_subnets() -> list[str]:
    """CIDR strings for this machine's IPv4 subnets (loopback/link-local excluded)."""
    pairs: list[tuple[str, str]] = []
    if platform.system() == "Windows":
        pairs = _windows_subnets()
    try:
        import netifaces  # type: ignore

        for iface in netifaces.interfaces():
            for entry in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                if entry.get("addr"):
                    pairs.append((entry["addr"], entry.get("netmask", "255.255.255.0")))
    except ImportError:
        pass
    if not pairs:
        pairs = _generic_addresses()

    subnets: list[str] = []
    for addr, mask in pairs:
        try:
            ip = ipaddress.IPv4Address(addr)
            if ip.is_loopback or ip.is_link_local:
                continue
            net = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
            if net.prefixlen < MAX_PREFIX:
                # Big flat network: sweep just the block around us.
                net = ipaddress.IPv4Network(f"{addr}/24", strict=False)
            cidr = str(net)
            if cidr not in subnets:
                subnets.append(cidr)
        except ValueError:
            continue
    return subnets


def _probe(ip: str, port: int, timeout: float, with_banner: bool):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if not with_banner:
                return ip, ""
            sock.settimeout(1.5)
            try:
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            except OSError:
                banner = ""
            return ip, banner.splitlines()[0][:60] if banner else ""
    except OSError:
        return None


def scan_subnet_for_ssh(
    subnet: str,
    port: int = 22,
    timeout: float = 0.6,
    max_workers: int = 64,
    with_banner: bool = False,
):
    """
    Probe every host in *subnet* for an open SSH port.

    Returns a sorted list of IP strings, or with ``with_banner=True`` a list of
    {"ip", "banner"} dicts (the SSH banner often names the vendor, e.g.
    "SSH-2.0-Cisco-1.25").
    """
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = [str(h) for h in network.hosts()]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = [r for r in pool.map(lambda h: _probe(h, port, timeout, with_banner), hosts) if r]
    results.sort(key=lambda r: ipaddress.IPv4Address(r[0]))
    if with_banner:
        return [{"ip": ip, "banner": banner} for ip, banner in results]
    return [ip for ip, _ in results]
