"""
Parse CDP / LLDP neighbour output into Neighbor records.

Every parser is a pure text -> list[Neighbor] function so it can be tested
against captured output and re-run offline with --replay.
"""

import re

from netsleuth_core.models import Neighbor
from netsleuth_core.platform import classify_platform, neighbor_role
from netsleuth_core.ports import expand_port

_IPV4 = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"


def _clean_name(raw: str) -> str:
    name = raw.strip().strip('"').rstrip("~")
    name = re.sub(r"\(.*?\)$", "", name)  # "SW1(FOC123)" -> "SW1"
    # Strip a domain suffix, but leave MAC-style IDs ("001b.3f5c.2e00") alone.
    if not re.fullmatch(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", name):
        name = name.split(".")[0]
    return name


def _finish(n: Neighbor, block: str) -> Neighbor:
    n.device_type_hint = classify_platform(block)
    n.role = neighbor_role(n.capabilities, n.platform, n.hostname)
    return n


# ---------------------------------------------------------------------------
# Cisco / Arista / NX-OS / Juniper
# ---------------------------------------------------------------------------

def parse_cdp_detail(output: str) -> list[Neighbor]:
    """Cisco IOS / NX-OS "show cdp neighbors detail"."""
    neighbors = []
    for block in re.split(r"\n-{5,}", output):
        host_m = re.search(r"Device ID:\s*(\S+)", block)
        local_m = re.search(r"Interface:\s*([^,\s]+),", block)
        if not (host_m and local_m):
            continue
        remote_m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block, re.I)
        ip_m = re.search(r"IP(?:v4)? [Aa]ddress:\s*" + _IPV4, block)
        plat_m = re.search(r"Platform:\s*([^,\n]+)", block)
        caps_m = re.search(r"Capabilities:\s*([^\n]+)", block)
        neighbors.append(_finish(Neighbor(
            hostname=_clean_name(host_m.group(1)),
            local_port=expand_port(local_m.group(1)),
            remote_port=expand_port(remote_m.group(1)) if remote_m else "",
            ip=ip_m.group(1) if ip_m else "",
            platform=plat_m.group(1).strip() if plat_m else "",
            capabilities=caps_m.group(1).strip() if caps_m else "",
        ), block))
    return neighbors


def parse_lldp_detail(output: str) -> list[Neighbor]:
    """
    Generic "show lldp neighbors detail" (Cisco IOS, NX-OS, Arista, Juniper).

    Cisco prints "Local Intf:", NX-OS "Local Port id:", Arista
    "Interface Ethernet1 detected ...", Juniper "Local Interface :".
    """
    neighbors = []
    blocks = re.split(r"\n-{5,}|\n={5,}|\n(?=Interface \S+ detected)", output)
    for block in blocks:
        local_m = (
            re.search(r"Local Intf:\s*(\S+)", block)
            or re.search(r"Local Port id:\s*(\S+)", block, re.I)
            or re.search(r"Local Interface\s*:\s*(\S+)", block, re.I)
            or re.search(r"^Interface\s+(\S+)\s+detected", block, re.M)
        )
        name_m = re.search(r"System Name\s*:\s*\"?([^\s\"]+)", block, re.I)
        if not name_m:
            name_m = re.search(r"Chassis id\s*:\s*\"?([^\s\"]+)", block, re.I)
        if not (local_m and name_m):
            continue
        remote_m = (
            re.search(r"^\s*Port id\s*:\s*\"?([^\s\"]+)", block, re.I | re.M)
            or re.search(r"Port description\s*:\s*(\S+)", block, re.I)
        )
        ip_m = re.search(r"Management Address(?:es)?.{0,200}?" + _IPV4, block, re.I | re.S)
        caps_m = (
            re.search(r"Enabled Capabilities\s*:\s*([^\n]+)", block, re.I)
            or re.search(r"System Capabilities\s*:\s*([^\n]+)", block, re.I)
        )
        desc_m = re.search(r"System Description\s*:\s*\n?\s*([^\n]+)", block, re.I)
        neighbors.append(_finish(Neighbor(
            hostname=_clean_name(name_m.group(1)),
            local_port=expand_port(local_m.group(1)),
            remote_port=expand_port(remote_m.group(1)) if remote_m else "",
            ip=ip_m.group(1) if ip_m else "",
            platform=desc_m.group(1).strip()[:80] if desc_m else "",
            capabilities=caps_m.group(1).strip() if caps_m else "",
        ), block))
    return neighbors


# ---------------------------------------------------------------------------
# HP ProCurve / Aruba-OS (AOS-S)
# ---------------------------------------------------------------------------

def parse_procurve_lldp_ports(output: str) -> list[str]:
    """Local ports listed in AOS-S "show lldp info remote-device" (table form)."""
    ports = []
    for line in output.splitlines():
        m = re.match(r"^\s*(\S+)\s+\|\s+\S", line)
        if not m:
            continue
        port = m.group(1)
        if port.lower() == "localport" or set(port) <= set("-+"):
            continue
        ports.append(port)
    return list(dict.fromkeys(ports))


def parse_procurve_lldp_detail(output: str) -> list[Neighbor]:
    """AOS-S "show lldp info remote-device <ports>" detail output."""
    neighbors = []
    for block in re.split(r"(?=^\s*Local Port\s*:)", output, flags=re.M):
        local_m = re.search(r"Local Port\s*:\s*(\S+)", block)
        if not local_m:
            continue
        name_m = re.search(r"SysName\s*:\s*(\S+)", block)
        chassis_m = re.search(r"ChassisId\s*:\s*([^\n]+)", block)
        if not (name_m or chassis_m):
            continue
        port_m = re.search(r"PortId\s*:\s*(\S+)", block)
        ip_m = re.search(r"Address\s*:\s*" + _IPV4, block)
        caps_m = (
            re.search(r"System Capabilities Enabled\s*:\s*([^\n]+)", block)
            or re.search(r"System Capabilities Supported\s*:\s*([^\n]+)", block)
        )
        desc_m = re.search(r"System Descr\s*:\s*([^\n]+)", block)
        hostname = name_m.group(1) if name_m else chassis_m.group(1).strip().replace(" ", "")
        neighbors.append(_finish(Neighbor(
            hostname=_clean_name(hostname),
            local_port=local_m.group(1),
            remote_port=expand_port(port_m.group(1)) if port_m else "",
            ip=ip_m.group(1) if ip_m else "",
            platform=desc_m.group(1).strip()[:80] if desc_m else "",
            capabilities=caps_m.group(1).strip() if caps_m else "",
        ), block))
    return neighbors


def parse_procurve_cdp_detail(output: str) -> list[Neighbor]:
    """AOS-S "show cdp neighbors detail" ("Port : 1", "Device ID : ...")."""
    neighbors = []
    for block in re.split(r"(?=^\s*Port\s*:)", output, flags=re.M):
        local_m = re.search(r"^\s*Port\s*:\s*(\S+)", block, re.M)
        host_m = re.search(r"Device ID\s*:\s*(\S+)", block)
        if not (local_m and host_m):
            continue
        ip_m = re.search(r"Address\s*:\s*" + _IPV4, block)
        remote_m = re.search(r"Device Port\s*:\s*(\S+)", block)
        plat_m = re.search(r"Platform\s*:\s*([^\n]+)", block)
        caps_m = re.search(r"Capability\s*:\s*([^\n]+)", block)
        neighbors.append(_finish(Neighbor(
            hostname=_clean_name(host_m.group(1)),
            local_port=local_m.group(1),
            remote_port=expand_port(remote_m.group(1)) if remote_m else "",
            ip=ip_m.group(1) if ip_m else "",
            platform=plat_m.group(1).strip()[:80] if plat_m else "",
            capabilities=caps_m.group(1).strip() if caps_m else "",
        ), block))
    return neighbors


# ---------------------------------------------------------------------------
# Aruba AOS-CX
# ---------------------------------------------------------------------------

def parse_aoscx_lldp_detail(output: str) -> list[Neighbor]:
    """AOS-CX "show lldp neighbor-info detail" (or per-port neighbor-info)."""
    neighbors = []
    for block in re.split(r"(?=^\s*Port\s*:\s*\S)", output, flags=re.M):
        local_m = re.search(r"^\s*Port\s*:\s*(\S+)", block, re.M)
        name_m = re.search(r"Neighbor System-Name\s*:\s*(\S+)", block)
        chassis_m = re.search(r"Neighbor Chassis-ID\s*:\s*(\S+)", block)
        if not local_m or not (name_m or chassis_m):
            continue
        port_m = re.search(r"Neighbor Port-ID\s*:\s*(\S+)", block)
        ip_m = re.search(r"Neighbor Management-Address\s*:\s*" + _IPV4, block)
        caps_m = (
            re.search(r"Neighbor Capabilities Enabled\s*:\s*([^\n]+)", block)
            or re.search(r"Neighbor Capabilities\s*:\s*([^\n]+)", block)
        )
        desc_m = re.search(r"Neighbor System-Description\s*:\s*([^\n]+)", block)
        neighbors.append(_finish(Neighbor(
            hostname=_clean_name((name_m or chassis_m).group(1)),
            local_port=local_m.group(1),
            remote_port=expand_port(port_m.group(1)) if port_m else "",
            ip=ip_m.group(1) if ip_m else "",
            platform=desc_m.group(1).strip()[:80] if desc_m else "",
            capabilities=caps_m.group(1).strip() if caps_m else "",
        ), block))
    return neighbors


def parse_aoscx_lldp_table(output: str) -> list[Neighbor]:
    """AOS-CX "show lldp neighbor-info" summary table (no IPs or capabilities)."""
    lines = output.splitlines()
    header_idx = next(
        (i for i, l in enumerate(lines) if "LOCAL-PORT" in l and "SYS-NAME" in l), None
    )
    if header_idx is None:
        return []
    header = lines[header_idx]
    cols = {name: header.index(name) for name in
            ("LOCAL-PORT", "CHASSIS-ID", "PORT-ID", "PORT-DESC", "TTL", "SYS-NAME")
            if name in header}
    if not {"LOCAL-PORT", "PORT-ID", "SYS-NAME"} <= cols.keys():
        return []
    ordered = sorted(cols.values())

    def _field(line: str, name: str) -> str:
        start = cols[name]
        later = [pos for pos in ordered if pos > start]
        end = later[0] if later else len(line)
        return line[start:end].strip()

    neighbors = []
    for line in lines[header_idx + 1:]:
        if not line.strip() or set(line.strip()) <= set("- "):
            continue
        local, name = _field(line, "LOCAL-PORT"), _field(line, "SYS-NAME")
        if not local or not name:
            continue
        neighbors.append(Neighbor(
            hostname=_clean_name(name), local_port=local,
            remote_port=expand_port(_field(line, "PORT-ID")),
        ))
    return neighbors


# ---------------------------------------------------------------------------
# Huawei VRP
# ---------------------------------------------------------------------------

def parse_huawei_lldp_detail(output: str) -> list[Neighbor]:
    """Huawei "display lldp neighbor" output."""
    neighbors = []
    for block in re.split(r"(?=^\S+\s+has\s+\d+\s+neighbor)", output, flags=re.M | re.I):
        local_m = re.match(r"^(\S+)\s+has\s+\d+\s+neighbor", block, re.I)
        name_m = re.search(r"System name\s*:\s*(\S+)", block, re.I)
        if not (local_m and name_m):
            continue
        port_m = re.search(r"Port ID\s*:\s*(\S+)", block, re.I)
        ip_m = re.search(r"Management address\s*:\s*" + _IPV4, block, re.I)
        caps_m = re.search(r"System capabilities enabled\s*:\s*([^\n]+)", block, re.I)
        desc_m = re.search(r"System description\s*:\s*([^\n]+)", block, re.I)
        neighbors.append(_finish(Neighbor(
            hostname=_clean_name(name_m.group(1)),
            local_port=local_m.group(1),
            remote_port=port_m.group(1) if port_m else "",
            ip=ip_m.group(1) if ip_m else "",
            platform=desc_m.group(1).strip()[:80] if desc_m else "",
            capabilities=caps_m.group(1).strip() if caps_m else "",
        ), block))
    return neighbors
