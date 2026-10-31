from dataclasses import dataclass, field
from typing import Any


@dataclass
class Neighbor:
    hostname: str
    local_port: str
    remote_port: str
    ip: str = ""
    # Short platform / system description as reported by CDP/LLDP.
    platform: str = ""
    # Raw capability text, e.g. "Switch IGMP", "B,T", "bridge, telephone".
    capabilities: str = ""
    # Netmiko device type guessed from the CDP/LLDP description ("" = unknown).
    device_type_hint: str = ""
    # "switch", "endpoint" (phone/AP/host/router) or "unknown".
    role: str = "unknown"


@dataclass
class Device:
    hostname: str
    ip: str
    neighbors: list[Neighbor] = field(default_factory=list)
    reachable: bool = True
    device_type: str = ""
    # Canonical port name -> merged STP state ("FWD", "BLK", "PART", "DIS", ...).
    stp: dict[str, str] = field(default_factory=dict)
    # "enabled", "disabled" or "unknown".
    stp_mode: str = "unknown"
    # Topology-change info per STP instance: {"instance", "count", "age_s", "from_port"}.
    tcn: list[dict] = field(default_factory=list)
    # Canonical member port -> LAG name (e.g. "Po1", "Trk1", "lag1").
    lags: dict[str, str] = field(default_factory=dict)
    # Port -> inbound broadcast(+multicast) packets per second.
    port_rates: dict[str, float] = field(default_factory=dict)
    rate_kind: str = ""
    # Ports shut down by the switch itself: {"port", "reason"}.
    disabled_ports: list[dict] = field(default_factory=list)
    log_findings: Any = None
    error: str = ""
    # Other management IPs this switch was reached on.
    alt_ips: list[str] = field(default_factory=list)
