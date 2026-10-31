"""
Scan switch logs for loop / broadcast-storm indicators.

Indicators checked (Cisco, NX-OS, HP ProCurve/Aruba-OS, AOS-CX):
  - MAC flapping / MAC moves (the most reliable loop signal)
  - Storm control and HP "excessive broadcasts" (FFI) events
  - Loop-protect / loopback detection
  - BPDU guard and other err-disable events
  - STP topology change bursts
"""

import re
from dataclasses import dataclass, field

from netsleuth_core.ports import expand_port as _raw_expand


def _expand_port(port: str) -> str:
    return _raw_expand(port.strip().rstrip(".,;:)"))


@dataclass
class LogFindings:
    mac_flaps: list[dict] = field(default_factory=list)
    storm_shutdowns: list[dict] = field(default_factory=list)
    bpdu_violations: list[dict] = field(default_factory=list)
    loop_detections: list[dict] = field(default_factory=list)
    tcn_bursts: list[dict] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return any([
            self.mac_flaps,
            self.storm_shutdowns,
            self.bpdu_violations,
            self.loop_detections,
            self.tcn_bursts,
        ])

    @property
    def suspect_ports(self) -> set[str]:
        """All ports mentioned across all findings."""
        ports = set()
        for f in self.mac_flaps:
            ports.update(f.get("ports", []))
        for group in (self.storm_shutdowns, self.bpdu_violations, self.loop_detections):
            for f in group:
                if f.get("port"):
                    ports.add(f["port"])
        return ports


# %SW_MATM-4-MACFLAP_NOTIF: Host aabb.ccdd.eeff in vlan 10 is flapping between port Gi0/1 and port Gi0/2
_MACFLAP_RE = re.compile(
    r"MACFLAP_NOTIF.*?Host\s+(?P<mac>\S+)\s+in vlan\s+(?P<vlan>\d+).*?"
    r"between port\s+(?P<port1>\S+)\s+and\s+(?:port\s+)?(?P<port2>\S+)",
    re.IGNORECASE,
)

# NX-OS / AOS-CX style: "Mac 0011.2233.4455 in vlan 10 has moved from Eth1/1 to Eth1/2"
_MACMOVE_RE = re.compile(
    r"(?:mac|host)(?:\s+address)?\s+(?P<mac>[0-9a-fA-F:.\-]{12,17})\s+(?:in|on)\s+vlan\s+(?P<vlan>\d+)"
    r".*?mov\w*\s+from\s+(?:port\s+|interface\s+)?(?P<port1>\S+)\s+to\s+(?:port\s+|interface\s+)?(?P<port2>\S+)",
    re.IGNORECASE,
)

# %STORM_CONTROL-3-SHUTDOWN: A packet storm was detected on Gi1/0/5. A packet filter action ...
# %STORM_CONTROL-3-FILTERED: A Broadcast storm detected on Gi1/0/5. ...
_STORM_RE = re.compile(
    r"STORM_CONTROL-\d-(?P<action>SHUTDOWN|FILTERED).*?\bon\s+(?:interface\s+)?(?P<port>[A-Za-z]+[\d/.]+)",
    re.IGNORECASE,
)

# HP ProCurve: "FFI: port 23-Excessive Broadcasts. See help."
_FFI_RE = re.compile(
    r"FFI:\s*port\s+(?P<port>[^\s\-]+)\s*-\s*Excessive\s+(?P<kind>Broadcasts|Multicasts)",
    re.IGNORECASE,
)

# %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi0/1 with BPDU Guard enabled
_BPDU_RE = re.compile(
    r"SPANTREE-\d-(?P<type>BLOCK_BPDUGUARD|RECV_PVID_ERR|LOOPBACK_INCONSISTENCY|LOOPGUARD_BLOCK)"
    r".*?(?:port|interface)\s+(?P<port>[A-Za-z]+[\d/.]+)",
    re.IGNORECASE,
)

# %PM-4-ERR_DISABLE: loopback error detected on Gi1/0/5, putting Gi1/0/5 in err-disable state
_ERRDISABLE_RE = re.compile(
    r"ERR_DISABLE:\s*(?P<reason>[\w\-]+)\s+error detected on\s+(?P<port>[^\s,]+)",
    re.IGNORECASE,
)

# %ETHCNTR-3-LOOP_BACK_DETECTED: Loop-back detected on GigabitEthernet1/0/5
# HP:     "loop-protect: port 5 disabled - loop detected"
# AOS-CX: "Loop protect: loop detected on port 1/1/5"
_LOOP_RE = re.compile(
    r"LOOP_BACK_DETECTED:.*?on\s+(?P<p1>\S+)"
    r"|loop[- ]protect:?\s*(?:loop detected on\s+)?(?:port|interface)\s+(?P<p2>[^\s,]+)"
    r"|loop detected on\s+(?:port|interface)\s+(?P<p3>[^\s,]+)",
    re.IGNORECASE,
)

# %SPANTREE-5-TOPOTRAP: Topology Change Trap ...  (many in a short burst = loop churning STP)
_TCN_RE = re.compile(r"SPANTREE-\d+-TOPOTRAP|SPANTREE.*?Topology Change|topology change", re.IGNORECASE)


def parse_logs(log_output: str) -> LogFindings:
    findings = LogFindings()
    if not log_output:
        return findings

    # Deduplicate MAC flaps by (mac, vlan) pair: switches log these repeatedly.
    seen_flaps: set[tuple] = set()
    for regex in (_MACFLAP_RE, _MACMOVE_RE):
        for m in regex.finditer(log_output):
            key = (m.group("mac").lower(), m.group("vlan"))
            if key in seen_flaps:
                continue
            seen_flaps.add(key)
            findings.mac_flaps.append({
                "mac": m.group("mac"),
                "vlan": m.group("vlan"),
                "ports": [_expand_port(m.group("port1")), _expand_port(m.group("port2"))],
            })

    seen_storm: set[str] = set()
    for m in _STORM_RE.finditer(log_output):
        port = _expand_port(m.group("port"))
        if port not in seen_storm:
            seen_storm.add(port)
            findings.storm_shutdowns.append({"port": port, "action": m.group("action").capitalize()})
    for m in _FFI_RE.finditer(log_output):
        port = _expand_port(m.group("port"))
        if port not in seen_storm:
            seen_storm.add(port)
            findings.storm_shutdowns.append({"port": port, "action": f"Excessive {m.group('kind').lower()}"})

    seen_bpdu: set[tuple] = set()
    for m in _BPDU_RE.finditer(log_output):
        key = (m.group("type"), _expand_port(m.group("port")))
        if key not in seen_bpdu:
            seen_bpdu.add(key)
            findings.bpdu_violations.append({"port": key[1], "type": m.group("type")})
    for m in _ERRDISABLE_RE.finditer(log_output):
        reason = m.group("reason").lower()
        port = _expand_port(m.group("port"))
        if "loop" in reason:
            findings.loop_detections.append({"port": port, "source": f"err-disable ({reason})"})
        elif "storm" in reason:
            if port not in seen_storm:
                seen_storm.add(port)
                findings.storm_shutdowns.append({"port": port, "action": "Err-disabled"})
        else:
            key = (f"ERR_DISABLE {reason}", port)
            if key not in seen_bpdu:
                seen_bpdu.add(key)
                findings.bpdu_violations.append({"port": port, "type": key[0]})

    seen_loop = {f["port"] for f in findings.loop_detections}
    for m in _LOOP_RE.finditer(log_output):
        port = _expand_port(m.group("p1") or m.group("p2") or m.group("p3"))
        if port not in seen_loop:
            seen_loop.add(port)
            findings.loop_detections.append({"port": port, "source": "loop detection"})

    tcn_count = sum(1 for line in log_output.splitlines() if _TCN_RE.search(line))
    if tcn_count >= 5:
        findings.tcn_bursts.append({
            "count": tcn_count,
            "note": "High TCN count suggests STP is reconverging repeatedly - possible loop.",
        })

    return findings


def merge_findings(items: list[LogFindings]) -> LogFindings:
    merged = LogFindings()
    for f in items:
        if f is None:
            continue
        merged.mac_flaps += f.mac_flaps
        merged.storm_shutdowns += f.storm_shutdowns
        merged.bpdu_violations += f.bpdu_violations
        merged.loop_detections += f.loop_detections
        merged.tcn_bursts += f.tcn_bursts
    return merged


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

MOCK_LOG_WITH_LOOP = """
Jan 1 00:01:00: %SW_MATM-4-MACFLAP_NOTIF: Host aabb.cc00.0001 in vlan 1 is flapping between port Gi0/1 and port Gi0/2
Jan 1 00:01:01: %SW_MATM-4-MACFLAP_NOTIF: Host aabb.cc00.0002 in vlan 1 is flapping between port Gi0/1 and port Gi0/2
Jan 1 00:01:02: %STORM_CONTROL-3-SHUTDOWN: A packet storm was detected on Gi0/2. A packet filter action has been applied on the interface.
Jan 1 00:01:03: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:04: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:05: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:06: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:07: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:08: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi0/1 with BPDU Guard enabled
"""

MOCK_LOG_CLEAN = """
Jan 1 00:00:01: %SYS-5-CONFIG_I: Configured from console by admin
Jan 1 00:00:02: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
"""
