"""
Phase 0: Pull 'show logging' from the seed switch and scan for indicators
of a loop before full topology discovery begins.

Indicators checked:
  - MAC flapping (most reliable loop signal)
  - Storm control shutdowns
  - BPDU guard violations
  - STP topology change notifications (TCN burst)
"""

import re
from dataclasses import dataclass, field
from rich.console import Console
from netsleuth_core.ports import expand_port as _expand_port

console = Console()


@dataclass
class LogFindings:
    mac_flaps: list[dict] = field(default_factory=list)
    storm_shutdowns: list[dict] = field(default_factory=list)
    bpdu_violations: list[dict] = field(default_factory=list)
    tcn_bursts: list[dict] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return any([
            self.mac_flaps,
            self.storm_shutdowns,
            self.bpdu_violations,
            self.tcn_bursts,
        ])

    @property
    def suspect_ports(self) -> set[str]:
        """All ports mentioned across all findings."""
        ports = set()
        for f in self.mac_flaps:
            ports.update(f.get("ports", []))
        for f in self.storm_shutdowns:
            if f.get("port"):
                ports.add(f["port"])
        for f in self.bpdu_violations:
            if f.get("port"):
                ports.add(f["port"])
        return ports


# %SW_MATM-4-MACFLAP_NOTIF: Host aabb.ccdd.eeff in vlan 10 is flapping between port Gi0/1 and Gi0/2
_MACFLAP_RE = re.compile(
    r"MACFLAP_NOTIF.*?Host\s+(?P<mac>\S+)\s+in vlan\s+(?P<vlan>\d+).*?"
    r"between port\s+(?P<port1>\S+)\s+and\s+(?P<port2>\S+)",
    re.IGNORECASE,
)

# %STORM_CONTROL-3-SHUTDOWN: A loop is detected on Gi0/1
# %STORM_CONTROL-3-FILTERED: ...
_STORM_RE = re.compile(
    r"STORM_CONTROL-\d-(?P<action>SHUTDOWN|FILTERED).*?(?:loop.*?on|on)\s+(?P<port>\S+)",
    re.IGNORECASE,
)

# %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi0/1 with BPDU Guard enabled
# %SPANTREE-2-RECV_PVID_ERR: Received BPDU with inconsistent peer vlan id on port Gi0/2
_BPDU_RE = re.compile(
    r"SPANTREE-\d-(?P<type>BLOCK_BPDUGUARD|RECV_PVID_ERR|LOOPBACK_INCONSISTENCY).*?port\s+(?P<port>\S+)",
    re.IGNORECASE,
)

# %SPANTREE-5-TOPOTRAP: Topology Change Trap ...  (many in a short burst = loop churning STP)
_TCN_RE = re.compile(r"SPANTREE-\d+-TOPOTRAP|SPANTREE.*?Topology Change", re.IGNORECASE)



def parse_logs(log_output: str) -> LogFindings:
    findings = LogFindings()

    # Deduplicate MAC flaps by (mac, vlan) pair — switches log these repeatedly
    seen_flaps: set[tuple] = set()
    for m in _MACFLAP_RE.finditer(log_output):
        key = (m.group("mac"), m.group("vlan"))
        if key not in seen_flaps:
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
            findings.storm_shutdowns.append({
                "port": port,
                "action": m.group("action").capitalize(),
            })

    seen_bpdu: set[tuple] = set()
    for m in _BPDU_RE.finditer(log_output):
        key = (m.group("type"), m.group("port"))
        if key not in seen_bpdu:
            seen_bpdu.add(key)
            findings.bpdu_violations.append({
                "port": _expand_port(m.group("port")),
                "type": m.group("type"),
            })

    tcn_count = len(_TCN_RE.findall(log_output))
    if tcn_count >= 5:
        findings.tcn_bursts.append({
            "count": tcn_count,
            "note": "High TCN count suggests STP is reconverging repeatedly — possible loop.",
        })

    return findings


def get_log_findings(conn, hostname: str) -> LogFindings:
    """Pull show logging from an open Netmiko connection and parse it."""
    console.print(f"[cyan]  Pulling logs from {hostname}...[/cyan]")
    try:
        output = conn.send_command("show logging")
        findings = parse_logs(output)
        if findings.has_findings:
            console.print(f"[bold red]  Loop indicators found in logs on {hostname}![/bold red]")
        else:
            console.print(f"[green]  No loop indicators in logs on {hostname}.[/green]")
        return findings
    except Exception as e:
        console.print(f"[yellow]  Could not retrieve logs from {hostname}: {e}[/yellow]")
        return LogFindings()


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

_MOCK_LOG_WITH_LOOP = """
Jan 1 00:01:00: %SW_MATM-4-MACFLAP_NOTIF: Host aabb.cc00.0001 in vlan 1 is flapping between port Gi0/1 and Gi0/2
Jan 1 00:01:01: %SW_MATM-4-MACFLAP_NOTIF: Host aabb.cc00.0002 in vlan 1 is flapping between port Gi0/1 and Gi0/2
Jan 1 00:01:02: %STORM_CONTROL-3-SHUTDOWN: A loop is detected on Gi0/2
Jan 1 00:01:03: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:04: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:05: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:06: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:07: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:08: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi0/1 with BPDU Guard enabled
"""

_MOCK_LOG_CLEAN = """
Jan 1 00:00:01: %SYS-5-CONFIG_I: Configured from console by admin
Jan 1 00:00:02: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
"""


def get_log_findings_mock(hostname: str, has_loop: bool = True) -> LogFindings:
    """Return synthetic log findings for mock/demo runs."""
    log = _MOCK_LOG_WITH_LOOP if has_loop else _MOCK_LOG_CLEAN
    findings = parse_logs(log)
    if findings.has_findings:
        console.print(f"[bold red]  Loop indicators found in logs on {hostname} (mock)![/bold red]")
    else:
        console.print(f"[green]  No loop indicators in logs on {hostname} (mock).[/green]")
    return findings
