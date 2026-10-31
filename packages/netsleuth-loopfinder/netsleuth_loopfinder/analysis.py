"""
The loop-finder pipeline: collect -> build graph -> evaluate -> findings and
recommended actions. Used by both the CLI and the TUIs.

    result = run_scan(ScanOptions(seed_ip="10.0.0.1", username="admin", password="..."), log=print)
    result = run_mock("topologies/simple_loop.yaml")
    result = run_replay("netsleuth-runs/2026-10-31_1012")
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

import networkx as nx

from netsleuth_core.models import Device
from netsleuth_core.ports import canonical_port

from netsleuth_loopfinder.collect import ReplayConn, collect_device, family, load_records
from netsleuth_loopfinder.counters import display_port
from netsleuth_loopfinder.graph import build_graph, evaluate_loop, find_loops, suggest_remediation
from netsleuth_loopfinder.logparse import LogFindings

LogFn = Callable[[str], None]

# Inbound broadcast+multicast packets/sec on one port.
HOT_EDGE_PPS = 1000      # an edge port (PC, printer, floor box) should be far below this
WARM_EDGE_PPS = 300
HOT_UPLINK_PPS = 5000    # uplinks carry everyone's broadcasts, so a higher bar
RECENT_TCN_SECONDS = 120


@dataclass
class ScanOptions:
    seed_ip: str
    username: str
    password: str = ""
    device_type: str = "auto"
    port: int = 22
    key_file: str | None = None
    extra_creds: list[dict] | None = None
    max_depth: int | None = None
    timeout_seconds: int | None = None
    workers: int = 6
    collect_counters: bool = True
    # Folder to save raw command output in (None = don't save).
    raw_dir: str | None = None


@dataclass
class LoopReport:
    index: int
    nodes: list[str]
    edges: list[dict]
    status: str            # "blocked" | "active" | "unknown"
    blocked_at: list[tuple]
    note: str = ""

    @property
    def path(self) -> str:
        if len(self.nodes) == 1:
            return f"{self.nodes[0]} -> itself"
        return " -> ".join(self.nodes + [self.nodes[0]])


@dataclass
class Finding:
    severity: str          # "critical" | "warning" | "info"
    title: str
    detail: str = ""
    device: str = ""
    port: str = ""


@dataclass
class Action:
    text: str
    device: str = ""
    commands: list[str] = field(default_factory=list)
    undo: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    devices: dict[str, Device]
    graph: nx.MultiGraph
    loops: list[LoopReport]
    findings: list[Finding]
    hot_ports: list[dict]
    actions: list[Action]
    raw_dir: str | None = None
    seed: str = ""

    @property
    def active_loops(self) -> list[LoopReport]:
        return [l for l in self.loops if l.status == "active"]

    @property
    def switches(self) -> list[Device]:
        return [d for d in self.devices.values()]

    @property
    def verdict(self) -> tuple[str, str]:
        """(level, one-line summary) where level is "critical", "warning" or "ok"."""
        crit = [f for f in self.findings if f.severity == "critical"]
        warn = [f for f in self.findings if f.severity == "warning"]
        if self.active_loops:
            n = len(self.active_loops)
            return "critical", f"{n} ACTIVE LOOP{'S' if n > 1 else ''} - STP is not blocking {'them' if n > 1 else 'it'}"
        if crit:
            return "critical", crit[0].title
        if warn:
            return "warning", f"No active loop between managed switches, but {len(warn)} warning(s) to check"
        return "ok", "No loop or broadcast storm detected"

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "verdict": dict(zip(("level", "summary"), self.verdict)),
            "devices": {
                name: {
                    "ip": d.ip,
                    "alt_ips": d.alt_ips,
                    "reachable": d.reachable,
                    "device_type": d.device_type,
                    "error": d.error,
                    "stp_mode": d.stp_mode,
                    "neighbors": [asdict(n) for n in d.neighbors],
                    "lags": d.lags,
                    "stp": d.stp,
                    "tcn": d.tcn,
                    "disabled_ports": d.disabled_ports,
                    "port_rates": {k: round(v, 1) for k, v in d.port_rates.items()},
                    "log_findings": asdict(d.log_findings) if isinstance(d.log_findings, LogFindings) else None,
                }
                for name, d in self.devices.items()
            },
            "loops": [
                {"index": l.index, "nodes": l.nodes, "status": l.status, "note": l.note,
                 "blocked_at": [list(b) for b in l.blocked_at],
                 "edges": [{k: v for k, v in e.items() if k != "members"} for e in l.edges]}
                for l in self.loops
            ],
            "findings": [asdict(f) for f in self.findings],
            "hot_ports": self.hot_ports,
            "actions": [asdict(a) for a in self.actions],
        }

    def write_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------

def default_raw_dir() -> str:
    return os.path.join("netsleuth-runs", time.strftime("%Y-%m-%d_%H%M%S"))


def run_scan(
    opts: ScanOptions,
    log: LogFn = lambda _m: None,
    on_device_found: Callable[[str, str, int], None] | None = None,
    on_device_failed: Callable[[str, str], None] | None = None,
) -> AnalysisResult:
    from netsleuth_loopfinder.discovery import discover

    creds = {
        "username": opts.username,
        "password": opts.password,
        "device_type": opts.device_type or "auto",
        "port": opts.port,
        "key_file": opts.key_file,
    }
    devices = discover(
        seed_ip=opts.seed_ip,
        creds=creds,
        max_depth=opts.max_depth,
        extra_creds=opts.extra_creds,
        timeout_seconds=opts.timeout_seconds,
        on_device_found=on_device_found,
        on_device_failed=on_device_failed,
        log=log,
        workers=opts.workers,
        collect_counters=opts.collect_counters,
        raw_dir=opts.raw_dir,
    )
    result = analyse(devices, seed=opts.seed_ip, raw_dir=opts.raw_dir)
    if opts.raw_dir:
        try:
            result.write_json(os.path.join(opts.raw_dir, "results.json"))
        except Exception:
            pass
    return result


def run_replay(raw_dir: str, log: LogFn = lambda _m: None) -> AnalysisResult:
    """Re-run the analysis from a saved run folder without touching the network."""
    devices: dict[str, Device] = {}
    records = load_records(raw_dir)
    if not records:
        raise FileNotFoundError(f"No saved switch records (*.json) in {raw_dir}")
    for rec in records:
        if rec.get("error") and not rec.get("commands"):
            devices[rec["ip"]] = Device(hostname=rec["ip"], ip=rec["ip"], reachable=False, error=rec["error"])
            continue
        device = collect_device(ReplayConn(rec), rec["ip"], rec.get("device_type", ""), True)
        name = device.hostname
        if name in devices:
            name = f"{name} ({device.ip})"
            device.hostname = name
        devices[name] = device
        log(f"[green]  Replayed {name} ({rec['ip']}): {len(device.neighbors)} neighbour(s)[/green]")
    seed = records[0]["ip"]
    return analyse(devices, seed=seed, raw_dir=raw_dir)


def run_mock(topology_path: str, log: LogFn = lambda _m: None) -> AnalysisResult:
    from netsleuth_loopfinder.mock import discover_mock

    devices = discover_mock(topology_path, log=log)
    seed = next(iter(devices.values())).ip if devices else ""
    return analyse(devices, seed=seed)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _neighbors_on(device: Device, port: str) -> list:
    """Neighbours on *port* or on any member of LAG *port*."""
    cp = canonical_port(port)
    members = {m for m, lag in device.lags.items() if canonical_port(lag) == cp}
    return [n for n in device.neighbors
            if canonical_port(n.local_port) == cp or canonical_port(n.local_port) in members]


def _is_uplink(device: Device, port: str) -> bool:
    if canonical_port(port) in device.lags or any(canonical_port(l) == canonical_port(port) for l in device.lags.values()):
        return True
    me = device.hostname.lower()
    return any(
        n.role in ("switch", "unknown") and n.hostname.lower() != me and n.ip not in (device.ip, *device.alt_ips)
        for n in _neighbors_on(device, port)
    )


def shutdown_commands(device_type: str, port: str) -> tuple[list[str], list[str]]:
    """Commands to shut a port (not saved, so a reboot undoes them) and to re-enable it."""
    fam = family(device_type)
    if fam == "procurve":
        return (["configure", f"interface {port} disable"],
                ["configure", f"interface {port} enable"])
    if fam == "juniper":
        return (["configure", f"set interfaces {port} disable", "commit"],
                ["configure", f"delete interfaces {port} disable", "commit"])
    if fam == "huawei":
        return (["system-view", f"interface {port}", "shutdown", "return"],
                ["system-view", f"interface {port}", "undo shutdown", "return"])
    return (["configure terminal", f"interface {port}", "shutdown", "end"],
            ["configure terminal", f"interface {port}", "no shutdown", "end"])


def _enable_stp_commands(device_type: str) -> list[str]:
    fam = family(device_type)
    if fam == "procurve":
        return ["configure", "spanning-tree"]
    if fam == "aoscx":
        return ["configure", "spanning-tree"]
    if fam in ("cisco", "nxos"):
        return ["configure terminal", "spanning-tree mode rapid-pvst", "(and check for 'no spanning-tree vlan X')"]
    return []


def analyse(devices: dict[str, Device], seed: str = "", raw_dir: str | None = None) -> AnalysisResult:
    G = build_graph(devices)
    cycles = find_loops(G)
    findings: list[Finding] = []
    actions: list[Action] = []

    # --- Loops -----------------------------------------------------------
    loops: list[LoopReport] = []
    for i, cycle in enumerate(cycles, 1):
        ev = evaluate_loop(G, devices, cycle)
        loops.append(LoopReport(i, cycle, ev["edges"], ev["status"], ev["blocked_at"], ev["note"]))

    active = [l for l in loops if l.status == "active"]
    suggestions = {s["loop"]: s for s in suggest_remediation(G, [l.nodes for l in active])}
    for n, loop in enumerate(active, 1):
        s = suggestions.get(n)
        what = "a cable looped back into the same switch" if len(loop.nodes) == 1 else "a forwarding loop"
        findings.append(Finding("critical", f"Loop #{loop.index} is ACTIVE: {loop.path}",
                                f"STP is not blocking any port on this path - {what}."))
        if s and s["port"] != "?":
            dt = devices[s["disable_on"]].device_type if s["disable_on"] in devices else ""
            cmds, undo = shutdown_commands(dt, s["port"])
            actions.append(Action(
                f"Break loop #{loop.index}: shut {s['port']} on {s['disable_on']}. {s['reason']} "
                "Then find out why STP isn't blocking it (STP off, BPDU filter, or an unmanaged "
                "switch dropping BPDUs).",
                s["disable_on"], cmds, undo,
            ))

    unknown = [l for l in loops if l.status == "unknown"]
    for loop in unknown:
        findings.append(Finding("warning", f"Loop #{loop.index} STP state unknown: {loop.path}", loop.note))
    blocked = [l for l in loops if l.status == "blocked"]
    if blocked:
        findings.append(Finding(
            "info", f"{len(blocked)} redundant path(s) correctly blocked by STP",
            "; ".join(f"#{l.index} at {', '.join(f'{d} {p}' for d, p, _s in l.blocked_at[:2])}" for l in blocked),
        ))

    # --- Switch health ---------------------------------------------------
    for name, d in devices.items():
        if not d.reachable:
            findings.append(Finding("warning", f"Couldn't log into {name}", d.error, name))
            continue
        if d.stp_mode == "disabled":
            findings.append(Finding("warning", f"Spanning tree is OFF on {name}",
                                    "Any loop through this switch will not be blocked.", name))
            cmds = _enable_stp_commands(d.device_type)
            if cmds:
                actions.append(Action(f"Turn spanning tree back on on {name} once things are stable.", name, cmds))
        for dp in d.disabled_ports:
            findings.append(Finding("warning", f"{name} has shut {dp['port']} itself ({dp['reason']})",
                                    "Whatever is plugged in there caused a loop or storm.", name, dp["port"]))

        lf = d.log_findings
        if isinstance(lf, LogFindings) and lf.has_findings:
            for flap in lf.mac_flaps[:5]:
                ports = " <-> ".join(flap["ports"])
                findings.append(Finding("critical", f"MAC flapping on {name}: {ports}",
                                        f"{flap['mac']} in VLAN {flap['vlan']} keeps moving between these "
                                        "ports - a loop is behind one of them.", name, flap["ports"][0]))
            if len(lf.mac_flaps) > 5:
                findings.append(Finding("critical", f"{len(lf.mac_flaps) - 5} more MAC flaps on {name}", "", name))
            for det in lf.loop_detections:
                findings.append(Finding("critical", f"Loop detected on {name} {det['port']}",
                                        f"Reported by the switch ({det['source']}).", name, det["port"]))
            for st in lf.storm_shutdowns:
                findings.append(Finding("warning", f"Storm control on {name} {st['port']}",
                                        st["action"], name, st["port"]))
            for bp in lf.bpdu_violations:
                findings.append(Finding("warning", f"{bp['type']} on {name} {bp['port']}",
                                        "BPDUs arriving on an edge port: a switch has been plugged in there.",
                                        name, bp["port"]))
            for burst in lf.tcn_bursts:
                findings.append(Finding("warning", f"STP topology change burst on {name}",
                                        f"{burst['count']} topology changes in the log.", name))

        for t in d.tcn:
            if t.get("age_s") is not None and t["age_s"] <= RECENT_TCN_SECONDS and t["count"] >= 10:
                src = t.get("from_port", "")
                detail = f"{t['count']} changes, last {t['age_s']}s ago"
                port = ""
                if src:
                    port = src
                    nbrs = [n.hostname for n in _neighbors_on(d, src) if n.role in ("switch", "unknown")]
                    if nbrs:
                        detail += f", from {src} (towards {', '.join(nbrs)}) - check that switch next"
                    else:
                        detail += f", from EDGE port {src} - likely source"
                findings.append(Finding("critical" if src and not _is_uplink(d, src) else "warning",
                                        f"STP is churning on {name} ({t['instance']})", detail, name, port))
                break  # one per switch is enough

        # Several devices on one port = something unmanaged in between.
        by_port: dict[str, list] = {}
        for n in d.neighbors:
            by_port.setdefault(canonical_port(n.local_port), []).append(n)
        for nbrs in by_port.values():
            names = sorted({n.hostname for n in nbrs})
            if len(names) >= 2 and canonical_port(nbrs[0].local_port) not in d.lags:
                findings.append(Finding(
                    "warning" if len(names) >= 3 or any(n.role == "switch" for n in nbrs) else "info",
                    f"{len(names)} devices seen on {name} {nbrs[0].local_port}",
                    "An unmanaged switch or hub is probably plugged in there: " + ", ".join(names[:6]),
                    name, nbrs[0].local_port,
                ))

    # --- Broadcast rates -------------------------------------------------
    hot_ports: list[dict] = []
    for name, d in devices.items():
        for port, rate in d.port_rates.items():
            if rate < 50:
                continue
            uplink = _is_uplink(d, port)
            nbrs = sorted({n.hostname for n in _neighbors_on(d, port)})
            hot_ports.append({
                "device": name, "port": display_port(port), "rate": round(rate, 1),
                "kind": d.rate_kind, "uplink": uplink, "neighbors": nbrs,
                "device_type": d.device_type,
            })
    hot_ports.sort(key=lambda h: h["rate"], reverse=True)
    in_active_loop = {
        (node, canonical_port(port))
        for loop in active for e in loop.edges
        for node, port in ((e["from"], e["local_port"]), (e["to"], e["remote_port"]))
    }
    for h in hot_ports:
        if not h["uplink"] and h["rate"] >= HOT_EDGE_PPS:
            findings.append(Finding("critical", f"Broadcast storm entering {h['device']} {h['port']}",
                                    f"{h['rate']:.0f} broadcast/multicast packets/s inbound on an edge port.",
                                    h["device"], h["port"]))
            if (h["device"], canonical_port(h["port"])) in in_active_loop:
                continue  # breaking the loop already covers this port
            cmds, undo = shutdown_commands(h["device_type"], h["port"])
            actions.append(Action(
                f"Shut edge port {h['port']} on {h['device']} ({h['rate']:.0f} pkt/s inbound) and check "
                "whether the network recovers. Then trace the cable: it often leads to a looped "
                "desk switch or a cable plugged into two wall ports.",
                h["device"], cmds, undo,
            ))
        elif not h["uplink"] and h["rate"] >= WARM_EDGE_PPS:
            findings.append(Finding("warning", f"High broadcast rate on {h['device']} {h['port']}",
                                    f"{h['rate']:.0f} pkt/s inbound on an edge port.", h["device"], h["port"]))
        elif h["uplink"] and h["rate"] >= HOT_UPLINK_PPS:
            findings.append(Finding("warning", f"Very high broadcast rate on uplink {h['device']} {h['port']}",
                                    f"{h['rate']:.0f} pkt/s inbound - the storm is coming from "
                                    f"{', '.join(h['neighbors']) or 'that direction'}.", h["device"], h["port"]))

    # --- Follow-up actions ----------------------------------------------
    flap_findings = [f for f in findings if f.title.startswith("MAC flapping")]
    named_flap_ports: set[tuple[str, str]] = set()
    if not active:
        for name, d in devices.items():
            lf = d.log_findings
            if not (d.reachable and isinstance(lf, LogFindings)):
                continue
            for flap in lf.mac_flaps:
                edge = [p for p in flap["ports"] if not _is_uplink(d, p)]
                if len(edge) == 1 and (name, edge[0]) not in named_flap_ports:
                    named_flap_ports.add((name, edge[0]))
                    cmds, undo = shutdown_commands(d.device_type, edge[0])
                    actions.append(Action(
                        f"MAC addresses are flapping between {' and '.join(flap['ports'])} on {name}. "
                        f"{edge[0]} is the non-uplink side, so the loop is behind it: shut it and "
                        "check whether the flapping stops, then trace that cable.",
                        name, cmds, undo,
                    ))
    if flap_findings and not active and not named_flap_ports:
        actions.append(Action(
            "MAC flapping means traffic is looping. For each flapping pair, the port that is NOT an "
            "uplink leads to the loop; shut it (or unplug it) and watch whether the flapping stops.",
        ))
    if any(not d.reachable for d in devices.values()):
        actions.append(Action(
            "Some switches couldn't be reached over SSH. During a storm their CPU may be overloaded; "
            "try again after shutting the suspect port, or use the console cable.",
        ))
    if not active and not any(f.severity == "critical" for f in findings):
        actions.append(Action(
            "No loop found between managed switches. If the network is still down, the loop may be "
            "entirely inside one unmanaged switch or a cable between two wall ports on the same "
            "switch. Check the broadcast-rate table and unplug/shut edge ports area by area.",
        ))

    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order.get(f.severity, 3))
    return AnalysisResult(devices, G, loops, findings, hot_ports, actions, raw_dir, seed)
