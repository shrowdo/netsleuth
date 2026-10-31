"""
Collect everything loop-finder needs from one switch over a single SSH session:
neighbours, STP state, topology-change history, link aggregation, logs,
self-disabled ports and broadcast rates.

Every command and its output is recorded so a run can be saved and replayed
offline (``--replay``) to re-analyse or debug parsing without the network.
"""

import json
import os
import re
import time
from collections.abc import Callable

from netsleuth_core.models import Device
from netsleuth_core.ports import canonical_port
from netsleuth_core.ssh import get_hostname, run

from netsleuth_loopfinder import counters, neighbors as nb, stp as stp_mod
from netsleuth_loopfinder.logparse import parse_logs

# Minimum gap between the two counter samples.
SAMPLE_SECONDS = 5.0


def family(device_type: str) -> str:
    dt = device_type or ""
    if dt.startswith("cisco_nxos"):
        return "nxos"
    if dt.startswith("cisco") or dt.startswith("arista"):
        return "cisco"
    if dt.startswith(("hp_procurve", "aruba_procurve", "aruba_osswitch", "aruba_os")):
        return "procurve"
    if dt.startswith("aruba_aoscx"):
        return "aoscx"
    if dt.startswith("juniper"):
        return "juniper"
    if dt.startswith("huawei"):
        return "huawei"
    return "generic"


class RecordingConn:
    """Wraps a Netmiko connection and records every command's output."""

    def __init__(self, conn):
        self._conn = conn
        self.device_type = getattr(conn, "device_type", "")
        self.commands: list[dict] = []

    def send_command(self, command: str, **kwargs) -> str:
        started = time.monotonic()
        output = self._conn.send_command(command, **kwargs)
        self.commands.append({
            "command": command,
            "output": output if isinstance(output, str) else "",
            "t": round(started, 3),
        })
        return output

    def find_prompt(self) -> str:
        prompt = self._conn.find_prompt()
        self.commands.append({"command": "__prompt__", "output": prompt, "t": round(time.monotonic(), 3)})
        return prompt

    def disconnect(self) -> None:
        try:
            self._conn.disconnect()
        except Exception:
            pass


class ReplayConn:
    """Plays back a recorded session. Repeated commands return outputs in order."""

    def __init__(self, record: dict):
        self.device_type = record.get("device_type", "")
        self._queue: dict[str, list[dict]] = {}
        for item in record.get("commands", []):
            self._queue.setdefault(item["command"], []).append(item)
        self._clock = 0.0
        self.commands: list[dict] = []

    def _next(self, command: str) -> str:
        items = self._queue.get(command, [])
        if not items:
            return ""
        item = items.pop(0) if len(items) > 1 else items[0]
        self._clock = item.get("t", self._clock)
        return item.get("output", "")

    def send_command(self, command: str, **_kwargs) -> str:
        return self._next(command)

    def find_prompt(self) -> str:
        return self._next("__prompt__")

    def monotonic(self) -> float:
        return self._clock

    def disconnect(self) -> None:
        pass


def _clock(conn) -> float:
    return conn.monotonic() if isinstance(conn, ReplayConn) else time.monotonic()


def _sleep(conn, seconds: float) -> None:
    if seconds > 0 and not isinstance(conn, ReplayConn):
        time.sleep(seconds)


# ---------------------------------------------------------------------------
# Per-family command sets
# ---------------------------------------------------------------------------

def _neighbors(conn, fam: str) -> list:
    if fam in ("cisco", "nxos"):
        found = nb.parse_cdp_detail(run(conn, "show cdp neighbors detail"))
        lldp = nb.parse_lldp_detail(run(conn, "show lldp neighbors detail"))
        # Add LLDP-only neighbours (non-Cisco kit) on ports CDP didn't cover.
        cdp_ports = {canonical_port(n.local_port) for n in found}
        found += [n for n in lldp if canonical_port(n.local_port) not in cdp_ports]
        return found
    if fam == "procurve":
        table = run(conn, "show lldp info remote-device")
        ports = nb.parse_procurve_lldp_ports(table)
        found = []
        if ports:
            found = nb.parse_procurve_lldp_detail(
                run(conn, f"show lldp info remote-device {','.join(ports)}")
            )
        cdp = nb.parse_procurve_cdp_detail(run(conn, "show cdp neighbors detail"))
        lldp_ports = {canonical_port(n.local_port) for n in found}
        found += [n for n in cdp if canonical_port(n.local_port) not in lldp_ports]
        return found
    if fam == "aoscx":
        found = nb.parse_aoscx_lldp_detail(run(conn, "show lldp neighbor-info detail"))
        if not found:
            found = nb.parse_aoscx_lldp_table(run(conn, "show lldp neighbor-info"))
            for n in found:
                detail = nb.parse_aoscx_lldp_detail(run(conn, f"show lldp neighbor-info {n.local_port}"))
                if detail:
                    n.ip, n.capabilities, n.platform = detail[0].ip, detail[0].capabilities, detail[0].platform
                    n.device_type_hint, n.role = detail[0].device_type_hint, detail[0].role
        return found
    if fam == "huawei":
        return nb.parse_huawei_lldp_detail(run(conn, "display lldp neighbor"))
    return nb.parse_lldp_detail(run(conn, "show lldp neighbors detail"))


def _stp(conn, fam: str, device: Device) -> None:
    if fam == "huawei":
        output = run(conn, "display stp brief")
    elif fam == "juniper":
        output = run(conn, "show spanning-tree interface")
    else:
        output = run(conn, "show spanning-tree")
    device.stp, device.stp_mode = stp_mod.parse_stp(output, device.device_type)

    if fam == "cisco":
        detail = run(conn, "show spanning-tree detail | include ieee|occur|from|is exec")
        device.tcn = stp_mod.parse_cisco_tcn(detail)
    elif fam == "nxos":
        device.tcn = stp_mod.parse_cisco_tcn(run(conn, "show spanning-tree detail"))
    elif fam in ("procurve", "aoscx"):
        device.tcn = stp_mod.parse_procurve_tcn(output)


def _lags(conn, fam: str) -> dict[str, str]:
    if fam == "cisco":
        out = run(conn, "show etherchannel summary") or run(conn, "show port-channel summary")
        return stp_mod.parse_cisco_lags(out)
    if fam == "nxos":
        return stp_mod.parse_cisco_lags(run(conn, "show port-channel summary"))
    if fam == "procurve":
        return stp_mod.parse_procurve_trunks(run(conn, "show trunks"))
    if fam == "aoscx":
        return stp_mod.parse_aoscx_lags(run(conn, "show lacp interfaces"))
    return {}


def _logs(conn, fam: str) -> str:
    if fam == "huawei":
        return run(conn, "display logbuffer", 90)
    if fam == "juniper":
        return run(conn, "show log messages | last 500", 90)
    if fam == "procurve":
        return run(conn, "show logging -r", 90) or run(conn, "show logging", 90)
    return run(conn, "show logging", 90)


def _disabled_ports(conn, fam: str) -> list[dict]:
    found = []
    if fam in ("cisco", "nxos"):
        out = run(conn, "show interfaces status err-disabled")
        for m in re.finditer(r"^(\S+\d)\s+.*?err-disabled\s+(\S+)", out, re.M):
            found.append({"port": m.group(1), "reason": m.group(2)})
    elif fam == "procurve":
        out = run(conn, "show loop-protect")
        for m in re.finditer(r"^\s*(\S+)\s*\|\s*Yes\s+Yes\s+(\d+)", out, re.M):
            found.append({"port": m.group(1), "reason": f"loop-protect ({m.group(2)} loops)"})
    elif fam == "aoscx":
        out = run(conn, "show loop-protect")
        for block in re.split(r"(?=^Interface\s+\S+)", out, flags=re.M):
            port_m = re.match(r"Interface\s+(\S+)", block)
            if port_m and re.search(r"Loop[- ]detected\s*:\s*Yes", block, re.I):
                found.append({"port": port_m.group(1), "reason": "loop-protect"})
    return found


def _counter_sample(conn, fam: str) -> tuple[dict, float]:
    if fam == "cisco":
        return counters.parse_cisco_counters(run(conn, "show interfaces counters")), _clock(conn)
    if fam == "nxos":
        return counters.parse_cisco_counters(run(conn, "show interface counters")), _clock(conn)
    if fam == "aoscx":
        return counters.parse_aoscx_counters(run(conn, "show interface", 90)), _clock(conn)
    return {}, _clock(conn)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def collect_device(
    conn,
    ip: str,
    device_type: str,
    collect_counters: bool = True,
    log: Callable[[str], None] = lambda _m: None,
) -> Device:
    """Run every collection step on an open (or replayed) connection."""
    fam = family(device_type)
    hostname = get_hostname(conn) or ip
    device = Device(hostname=hostname, ip=ip, device_type=device_type)

    sample1: dict = {}
    t1 = 0.0
    if collect_counters and fam in ("cisco", "nxos", "aoscx"):
        sample1, t1 = _counter_sample(conn, fam)

    device.neighbors = _neighbors(conn, fam)
    _stp(conn, fam, device)
    device.lags = _lags(conn, fam)
    device.log_findings = parse_logs(_logs(conn, fam))
    device.disabled_ports = _disabled_ports(conn, fam)

    if collect_counters:
        if fam == "procurve":
            up_ports = counters.parse_procurve_port_list(run(conn, "show interfaces brief"))
            if up_ports:
                device.port_rates = counters.parse_procurve_rates(
                    run(conn, f"show interfaces {','.join(up_ports)}", 90)
                )
                device.rate_kind = "5-min avg"
        elif sample1:
            _sleep(conn, SAMPLE_SECONDS - (_clock(conn) - t1))
            sample2, t2 = _counter_sample(conn, fam)
            device.port_rates = counters.rates_from_samples(sample1, sample2, t2 - t1)
            device.rate_kind = f"{t2 - t1:.0f}s sample"
    return device


def save_record(raw_dir: str, ip: str, device_type: str, conn: RecordingConn, error: str = "") -> None:
    os.makedirs(raw_dir, exist_ok=True)
    record = {"ip": ip, "device_type": device_type, "error": error, "commands": conn.commands}
    safe = re.sub(r"[^\w.\-]", "_", ip)
    with open(os.path.join(raw_dir, f"{safe}.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1)
    # Plain-text copy that's easy to read or paste into a ticket.
    with open(os.path.join(raw_dir, f"{safe}.txt"), "w", encoding="utf-8") as fh:
        for item in conn.commands:
            fh.write(f"===== {item['command']} =====\n{item['output']}\n\n")


def load_records(raw_dir: str) -> list[dict]:
    records = []
    for name in sorted(os.listdir(raw_dir)):
        if name.endswith(".json") and name != "results.json":
            with open(os.path.join(raw_dir, name), encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and "commands" in data:
                records.append(data)
    return records
