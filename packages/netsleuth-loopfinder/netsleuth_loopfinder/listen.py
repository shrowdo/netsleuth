"""
Passive "listen" mode: no switch login needed.

Plug the laptop into any switch port and listen for a few seconds. Reports:
  - which switch / port you are plugged into (from CDP or LLDP)
  - broadcast and multicast packets per second reaching this port
  - the same broadcast frame arriving over and over (frames going round a loop)
  - spanning-tree BPDUs, topology-change flags and how many root bridges are seen
  - the busiest broadcast senders by MAC address

Needs packet capture: Npcap on Windows (https://npcap.com, tick "WinPcap API
compatible mode"), or root on Linux/macOS.
"""

from __future__ import annotations

import hashlib
import struct
import time
from collections import Counter
from dataclasses import dataclass, field

BCAST = b"\xff\xff\xff\xff\xff\xff"
STP_MAC = bytes.fromhex("0180c2000000")
PVST_MAC = bytes.fromhex("01000ccccccd")
CDP_MAC = bytes.fromhex("01000ccccccc")
LLDP_MACS = {bytes.fromhex("0180c200000e"), bytes.fromhex("0180c2000003"), bytes.fromhex("0180c2000000")}

STORM_PPS = 1000
BUSY_PPS = 200
LOOP_REPEATS = 20


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


@dataclass
class Peer:
    protocol: str
    name: str = ""
    port: str = ""
    ip: str = ""
    platform: str = ""


@dataclass
class ListenStats:
    started: float = 0.0
    ended: float = 0.0
    total: int = 0
    broadcast: int = 0
    multicast: int = 0
    bcast_senders: Counter = field(default_factory=Counter)
    frame_repeats: Counter = field(default_factory=Counter)
    bpdus: int = 0
    tc_bpdus: int = 0
    roots: set = field(default_factory=set)
    bpdu_senders: set = field(default_factory=set)
    peers: dict = field(default_factory=dict)
    per_second: list = field(default_factory=list)

    @property
    def seconds(self) -> float:
        return max(self.ended - self.started, 0.001)

    @property
    def bm_pps(self) -> float:
        return (self.broadcast + self.multicast) / self.seconds

    @property
    def max_repeats(self) -> int:
        return max(self.frame_repeats.values(), default=0)

    # ------------------------------------------------------------------
    def feed(self, frame: bytes) -> None:
        if len(frame) < 14:
            return
        self.total += 1
        dst, src = frame[0:6], frame[6:12]
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        if ethertype == 0x8100 and len(frame) >= 18:  # 802.1Q tag
            ethertype = struct.unpack("!H", frame[16:18])[0]
            offset = 18

        if dst == BCAST:
            self.broadcast += 1
            self.bcast_senders[_mac(src)] += 1
            # Identical broadcast frames repeating = frames circulating a loop.
            self.frame_repeats[hashlib.blake2s(frame, digest_size=8).digest()] += 1
        elif dst[0] & 1:
            self.multicast += 1

        if dst in (STP_MAC, PVST_MAC) and ethertype <= 1500:
            self._bpdu(frame, offset, dst == PVST_MAC)
        if dst == CDP_MAC and ethertype <= 1500:
            self._cdp(frame[offset + 8:])
        if ethertype == 0x88CC and dst in LLDP_MACS:
            self._lldp(frame[offset:])

    def _bpdu(self, frame: bytes, offset: int, snap: bool) -> None:
        body = frame[offset + (8 if snap else 3):]
        if len(body) < 4 or body[0:2] != b"\x00\x00":
            return
        self.bpdus += 1
        bpdu_type = body[3]
        if bpdu_type in (0x00, 0x02) and len(body) >= 35:  # config / RSTP
            flags = body[4]
            if flags & 0x01:
                self.tc_bpdus += 1
            self.roots.add(body[5:13].hex())
            self.bpdu_senders.add(body[17:25].hex())
        elif bpdu_type == 0x80:  # TCN
            self.tc_bpdus += 1

    def _cdp(self, body: bytes) -> None:
        if len(body) < 4:
            return
        peer = Peer("CDP")
        pos = 4
        while pos + 4 <= len(body):
            t, length = struct.unpack("!HH", body[pos:pos + 4])
            if length < 4:
                break
            value = body[pos + 4:pos + length]
            if t == 0x0001:
                peer.name = value.decode(errors="replace")
            elif t == 0x0003:
                peer.port = value.decode(errors="replace")
            elif t == 0x0006:
                peer.platform = value.decode(errors="replace")
            elif t == 0x0002 and len(value) >= 4:
                peer.ip = _cdp_first_ipv4(value) or peer.ip
            pos += length
        if peer.name:
            self.peers[("CDP", peer.name)] = peer

    def _lldp(self, body: bytes) -> None:
        peer = Peer("LLDP")
        chassis = ""
        pos = 0
        while pos + 2 <= len(body):
            header = struct.unpack("!H", body[pos:pos + 2])[0]
            t, length = header >> 9, header & 0x1FF
            value = body[pos + 2:pos + 2 + length]
            if t == 0:
                break
            if t == 1 and value:
                chassis = value[1:].hex(":") if value[0] == 4 else value[1:].decode(errors="replace")
            elif t == 2 and value:
                raw = value[1:]
                peer.port = raw.hex(":") if value[0] == 3 else raw.decode(errors="replace")
            elif t == 4 and not peer.port:
                peer.port = value.decode(errors="replace")
            elif t == 5:
                peer.name = value.decode(errors="replace")
            elif t == 6:
                peer.platform = value.decode(errors="replace").splitlines()[0][:70] if value else ""
            elif t == 8 and len(value) >= 6 and value[1] == 1:
                peer.ip = ".".join(str(b) for b in value[2:6])
            pos += 2 + length
        peer.name = peer.name or chassis
        if peer.name:
            self.peers[("LLDP", peer.name)] = peer

    # ------------------------------------------------------------------
    def verdict(self) -> list[tuple[str, str]]:
        out = []
        if self.bm_pps >= STORM_PPS:
            out.append(("critical", f"Broadcast storm: {self.bm_pps:,.0f} broadcast/multicast packets/s reaching this port"))
        elif self.bm_pps >= BUSY_PPS:
            out.append(("warning", f"Busy: {self.bm_pps:,.0f} broadcast/multicast packets/s (normal is well under 100)"))
        if self.max_repeats >= LOOP_REPEATS:
            out.append(("critical", f"The same broadcast frame arrived {self.max_repeats} times in {self.seconds:.0f}s "
                                    "- frames are going round a loop"))
        if self.tc_bpdus >= 3:
            out.append(("warning", f"{self.tc_bpdus} spanning-tree topology-change BPDUs - STP is reconverging"))
        if len(self.roots) > 1:
            out.append(("warning", f"{len(self.roots)} different STP root bridges seen on one port"))
        if not out:
            out.append(("ok", f"Quiet: {self.bm_pps:,.0f} broadcast/multicast packets/s, no repeating frames"))
        return out


def _cdp_first_ipv4(value: bytes) -> str:
    try:
        count = struct.unpack("!I", value[0:4])[0]
        pos = 4
        for _ in range(count):
            ptype, plen = value[pos], value[pos + 1]
            proto = value[pos + 2:pos + 2 + plen]
            pos += 2 + plen
            alen = struct.unpack("!H", value[pos:pos + 2])[0]
            addr = value[pos + 2:pos + 2 + alen]
            pos += 2 + alen
            if ptype == 1 and proto == b"\xcc" and alen == 4:
                return ".".join(str(b) for b in addr)
    except (IndexError, struct.error):
        pass
    return ""


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

class CaptureUnavailable(RuntimeError):
    pass


def _scapy():
    try:
        import logging
        for name in ("scapy", "scapy.runtime", "scapy.loading"):
            logging.getLogger(name).setLevel(logging.ERROR)
        from scapy.config import conf
        from scapy.sendrecv import sniff
    except Exception as exc:  # pragma: no cover
        raise CaptureUnavailable(f"Packet capture library failed to load: {exc}")
    import platform
    if platform.system() == "Windows" and not conf.use_pcap:
        raise CaptureUnavailable(
            "Npcap is not installed. Download it free from https://npcap.com, install with "
            "'WinPcap API-compatible mode' ticked, then run this again."
        )
    return conf, sniff


def list_interfaces() -> list[tuple[str, str]]:
    conf, _ = _scapy()
    rows = []
    for iface in conf.ifaces.values():
        ip = getattr(iface, "ip", "") or ""
        rows.append((iface.name, f"{iface.description or ''} {ip}".strip()))
    return rows


def capture(seconds: int, iface: str | None = None, on_tick=None) -> tuple[ListenStats, str]:
    conf, sniff = _scapy()
    chosen = iface or conf.iface
    stats = ListenStats(started=time.monotonic())
    end = stats.started + seconds
    last = 0
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        before = stats.broadcast + stats.multicast
        sniff(iface=chosen, timeout=min(1.0, remaining), store=False,
              prn=lambda pkt: stats.feed(bytes(pkt)))
        stats.per_second.append(stats.broadcast + stats.multicast - before)
        last += 1
        if on_tick:
            on_tick(last, stats)
    stats.ended = time.monotonic()
    return stats, str(getattr(chosen, "name", chosen))


def run_listen(seconds: int, iface: str | None, console) -> int:
    """CLI entry for --listen. Returns an exit code."""
    from rich.table import Table
    from rich import box

    if iface == "list":
        try:
            for name, desc in list_interfaces():
                console.print(f"  [cyan]{name}[/cyan]  [dim]{desc}[/dim]")
        except CaptureUnavailable as exc:
            console.print(f"[red]{exc}[/red]")
            return 2
        return 0

    console.rule("[bold blue]Loop Finder - listen mode (no login)[/bold blue]")
    try:
        def tick(sec, s):
            console.print(f"  [dim]{sec:>3}s[/dim]  {s.per_second[-1]:>7,} bcast/mcast pkts   "
                          f"[dim]({s.total:,} frames total)[/dim]")
        console.print(f"[dim]Listening for {seconds}s... (Ctrl+C to stop)[/dim]")
        stats, used = capture(seconds, iface, tick)
    except CaptureUnavailable as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    except PermissionError:
        console.print("[red]Packet capture needs admin/root rights.[/red]")
        return 2
    except Exception as exc:
        console.print(f"[red]Capture failed: {exc}[/red]")
        console.print("[dim]Pick the wired adapter with --iface (see: loop-finder --listen --iface list)[/dim]")
        return 2

    console.print(f"\n[dim]Adapter: {used}[/dim]")
    level_style = {"critical": "bold red", "warning": "yellow", "ok": "green"}
    worst = "ok"
    for level, text in stats.verdict():
        console.print(f"[{level_style[level]}]{'!!' if level == 'critical' else ' *'} {text}[/]")
        if level == "critical" or (level == "warning" and worst == "ok"):
            worst = level

    if stats.peers:
        t = Table(title="You are plugged into", box=box.SIMPLE)
        for col in ("Via", "Switch", "Port", "Mgmt IP", "Platform"):
            t.add_column(col)
        for p in stats.peers.values():
            t.add_row(p.protocol, p.name, p.port, p.ip or "-", p.platform)
        console.print(t)
        ips = [p.ip for p in stats.peers.values() if p.ip]
        if ips:
            console.print(f"[dim]Next: loop-finder {ips[0]} -u <username>   (full scan from this switch)[/dim]")
    else:
        console.print("[dim]No CDP/LLDP heard (they're sent every 30-60s; try --listen 60, "
                      "or the port may have them disabled).[/dim]")

    if stats.bpdus:
        console.print(f"[dim]STP: {stats.bpdus} BPDUs, {stats.tc_bpdus} with topology change, "
                      f"{len(stats.roots)} root bridge(s), {len(stats.bpdu_senders)} sender(s)[/dim]")
    if stats.bcast_senders:
        t = Table(title="Top broadcast senders", box=box.SIMPLE)
        t.add_column("MAC")
        t.add_column("Frames", justify="right")
        for mac, n in stats.bcast_senders.most_common(5):
            t.add_row(mac, f"{n:,}")
        console.print(t)
        console.print("[dim]Look the top MACs up in the switch MAC table (show mac address-table address <mac> "
                      "/ show mac-address <mac>) to find the port they arrive on.[/dim]")
    return 1 if worst == "critical" else 0
