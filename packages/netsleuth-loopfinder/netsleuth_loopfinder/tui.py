"""
Textual TUI for the loop-finder tool.

    SetupScreen    -> form (switch IP, login, options, demo mode)
    RunningScreen  -> live log + table of switches while the scan runs
    ResultsScreen  -> verdict, what to do, findings, busy ports, loops, topology

The screens are self-contained (their CSS is in DEFAULT_CSS, IDs are prefixed
"lf-") so the all-in-one NetSleuth app pushes the same SetupScreen in-process:

    app.push_screen(SetupScreen(escape_quits=False))

Background work runs in daemon threads, so quitting never waits for a slow
SSH timeout. Everything shown on screen is plain ASCII where possible so it
works in old conhost as well as Windows Terminal.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import traceback
from pathlib import Path
from typing import Callable

from rich import box
from rich.console import Group
from rich.markup import escape
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
)

DEVICE_TYPE_OPTIONS: list[tuple[str, str]] = [
    ("Auto-detect", "auto"),
    ("Cisco IOS / IOS-XE", "cisco_ios"),
    ("Cisco NX-OS", "cisco_nxos"),
    ("Arista EOS", "arista_eos"),
    ("HP ProCurve / Aruba OS-S", "hp_procurve"),
    ("Aruba AOS-CX", "aruba_aoscx"),
    ("Juniper JunOS", "juniper_junos"),
    ("Huawei", "huawei"),
]

DEMO_TOPOLOGY = "topologies/school_storm.yaml"

_VERDICT_LABEL = {"critical": "PROBLEM FOUND", "warning": "CHECK", "ok": "ALL CLEAR"}
_SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "dim"}
_SEV_TAG = {"critical": "!!!", "warning": "!", "info": "i"}
_STATE_STYLE = {"BLK": "green", "PART": "yellow", "FWD": "white"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def demo_topology_path() -> str:
    """The demo topology: cwd, PyInstaller bundle, or the repo checkout."""
    from netsleuth_loopfinder.entry import _resolve_path

    path = _resolve_path(DEMO_TOPOLOGY)
    if os.path.exists(path):
        return path
    for parent in Path(__file__).resolve().parents:
        candidate = parent / DEMO_TOPOLOGY
        if candidate.exists():
            return str(candidate)
    return path


def _markup(msg) -> Text:
    """Rich markup -> Text, falling back to plain text if the markup is broken."""
    if isinstance(msg, Text):
        return msg
    msg = str(msg)
    try:
        return Text.from_markup(msg)
    except Exception:
        return Text(msg)


def _start_thread(target: Callable[[], None], name: str) -> threading.Thread:
    # Daemon thread (not a Textual worker) so quitting never blocks on an SSH timeout.
    t = threading.Thread(target=target, name=name, daemon=True)
    t.start()
    return t


def _cli_name(app) -> str:
    """How the engineer runs the CLI from this exe ("loop-finder" or "netsleuth lf")."""
    return getattr(app, "CLI_NAME", "loop-finder")


def _valid_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


# A scan job: (log, on_device_found, on_device_failed) -> AnalysisResult
Job = Callable[[Callable[[str], None], Callable, Callable], object]


# ---------------------------------------------------------------------------
# Screen 1: setup
# ---------------------------------------------------------------------------

class SetupScreen(Screen):
    """Collect the seed switch and login, then start the scan."""

    AUTO_FOCUS = "#lf-host"

    BINDINGS = [
        Binding("escape", "back", "Back / Quit"),
        Binding("ctrl+r", "start", "Start"),
        Binding("f5", "start", "Start", show=False),
    ]

    DEFAULT_CSS = """
    SetupScreen #lf-setup { padding: 0 1; }
    SetupScreen #lf-setup-title { color: cyan; text-style: bold; height: 1; margin-bottom: 1; }
    SetupScreen .lf-row { height: 1; margin-bottom: 1; }
    SetupScreen .lf-label { width: 14; color: $text-muted; }
    SetupScreen .lf-input { width: 1fr; }
    SetupScreen #lf-scan-btn { width: 16; margin-left: 1; }
    SetupScreen #lf-show-pw { width: 10; margin-left: 1; }
    SetupScreen #lf-port-label { width: 6; margin-left: 2; color: $text-muted; }
    SetupScreen #lf-port { width: 8; }
    SetupScreen #lf-scan-status { height: auto; margin-left: 14; color: $text-muted; }
    SetupScreen #lf-scan-select { width: 1fr; }
    SetupScreen #lf-scan-pick { display: none; }
    SetupScreen .lf-check { height: 1; margin-left: 14; }
    SetupScreen #lf-fallback { margin: 0 0 1 0; padding: 0; }
    SetupScreen .lf-fb-row { height: 1; margin-bottom: 1; }
    SetupScreen .lf-fb-label { width: 8; color: $text-muted; }
    SetupScreen .lf-fb-input { width: 1fr; margin-right: 1; }
    SetupScreen #lf-start { width: 30; margin-left: 14; }
    SetupScreen #lf-error { color: red; text-style: bold; height: auto; margin-left: 14; }
    SetupScreen #lf-hint { color: $text-muted; height: auto; margin-top: 1; }
    """

    def __init__(self, escape_quits: bool = True) -> None:
        super().__init__()
        # Standalone app: Escape quits. Inside NetSleuth: Escape goes back to the menu.
        self.escape_quits = escape_quits
        self._scanning = False

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="lf-setup"):
            yield Static("Loop Finder - find the loop / broadcast storm", id="lf-setup-title")
            with Horizontal(classes="lf-row"):
                yield Label("Switch IP", classes="lf-label")
                yield Input(placeholder="e.g. 10.0.0.1 (core switch)", id="lf-host",
                            classes="lf-input", compact=True)
                yield Button("Scan network", id="lf-scan-btn", compact=True)
            with Horizontal(classes="lf-row", id="lf-scan-pick"):
                yield Label("Found", classes="lf-label")
                yield Select([], id="lf-scan-select", prompt="Pick a host", compact=True)
            yield Static("", id="lf-scan-status")
            with Horizontal(classes="lf-row"):
                yield Label("Username", classes="lf-label")
                yield Input(placeholder="admin", id="lf-username", classes="lf-input", compact=True)
            with Horizontal(classes="lf-row"):
                yield Label("Password", classes="lf-label")
                yield Input(placeholder="(hidden)", password=True, id="lf-password",
                            classes="lf-input", compact=True)
                yield Checkbox("Show", id="lf-show-pw", compact=True)
            with Horizontal(classes="lf-row"):
                yield Label("Switch type", classes="lf-label")
                yield Select(DEVICE_TYPE_OPTIONS, value="auto", allow_blank=False,
                             id="lf-device-type", classes="lf-input", compact=True)
                yield Label("Port", id="lf-port-label")
                yield Input("22", id="lf-port", restrict=r"[0-9]*", max_length=5, compact=True)
            with Collapsible(title="Fallback logins (optional, tried if the first fails)",
                             id="lf-fallback", collapsed=True):
                for i in range(1, 4):
                    with Horizontal(classes="lf-fb-row"):
                        yield Label(f"Login {i}", classes="lf-fb-label")
                        yield Input(placeholder="username", id=f"lf-fb-user-{i}",
                                    classes="lf-fb-input", compact=True)
                        yield Input(placeholder="password", password=True, id=f"lf-fb-pass-{i}",
                                    classes="lf-fb-input", compact=True)
            yield Checkbox("Measure broadcast rates (adds ~5s per switch)", value=True,
                           id="lf-counters", classes="lf-check", compact=True)
            yield Checkbox("Demo (mock) mode - no switches needed", value=False,
                           id="lf-demo", classes="lf-check", compact=True)
            yield Static("", id="lf-error")
            yield Button("Start scan (Ctrl+R)", variant="primary", id="lf-start", compact=True)
            yield Static(f"No login? Quit and run: {_cli_name(self.app)} --listen", id="lf-hint")
        yield Footer()

    # -- events ------------------------------------------------------------

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "lf-show-pw":
            self.query_one("#lf-password", Input).password = not event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "lf-scan-btn":
            event.stop()
            self.action_scan_network()
        elif event.button.id == "lf-start":
            event.stop()
            self.action_start()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "lf-scan-select" and isinstance(event.value, str):
            self.query_one("#lf-host", Input).value = event.value

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        nxt = {"lf-host": "#lf-username", "lf-username": "#lf-password"}.get(event.input.id or "")
        if nxt:
            self.query_one(nxt, Input).focus()
        else:
            # Enter on the password, port or a fallback login starts the scan.
            self.action_start()

    def action_back(self) -> None:
        if self.escape_quits:
            self.app.exit()
        else:
            self.app.pop_screen()

    # -- network scan --------------------------------------------------------

    def action_scan_network(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self.query_one("#lf-scan-btn", Button).disabled = True
        self.query_one("#lf-scan-status", Static).update("Looking for this laptop's subnets...")
        _start_thread(self._scan_thread, "lf-ssh-scan")

    def _ui(self, fn, *args) -> None:
        """Run fn on the UI thread; ignore errors if the app/screen has gone."""
        try:
            self.app.call_from_thread(fn, *args)
        except Exception:
            pass

    def _scan_thread(self) -> None:
        found: list[dict] = []
        error = None
        try:
            from netsleuth_loopfinder.scan import get_local_subnets, scan_subnet_for_ssh

            subnets = get_local_subnets()
            if not subnets:
                error = "No local subnet found - is the cable plugged in and does the laptop have an IP?"
            for subnet in subnets:
                self._ui(self._scan_status, f"Scanning {subnet} for SSH (port 22)...")
                try:
                    found.extend(scan_subnet_for_ssh(subnet, with_banner=True))
                except Exception as exc:  # one bad subnet shouldn't stop the rest
                    error = f"{subnet}: {exc}"
        except Exception as exc:
            error = str(exc)
        self._ui(self._scan_done, found, error)

    def _scan_status(self, text: str) -> None:
        self.query_one("#lf-scan-status", Static).update(text)

    def _scan_done(self, found: list[dict], error: str | None) -> None:
        self._scanning = False
        self.query_one("#lf-scan-btn", Button).disabled = False
        status = self.query_one("#lf-scan-status", Static)
        if not found:
            msg = error or "No SSH hosts found - type the switch IP."
            status.update(Text(msg, style="yellow"))
            return
        options = []
        for h in found:
            banner = (h.get("banner") or "").replace("\n", " ")[:40]
            options.append((f"{h['ip']:<15}  {banner}", h["ip"]))
        select = self.query_one("#lf-scan-select", Select)
        select.set_options(options)
        self.query_one("#lf-scan-pick").display = True
        if len(found) == 1:
            select.value = found[0]["ip"]
            self.query_one("#lf-host", Input).value = found[0]["ip"]
        status.update(Text(f"Found {len(found)} SSH host(s). Banners often name the vendor.",
                           style="green"))

    # -- start ---------------------------------------------------------------

    def _error(self, text: str) -> None:
        self.query_one("#lf-error", Static).update(text)

    def action_start(self) -> None:
        self._error("")
        if self.query_one("#lf-demo", Checkbox).value:
            path = demo_topology_path()

            def job(log, _found, _failed):
                from netsleuth_loopfinder.analysis import run_mock
                log(f"[yellow]Demo mode: {escape(path)}[/yellow]")
                return run_mock(path, log=log)

            self.app.push_screen(RunningScreen(job, "Demo (mock) scan", live=False))
            return

        host = self.query_one("#lf-host", Input).value.strip()
        username = self.query_one("#lf-username", Input).value.strip()
        port_text = self.query_one("#lf-port", Input).value.strip() or "22"
        problems = []
        if not host:
            problems.append("Enter the switch IP (or use Scan network).")
        elif not _valid_ipv4(host):
            problems.append(f"'{host}' is not an IPv4 address (e.g. 10.0.0.1).")
        if not username:
            problems.append("Enter the SSH username.")
        port = int(port_text) if port_text.isdigit() else 0
        if not 1 <= port <= 65535:
            problems.append("SSH port must be 1-65535.")
        if problems:
            self._error("\n".join(problems))
            self.query_one("#lf-host" if (not host or not _valid_ipv4(host))
                           else "#lf-username" if not username else "#lf-port", Input).focus()
            return

        extra = []
        for i in range(1, 4):
            u = self.query_one(f"#lf-fb-user-{i}", Input).value.strip()
            if u:
                extra.append({"username": u, "password": self.query_one(f"#lf-fb-pass-{i}", Input).value})
        dtype = self.query_one("#lf-device-type", Select).value
        from netsleuth_loopfinder.analysis import ScanOptions, default_raw_dir

        opts = ScanOptions(
            seed_ip=host,
            username=username,
            password=self.query_one("#lf-password", Input).value,
            device_type=dtype if isinstance(dtype, str) else "auto",
            port=port,
            extra_creds=extra or None,
            collect_counters=self.query_one("#lf-counters", Checkbox).value,
            raw_dir=default_raw_dir(),
        )

        def job(log, found, failed):
            from netsleuth_loopfinder.analysis import run_scan
            log(f"[cyan]Starting from {opts.seed_ip} as {escape(opts.username)}"
                f" (type: {opts.device_type}, port {opts.port})[/cyan]")
            if not opts.collect_counters:
                log("[dim]Broadcast-rate measurement is off.[/dim]")
            return run_scan(opts, log=log, on_device_found=found, on_device_failed=failed)

        self.app.push_screen(RunningScreen(job, f"Scanning from {host}", live=True))


# ---------------------------------------------------------------------------
# Screen 2: running
# ---------------------------------------------------------------------------

class RunningScreen(Screen):
    """Live log and switch table while the scan runs. Escape cancels."""

    BINDINGS = [Binding("escape", "cancel", "Cancel / Back")]

    DEFAULT_CSS = """
    RunningScreen #lf-run-title { height: 1; padding: 0 1; color: cyan; text-style: bold; }
    RunningScreen #lf-run-log { height: 2fr; border: solid $primary; }
    RunningScreen #lf-run-table { height: 1fr; border: solid $primary; }
    """

    def __init__(self, job: Job, title: str, live: bool = True) -> None:
        super().__init__()
        self._job = job
        self._title = title
        self._live = live          # live scan: no reachable switch = failure
        self.cancelled = False
        self.done = False
        self.error: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(f"{self._title} ... (Esc to cancel)", id="lf-run-title")
        yield RichLog(id="lf-run-log", markup=True, wrap=True, highlight=False, max_lines=5000)
        yield DataTable(id="lf-run-table", cursor_type="none", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self._log_widget = self.query_one("#lf-run-log", RichLog)
        self._table = self.query_one("#lf-run-table", DataTable)
        self._table.add_column("Switch", key="name")
        self._table.add_column("IP", key="ip")
        self._table.add_column("Status", key="status")
        _start_thread(self._run, "lf-scan")

    # -- worker side (background thread) ------------------------------------

    def _ui(self, fn, *args) -> None:
        if self.cancelled:
            return
        try:
            self.app.call_from_thread(fn, *args)
        except Exception:
            pass

    def _run(self) -> None:
        def log(msg) -> None:
            self._ui(self._write, _markup(msg))

        def found(hostname, ip, n_neighbors) -> None:
            self._ui(self._set_row, str(ip), str(hostname), Text(f"OK ({n_neighbors} neighbours)", style="green"))

        def failed(ip, reason) -> None:
            self._ui(self._set_row, str(ip), "?", Text(f"FAILED: {reason}"[:80], style="red"))

        try:
            result = self._job(log, found, failed)
        except Exception as exc:
            tb = traceback.format_exc()
            self._ui(self._failed, f"{type(exc).__name__}: {exc}", tb)
            return
        self._ui(self._finished, result)

    # -- UI side --------------------------------------------------------------

    def _write(self, text: Text) -> None:
        self._log_widget.write(text)

    def _set_row(self, ip: str, name: str, status: Text) -> None:
        try:
            self._table.update_cell(ip, "status", status)
            if name != "?":
                self._table.update_cell(ip, "name", name)
        except Exception:
            self._table.add_row(name, ip, status, key=ip)

    def _set_title(self, text: str, style: str) -> None:
        self.query_one("#lf-run-title", Static).update(Text(text, style=style))

    def _failed(self, message: str, tb: str = "") -> None:
        self.done = True
        self.error = message
        self._write(Text(f"ERROR: {message}", style="bold red"))
        if tb:
            self._write(Text(tb, style="dim"))
        self._set_title("Scan failed - read the log above, then Esc to go back", "bold red")

    def _finished(self, result) -> None:
        if self.cancelled:
            return
        self.done = True
        devices = getattr(result, "devices", {}) or {}
        if self._live and not any(d.reachable for d in devices.values()):
            for d in devices.values():
                self._write(Text(f"{d.ip}: {d.error}", style="red"))
            self._failed("Couldn't log into any switch. Check the IP, that this laptop can "
                         "reach it (ping), the username/password and the switch type.")
            return
        results = ResultsScreen(result)
        if self.app.screen is self:
            self.app.switch_screen(results)
        else:
            self.app.push_screen(results)

    def action_cancel(self) -> None:
        # The thread can't be killed; the flag stops it touching the UI later.
        self.cancelled = True
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Screen 3: results
# ---------------------------------------------------------------------------

def _actions_renderable(result):
    if not result.actions:
        return Text("Nothing to do.", style="dim")
    out = Text()
    for i, a in enumerate(result.actions, 1):
        out.append(f"{i}. ", style="bold cyan")
        out.append(a.text + "\n")
        if a.commands:
            out.append(f"   On {a.device}:\n", style="dim")
            for cmd in a.commands:
                out.append(f"     {cmd}\n", style="bold green")
            if a.undo:
                out.append("   To undo (not saved, a reboot also undoes it):\n", style="dim")
                for cmd in a.undo:
                    out.append(f"     {cmd}\n", style="dim")
        out.append("\n")
    out.rstrip()
    return out


def _findings_renderable(result):
    if not result.findings:
        return Text("No findings.", style="green")
    t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
    t.add_column("Sev", width=4, no_wrap=True)
    t.add_column("Finding", ratio=1, overflow="fold")
    t.add_column("Detail", ratio=1, overflow="fold", style="dim")
    for f in result.findings:
        style = _SEV_STYLE.get(f.severity, "")
        t.add_row(Text(_SEV_TAG.get(f.severity, "?"), style=style), Text(f.title, style=style),
                  Text(f.detail or ""))
    return t


def _hot_ports_renderable(result, limit: int = 12):
    if not result.hot_ports:
        return Text("No busy ports measured (or measurement was off).", style="dim")
    t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
    t.add_column("Switch", style="cyan", overflow="fold")
    t.add_column("Port", style="yellow", no_wrap=True)
    t.add_column("Pkts/s", justify="right", no_wrap=True)
    t.add_column("Type", no_wrap=True)
    t.add_column("Connected to", overflow="fold")
    for h in result.hot_ports[:limit]:
        hot = not h.get("uplink") and h.get("rate", 0) >= 1000
        rate = Text(f"{h.get('rate', 0):,.0f}", style="bold red" if hot else "")
        kind = Text("uplink") if h.get("uplink") else Text("EDGE" if hot else "edge",
                                                           style="bold red" if hot else "")
        t.add_row(str(h.get("device", "")), str(h.get("port", "")), rate, kind,
                  ", ".join(h.get("neighbors") or []) or "-")
    note = Text("Uplinks carry everyone's broadcasts, so high numbers there are expected in a storm. "
                "A busy EDGE port is where a storm is entering.", style="dim")
    return Group(t, note)


def _state(s: str) -> Text:
    return Text(s or "?", style=_STATE_STYLE.get(s, "dim"))


def _loops_renderable(result):
    if not result.loops:
        return Text("No redundant paths between switches.", style="green")
    parts = []
    for loop in result.loops:
        status = {
            "active": ("ACTIVE - forwarding (this is the loop)", "bold red"),
            "blocked": ("blocked by STP (normal)", "green"),
            "unknown": ("STP state unknown", "yellow"),
        }.get(loop.status, (loop.status, ""))
        head = Text()
        head.append(f"Loop #{loop.index}: ", style="bold")
        head.append(loop.path + "  ")
        head.append(status[0], style=status[1])
        parts.append(head)
        t = Table(box=box.SIMPLE, expand=True, show_edge=False, pad_edge=False)
        for col in ("From", "Port", "STP", "To", "Port", "STP"):
            t.add_column(col, overflow="fold")
        for e in loop.edges:
            members = e.get("members") or {}
            lp, rp = str(e.get("local_port", "?")), str(e.get("remote_port", "?"))
            if members.get(e.get("from")):
                lp += f" ({', '.join(members[e['from']])})"
            if members.get(e.get("to")):
                rp += f" ({', '.join(members[e['to']])})"
            t.add_row(Text(str(e.get("from", "")), style="cyan"), lp, _state(e.get("from_state", "")),
                      Text(str(e.get("to", "")), style="cyan"), rp, _state(e.get("to_state", "")))
        parts.append(t)
        if loop.note:
            parts.append(Text(f"  {loop.note}", style="dim"))
    return Group(*parts)


def _topology_renderable(result):
    G = result.graph
    if G is None or G.number_of_nodes() == 0:
        return Text("No switches to show.", style="dim")
    from netsleuth_loopfinder.cli import build_topology_tree

    seed_name = next((n for n, d in result.devices.items() if d.ip == result.seed), None)
    return build_topology_tree(G, [l.nodes for l in result.loops], seed_name)


class ResultsScreen(Screen):
    """Verdict first, then what to do, then the evidence."""

    BINDINGS = [
        Binding("e", "export", "Export JSON"),
        Binding("n", "new_scan", "New scan"),
        Binding("escape", "new_scan", "Back", show=False),
        Binding("q", "quit_app", "Quit"),
    ]

    DEFAULT_CSS = """
    ResultsScreen #lf-res { padding: 0 1; }
    ResultsScreen #lf-verdict { padding: 1 2; margin-bottom: 1; text-style: bold; }
    ResultsScreen #lf-verdict.lf-critical { background: #b00000; color: white; }
    ResultsScreen #lf-verdict.lf-warning { background: #b08800; color: black; }
    ResultsScreen #lf-verdict.lf-ok { background: #007a00; color: white; }
    ResultsScreen .lf-h { color: cyan; text-style: bold; margin-top: 1; }
    ResultsScreen #lf-footer-note { color: $text-muted; margin-top: 1; }
    """

    def __init__(self, result) -> None:
        super().__init__()
        self.result = result

    def compose(self) -> ComposeResult:
        r = self.result
        level, text = r.verdict
        reachable = sum(1 for d in r.devices.values() if d.reachable)
        banner = Text()
        banner.append(f"{_VERDICT_LABEL.get(level, level.upper())}: {text}\n")
        banner.append(f"{reachable}/{len(r.devices)} switch(es) checked, "
                      f"{len(r.loops)} redundant path(s), {len(r.active_loops)} active loop(s)")

        yield Header()
        with VerticalScroll(id="lf-res"):
            yield Static(banner, id="lf-verdict", classes=f"lf-{level}")
            yield Static("What to do", classes="lf-h")
            yield Static(_actions_renderable(r), id="lf-actions")
            yield Static("Findings", classes="lf-h")
            yield Static(_findings_renderable(r), id="lf-findings")
            yield Static("Busiest ports (inbound broadcast/multicast)", classes="lf-h")
            yield Static(_hot_ports_renderable(r), id="lf-hot")
            yield Static("Loops / redundant paths", classes="lf-h")
            yield Static(_loops_renderable(r), id="lf-loops")
            yield Static("Topology", classes="lf-h")
            yield Static(_topology_renderable(r), id="lf-topology")
            yield Static(self._footer_note(), id="lf-footer-note")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#lf-res", VerticalScroll).focus()

    def _footer_note(self) -> Text:
        raw = self.result.raw_dir
        if raw:
            return Text(f"Raw switch output saved in: {os.path.abspath(raw)}\n"
                        f"Re-analyse offline later:  {_cli_name(self.app)} --replay \"{raw}\"\n"
                        "Keys: e = export JSON, n = new scan, q = quit")
        return Text("Raw output not saved (demo mode).\nKeys: e = export JSON, n = new scan, q = quit")

    def action_export(self) -> None:
        folder = self.result.raw_dir or os.getcwd()
        path = os.path.abspath(os.path.join(folder, "results.json"))
        try:
            os.makedirs(folder, exist_ok=True)
            self.result.write_json(path)
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error", timeout=10)
            return
        self.last_export = path
        self.notify(f"Saved {path}", timeout=10)

    def action_new_scan(self) -> None:
        # The SetupScreen (with the typed host/username) sits directly underneath.
        self.app.pop_screen()

    def action_quit_app(self) -> None:
        self.app.exit()


# ---------------------------------------------------------------------------
# Standalone app
# ---------------------------------------------------------------------------

class LoopFinderTUI(App):
    """Standalone Textual TUI for the loop-finder tool."""

    TITLE = "Loop Finder"
    SUB_TITLE = "Network loop / broadcast storm finder"
    ENABLE_COMMAND_PALETTE = False
    CLI_NAME = "loop-finder"

    def on_mount(self) -> None:
        self.push_screen(SetupScreen(escape_quits=True))
