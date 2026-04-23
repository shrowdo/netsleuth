"""
Textual TUI for the standalone loop-finder tool.

Launched automatically when `loop-finder` is run with no arguments.
Three-screen flow:
    SetupScreen      → form (host, creds, device type, fallback creds)
    DiscoveryScreen  → live progress while topology is crawled
    ResultsScreen    → summary, loop table, topology diagram, export
"""

from __future__ import annotations

import io
import json
from typing import Callable

import networkx as nx
from rich.console import Console as RichConsole
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Collapsible,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    Select,
    Static,
    Switch,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

DEVICE_TYPE_OPTIONS: list[tuple[str, str]] = [
    ("Auto-detect", "auto"),
    ("Cisco IOS", "cisco_ios"),
    ("Cisco NX-OS", "cisco_nxos"),
    ("Arista EOS", "arista_eos"),
    ("Juniper JunOS", "juniper_junos"),
    ("HP ProCurve", "hp_procurve"),
    ("Aruba", "aruba"),
    ("Huawei", "huawei"),
]

# ---------------------------------------------------------------------------
# Screen 1: SetupScreen
# ---------------------------------------------------------------------------


class SetupScreen(Screen):
    """Form screen — collect target + credentials before starting discovery."""

    BINDINGS = [
        Binding("q", "quit_app", "Quit"),
        Binding("tab", "focus_next", "Next field", show=False),
        Binding("shift+tab", "focus_previous", "Prev field", show=False),
    ]

    CSS = """
    SetupScreen {
        background: $surface;
    }
    #setup-outer {
        height: 1fr;
        padding: 1 2;
    }
    #setup-title {
        padding-bottom: 1;
        color: cyan;
        text-style: bold;
    }
    .field-row {
        height: 3;
        align: left middle;
        margin-bottom: 0;
    }
    .field-label {
        width: 18;
        color: $text-muted;
        padding-top: 1;
    }
    .field-input {
        width: 1fr;
    }
    #scan-row {
        height: 3;
        align: left middle;
        margin-bottom: 0;
    }
    #scan-btn {
        width: auto;
        margin-left: 18;
    }
    #scan-status {
        margin-left: 1;
        color: $text-muted;
    }
    #scan-select-row {
        height: 3;
        align: left middle;
        margin-bottom: 0;
        display: none;
    }
    #scan-select {
        width: 1fr;
        margin-left: 18;
    }
    #host-error {
        color: red;
        margin-left: 18;
        display: none;
    }
    #user-error {
        color: red;
        margin-left: 18;
        display: none;
    }
    #fallback-collapsible {
        margin-top: 1;
        border: solid $primary;
        padding: 0 1;
    }
    .fallback-row {
        height: 3;
        align: left middle;
    }
    .fb-label {
        width: 12;
        color: $text-muted;
    }
    .fb-input {
        width: 1fr;
        margin-right: 1;
    }
    #start-btn {
        width: 1fr;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="setup-outer"):
            yield Static(
                "[bold cyan]Loop Finder[/bold cyan]  —  Network Loop Detection",
                id="setup-title",
            )

            # Host IP
            with Horizontal(classes="field-row"):
                yield Label("Host IP", classes="field-label")
                yield Input(
                    placeholder="Auto-scan will find it",
                    id="host",
                    classes="field-input",
                )
            # Scan Network button + status
            with Horizontal(id="scan-row"):
                yield Button("Scan Network", id="scan-btn", variant="default")
                yield Static("", id="scan-status")
            # Dropdown when multiple IPs found
            with Horizontal(id="scan-select-row"):
                yield Select([], id="scan-select", classes="field-input")
            yield Label("", id="host-error")

            # Username
            with Horizontal(classes="field-row"):
                yield Label("Username", classes="field-label")
                yield Input(placeholder="admin", id="username", classes="field-input")
            yield Label("", id="user-error")

            # Password
            with Horizontal(classes="field-row"):
                yield Label("Password", classes="field-label")
                yield Input(
                    placeholder="(hidden)",
                    password=True,
                    id="password",
                    classes="field-input",
                )
            # Show password toggle
            with Horizontal(classes="field-row"):
                yield Label("Show Password", classes="field-label")
                yield Switch(id="show-password", value=False)

            # Device type
            with Horizontal(classes="field-row"):
                yield Label("Device Type", classes="field-label")
                yield Select(
                    DEVICE_TYPE_OPTIONS,
                    value="auto",
                    id="device-type",
                    classes="field-input",
                )

            # Fallback credentials (collapsible)
            with Collapsible(title="Fallback Credentials", id="fallback-collapsible"):
                with Horizontal(classes="fallback-row"):
                    yield Label("User 1", classes="fb-label")
                    yield Input(placeholder="username", id="fb-user-1", classes="fb-input")
                    yield Input(
                        placeholder="password",
                        password=True,
                        id="fb-pass-1",
                        classes="fb-input",
                    )
                with Horizontal(classes="fallback-row"):
                    yield Label("User 2", classes="fb-label")
                    yield Input(placeholder="username", id="fb-user-2", classes="fb-input")
                    yield Input(
                        placeholder="password",
                        password=True,
                        id="fb-pass-2",
                        classes="fb-input",
                    )
                with Horizontal(classes="fallback-row"):
                    yield Label("User 3", classes="fb-label")
                    yield Input(placeholder="username", id="fb-user-3", classes="fb-input")
                    yield Input(
                        placeholder="password",
                        password=True,
                        id="fb-pass-3",
                        classes="fb-input",
                    )

            yield Button("Start", id="start-btn", variant="primary")

        yield Footer()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "show-password":
            pw_input = self.query_one("#password", Input)
            pw_input.password = not event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-btn":
            self._do_scan()
        elif event.button.id == "start-btn":
            self._do_start()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "scan-select" and event.value is not Select.BLANK:
            self.query_one("#host", Input).value = str(event.value)

    # ------------------------------------------------------------------
    # Scan logic
    # ------------------------------------------------------------------

    def _do_scan(self) -> None:
        btn = self.query_one("#scan-btn", Button)
        status = self.query_one("#scan-status", Static)
        btn.disabled = True
        status.update("[dim]Scanning...[/dim]")
        # Hide any previous select row
        self.query_one("#scan-select-row").display = False
        self.run_worker(self._scan_worker, thread=True)

    def _scan_worker(self) -> None:
        """Background: run subnet scan and update UI via call_from_thread."""
        try:
            from netsleuth_loopfinder.scan import get_local_subnets, scan_subnet_for_ssh

            subnets = get_local_subnets()
            found: list[str] = []
            for subnet in subnets:
                try:
                    found.extend(scan_subnet_for_ssh(subnet))
                except Exception:
                    pass
        except Exception as exc:
            self.app.call_from_thread(self._scan_done, [], str(exc))
            return
        self.app.call_from_thread(self._scan_done, found, None)

    def _scan_done(self, found: list[str], error: str | None) -> None:
        btn = self.query_one("#scan-btn", Button)
        status = self.query_one("#scan-status", Static)
        btn.disabled = False

        if error:
            status.update(f"[yellow]Scan error: {error}[/yellow]")
            return

        if not found:
            status.update("[yellow]No switches found — enter IP manually[/yellow]")
            return

        if len(found) == 1:
            self.query_one("#host", Input).value = found[0]
            status.update(f"[green]Found: {found[0]}[/green]")
            return

        # Multiple found — show select
        select = self.query_one("#scan-select", Select)
        select.set_options((ip, ip) for ip in found)
        self.query_one("#scan-select-row").display = True
        status.update(f"[cyan]Found {len(found)} hosts — pick one:[/cyan]")

    # ------------------------------------------------------------------
    # Start / validation
    # ------------------------------------------------------------------

    def _do_start(self) -> None:
        host = self.query_one("#host", Input).value.strip()
        username = self.query_one("#username", Input).value.strip()

        host_err = self.query_one("#host-error", Label)
        user_err = self.query_one("#user-error", Label)

        valid = True
        if not host:
            host_err.update("[red]Host IP is required.[/red]")
            host_err.display = True
            valid = False
        else:
            host_err.display = False

        if not username:
            user_err.update("[red]Username is required.[/red]")
            user_err.display = True
            valid = False
        else:
            user_err.display = False

        if not valid:
            return

        password = self.query_one("#password", Input).value
        device_type_val = self.query_one("#device-type", Select).value
        device_type = str(device_type_val) if device_type_val is not Select.BLANK else "auto"

        # Collect fallback creds
        extra_creds: list[dict] = []
        for i in range(1, 4):
            fb_user = self.query_one(f"#fb-user-{i}", Input).value.strip()
            fb_pass = self.query_one(f"#fb-pass-{i}", Input).value
            if fb_user:
                extra_creds.append({"username": fb_user, "password": fb_pass})

        self.app.push_screen(
            DiscoveryScreen(
                host=host,
                username=username,
                password=password,
                device_type=device_type,
                extra_creds=extra_creds,
            )
        )

    def action_quit_app(self) -> None:
        self.app.exit()


# ---------------------------------------------------------------------------
# Screen 2: DiscoveryScreen
# ---------------------------------------------------------------------------


class DiscoveryScreen(Screen):
    """Live discovery progress screen."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    CSS = """
    DiscoveryScreen {
        background: $surface;
    }
    #disc-layout {
        height: 1fr;
        padding: 1 2;
    }
    #disc-title {
        color: cyan;
        text-style: bold;
        padding-bottom: 1;
    }
    #disc-log {
        height: 10;
        border: solid $primary;
        margin-bottom: 1;
    }
    #disc-table {
        height: 1fr;
        border: solid $primary;
    }
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        device_type: str,
        extra_creds: list[dict],
    ) -> None:
        super().__init__()
        self._host = host
        self._username = username
        self._password = password
        self._device_type = device_type
        self._extra_creds = extra_creds

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="disc-layout"):
            yield Static(
                "[bold cyan]Discovering network topology...[/bold cyan]",
                id="disc-title",
            )
            yield Log(id="disc-log", highlight=False)
            yield DataTable(id="disc-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#disc-table", DataTable)
        table.add_columns("Device", "IP", "Neighbors Found", "Status")
        self.run_worker(self._discovery_worker, thread=True)

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------

    def _discovery_worker(self) -> None:
        """Run discovery in a background thread; post updates to the UI."""
        log = self.query_one("#disc-log", Log)

        def _log(msg: str) -> None:
            self.app.call_from_thread(log.write_line, msg)

        def _on_device(hostname: str, ip: str, n_neighbors: int) -> None:
            self.app.call_from_thread(self._add_device_row, hostname, ip, n_neighbors, True)

        def _on_device_failed(ip: str, _ip2: str) -> None:
            self.app.call_from_thread(self._add_device_row, ip, ip, 0, False)

        _log("Starting discovery...")

        try:
            from netsleuth_core.ssh import detect_device_type
            from netsleuth_loopfinder.discovery import discover
            from netsleuth_loopfinder.graph import build_graph, find_loops

            # Resolve device type
            device_type = self._device_type
            if device_type == "auto":
                _log(f"Auto-detecting device type for {self._host}...")
                try:
                    device_type = detect_device_type(
                        ip=self._host,
                        port=22,
                        username=self._username,
                        password=self._password,
                    )
                    _log(f"  Detected: {device_type}")
                except Exception as exc:
                    _log(f"  Detection failed ({exc}), using cisco_ios as fallback")
                    device_type = "cisco_ios"

            creds = {
                "username": self._username,
                "password": self._password,
                "device_type": device_type,
                "port": 22,
            }

            _log(f"Connecting to seed device {self._host}...")

            devices = discover(
                seed_ip=self._host,
                creds=creds,
                max_depth=None,
                use_hint_for_all=False,
                extra_creds=self._extra_creds if self._extra_creds else None,
                on_device_found=_on_device,
                on_device_failed=_on_device_failed,
            )

            _log(f"Discovery complete. {len(devices)} device(s) found.")

            G = build_graph(devices)
            loops = find_loops(G)

            _log(
                f"Loop analysis: {'[red]' + str(len(loops)) + ' loop(s) found[/red]' if loops else '[green]No loops detected[/green]'}"
            )

            self.app.call_from_thread(
                self._push_results, devices, loops, G
            )

        except Exception as exc:
            _log(f"[red]Fatal error: {exc}[/red]")

    def _add_device_row(
        self, hostname: str, ip: str, n_neighbors: int, success: bool
    ) -> None:
        table = self.query_one("#disc-table", DataTable)
        status = "[green]✓ Connected[/green]" if success else "[red]✗ Failed[/red]"
        table.add_row(
            hostname,
            ip,
            str(n_neighbors),
            status,
        )

    def _push_results(self, devices, loops, G) -> None:
        self.app.push_screen(ResultsScreen(devices=devices, loops=loops, G=G))

    def action_cancel(self) -> None:
        self.app.pop_screen()


# ---------------------------------------------------------------------------
# Screen 3: ResultsScreen
# ---------------------------------------------------------------------------


class ResultsScreen(Screen):
    """Display topology, loops, remediation, and export options."""

    BINDINGS = [
        Binding("e", "export_json", "Export JSON"),
        Binding("n", "new_scan", "New Scan"),
        Binding("r", "new_scan", "New Scan", show=False),
        Binding("q", "quit_app", "Quit"),
    ]

    CSS = """
    ResultsScreen {
        background: $surface;
    }
    #results-outer {
        height: 1fr;
        padding: 1 2;
    }
    #results-title {
        padding-bottom: 1;
        text-style: bold;
    }
    #status-banner {
        padding: 0 1;
        margin-bottom: 1;
        border: solid $primary;
    }
    #panels {
        height: 1fr;
    }
    #left-panel {
        width: 1fr;
        height: 1fr;
        padding-right: 1;
        border: solid $primary;
        margin-right: 1;
    }
    #right-panel {
        width: 1fr;
        height: 1fr;
        border: solid $primary;
    }
    .section-header {
        color: cyan;
        text-style: bold;
        padding: 0 1;
    }
    #devices-table {
        height: auto;
        max-height: 12;
        margin: 0 1 1 1;
    }
    #topo-diagram {
        padding: 1;
    }
    .loop-table-wrap {
        height: auto;
        margin: 0 1 1 1;
    }
    .remediation-table-wrap {
        height: auto;
        margin: 0 1 1 1;
    }
    """

    def __init__(
        self,
        devices: dict,
        loops: list,
        G: nx.MultiGraph,
    ) -> None:
        super().__init__()
        self._devices = devices
        self._loops = loops
        self._G = G

    def compose(self) -> ComposeResult:
        from netsleuth_loopfinder.graph import get_loop_edges, suggest_remediation

        loops = self._loops
        devices = self._devices
        G = self._G

        loop_count = len(loops)
        if loop_count == 0:
            status_markup = "[bold green]✓ No loops detected[/bold green]"
        else:
            noun = "loop" if loop_count == 1 else "loops"
            status_markup = f"[bold red]✗ {loop_count} {noun} found[/bold red]"

        suggestions = suggest_remediation(G, loops) if loops else []
        diagram_text = _capture_topology_diagram(G, loops)

        yield Header(show_clock=False)
        with ScrollableContainer(id="results-outer"):
            yield Static(
                "[bold cyan]Loop Finder — Results[/bold cyan]",
                id="results-title",
            )
            yield Static(status_markup, id="status-banner")

            with Horizontal(id="panels"):
                # Left panel — summary + loops
                with VerticalScroll(id="left-panel"):
                    yield Static("Discovered Devices", classes="section-header")
                    yield DataTable(id="devices-table")

                    if loops:
                        yield Static("Detected Loops", classes="section-header")
                        for i, cycle in enumerate(loops, 1):
                            edges = get_loop_edges(G, cycle)
                            yield Static(
                                f"[red]Loop #{i}[/red]  ({' → '.join(cycle + [cycle[0]])})",
                                classes="section-header",
                            )
                            lt = DataTable(classes="loop-table-wrap")
                            lt.add_columns("From", "Local Port", "Remote Port", "To")
                            for edge in edges:
                                lt.add_row(
                                    edge["from"],
                                    edge["local_port"],
                                    edge["remote_port"],
                                    edge["to"],
                                )
                            yield lt

                        yield Static("Remediation", classes="section-header")
                        rt = DataTable(classes="remediation-table-wrap")
                        rt.add_columns("Loop #", "Device", "Port", "Action")
                        for s in suggestions:
                            rt.add_row(
                                str(s["loop"]),
                                s["disable_on"],
                                s["port"],
                                s["reason"],
                            )
                        yield rt

                # Right panel — topology diagram
                with VerticalScroll(id="right-panel"):
                    yield Static("Topology Diagram", classes="section-header")
                    yield Static(diagram_text, id="topo-diagram")

        yield Footer()

    def on_mount(self) -> None:
        # Populate the devices DataTable
        table = self.query_one("#devices-table", DataTable)
        table.add_columns("Device", "IP", "Reachable")
        for hostname, device in self._devices.items():
            reachable = getattr(device, "reachable", True)
            reachable_label = (
                "[green]✓ Yes[/green]" if reachable else "[yellow]✗ No[/yellow]"
            )
            table.add_row(hostname, device.ip or "", reachable_label)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_export_json(self) -> None:
        filename = "loop-finder-results.json"
        results = {
            "devices": {
                h: {"ip": d.ip, "neighbors": [vars(n) for n in d.neighbors]}
                for h, d in self._devices.items()
            },
            "loops": self._loops,
        }
        try:
            with open(filename, "w") as f:
                json.dump(results, f, indent=2)
            self.notify(f"Results exported to {filename}", severity="information")
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")

    def action_new_scan(self) -> None:
        # Pop back to SetupScreen (which is at the bottom of the screen stack)
        self.app.pop_screen()  # pop ResultsScreen
        self.app.pop_screen()  # pop DiscoveryScreen

    def action_quit_app(self) -> None:
        self.app.exit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_topology_diagram(G: nx.MultiGraph, loops: list) -> str:
    """Render the topology tree via Rich and return it as a plain string."""
    if G.number_of_nodes() == 0:
        return "[dim]No devices to display.[/dim]"

    from netsleuth_loopfinder.cli import build_topology_tree

    buf = io.StringIO()
    capture_console = RichConsole(file=buf, highlight=False, width=60)
    capture_console.print(build_topology_tree(G, loops))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class LoopFinderTUI(App):
    """Standalone Textual TUI for the loop-finder tool."""

    TITLE = "Loop Finder"
    SUB_TITLE = "Network Loop Detection"

    CSS = """
    LoopFinderTUI {
        background: $surface;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    def on_mount(self) -> None:
        self.push_screen(SetupScreen())
