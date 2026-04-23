import os
import re
import subprocess
import sys

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Log,
    Select,
    Static,
    Switch,
)

TOOLS = [
    ("Loop Finder", "loopfinder", "Discover topology & detect Layer 2 loops"),
]

DEVICE_TYPES = [
    ("Cisco IOS", "cisco_ios"),
    ("Cisco NX-OS", "cisco_nxos"),
    ("Cisco IOS-XE", "cisco_xe"),
    ("Cisco IOS-XR", "cisco_xr"),
    ("Arista EOS", "arista_eos"),
    ("Juniper JunOS", "juniper_junos"),
    ("HP ProCurve", "hp_procurve"),
    ("Aruba", "aruba"),
]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class HomeScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("enter", "select_tool", "Select"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold cyan]NetSleuth[/bold cyan] — Network Engineering Toolkit\n", id="title")
        yield Static("Select a tool:\n", id="subtitle")
        yield ListView(
            *[ListItem(Label(f"[cyan]{name}[/cyan]  {desc}"), id=key) for name, key, desc in TOOLS],
            id="tool-list",
        )
        yield Footer()

    def action_select_tool(self) -> None:
        lv = self.query_one("#tool-list", ListView)
        if lv.highlighted_child is not None:
            self.app.push_screen(lv.highlighted_child.id)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.app.push_screen(event.item.id)


class LoopFinderScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("ctrl+r", "run", "Run"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="lf-layout"):
            with Vertical(id="form"):
                yield Static("[bold cyan]Loop Finder[/bold cyan]", id="lf-title")
                with Horizontal(classes="field-row"):
                    yield Label("Host IP", classes="field-label")
                    yield Input(placeholder="192.168.1.1", id="host")
                with Horizontal(classes="field-row"):
                    yield Label("Username", classes="field-label")
                    yield Input(placeholder="admin", id="username")
                with Horizontal(classes="field-row"):
                    yield Label("Password", classes="field-label")
                    yield Input(placeholder="(hidden)", password=True, id="password")
                with Horizontal(classes="field-row"):
                    yield Label("Device Type", classes="field-label")
                    yield Select(DEVICE_TYPES, value="cisco_ios", id="device_type")
                with Horizontal(classes="field-row"):
                    yield Label("Mock Mode", classes="field-label")
                    yield Switch(id="mock_mode", value=False)
                with Horizontal(classes="field-row", id="topology-row"):
                    yield Label("Topology File", classes="field-label")
                    yield Input(placeholder="topologies/simple_loop.yaml", id="topology")
                with Horizontal(id="btn-row"):
                    yield Button("Run (Ctrl+R)", variant="primary", id="run-btn")
                    yield Button("Clear", id="clear-btn")
            yield Log(id="output", highlight=False)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#topology-row").display = False

    def on_switch_changed(self, event: Switch.Changed) -> None:
        self.query_one("#topology-row").display = event.value

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-btn":
            self.action_run()
        elif event.button.id == "clear-btn":
            self.query_one("#output", Log).clear()

    def action_run(self) -> None:
        log = self.query_one("#output", Log)
        mock = self.query_one("#mock_mode", Switch).value

        if mock:
            topology = self.query_one("#topology", Input).value.strip()
            if not topology:
                topology = "topologies/simple_loop.yaml"
            cmd = [sys.executable, "-m", "netsleuth_loopfinder.entry", "--mock", topology]
        else:
            host = self.query_one("#host", Input).value.strip()
            username = self.query_one("#username", Input).value.strip()
            password = self.query_one("#password", Input).value
            device_type = self.query_one("#device_type", Select).value

            if not host or not username:
                log.write_line("ERROR: Host IP and Username are required.")
                return

            cmd = [sys.executable, "-m", "netsleuth_loopfinder.entry", host, "-u", username]
            if device_type and device_type is not Select.BLANK:
                cmd += ["--device-type", str(device_type)]

        self.run_worker(lambda: self._stream(cmd, password if not mock else ""), thread=True)

    def _stream(self, cmd: list, password: str = "") -> None:
        log = self.query_one("#output", Log)

        def write(line: str) -> None:
            self.app.call_from_thread(log.write_line, line)

        write("-" * 60)
        write("Running...")
        write("-" * 60)

        # Pass password via environment variable to avoid exposing it in the process list.
        env = {**os.environ, "NO_COLOR": "1"}
        if password:
            env["NETSLEUTH_PASSWORD"] = password
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        for line in proc.stdout:
            write(_strip_ansi(line.rstrip()))
        proc.wait()
        write("-" * 60)
        write(f"Done.  Exit code: {proc.returncode}  ({'loops found' if proc.returncode == 1 else 'clean' if proc.returncode == 0 else 'error'})")


class NetSleuthApp(App):
    CSS = """
    #title {
        content-align: center middle;
        padding: 1 2;
        color: cyan;
    }
    #subtitle { padding: 0 2; }
    #tool-list {
        margin: 0 2;
        border: solid $primary;
        height: auto;
    }

    #lf-layout {
        height: 1fr;
    }
    #form {
        height: auto;
        padding: 1 2;
        border-bottom: solid $primary;
    }
    #lf-title {
        padding-bottom: 1;
        color: cyan;
    }
    .field-row {
        height: 3;
        align: left middle;
    }
    .field-label {
        width: 14;
        color: $text-muted;
    }
    .field-row Input, .field-row Select {
        width: 1fr;
    }
    #btn-row {
        padding-top: 1;
        height: 4;
    }
    #btn-row Button {
        margin-right: 1;
    }
    #output {
        height: 1fr;
        border: solid $primary;
        margin: 0 2 1 2;
    }
    """

    SCREENS = {
        "loopfinder": LoopFinderScreen,
    }

    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    TITLE = "NetSleuth"
    SUB_TITLE = "Network Engineering Toolkit"

    def on_mount(self) -> None:
        self.push_screen(HomeScreen())
