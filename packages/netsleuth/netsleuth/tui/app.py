"""
NetSleuth all-in-one TUI: a home menu listing the tools.

Tools run in-process (their screens are pushed onto this app), so this works
inside the single PyInstaller exe where sys.executable is netsleuth.exe itself.
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, ListItem, ListView, Static

# (name, key, description)
TOOLS = [
    ("Loop Finder", "loopfinder", "Find Layer 2 loops and broadcast storms (SSH to switches)"),
]


def open_tool(app: App, key: str) -> None:
    """Push the first screen of a tool onto *app*."""
    if key == "loopfinder":
        from netsleuth_loopfinder.tui import SetupScreen

        # Escape on its setup screen comes back to this menu.
        app.push_screen(SetupScreen(escape_quits=False))
    else:
        app.notify(f"Unknown tool: {key}", severity="error")


class HomeScreen(Screen):
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("escape", "app.quit", "Quit", show=False),
    ]

    DEFAULT_CSS = """
    HomeScreen #home-title { padding: 1 2 0 2; color: cyan; text-style: bold; }
    HomeScreen #home-subtitle { padding: 0 2 1 2; color: $text-muted; }
    HomeScreen #home-tools { margin: 0 2; border: solid $primary; height: auto; }
    HomeScreen #home-hint { padding: 1 2; color: $text-muted; }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("NetSleuth - Network Engineering Toolkit", id="home-title")
        yield Static("Pick a tool with the arrow keys and press Enter:", id="home-subtitle")
        yield ListView(
            *[ListItem(Label(f"[bold cyan]{name}[/bold cyan]  {desc}"), id=f"home-tool-{key}")
              for name, key, desc in TOOLS],
            id="home-tools",
        )
        yield Static("No switch login? Quit and run: netsleuth lf --listen", id="home-hint")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#home-tools", ListView).focus()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        open_tool(self.app, item_id.removeprefix("home-tool-"))


class NetSleuthApp(App):
    TITLE = "NetSleuth"
    SUB_TITLE = "Network Engineering Toolkit"
    ENABLE_COMMAND_PALETTE = False
    # Used by tool screens when they print CLI hints.
    CLI_NAME = "netsleuth lf"

    def on_mount(self) -> None:
        self.push_screen(HomeScreen())
