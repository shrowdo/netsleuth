from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, ListView, ListItem, Label
from textual.screen import Screen
from textual.binding import Binding

TOOLS = [
    ("Loop Finder", "loopfinder", "Discover topology & detect Layer 2 loops"),
]


class HomeScreen(Screen):
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("enter", "select_tool", "Select"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("[bold cyan]NetSleuth[/bold cyan] — Network Engineering Toolkit\n", id="title")
        yield Static("Select a tool to run:\n", id="subtitle")
        yield ListView(
            *[ListItem(Label(f"[cyan]{name}[/cyan]  {desc}"), id=key) for name, key, desc in TOOLS],
            id="tool-list",
        )
        yield Footer()

    def action_select_tool(self) -> None:
        list_view = self.query_one("#tool-list", ListView)
        if list_view.highlighted_child is not None:
            tool_id = list_view.highlighted_child.id
            self.app.push_screen(tool_id)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self.app.push_screen(event.item.id)


class LoopFinderScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "[bold]Loop Finder[/bold]\n\n"
            "This tool is best used from the CLI for full output.\n\n"
            "Run: [cyan]netsleuth loopfinder <ip> -u <username>[/cyan]\n"
            "  or: [cyan]loop-finder <ip> -u <username>[/cyan] (standalone)\n\n"
            "Press [bold]Escape[/bold] to go back.",
            id="loopfinder-info",
        )
        yield Footer()


class NetSleuthApp(App):
    CSS = """
    #title {
        content-align: center middle;
        padding: 1 2;
        color: cyan;
    }
    #subtitle {
        padding: 0 2;
    }
    #tool-list {
        margin: 0 2;
        border: solid $primary;
    }
    #loopfinder-info {
        padding: 2 4;
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
