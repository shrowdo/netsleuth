import sys


def main():
    if len(sys.argv) < 2:
        # No subcommand — launch the TUI
        from netsleuth.tui.app import NetSleuthApp
        NetSleuthApp().run()
        return

    subcommand = sys.argv[1]

    if subcommand in ("loopfinder", "loop-finder", "lf"):
        # Strip the subcommand, pass remaining args to loopfinder
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        from netsleuth_loopfinder.entry import main as loopfinder_main
        loopfinder_main()
    elif subcommand in ("--help", "-h", "help"):
        _print_help()
    else:
        print(f"Unknown tool: {subcommand}")
        _print_help()
        sys.exit(1)


def _print_help():
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    console.print(Panel("[bold cyan]NetSleuth[/bold cyan] — Network Engineering Toolkit", expand=False))
    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool", style="cyan")
    table.add_column("Alias")
    table.add_column("Description")
    table.add_row("loopfinder", "lf", "Discover network topology and detect Layer 2 loops")
    console.print(table)
    console.print("\nRun [bold]netsleuth[/bold] with no arguments to launch the interactive TUI.")
    console.print("Run [bold]netsleuth <tool> --help[/bold] for tool-specific help.")


if __name__ == "__main__":
    main()
