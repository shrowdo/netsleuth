"""
Rich CLI output for loop detection results.
"""

import networkx as nx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from loop_finder.graph import get_loop_edges

console = Console()


def print_topology(G: nx.Graph):
    table = Table(title="Discovered Topology", box=box.ROUNDED)
    table.add_column("Device", style="cyan")
    table.add_column("IP", style="white")
    table.add_column("Neighbors", style="green")

    for node, data in G.nodes(data=True):
        neighbors = ", ".join(G.neighbors(node))
        table.add_row(node, data.get("ip", ""), neighbors)

    console.print(table)


def print_loops(G: nx.Graph, loops: list[list[str]]):
    if not loops:
        console.print(Panel(
            "[bold green]No loops detected.[/bold green]\n"
            "The network topology appears to be loop-free.",
            title="Result",
            border_style="green",
        ))
        return

    console.print(Panel(
        f"[bold red]{len(loops)} loop(s) detected![/bold red]",
        title="Result",
        border_style="red",
    ))

    for i, cycle in enumerate(loops, 1):
        edges = get_loop_edges(G, cycle)

        table = Table(title=f"Loop #{i}  ({' -> '.join(cycle + [cycle[0]])})", box=box.SIMPLE_HEAVY)
        table.add_column("From", style="red")
        table.add_column("Local Port", style="yellow")
        table.add_column("Remote Port", style="yellow")
        table.add_column("To", style="red")

        for edge in edges:
            table.add_row(edge["from"], edge["local_port"], edge["remote_port"], edge["to"])

        console.print(table)


def print_summary(device_count: int, loop_count: int):
    console.print(
        f"\n[bold]Summary:[/bold] Scanned [cyan]{device_count}[/cyan] device(s), "
        f"found [{'red' if loop_count else 'green'}]{loop_count}[/{'red' if loop_count else 'green'}] loop(s).\n"
    )
