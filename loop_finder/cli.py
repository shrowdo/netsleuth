"""
Rich CLI output for loop detection results.
"""

import networkx as nx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from loop_finder.graph import get_loop_edges

console = Console()


def _pluralize(count: int, singular: str, plural: str) -> str:
    """Return the correctly pluralized form for *count* items."""
    return f"{count} {singular if count == 1 else plural}"


def print_topology(G: nx.Graph):
    table = Table(title="Discovered Topology", box=box.ROUNDED)
    table.add_column("Device", style="cyan")
    table.add_column("IP", style="white")
    table.add_column("Neighbors", style="green")

    for node, data in G.nodes(data=True):
        neighbors = ", ".join(G.neighbors(node))
        table.add_row(node, data.get("ip", ""), neighbors)

    console.print(table)


def print_topology_diagram(G: nx.Graph, loops: list[list[str]]):
    """
    Draw a simple ASCII spanning-tree diagram of the network using Rich's Tree
    widget. Edges that are part of a detected loop are labelled in red with
    [LOOP].

    The diagram is rooted at the first node in the graph (or skipped entirely
    when the graph is empty).
    """
    if G.number_of_nodes() == 0:
        return

    # Build a set of canonical loop edges for fast lookup.
    loop_edge_set: set[frozenset] = set()
    for cycle in loops:
        for i in range(len(cycle)):
            a = cycle[i]
            b = cycle[(i + 1) % len(cycle)]
            if G.has_edge(a, b):
                loop_edge_set.add(frozenset((a, b)))

    root_node = next(iter(G.nodes()))

    # Use BFS over the graph to build a spanning tree so we visit every node
    # exactly once, even when the graph has cycles.
    tree = Tree(f"[bold cyan]{root_node}[/bold cyan]")
    visited: set[str] = {root_node}

    def _add_children(parent_label: Tree, parent: str) -> None:
        for neighbor in G.neighbors(parent):
            if neighbor in visited:
                continue
            visited.add(neighbor)

            data = G[parent][neighbor]
            local_port = data.get("local_port", "?")
            remote_port = data.get("remote_port", "?")
            port_label = f"{local_port} -> {remote_port}"

            is_loop = frozenset((parent, neighbor)) in loop_edge_set
            if is_loop:
                label = (
                    f"[bold cyan]{neighbor}[/bold cyan]  "
                    f"[yellow]{port_label}[/yellow]  "
                    "[bold red]\\[LOOP][/bold red]"
                )
            else:
                label = (
                    f"[bold cyan]{neighbor}[/bold cyan]  "
                    f"[yellow]{port_label}[/yellow]"
                )

            child_branch = parent_label.add(label)
            _add_children(child_branch, neighbor)

    _add_children(tree, root_node)

    console.print()
    console.print("[bold]Topology Diagram[/bold]")
    console.print(tree)


def print_loops(G: nx.Graph, loops: list[list[str]]):
    if not loops:
        console.print(Panel(
            "[bold green]No loops detected.[/bold green]\n"
            "The network topology appears to be loop-free.",
            title="Result",
            border_style="green",
        ))
        return

    loop_word = _pluralize(len(loops), "loop", "loops")
    console.print(Panel(
        f"[bold red]{loop_word} detected![/bold red]",
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


def print_remediation(suggestions: list[dict]):
    """
    Print a Rich table of suggested remediations — one row per loop.

    Each suggestion dict must contain the keys produced by
    graph.suggest_remediation(): loop, disable_on, port, reason.
    """
    if not suggestions:
        return

    console.print()
    console.print("[bold]Suggested Remediation[/bold]")

    table = Table(box=box.ROUNDED)
    table.add_column("Loop #", style="bold red", justify="right")
    table.add_column("Action", style="bold yellow")
    table.add_column("Device", style="cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Reason", style="white")

    for s in suggestions:
        table.add_row(
            str(s["loop"]),
            "Disable port",
            s["disable_on"],
            s["port"],
            s["reason"],
        )

    console.print(table)


def print_summary(device_count: int, loop_count: int):
    device_noun = "device" if device_count == 1 else "devices"
    loop_noun = "loop" if loop_count == 1 else "loops"
    color = "red" if loop_count else "green"
    console.print(
        f"\n[bold]Summary:[/bold] Scanned [cyan]{device_count}[/cyan] {device_noun}, "
        f"found [{color}]{loop_count}[/{color}] {loop_noun}.\n"
    )


def print_stp_status(stp_results: list[dict]):
    """
    Print a Rich table summarising whether each detected loop is already
    being handled by Spanning Tree Protocol.

    Each entry in stp_results must contain:
        "loop_index"      -- 1-based int
        "blocked"         -- bool
        "blocking_device" -- str (empty when not blocked)
        "blocking_port"   -- str (empty when not blocked)
    """
    table = Table(title="Phase 3: STP Status", box=box.ROUNDED)
    table.add_column("Loop #", style="cyan", justify="center")
    table.add_column("Blocked by STP?", justify="center")
    table.add_column("Blocking Device", style="magenta")
    table.add_column("Blocking Port", style="white")

    for entry in stp_results:
        loop_num = str(entry.get("loop_index", "?"))
        blocked = entry.get("blocked", False)
        device = entry.get("blocking_device", "")
        port = entry.get("blocking_port", "")

        if blocked:
            status_cell = "[bold green]Yes - STP handling it[/bold green]"
        else:
            status_cell = "[bold red]No - active loop![/bold red]"

        table.add_row(loop_num, status_cell, device, port)

    console.print(table)
