"""
Rich CLI output for loop detection results.
"""

import networkx as nx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from netsleuth_loopfinder.graph import get_loop_edges

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
        reachable = data.get("reachable", True)
        node_label = node if reachable else f"[dim]{node} [unreachable][/dim]"
        table.add_row(node_label, data.get("ip", ""), neighbors)

    console.print(table)


def build_topology_tree(G: nx.Graph, loops: list[list[str]]) -> Tree:
    """
    Build a Rich Tree spanning the network graph with loop edges highlighted.
    Returns the Tree object; callers decide how to render it.
    """
    loop_edge_set: set[frozenset] = set()
    for cycle in loops:
        for i in range(len(cycle)):
            a = cycle[i]
            b = cycle[(i + 1) % len(cycle)]
            if G.has_edge(a, b):
                loop_edge_set.add(frozenset((a, b)))

    root_node = next(iter(G.nodes()))
    tree = Tree(f"[bold cyan]{root_node}[/bold cyan]")
    visited: set[str] = {root_node}

    def _add_children(parent_branch: Tree, parent: str) -> None:
        for neighbor in G.neighbors(parent):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            edge_dict = G[parent][neighbor]
            first_key = sorted(edge_dict.keys())[0]
            data = edge_dict[first_key]
            local_port = data.get("local_port", "?")
            remote_port = data.get("remote_port", "?")
            port_label = f"{local_port} -> {remote_port}"
            if len(edge_dict) > 1:
                port_label += f" (+{len(edge_dict) - 1} parallel)"
            is_loop = frozenset((parent, neighbor)) in loop_edge_set
            neighbor_reachable = G.nodes[neighbor].get("reachable", True)
            neighbor_label = neighbor if neighbor_reachable else f"{neighbor} [unreachable]"
            if is_loop:
                label = (
                    f"[bold cyan]{neighbor_label}[/bold cyan]  "
                    f"[yellow]{port_label}[/yellow]  "
                    "[bold red]\\[LOOP][/bold red]"
                )
            else:
                label = (
                    f"[bold cyan]{neighbor_label}[/bold cyan]  "
                    f"[yellow]{port_label}[/yellow]"
                )
            child_branch = parent_branch.add(label)
            _add_children(child_branch, neighbor)

    _add_children(tree, root_node)
    return tree


def print_topology_diagram(G: nx.Graph, loops: list[list[str]]):
    """Print an ASCII spanning-tree diagram with loop edges highlighted."""
    if G.number_of_nodes() == 0:
        return
    console.print()
    console.print("[bold]Topology Diagram[/bold]")
    console.print(build_topology_tree(G, loops))


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
    table.add_column("Recommended Action", style="bold yellow")
    table.add_column("Device", style="cyan")
    table.add_column("Port", style="yellow")
    table.add_column("STP Command", style="dim")
    table.add_column("Reason", style="white")

    for s in suggestions:
        stp_cmd = (
            f"int {s['port']}\n spanning-tree port-priority 240"
            if s["port"] != "?"
            else "N/A"
        )
        table.add_row(
            str(s["loop"]),
            "Configure STP block",
            s["disable_on"],
            s["port"],
            stp_cmd,
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


def print_log_findings(findings) -> None:
    """Print a summary of Phase 0 log analysis findings."""
    from rich.panel import Panel

    if not findings.has_findings:
        console.print(Panel(
            "[bold green]No loop indicators found in switch logs.[/bold green]",
            title="Phase 0: Log Analysis",
            border_style="green",
        ))
        return

    console.print(Panel(
        "[bold red]Loop indicators detected in switch logs![/bold red]",
        title="Phase 0: Log Analysis",
        border_style="red",
    ))

    if findings.mac_flaps:
        t = Table(title="MAC Flapping", box=box.SIMPLE_HEAVY)
        t.add_column("MAC Address", style="yellow")
        t.add_column("VLAN", style="cyan")
        t.add_column("Flapping Between Ports", style="red")
        for f in findings.mac_flaps:
            t.add_row(f["mac"], f["vlan"], "  <->  ".join(f["ports"]))
        console.print(t)

    if findings.storm_shutdowns:
        t = Table(title="Storm Control Events", box=box.SIMPLE_HEAVY)
        t.add_column("Port", style="red")
        t.add_column("Action Taken", style="yellow")
        for f in findings.storm_shutdowns:
            t.add_row(f["port"], f["action"])
        console.print(t)

    if findings.bpdu_violations:
        t = Table(title="BPDU Violations", box=box.SIMPLE_HEAVY)
        t.add_column("Port", style="red")
        t.add_column("Type", style="yellow")
        for f in findings.bpdu_violations:
            t.add_row(f["port"], f["type"])
        console.print(t)

    if findings.tcn_bursts:
        for b in findings.tcn_bursts:
            console.print(f"[bold red]  STP Topology Changes: {b['count']} TCNs detected - {b['note']}[/bold red]")

    if findings.suspect_ports:
        console.print(
            f"\n[bold yellow]Suspect ports from logs:[/bold yellow] "
            + ", ".join(sorted(findings.suspect_ports))
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
