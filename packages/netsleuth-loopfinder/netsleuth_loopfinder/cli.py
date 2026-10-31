"""
Rich CLI output for loop-finder results, ordered for use mid-outage:
verdict and actions first, details after.
"""

import networkx as nx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from netsleuth_loopfinder.graph import get_loop_edges

console = Console()

_SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "dim"}
_STATE_STYLE = {"BLK": "green", "PART": "yellow", "FWD": "white", "": "dim"}


def _pluralize(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _state(s: str) -> str:
    label = s or "?"
    return f"[{_STATE_STYLE.get(s, 'white')}]{label}[/]"


# ---------------------------------------------------------------------------
# Result sections
# ---------------------------------------------------------------------------

def print_verdict(result) -> None:
    level, text = result.verdict
    style = {"critical": "red", "warning": "yellow", "ok": "green"}[level]
    icon = {"critical": "PROBLEM FOUND", "warning": "CHECK", "ok": "ALL CLEAR"}[level]
    reachable = sum(1 for d in result.devices.values() if d.reachable)
    console.print(Panel(
        f"[bold {style}]{text}[/bold {style}]\n"
        f"[dim]{reachable}/{len(result.devices)} switch(es) checked, "
        f"{_pluralize(len(result.loops), 'redundant path', 'redundant paths')}, "
        f"{len(result.active_loops)} active[/dim]",
        title=f"[bold {style}]{icon}[/bold {style}]",
        border_style=style,
    ))


def print_actions(result) -> None:
    if not result.actions:
        return
    console.print("\n[bold]What to do[/bold]")
    for i, action in enumerate(result.actions, 1):
        console.print(f" [bold cyan]{i}.[/bold cyan] {action.text}")
        if action.commands:
            console.print(f"    [dim]On {action.device}:[/dim]")
            for cmd in action.commands:
                console.print(f"      [green]{cmd}[/green]")
            if action.undo:
                console.print(f"    [dim]To undo: {' / '.join(action.undo)}  (not saved - a reboot also undoes it)[/dim]")


def print_findings(result) -> None:
    findings = [f for f in result.findings]
    if not findings:
        return
    table = Table(title="Findings", box=box.SIMPLE_HEAVY, show_lines=False, expand=False)
    table.add_column("", width=4)
    table.add_column("Finding", overflow="fold")
    table.add_column("Detail", overflow="fold", style="dim")
    for f in findings:
        tag = {"critical": "[bold red]!!![/]", "warning": "[yellow]![/]", "info": "[dim]i[/]"}[f.severity]
        table.add_row(tag, f"[{_SEV_STYLE[f.severity]}]{f.title}[/]", f.detail)
    console.print(table)


def print_hot_ports(result, limit: int = 12) -> None:
    if not result.hot_ports:
        return
    table = Table(title="Busiest ports by inbound broadcast/multicast", box=box.SIMPLE_HEAVY)
    table.add_column("Switch", style="cyan")
    table.add_column("Port", style="yellow")
    table.add_column("Pkts/s", justify="right")
    table.add_column("Type")
    table.add_column("Connected to", overflow="fold")
    for h in result.hot_ports[:limit]:
        hot = not h["uplink"] and h["rate"] >= 1000
        rate = f"[bold red]{h['rate']:,.0f}[/]" if hot else f"{h['rate']:,.0f}"
        kind = "uplink" if h["uplink"] else ("[bold red]EDGE[/]" if hot else "edge")
        table.add_row(h["device"], h["port"], rate, kind, ", ".join(h["neighbors"]) or "-")
    console.print(table)
    console.print("[dim]Uplinks carry everyone's broadcasts, so high numbers there are expected in a storm. "
                  "A busy EDGE port is where a storm is entering.[/dim]")


def print_loop_reports(result) -> None:
    if not result.loops:
        console.print("[green]No redundant paths between switches.[/green]")
        return
    for loop in result.loops:
        status = {
            "active": "[bold red]ACTIVE - forwarding[/]",
            "blocked": "[green]blocked by STP (normal)[/]",
            "unknown": "[yellow]STP state unknown[/]",
        }[loop.status]
        table = Table(title=f"Loop #{loop.index}: {loop.path}  -  {status}", box=box.SIMPLE, title_justify="left")
        table.add_column("From", style="cyan")
        table.add_column("Port")
        table.add_column("STP")
        table.add_column("To", style="cyan")
        table.add_column("Port")
        table.add_column("STP")
        for e in loop.edges:
            members = e.get("members", {})
            lp, rp = e["local_port"], e["remote_port"]
            if members.get(e["from"]):
                lp += f" ({', '.join(members[e['from']])})"
            if members.get(e["to"]):
                rp += f" ({', '.join(members[e['to']])})"
            table.add_row(e["from"], lp, _state(e.get("from_state", "")),
                          e["to"], rp, _state(e.get("to_state", "")))
        console.print(table)
        if loop.note:
            console.print(f"  [dim]{loop.note}[/dim]")


def print_topology(G: nx.Graph, show_endpoints: bool = False):
    table = Table(title="Switches", box=box.ROUNDED)
    table.add_column("Device", style="cyan")
    table.add_column("IP", style="white")
    table.add_column("Neighbours", style="green", overflow="fold")
    for node, data in G.nodes(data=True):
        if data.get("kind") == "endpoint" and not show_endpoints:
            continue
        neighbors = sorted({
            n for n in G.neighbors(node)
            if n != node and (show_endpoints or G.nodes[n].get("kind") != "endpoint")
        })
        endpoints = sum(1 for n in set(G.neighbors(node)) if G.nodes[n].get("kind") == "endpoint")
        label = node if data.get("reachable", True) else f"[dim]{node} (not logged into)[/dim]"
        extra = f"  [dim]+{endpoints} phones/APs/other[/dim]" if endpoints and not show_endpoints else ""
        table.add_row(label, data.get("ip", "") or "", ", ".join(neighbors) + extra)
    console.print(table)


def build_topology_tree(G: nx.Graph, loops: list[list[str]], root: str | None = None) -> Tree:
    """A spanning-tree view of the switches with loop links marked."""
    loop_edge_set: set[frozenset] = set()
    for cycle in loops:
        for i in range(len(cycle)):
            a, b = cycle[i], cycle[(i + 1) % len(cycle)]
            if G.has_edge(a, b):
                loop_edge_set.add(frozenset((a, b)))

    switches = [n for n, d in G.nodes(data=True) if d.get("kind") != "endpoint"]
    if not switches:
        return Tree("[dim]No switches[/dim]")
    root_node = root if root in switches else switches[0]
    tree = Tree(f"[bold cyan]{root_node}[/bold cyan]")
    visited: set[str] = {root_node}

    def _add_children(parent_branch: Tree, parent: str) -> None:
        for neighbor in sorted(set(G.neighbors(parent))):
            if neighbor in visited or G.nodes[neighbor].get("kind") == "endpoint":
                continue
            visited.add(neighbor)
            edge_dict = G[parent][neighbor]
            data = edge_dict[sorted(edge_dict.keys())[0]]
            ports = data.get("ports", {})
            port_label = f"{ports.get(parent, data.get('local_port', '?'))} -> {ports.get(neighbor, data.get('remote_port', '?'))}"
            if len(edge_dict) > 1:
                port_label += f" (+{len(edge_dict) - 1} more link(s))"
            reachable = G.nodes[neighbor].get("reachable", True)
            name = neighbor if reachable else f"{neighbor} (not logged into)"
            label = f"[bold cyan]{name}[/bold cyan]  [yellow]{port_label}[/yellow]"
            if frozenset((parent, neighbor)) in loop_edge_set:
                label += "  [bold red]\\[LOOP][/bold red]"
            _add_children(parent_branch.add(label), neighbor)

    _add_children(tree, root_node)
    # Self-loops and switches not reachable from the root.
    for node in switches:
        if G.has_edge(node, node):
            tree.add(f"[bold red]{node} is cabled to itself[/bold red]")
        if node not in visited:
            visited.add(node)
            _add_children(tree.add(f"[cyan]{node}[/cyan] [dim](separate)[/dim]"), node)
    return tree


def print_topology_diagram(G: nx.Graph, loops: list[list[str]], root: str | None = None):
    if G.number_of_nodes() == 0:
        return
    console.print()
    console.print("[bold]Topology[/bold]")
    console.print(build_topology_tree(G, loops, root))


def print_result(result, verbose: bool = False) -> None:
    """Print a full AnalysisResult."""
    console.print()
    print_verdict(result)
    print_actions(result)
    console.print()
    print_findings(result)
    print_hot_ports(result)
    console.print()
    print_loop_reports(result)
    console.print()
    print_topology(result.graph, show_endpoints=verbose)
    seed_name = next((n for n, d in result.devices.items() if d.ip == result.seed), None)
    print_topology_diagram(result.graph, [l.nodes for l in result.loops if l.status != "blocked"], seed_name)
    if result.raw_dir:
        console.print(f"\n[dim]Raw switch output saved to {result.raw_dir} "
                      f"(re-analyse offline with: loop-finder --replay \"{result.raw_dir}\")[/dim]")


# ---------------------------------------------------------------------------
# Legacy helpers (kept for compatibility)
# ---------------------------------------------------------------------------

def print_loops(G: nx.Graph, loops: list[list[str]]):
    if not loops:
        console.print(Panel("[bold green]No loops detected.[/bold green]", title="Result", border_style="green"))
        return
    for i, cycle in enumerate(loops, 1):
        table = Table(title=f"Loop #{i}  ({' -> '.join(cycle + [cycle[0]])})", box=box.SIMPLE_HEAVY)
        for col in ("From", "Local Port", "Remote Port", "To"):
            table.add_column(col)
        for edge in get_loop_edges(G, cycle):
            table.add_row(edge["from"], edge["local_port"], edge["remote_port"], edge["to"])
        console.print(table)


def print_summary(device_count: int, loop_count: int):
    color = "red" if loop_count else "green"
    console.print(
        f"\n[bold]Summary:[/bold] Scanned [cyan]{_pluralize(device_count, 'device', 'devices')}[/cyan], "
        f"found [{color}]{_pluralize(loop_count, 'loop', 'loops')}[/{color}].\n"
    )
