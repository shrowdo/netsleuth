"""
Build a topology graph from discovered devices and detect loops.
"""

import networkx as nx
from loop_finder.discovery import Device


def build_graph(devices: dict[str, Device]) -> nx.Graph:
    G = nx.Graph()
    for hostname, device in devices.items():
        G.add_node(hostname, ip=device.ip)
        for neighbor in device.neighbors:
            if neighbor.hostname in devices:
                G.add_edge(
                    hostname,
                    neighbor.hostname,
                    local_port=neighbor.local_port,
                    remote_port=neighbor.remote_port,
                )
    return G


def find_loops(G: nx.Graph) -> list[list[str]]:
    """
    Return a list of cycles found in the graph.
    Each cycle is a list of hostnames forming the loop.
    """
    try:
        cycles = nx.cycle_basis(G)
    except Exception:
        cycles = []
    return cycles


def get_loop_edges(G: nx.Graph, cycle: list[str]) -> list[dict]:
    """
    For a given cycle (list of hostnames), return the edges with port info.
    """
    edges = []
    for i in range(len(cycle)):
        a = cycle[i]
        b = cycle[(i + 1) % len(cycle)]
        if G.has_edge(a, b):
            data = G[a][b]
            edges.append({
                "from": a,
                "to": b,
                "local_port": data.get("local_port", "?"),
                "remote_port": data.get("remote_port", "?"),
            })
    return edges


def suggest_remediation(G: nx.Graph, loops: list[list[str]]) -> list[dict]:
    """
    For each detected loop, suggest one link to disable to break it.

    Strategy: pick the edge that appears in the most loops (greedy coverage),
    falling back to the first edge in the cycle when there is no overlap.

    Returns a list of dicts with keys:
        loop       - 1-based loop index
        disable_on - hostname of the device to act on
        port       - local port to disable on that device
        reason     - human-readable explanation
    """
    if not loops:
        return []

    # Build a mapping: canonical edge (frozenset) -> list of loop indices it appears in
    edge_loop_map: dict[frozenset, list[int]] = {}
    loop_edges: list[list[tuple[str, str]]] = []

    for loop_idx, cycle in enumerate(loops):
        edges_in_cycle: list[tuple[str, str]] = []
        for i in range(len(cycle)):
            a = cycle[i]
            b = cycle[(i + 1) % len(cycle)]
            if G.has_edge(a, b):
                key = frozenset((a, b))
                edge_loop_map.setdefault(key, []).append(loop_idx)
                edges_in_cycle.append((a, b))
        loop_edges.append(edges_in_cycle)

    suggestions: list[dict] = []
    # Track which loops have already been "covered" by a previously chosen edge
    covered: set[int] = set()

    for loop_idx, cycle in enumerate(loops):
        edges_in_cycle = loop_edges[loop_idx]
        if not edges_in_cycle:
            suggestions.append({
                "loop": loop_idx + 1,
                "disable_on": cycle[0],
                "port": "?",
                "reason": "No edge data available for this loop.",
            })
            continue

        # Pick the edge in this cycle that covers the most loops
        best_edge: tuple[str, str] | None = None
        best_coverage = -1
        for a, b in edges_in_cycle:
            key = frozenset((a, b))
            coverage = len(edge_loop_map.get(key, []))
            if coverage > best_coverage:
                best_coverage = coverage
                best_edge = (a, b)

        a, b = best_edge  # type: ignore[misc]
        data = G[a][b]
        local_port = data.get("local_port", "?")

        loops_broken = edge_loop_map.get(frozenset((a, b)), [loop_idx])
        if len(loops_broken) > 1:
            reason = (
                f"Block {local_port} on {a} via STP priority — breaks loops "
                + ", ".join(f"#{li + 1}" for li in sorted(loops_broken))
                + ". If STP is unavailable, disable the port as a last resort."
            )
        else:
            reason = (
                f"Block {local_port} on {a} via STP priority to break this loop. "
                "If STP is unavailable, disable the port as a last resort."
            )

        covered.update(loops_broken)

        suggestions.append({
            "loop": loop_idx + 1,
            "disable_on": a,
            "port": local_port,
            "reason": reason,
        })

    return suggestions
