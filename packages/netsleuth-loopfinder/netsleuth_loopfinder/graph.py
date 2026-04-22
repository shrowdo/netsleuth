"""
Build a topology graph from discovered devices and detect loops.
"""

import networkx as nx
from netsleuth_loopfinder.discovery import Device


def build_graph(devices: dict[str, Device]) -> nx.MultiGraph:
    G = nx.MultiGraph()
    for hostname, device in devices.items():
        G.add_node(hostname, ip=device.ip, reachable=getattr(device, "reachable", True))
        for neighbor in device.neighbors:
            if not neighbor.hostname:
                continue
            # Ensure the neighbor node exists even if it has no Device entry
            if neighbor.hostname not in G:
                G.add_node(neighbor.hostname, ip=neighbor.ip, reachable=False)
            G.add_edge(
                hostname,
                neighbor.hostname,
                local_port=neighbor.local_port,
                remote_port=neighbor.remote_port,
            )
    return G


def find_loops(G: nx.MultiGraph) -> list[list[str]]:
    """
    Return a list of cycles found in the graph.
    Each cycle is a list of hostnames forming the loop.

    Two-node cycles (parallel/dual uplinks) are detected first because
    nx.cycle_basis does not report them.  Longer cycles are found via
    cycle_basis on the simple (de-duplicated) projection of the graph.
    """
    cycles: list[list[str]] = []
    seen_pairs: set[frozenset] = set()

    # --- Parallel-edge detection (2-node loops) ---
    for u, v, data in G.edges(data=True):
        if u == v:
            continue  # self-loops are not network loops
        pair = frozenset((u, v))
        if pair in seen_pairs:
            continue
        edge_keys = G[u][v]  # {key: data_dict, ...}
        if len(edge_keys) > 1:
            cycles.append([u, v])
            seen_pairs.add(pair)

    # --- Longer cycles via cycle_basis on the simple projection ---
    simple_G = nx.Graph(G)
    try:
        longer = nx.cycle_basis(simple_G)
    except Exception:
        longer = []

    # Only keep cycles with 3+ nodes (2-node ones already handled above)
    for cycle in longer:
        if len(cycle) >= 3:
            cycles.append(cycle)

    return cycles


def get_loop_edges(G: nx.MultiGraph, cycle: list[str]) -> list[dict]:
    """
    For a given cycle (list of hostnames), return the edges with port info.

    For parallel edges (2-node cycle) all parallel links are returned so
    every offending connection is visible in the output.
    For longer cycles, the first (lowest key) edge between consecutive
    nodes is returned.
    """
    edges = []
    n = len(cycle)
    for i in range(n):
        a = cycle[i]
        b = cycle[(i + 1) % n]
        if not G.has_edge(a, b):
            continue
        parallel = G[a][b]  # {key: data_dict}
        for key in sorted(parallel.keys()):
            data = parallel[key]
            edges.append({
                "from": a,
                "to": b,
                "local_port": data.get("local_port", "?"),
                "remote_port": data.get("remote_port", "?"),
            })
            # For non-parallel hops (longer cycles) only take the first edge
            if n > 2:
                break
    return edges


def suggest_remediation(G: nx.MultiGraph, loops: list[list[str]]) -> list[dict]:
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

    # Build a mapping: canonical edge (frozenset) -> list of loop indices it appears in.
    # For MultiGraph we treat any pair (a, b) with at least one edge as one canonical key.
    edge_loop_map: dict[frozenset, list[int]] = {}
    loop_edges: list[list[tuple[str, str]]] = []

    for loop_idx, cycle in enumerate(loops):
        edges_in_cycle: list[tuple[str, str]] = []
        n = len(cycle)
        for i in range(n):
            a = cycle[i]
            b = cycle[(i + 1) % n]
            if G.has_edge(a, b):
                key = frozenset((a, b))
                edge_loop_map.setdefault(key, []).append(loop_idx)
                edges_in_cycle.append((a, b))
        loop_edges.append(edges_in_cycle)

    suggestions: list[dict] = []
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

        # Pick the first parallel edge for port info
        parallel = G[a][b]
        first_key = sorted(parallel.keys())[0]
        data = parallel[first_key]
        local_port = data.get("local_port", "?")

        loops_broken = edge_loop_map.get(frozenset((a, b)), [loop_idx])
        if len(loops_broken) > 1:
            reason = (
                f"Block {local_port} on {a} via STP priority - breaks loops "
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
