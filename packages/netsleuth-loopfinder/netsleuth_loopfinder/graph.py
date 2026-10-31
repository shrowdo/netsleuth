"""
Build a topology graph from discovered devices and evaluate every loop
(redundant path) against live spanning-tree state.

Edges store the port at *each* end (``ports[node]``) so the direction a loop
is walked in never mixes up local and remote ports. Members of a port-channel
/ trunk / LAG are collapsed into one logical link, because STP treats them as
one port and they are not a loop.
"""

from collections import defaultdict

import networkx as nx

from netsleuth_core.models import Device
from netsleuth_core.ports import canonical_port

from netsleuth_loopfinder.stp import port_state

# Kept for backwards compatibility with older imports.
_canonical_port = canonical_port


# ---------------------------------------------------------------------------
# Building the graph
# ---------------------------------------------------------------------------

def _resolver(devices: dict[str, Device]):
    by_ip: dict[str, str] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    for name, d in devices.items():
        for ip in [d.ip, *getattr(d, "alt_ips", [])]:
            if ip:
                by_ip.setdefault(ip, name)
        by_name[d.hostname.lower()].append(name)
        by_name[name.lower()].append(name)
    stubs_by_ip: dict[str, str] = {}

    def resolve(neighbor) -> tuple[str, bool]:
        """Return (node name, is_known_device)."""
        if neighbor.ip and neighbor.ip in by_ip:
            return by_ip[neighbor.ip], True
        matches = set(by_name.get(neighbor.hostname.lower(), []))
        if len(matches) == 1:
            return matches.pop(), True
        if neighbor.ip:
            return stubs_by_ip.setdefault(neighbor.ip, neighbor.hostname or neighbor.ip), False
        return neighbor.hostname, False

    return resolve


def _pair_links(a_list: list[tuple[str, str]], b_list: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """
    Merge A's view [(a_local, a_remote)] and B's view [(b_local, b_remote)]
    of the cables between A and B into [(port_on_A, port_on_B)].

    Each side's *local* port name is authoritative; the remote names are only
    used to pair entries up. Unpaired entries are matched positionally so a
    neighbour that reports a port description instead of a port ID can't
    double-count a cable (which would show up as a fake loop).
    """
    links: list[tuple[str, str]] = []
    unmatched_b = list(b_list)
    unmatched_a: list[tuple[str, str]] = []
    for a_loc, a_rem in a_list:
        match = next(
            (b for b in unmatched_b
             if canonical_port(b[0]) == canonical_port(a_rem)
             or canonical_port(b[1]) == canonical_port(a_loc)),
            None,
        )
        if match:
            unmatched_b.remove(match)
            links.append((a_loc, match[0]))
        else:
            unmatched_a.append((a_loc, a_rem))
    for (a_loc, a_rem), (b_loc, _b_rem) in zip(unmatched_a, unmatched_b):
        links.append((a_loc, b_loc))
    links += [(a_loc, a_rem) for a_loc, a_rem in unmatched_a[len(unmatched_b):]]
    links += [(b_rem, b_loc) for b_loc, b_rem in unmatched_b[len(unmatched_a):]]
    return links


def _pair_self_links(entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """A switch that sees itself: one cable reported from both ends."""
    seen: set[frozenset] = set()
    links = []
    for loc, rem in entries:
        key = frozenset((canonical_port(loc), canonical_port(rem)))
        if key not in seen:
            seen.add(key)
            links.append((loc, rem))
    return links


def build_graph(devices: dict[str, Device]) -> nx.MultiGraph:
    G = nx.MultiGraph()
    resolve = _resolver(devices)

    for name, d in devices.items():
        G.add_node(
            name,
            ip=d.ip,
            reachable=getattr(d, "reachable", True),
            kind="switch",
            device_type=d.device_type,
        )

    # views[(A, B)][X] = [(local, remote), ...] as reported by X.
    views: dict[tuple[str, str], dict[str, list[tuple[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for name, d in devices.items():
        for n in d.neighbors:
            if not n.hostname:
                continue
            target, known = resolve(n)
            if not known and target not in G:
                kind = "switch" if n.role in ("switch", "unknown") else "endpoint"
                G.add_node(target, ip=n.ip, reachable=False, kind=kind,
                           device_type=n.device_type_hint, platform=n.platform)
            pair = tuple(sorted((name, target)))
            views[pair][name].append((n.local_port, n.remote_port))

    for (a, b), by_reporter in views.items():
        if a == b:
            links = _pair_self_links(by_reporter[a])
        else:
            links = _pair_links(by_reporter.get(a, []), by_reporter.get(b, []))
        for port_a, port_b, members_a, members_b in _collapse_lags(devices, a, b, links):
            G.add_edge(
                a, b,
                ports={a: port_a, b: port_b} if a != b else {a: port_a, "_peer": port_b},
                members={a: members_a, b: members_b} if a != b else {a: members_a + members_b},
                # Back-compat orientation (as seen from the first node).
                local_port=port_a,
                remote_port=port_b,
            )
    return G


def _collapse_lags(devices, a: str, b: str, links: list[tuple[str, str]]):
    lags_a = devices[a].lags if a in devices else {}
    lags_b = devices[b].lags if b in devices else {}
    groups: dict[tuple, list[tuple[str, str]]] = {}
    for pa, pb in links:
        lag_a = lags_a.get(canonical_port(pa))
        lag_b = lags_b.get(canonical_port(pb))
        if lag_a:
            key = ("a", lag_a)
        elif lag_b:
            key = ("b", lag_b)
        else:
            key = ("link", canonical_port(pa), canonical_port(pb))
        groups.setdefault(key, []).append((pa, pb))
    for key, members in groups.items():
        if key[0] == "link":
            pa, pb = members[0]
            yield pa, pb, [], []
            continue
        first_a, first_b = members[0]
        port_a = lags_a.get(canonical_port(first_a)) or first_a
        port_b = lags_b.get(canonical_port(first_b)) or first_b
        yield port_a, port_b, [m[0] for m in members], [m[1] for m in members]


# ---------------------------------------------------------------------------
# Finding loops
# ---------------------------------------------------------------------------

def find_loops(G: nx.MultiGraph) -> list[list[str]]:
    """
    Return one cycle per independent loop (the cycle basis), each a list of
    node names. Includes:
      - [A]      a cable looped back into the same switch
      - [A, B]   two or more separate links between the same pair
      - [A,B,C…] longer rings
    The count equals the number of links STP must block for a loop-free network.
    """
    cycles: list[list[str]] = []
    seen_pairs: set[frozenset] = set()

    for u, v in G.edges():
        pair = frozenset((u, v))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        count = G.number_of_edges(u, v)
        if u == v:
            cycles.extend([[u]] * count)
        elif count > 1:
            # k parallel links = k-1 independent loops; report the pair once.
            cycles.append([u, v])

    simple_G = nx.Graph(G)
    simple_G.remove_edges_from(nx.selfloop_edges(simple_G))
    try:
        longer = nx.cycle_basis(simple_G)
    except Exception:
        longer = []
    cycles.extend(c for c in longer if len(c) >= 3)
    return cycles


def _port_at(data: dict, node: str, other: str) -> str:
    ports = data.get("ports", {})
    if node in ports:
        return ports[node]
    return data.get("local_port", "?")


def get_loop_edges(G: nx.MultiGraph, cycle: list[str]) -> list[dict]:
    """
    Edges making up *cycle* with the port on each side.

    For a two-node loop every parallel link is returned; for a self-loop the
    cable's two ports; for longer loops every link between consecutive nodes.
    """
    edges = []
    n = len(cycle)
    if n == 1:
        a = cycle[0]
        for _key, data in sorted(G[a][a].items()):
            ports = data.get("ports", {})
            edges.append({
                "from": a, "to": a,
                "local_port": ports.get(a, data.get("local_port", "?")),
                "remote_port": ports.get("_peer", data.get("remote_port", "?")),
                "members": data.get("members", {}),
            })
        return edges

    hops = 1 if n == 2 else n
    for i in range(hops):
        a, b = cycle[i], cycle[(i + 1) % n]
        if not G.has_edge(a, b):
            continue
        for _key, data in sorted(G[a][b].items()):
            edges.append({
                "from": a, "to": b,
                "local_port": _port_at(data, a, b),
                "remote_port": _port_at(data, b, a),
                "members": data.get("members", {}),
            })
    return edges


# ---------------------------------------------------------------------------
# STP evaluation
# ---------------------------------------------------------------------------

def _side_state(devices: dict[str, Device], G: nx.MultiGraph, node: str, port: str) -> str:
    """
    STP state for one end of a link:
      - managed switch we logged into: its STP state ("" if unreadable)
      - endpoint / unmanaged device: "FWD" (it just passes traffic)
      - switch we couldn't log into: "" (unknown)
    """
    d = devices.get(node)
    if d is not None and d.reachable:
        return port_state(d.stp, d.stp_mode, port)
    if G.nodes[node].get("kind") == "endpoint":
        return "FWD"
    return ""


def evaluate_loop(G: nx.MultiGraph, devices: dict[str, Device], cycle: list[str]) -> dict:
    """
    Decide whether a loop is broken by STP.

    Returns {"status": "blocked"|"active"|"unknown", "edges": [...with states],
             "blocked_at": [(device, port, state)], "note": str}
    """
    edges = get_loop_edges(G, cycle)
    for e in edges:
        e["from_state"] = _side_state(devices, G, e["from"], e["local_port"])
        to_port = e["remote_port"]
        e["to_state"] = _side_state(devices, G, e["to"], to_port)

    def link_blocked(e) -> bool:
        return e["from_state"] in ("BLK", "PART") or e["to_state"] in ("BLK", "PART")

    def link_known_forwarding(e) -> bool:
        ok = ("FWD", "LRN", "LIS")
        return e["from_state"] in ok and e["to_state"] in ok

    blocked_at = []
    for e in edges:
        if e["from_state"] in ("BLK", "PART"):
            blocked_at.append((e["from"], e["local_port"], e["from_state"]))
        if e["to_state"] in ("BLK", "PART"):
            blocked_at.append((e["to"], e["remote_port"], e["to_state"]))

    if len(cycle) <= 2:
        # Parallel links / self-loop: loop-free if at most one link forwards.
        open_links = [e for e in edges if not link_blocked(e)]
        if len(cycle) == 1:
            status = "blocked" if not open_links else (
                "active" if all(link_known_forwarding(e) for e in open_links) else "unknown")
        elif len(open_links) <= 1:
            status = "blocked"
        elif sum(link_known_forwarding(e) for e in open_links) >= 2:
            status = "active"
        else:
            status = "unknown"
    else:
        hops: dict[frozenset, list[dict]] = defaultdict(list)
        for e in edges:
            hops[frozenset((e["from"], e["to"]))].append(e)
        if any(all(link_blocked(e) for e in hop) for hop in hops.values()):
            status = "blocked"
        elif all(any(link_known_forwarding(e) for e in hop) for hop in hops.values()):
            status = "active"
        else:
            status = "unknown"

    note = ""
    if status == "blocked" and any(state == "PART" for _d, _p, state in blocked_at):
        note = "Blocked in some VLANs only - check the per-VLAN STP output."
    elif status == "unknown":
        missing = sorted({e["from"] for e in edges if not e["from_state"]}
                         | {e["to"] for e in edges if not e["to_state"]})
        note = "No STP data for: " + ", ".join(missing) if missing else ""
    return {"status": status, "edges": edges, "blocked_at": blocked_at, "note": note}


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------

def suggest_remediation(G: nx.MultiGraph, loops: list[list[str]]) -> list[dict]:
    """
    For each loop suggest one link to break it, preferring links shared by
    the most loops and links that lead to unmanaged/endpoint devices.

    Returns [{loop, disable_on, port, reason}] (1-based loop index).
    """
    if not loops:
        return []

    edge_loop_map: dict[frozenset, list[int]] = defaultdict(list)
    loop_edges: list[list[dict]] = []
    for idx, cycle in enumerate(loops):
        edges = get_loop_edges(G, cycle)
        loop_edges.append(edges)
        for e in {frozenset((e["from"], e["to"])): e for e in edges}.values():
            edge_loop_map[frozenset((e["from"], e["to"]))].append(idx)

    def score(e: dict) -> tuple:
        key = frozenset((e["from"], e["to"]))
        touches_endpoint = any(
            G.nodes[n].get("kind") == "endpoint" or not G.nodes[n].get("reachable", True)
            for n in (e["from"], e["to"])
        )
        is_lag = bool(e.get("members", {}).get(e["from"]))
        return (len(edge_loop_map[key]), touches_endpoint, not is_lag)

    suggestions = []
    for idx, edges in enumerate(loop_edges):
        if not edges:
            suggestions.append({"loop": idx + 1, "disable_on": loops[idx][0], "port": "?",
                                "reason": "No link data available for this loop."})
            continue
        best = max(edges, key=score)
        # Act on a switch we can log into; if "from" is unmanaged use the other side.
        node, port = best["from"], best["local_port"]
        if not G.nodes[node].get("reachable", True) and G.nodes[best["to"]].get("reachable", True):
            node, port = best["to"], best["remote_port"]
        covered = edge_loop_map[frozenset((best["from"], best["to"]))]
        if len(covered) > 1:
            reason = "Breaks loops " + ", ".join(f"#{i + 1}" for i in sorted(covered)) + "."
        else:
            reason = "Breaks this loop."
        suggestions.append({"loop": idx + 1, "disable_on": node, "port": port, "reason": reason})
    return suggestions
