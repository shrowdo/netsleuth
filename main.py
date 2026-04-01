#!/usr/bin/env python3
"""
network-loop-finder: Detect loops in a switch network via SSH + CDP/LLDP discovery.

Usage:
    python main.py inventory.yaml
    python main.py inventory.yaml --json results.json
    python main.py --mock topologies/simple_loop.yaml
    python main.py --mock topologies/simple_loop.yaml --json results.json

Flags:
    --mock TOPOLOGY   Skip SSH discovery and load a static topology YAML instead.
                      When --mock is given, the inventory positional argument is
                      not required and no credentials are read.
"""

import argparse
import json
import sys
import yaml
from rich.console import Console

from loop_finder.discovery import discover
from loop_finder.mock import discover_mock
from loop_finder.graph import build_graph, find_loops, get_loop_edges, suggest_remediation
from loop_finder.cli import (
    print_topology,
    print_topology_diagram,
    print_loops,
    print_remediation,
    print_summary,
    print_stp_status,
    print_log_findings,
)
from loop_finder.stp import get_stp_status, get_stp_status_mock, check_loops_stp_status
from loop_finder.logparse import get_log_findings, get_log_findings_mock

console = Console()


def load_inventory(path: str) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f)
    required = {"seed", "username", "password", "device_type"}
    missing = required - data.keys()
    if missing:
        console.print(f"[red]Inventory missing required fields: {missing}[/red]")
        sys.exit(1)
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Detect loops in a switch network.",
        epilog=(
            "Examples:\n"
            "  python main.py inventory.yaml\n"
            "  python main.py inventory.yaml --json results.json\n"
            "  python main.py --mock topologies/simple_loop.yaml\n"
            "  python main.py --mock topologies/simple_loop.yaml --json results.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "inventory",
        nargs="?",
        help="Path to inventory YAML file (required unless --mock is used)",
    )
    parser.add_argument(
        "--mock",
        metavar="TOPOLOGY",
        help="Load a static topology YAML instead of performing SSH discovery; "
             "inventory file is not required when this flag is provided",
    )
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--max-depth", type=int, default=None, help="Limit discovery depth")
    args = parser.parse_args()

    # Validate argument combinations before doing any work.
    if args.mock is None and args.inventory is None:
        parser.error("inventory is required unless --mock is specified")

    console.rule("[bold blue]Network Loop Finder[/bold blue]")

    console.print("\n[bold]Phase 0: Log Analysis[/bold]")
    if args.mock:
        log_findings = get_log_findings_mock("seed-switch", has_loop=True)
    else:
        inventory = load_inventory(args.inventory)
        creds = {k: inventory[k] for k in ("username", "password", "device_type") if k in inventory}
        if "port" in inventory:
            creds["port"] = inventory["port"]
        if "key_file" in inventory:
            creds["key_file"] = inventory["key_file"]
        from loop_finder.discovery import connect
        conn = connect(
            ip=inventory["seed"],
            username=creds["username"],
            password=creds["password"],
            device_type=creds["device_type"],
            port=creds.get("port", 22),
            key_file=creds.get("key_file"),
        )
        log_findings = get_log_findings(conn, inventory["seed"])
        conn.disconnect()
    print_log_findings(log_findings)

    console.print("\n[bold]Phase 1: Discovery[/bold]")

    if args.mock:
        console.print(f"[yellow]Mock mode: loading topology from {args.mock}[/yellow]")
        devices = discover_mock(args.mock)
    else:
        devices = discover(
            seed_ip=inventory["seed"],
            creds=creds,
            max_depth=args.max_depth or inventory.get("max_depth"),
        )

    if not devices:
        console.print("[red]No devices discovered. Check your seed IP and credentials.[/red]")
        sys.exit(1)

    console.print("\n[bold]Phase 2: Topology Analysis[/bold]")
    G = build_graph(devices)
    loops = find_loops(G)

    console.print()
    print_topology(G)
    print_topology_diagram(G, loops)
    console.print()
    print_loops(G, loops)

    if loops:
        # Build per-loop edge lists once; reused by remediation and STP checks.
        all_loop_edges = [get_loop_edges(G, cycle) for cycle in loops]

        suggestions = suggest_remediation(G, loops)
        print_remediation(suggestions)

        console.print("\n[bold]Phase 3: STP Status[/bold]")
        if args.mock:
            stp_data = get_stp_status_mock(devices)
        else:
            stp_data = get_stp_status(devices, creds)

        stp_results = check_loops_stp_status(loops, all_loop_edges, stp_data)
        print_stp_status(stp_results)

    print_summary(len(devices), len(loops))

    if args.json:
        results = {
            "devices": {h: {"ip": d.ip, "neighbors": [vars(n) for n in d.neighbors]} for h, d in devices.items()},
            "loops": loops,
        }
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[dim]Results written to {args.json}[/dim]")

    sys.exit(1 if loops else 0)


if __name__ == "__main__":
    main()
