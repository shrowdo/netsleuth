#!/usr/bin/env python3
"""
network-loop-finder: Detect loops in a switch network via SSH + CDP/LLDP discovery.

Usage:
    python main.py inventory.yaml
    python main.py inventory.yaml --json results.json
"""

import argparse
import json
import sys
import yaml
from rich.console import Console

from loop_finder.discovery import discover
from loop_finder.graph import build_graph, find_loops
from loop_finder.cli import print_topology, print_loops, print_summary

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
    parser = argparse.ArgumentParser(description="Detect loops in a switch network.")
    parser.add_argument("inventory", help="Path to inventory YAML file")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--max-depth", type=int, default=None, help="Limit discovery depth")
    args = parser.parse_args()

    console.rule("[bold blue]Network Loop Finder[/bold blue]")

    inventory = load_inventory(args.inventory)
    creds = {k: inventory[k] for k in ("username", "password", "device_type") if k in inventory}
    if "port" in inventory:
        creds["port"] = inventory["port"]
    if "key_file" in inventory:
        creds["key_file"] = inventory["key_file"]

    console.print("\n[bold]Phase 1: Discovery[/bold]")
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
    console.print()
    print_loops(G, loops)
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
