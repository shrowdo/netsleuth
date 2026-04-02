"""
Entry point for the `loop-finder` CLI command.

Usage:
    loop-finder 192.168.1.1 -u admin -p secret
    loop-finder 192.168.1.1 -u admin          # prompts for password
    loop-finder 192.168.1.1 -u admin --device-type cisco_nxos
    loop-finder 192.168.1.1 -u admin --json results.json
    loop-finder --mock topologies/simple_loop.yaml
"""

import argparse
import getpass
import json
import os
import sys


def _resolve_path(path: str) -> str:
    """
    Resolve a file path, checking the PyInstaller bundle directory (_MEIPASS)
    as a fallback when the file doesn't exist relative to the current directory.
    """
    if os.path.exists(path):
        return path
    if hasattr(sys, "_MEIPASS"):
        bundled = os.path.join(sys._MEIPASS, path)
        if os.path.exists(bundled):
            return bundled
    return path  # let the caller produce the FileNotFoundError

from rich.console import Console

from loop_finder.discovery import connect, discover
from loop_finder.mock import discover_mock
from loop_finder.graph import build_graph, find_loops, get_loop_edges, suggest_remediation
from loop_finder.logparse import get_log_findings, get_log_findings_mock
from loop_finder.stp import get_stp_status, get_stp_status_mock, check_loops_stp_status
from loop_finder.cli import (
    print_log_findings,
    print_topology,
    print_topology_diagram,
    print_loops,
    print_remediation,
    print_stp_status,
    print_summary,
)

console = Console()

DEVICE_TYPES = [
    "cisco_ios",
    "cisco_nxos",
    "cisco_xe",
    "cisco_xr",
    "arista_eos",
    "juniper_junos",
    "hp_procurve",
    "hp_comware",
    # Shorthands — auto-probes the right variant on connect
    "aruba",
    "hp",
    "juniper",
    "huawei",
    "extreme",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loop-finder",
        description="Detect loops in a switch network via SSH + CDP/LLDP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  loop-finder 192.168.1.1 -u admin\n"
            "  loop-finder 192.168.1.1 -u admin -p secret --device-type cisco_nxos\n"
            "  loop-finder 192.168.1.1 -u admin --json results.json\n"
            "  loop-finder --mock topologies/simple_loop.yaml"
        ),
    )

    parser.add_argument(
        "host",
        nargs="?",
        metavar="HOST",
        help="IP address of the seed switch to start discovery from",
    )
    parser.add_argument(
        "-u", "--username",
        help="SSH username",
    )
    parser.add_argument(
        "-p", "--password",
        help="SSH password (omit to be prompted securely)",
    )
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        metavar="TYPE",
        help=f"Device type (default: cisco_ios). Common values: {', '.join(DEVICE_TYPES)}",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)",
    )
    parser.add_argument(
        "--key-file",
        metavar="PATH",
        help="Path to SSH private key file (alternative to password)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Limit how many hops deep discovery will crawl",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export full results to a JSON file",
    )
    parser.add_argument(
        "--mock",
        metavar="TOPOLOGY",
        help="Skip SSH entirely and load a static topology YAML (for testing)",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # If run with no arguments at all, go fully interactive
    if not args.mock and not args.host:
        console.rule("[bold blue]Network Loop Finder[/bold blue]")
        console.print("[dim]Press Ctrl+C to exit[/dim]\n")
        try:
            args.host = input("Switch IP:    ").strip()
            args.username = input("Username:     ").strip()
            show = input("Show password? [y/N]: ").strip().lower() == "y"
            args.password = input("Password:     ") if show else getpass.getpass("Password:     ")
            device_type = input("Device type   [cisco_ios] (e.g. aruba, cisco_ios, arista_eos): ").strip()
            args.device_type = device_type if device_type else "cisco_ios"
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]")
            sys.exit(0)
        console.print()

    # Prompt for any missing credentials when flags were partially provided
    elif not args.mock:
        if not args.username:
            args.username = input("Username: ").strip()
        if not args.password and not args.key_file:
            args.password = getpass.getpass("Password: ")

    creds = {}
    if not args.mock:
        creds = {
            "username": args.username,
            "password": args.password or "",
            "device_type": args.device_type,
            "port": args.port,
        }
        if args.key_file:
            creds["key_file"] = args.key_file

    if args.mock or args.username:
        # Non-interactive mode — print the header here (interactive mode already printed it)
        console.rule("[bold blue]Network Loop Finder[/bold blue]")

    # Phase 0: Log analysis
    console.print("\n[bold]Phase 0: Log Analysis[/bold]")
    if args.mock:
        log_findings = get_log_findings_mock("seed-switch", has_loop=True)
    else:
        try:
            conn = connect(
                ip=args.host,
                username=creds["username"],
                password=creds["password"],
                device_type=creds["device_type"],
                port=creds.get("port", 22),
                key_file=creds.get("key_file"),
            )
            log_findings = get_log_findings(conn, args.host)
            conn.disconnect()
        except Exception as e:
            console.print(f"[yellow]Could not connect for log analysis: {e}[/yellow]")
            from loop_finder.logparse import LogFindings
            log_findings = LogFindings()
    print_log_findings(log_findings)

    # Phase 1: Discovery
    console.print("\n[bold]Phase 1: Discovery[/bold]")
    if args.mock:
        console.print(f"[yellow]Mock mode: loading topology from {args.mock}[/yellow]")
        devices = discover_mock(_resolve_path(args.mock))
    else:
        devices = discover(
            seed_ip=args.host,
            creds=creds,
            max_depth=args.max_depth,
        )

    if not devices:
        console.print("[red]No devices discovered. Check the IP address and credentials.[/red]")
        sys.exit(1)

    # Phase 2: Topology analysis
    console.print("\n[bold]Phase 2: Topology Analysis[/bold]")
    G = build_graph(devices)
    loops = find_loops(G)

    console.print()
    print_topology(G)
    print_topology_diagram(G, loops)
    console.print()
    print_loops(G, loops)

    if loops:
        all_loop_edges = [get_loop_edges(G, cycle) for cycle in loops]
        suggestions = suggest_remediation(G, loops)
        print_remediation(suggestions)

        console.print("\n[bold]Phase 3: STP Status[/bold]")
        stp_data = get_stp_status_mock(devices) if args.mock else get_stp_status(devices, creds)
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
