"""
Entry point for the `loop-finder` CLI command.

Usage:
    loop-finder 192.168.1.1 -u admin -p secret
    loop-finder 192.168.1.1 -u admin          # prompts for password
    loop-finder 192.168.1.1 -u admin --device-type cisco_nxos
    loop-finder 192.168.1.1 -u admin --json results.json
    loop-finder --mock topologies/simple_loop.yaml
    loop-finder --scan                         # find SSH-reachable hosts and exit
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

from netsleuth_core.ssh import connect, detect_device_type
from netsleuth_loopfinder.discovery import discover
from netsleuth_loopfinder.mock import discover_mock
from netsleuth_loopfinder.graph import build_graph, find_loops, get_loop_edges, suggest_remediation
from netsleuth_loopfinder.logparse import get_log_findings, get_log_findings_mock
from netsleuth_loopfinder.stp import get_stp_status, get_stp_status_mock, check_loops_stp_status
from netsleuth_loopfinder.cli import (
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
            "  loop-finder 192.168.1.1 -u admin --extra-creds backup:secret\n"
            "  loop-finder 192.168.1.1 -u admin --json results.json\n"
            "  loop-finder --mock topologies/simple_loop.yaml\n"
            "  loop-finder --scan"
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
        default="auto",
        metavar="TYPE",
        help=(
            f"Device type for the seed switch (default: auto-detect). "
            f"Common values: {', '.join(DEVICE_TYPES)}. "
            "Discovered neighbors are always auto-detected regardless of this setting."
        ),
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
    parser.add_argument(
        "--extra-creds",
        nargs="+",
        metavar="user:pass",
        help=(
            "One or more fallback credentials in user:pass format, tried in order "
            "when the primary credentials fail authentication on a device."
        ),
    )
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Skip auto-scan of local network and go straight to manual IP prompt",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan local network for SSH-reachable hosts and print results, then exit",
    )
    return parser


def _auto_scan_for_host() -> str | None:
    """
    Run subnet auto-discovery and return the chosen host IP, or None if the
    user should be prompted manually.  All exceptions are caught internally.
    """
    from netsleuth_loopfinder.scan import get_local_subnets, scan_subnet_for_ssh

    try:
        subnets = get_local_subnets()
    except Exception as exc:
        console.print(f"[yellow]Could not determine local subnets: {exc}[/yellow]")
        return None

    if not subnets:
        console.print("[yellow]No local subnets found — falling back to manual entry.[/yellow]")
        return None

    console.print(f"[dim]Found subnet(s): {', '.join(subnets)}[/dim]")

    all_found: list[str] = []
    for subnet in subnets:
        try:
            found = scan_subnet_for_ssh(subnet)
            all_found.extend(found)
        except Exception as exc:
            console.print(f"[yellow]Scan of {subnet} failed: {exc}[/yellow]")

    if not all_found:
        console.print("[yellow]No SSH-reachable hosts found — falling back to manual entry.[/yellow]")
        return None

    if len(all_found) == 1:
        console.print(f"Found 1 switch: [bold]{all_found[0]}[/bold]")
        return all_found[0]

    # Multiple candidates — let the user pick
    console.print(f"\nFound [bold]{len(all_found)}[/bold] SSH-reachable hosts:")
    for idx, ip in enumerate(all_found, start=1):
        console.print(f"  [bold]{idx}.[/bold] {ip}")
    try:
        raw = input("\nSelect switch [1]: ").strip()
        choice = int(raw) if raw else 1
        if 1 <= choice <= len(all_found):
            return all_found[choice - 1]
        console.print("[yellow]Invalid selection — falling back to manual entry.[/yellow]")
    except (ValueError, KeyboardInterrupt):
        pass
    return None


def main():
    parser = build_parser()
    args = parser.parse_args()

    # --scan: quick "what switches can I reach?" utility, then exit
    if args.scan:
        console.rule("[bold blue]Network Loop Finder — SSH Scan[/bold blue]")
        from netsleuth_loopfinder.scan import get_local_subnets, scan_subnet_for_ssh
        try:
            subnets = get_local_subnets()
            if not subnets:
                console.print("[yellow]No local subnets detected.[/yellow]")
                sys.exit(0)
            console.print(f"[dim]Scanning: {', '.join(subnets)}[/dim]\n")
            found_any = False
            for subnet in subnets:
                results = scan_subnet_for_ssh(subnet)
                if results:
                    found_any = True
                    for ip in results:
                        console.print(f"  [green]{ip}[/green]")
            if not found_any:
                console.print("[yellow]No SSH-reachable hosts found.[/yellow]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(0)

    # If run with no arguments at all, launch the Textual TUI
    if not args.mock and not args.host and not args.username:
        from netsleuth_loopfinder.tui import LoopFinderTUI
        LoopFinderTUI().run()
        return

    # Prompt for any missing credentials when flags were partially provided
    elif not args.mock:
        if not args.username:
            args.username = input("Username: ").strip()
        if not args.password and not args.key_file:
            args.password = getpass.getpass("Password: ")

    # Parse --extra-creds "user:pass" tokens into dicts (CLI path).
    # In interactive mode args.extra_creds is already a list[dict] or None.
    extra_creds = None
    if not args.mock:
        raw_extra = getattr(args, "extra_creds", None)
        if isinstance(raw_extra, list) and raw_extra and isinstance(raw_extra[0], str):
            # CLI path: list of "username:password" strings.
            parsed = []
            for token in raw_extra:
                if ":" in token:
                    u, p = token.split(":", 1)
                    parsed.append({"username": u, "password": p})
                else:
                    console.print(f"[yellow]Ignoring malformed --extra-creds entry (expected user:pass): {token!r}[/yellow]")
            extra_creds = parsed if parsed else None
        elif isinstance(raw_extra, list):
            # Interactive path: already a list[dict].
            extra_creds = raw_extra if raw_extra else None

    creds = {}
    if not args.mock:
        # Resolve the seed device type — auto-detect now if the user didn't specify one.
        seed_device_type = args.device_type
        if seed_device_type == "auto":
            console.print(f"[dim]Auto-detecting device type for {args.host}...[/dim]")
            seed_device_type = detect_device_type(
                ip=args.host,
                port=args.port,
                username=args.username,
                password=args.password or "",
                key_file=args.key_file if hasattr(args, "key_file") else None,
            )
            console.print(f"[dim]  Detected: {seed_device_type}[/dim]")

        creds = {
            "username": args.username,
            "password": args.password or "",
            "device_type": seed_device_type,
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
            from netsleuth_loopfinder.logparse import LogFindings
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
            use_hint_for_all=False,
            extra_creds=extra_creds,
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
