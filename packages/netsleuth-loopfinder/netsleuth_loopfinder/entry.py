"""
Entry point for the `loop-finder` CLI command.

Usage:
    loop-finder                                  # interactive TUI
    loop-finder 10.0.0.1 -u admin                # scan from a seed switch (prompts for password)
    loop-finder 10.0.0.1 -u admin --extra-creds manager:secret
    loop-finder --listen                         # no login: listen on this port for storms / CDP / LLDP / STP
    loop-finder --scan                           # list SSH hosts on the local subnet
    loop-finder --replay netsleuth-runs/<run>    # re-analyse a saved run offline
    loop-finder --mock topologies/school_storm.yaml
"""

import argparse
import getpass
import os
import sys

from rich.console import Console

console = Console()

DEVICE_TYPES = [
    "netgear_web",
    "auto", "cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos", "hp_procurve",
    "aruba_aoscx", "juniper_junos", "huawei", "hp_comware",
    # Shorthands - try each variant on connect
    "aruba", "hp",
]


def _resolve_path(path: str) -> str:
    """Resolve a path, falling back to files bundled inside the PyInstaller exe."""
    if os.path.exists(path):
        return path
    if hasattr(sys, "_MEIPASS"):
        bundled = os.path.join(sys._MEIPASS, path)
        if os.path.exists(bundled):
            return bundled
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loop-finder",
        description="Find network loops and broadcast storms via SSH + CDP/LLDP + STP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  loop-finder                                   (interactive)\n"
            "  loop-finder 10.0.0.1 -u admin\n"
            "  loop-finder 10.0.0.1 -u admin --extra-creds manager:secret\n"
            "  loop-finder --listen                          (no login needed)\n"
            "  loop-finder --scan\n"
            "  loop-finder --replay netsleuth-runs/2026-10-31_101500\n"
            "  loop-finder --mock topologies/school_storm.yaml\n\n"
            "Exit code: 0 = all clear, 1 = problem found, 2 = error."
        ),
    )
    parser.add_argument("host", nargs="?", metavar="HOST", help="IP of the seed switch to start from")
    parser.add_argument("-u", "--username", help="SSH username")
    parser.add_argument("-p", "--password",
                        help="SSH password (omit to be prompted; or set NETSLEUTH_PASSWORD)")
    parser.add_argument("--device-type", default="auto", metavar="TYPE",
                        help=f"Seed switch type (default: auto). One of: {', '.join(DEVICE_TYPES)}. "
                             "Other switches are identified from CDP/LLDP.")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy URL for netgear_web collection")
    parser.add_argument("--key-file", metavar="PATH", help="SSH private key file")
    parser.add_argument("--extra-creds", nargs="+", metavar="user:pass",
                        help="Fallback credentials tried in order when login fails")
    parser.add_argument("--max-depth", type=int, default=None, help="Limit hops from the seed switch")
    parser.add_argument("--timeout", type=int, default=None, metavar="SECONDS",
                        help="Stop starting new switches after this long")
    parser.add_argument("--workers", type=int, default=6, help="Switches to query in parallel (default: 6)")
    parser.add_argument("--no-counters", action="store_true",
                        help="Skip broadcast-rate sampling (saves ~5s per switch)")
    parser.add_argument("--json", metavar="FILE", help="Also write full results to a JSON file")
    parser.add_argument("--save-dir", metavar="DIR",
                        help="Where to save raw switch output (default: netsleuth-runs/<timestamp>)")
    parser.add_argument("--no-save", action="store_true", help="Don't save raw switch output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show phones/APs in the topology")
    parser.add_argument("--mock", metavar="TOPOLOGY", help="Load a topology YAML instead of SSH (testing)")
    parser.add_argument("--replay", metavar="DIR", help="Re-analyse a saved run folder offline")
    parser.add_argument("--scan", action="store_true",
                        help="List SSH-reachable hosts on the local subnet(s), then exit")
    parser.add_argument("--listen", nargs="?", const=15, type=int, metavar="SECONDS",
                        help="Passive mode, no login: listen on this laptop's port for broadcast "
                             "storms, looping frames, STP changes and CDP/LLDP (default 15s; needs Npcap)")
    parser.add_argument("--iface", metavar="NAME", help="Network adapter for --listen")
    parser.add_argument("--no-scan", action="store_true", help=argparse.SUPPRESS)
    return parser


def _parse_extra_creds(raw: list[str] | None) -> list[dict] | None:
    if not raw:
        return None
    parsed = []
    for token in raw:
        if ":" in token:
            u, p = token.split(":", 1)
            parsed.append({"username": u, "password": p})
        else:
            console.print(f"[yellow]Ignoring --extra-creds entry {token!r} (expected user:pass)[/yellow]")
    return parsed or None


def _run_scan() -> None:
    from netsleuth_loopfinder.scan import get_local_subnets, scan_subnet_for_ssh

    console.rule("[bold blue]Loop Finder - SSH scan[/bold blue]")
    subnets = get_local_subnets()
    if not subnets:
        console.print("[yellow]No local subnets detected - is the network cable plugged in "
                      "and does the adapter have an IP?[/yellow]")
        return
    console.print(f"[dim]Scanning: {', '.join(subnets)}[/dim]\n")
    found_any = False
    for subnet in subnets:
        for host in scan_subnet_for_ssh(subnet, with_banner=True):
            found_any = True
            console.print(f"  [green]{host['ip']:<16}[/green] [dim]{host['banner']}[/dim]")
    if not found_any:
        console.print("[yellow]No SSH-reachable hosts found.[/yellow]")


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.scan:
            _run_scan()
            sys.exit(0)

        if args.listen is not None:
            from netsleuth_loopfinder.listen import run_listen
            sys.exit(run_listen(args.listen, args.iface, console))

        # No arguments at all: interactive TUI.
        if not (args.mock or args.replay or args.host or args.username):
            try:
                from netsleuth_loopfinder.tui import LoopFinderTUI
                LoopFinderTUI().run()
            except Exception as e:
                console.print(f"[red]TUI failed to start: {e}[/red]")
                console.print("[dim]Try Windows Terminal, or run: loop-finder <switch-ip> -u <username>[/dim]")
                sys.exit(2)
            return

        from netsleuth_loopfinder.analysis import ScanOptions, default_raw_dir, run_mock, run_replay, run_scan
        from netsleuth_loopfinder.cli import print_result

        log = console.print
        console.rule("[bold blue]Network Loop Finder[/bold blue]")

        if args.mock:
            console.print(f"[yellow]Mock mode: {args.mock}[/yellow]")
            result = run_mock(_resolve_path(args.mock), log=log)
        elif args.replay:
            console.print(f"[yellow]Replaying saved run: {args.replay}[/yellow]")
            result = run_replay(args.replay, log=log)
        else:
            if not args.host:
                parser.error("HOST (the seed switch IP) is required")
            if not args.username:
                args.username = input("Username: ").strip()
            if not args.password and not args.key_file:
                args.password = os.environ.get("NETSLEUTH_PASSWORD") or getpass.getpass("Password: ")

            raw_dir = None if args.no_save else (args.save_dir or default_raw_dir())
            opts = ScanOptions(
                seed_ip=args.host,
                username=args.username,
                password=args.password or "",
                device_type=args.device_type,
                port=args.port,
                key_file=args.key_file,
                extra_creds=_parse_extra_creds(args.extra_creds),
                max_depth=args.max_depth,
                timeout_seconds=args.timeout,
                workers=args.workers,
                collect_counters=not args.no_counters,
                raw_dir=raw_dir,
                proxy_url=args.proxy,
            )
            with console.status("[cyan]Discovering switches...[/cyan]", spinner="line"):
                result = run_scan(opts, log=log)

        if not result.devices or not any(d.reachable for d in result.devices.values()):
            for d in result.devices.values():
                console.print(f"[red]{d.ip}: {d.error}[/red]")
            console.print("[red]Couldn't log into any switch. Check the IP, that this laptop can reach "
                          "it (ping), and the credentials.[/red]")
            sys.exit(2)

        print_result(result, verbose=args.verbose)

        if args.json:
            result.write_json(args.json)
            console.print(f"[dim]Results written to {args.json}[/dim]")

        level, _ = result.verdict
        sys.exit(1 if level == "critical" else (0 if result.coverage_complete else 2))

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(2)


if __name__ == "__main__":
    main()
