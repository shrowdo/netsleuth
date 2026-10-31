# NetSleuth

All-in-one network engineering toolkit. Monorepo with individually-installable packages.

**GitHub:** https://github.com/shrowdo/netsleuth

## Stack
- Python, Netmiko (SSH), NetworkX (graph/cycles), Rich (CLI output), Textual (TUI), PyYAML

## Monorepo structure
```
packages/
  netsleuth-core/        # Shared: SSH (connect/detect), Device/Neighbor models, port + platform helpers
  netsleuth-loopfinder/  # Loop / broadcast-storm finder (depends on netsleuth-core)
    netsleuth_loopfinder/
      analysis.py        # Pipeline: run_scan / run_mock / run_replay -> AnalysisResult (verdict, findings, actions)
      discovery.py       # Parallel CDP/LLDP crawl, switches only (phones/APs are leaves, never SSH'd)
      collect.py         # Everything gathered per switch in one session; records raw output for --replay
      neighbors.py stp.py counters.py logparse.py   # Pure text parsers per vendor (Cisco, ProCurve/AOS-S, AOS-CX, Huawei, Juniper)
      graph.py           # Graph build (IP-based identity, LAG collapse), loops, STP evaluation at both ends
      listen.py          # Passive no-login mode (needs Npcap on Windows)
      cli.py tui.py entry.py mock.py scan.py
      topologies/        # Mock topologies (package data, bundled into the exe)
    tests/               # Parser tests on realistic output, analysis, fake-SSH-switch integration, TUI pilot tests
  netsleuth/             # Meta-package: CLI dispatcher + menu TUI (runs loop-finder screens in-process)
loop_finder/             # LEGACY - superseded by packages/
```

## Using it
```
loop-finder                                   # TUI
loop-finder 10.0.0.1 -u admin                 # scan from a seed switch (raw output saved to netsleuth-runs/<time>)
loop-finder 10.0.0.1 -u admin --extra-creds manager:other
loop-finder --listen [SECONDS] [--iface NAME|list]   # no login: storm / looping frames / STP / which switch+port
loop-finder --scan                            # SSH hosts on the local subnet, with banners
loop-finder --replay netsleuth-runs/<time>    # re-analyse saved output offline (debug parsers with real data)
loop-finder --mock school_storm.yaml          # demo
```
Exit code: 0 all clear, 1 problem found, 2 error. `netsleuth lf ...` takes the same arguments.

How loops are judged: every cycle in the CDP/LLDP topology is a *redundant path*. It is only a problem
if STP isn't blocking it (checked at both ends of every link, per VLAN). Port-channel/trunk/LAG
members are one logical link. Unmanaged devices are invisible to CDP/LLDP, so storms are also hunted via
inbound broadcast rates per port, MAC flapping / loop-protect / storm-control logs, STP topology-change
source ports, ports with several LLDP neighbours, and a switch seeing its own LLDP.

## Testing
```bash
pip install -e packages/netsleuth-core -e packages/netsleuth-loopfinder -e packages/netsleuth pytest
pytest -q packages
```

## Building executables (Windows)
```powershell
powershell -ExecutionPolicy Bypass -File build.ps1 [-Python path	o\python.exe]
```
Runs the tests, then builds `dist/loop-finder.exe` and `dist/netsleuth.exe` (topologies bundled,
Textual + scapy collected). Do NOT commit `dist/` - it's in `.gitignore`.

## Adding a new tool
1. Create `packages/netsleuth-<toolname>/` with its own `pyproject.toml`
2. Add dependency on `netsleuth-core` for shared SSH/models
3. Register it as a subcommand in `packages/netsleuth/netsleuth/entry.py`
4. Add a screen in `packages/netsleuth/netsleuth/tui/app.py`
5. Add its package as a dependency in `packages/netsleuth/pyproject.toml`

## Working style
Use parallel subagents with `isolation: "worktree"` whenever tasks split across non-overlapping files or modules. Don't do sequential work when parallel is possible.
