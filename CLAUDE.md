# network-loop-finder

Tool that discovers switch network topology via SSH + CDP/LLDP and detects loops using graph cycle detection.

## Stack
- Python, Netmiko (SSH), NetworkX (graph/cycles), Rich (CLI output), PyYAML

## Running
```bash
pip install -r requirements.txt
python main.py inventory.yaml              # real switches
python main.py --mock topologies/simple_loop.yaml  # simulation
```

## Working style
Use parallel subagents with `isolation: "worktree"` whenever tasks split across non-overlapping files or modules. Don't do sequential work when parallel is possible.
