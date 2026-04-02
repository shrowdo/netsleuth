# network-loop-finder

Tool that discovers switch network topology via SSH + CDP/LLDP and detects loops using graph cycle detection.

## Stack
- Python, Netmiko (SSH), NetworkX (graph/cycles), Rich (CLI output), PyYAML

## Running
```bash
pip install -r requirements.txt
python main.py inventory.yaml              # real switches
python main.py --mock topologies/simple_loop.yaml  # simulation
loop-finder 192.168.1.1 -u admin          # installed CLI
```

## Building the executable
After any code changes, rebuild the `.exe`:
```bash
rm -rf build/ dist/ loop-finder.spec loop_finder/__pycache__
pyinstaller --onefile --name loop-finder --collect-all netmiko --collect-all rich --collect-all networkx loop_finder/entry.py
```
Output: `dist/loop-finder.exe` (81MB, self-contained, no Python needed on target machine).
Do NOT commit `dist/` — it's in `.gitignore`.

## Working style
Use parallel subagents with `isolation: "worktree"` whenever tasks split across non-overlapping files or modules. Don't do sequential work when parallel is possible.
