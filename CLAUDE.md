# NetSleuth

All-in-one network engineering toolkit. Monorepo with individually-installable packages.

**GitHub:** https://github.com/shrowdo/netsleuth

## Stack
- Python, Netmiko (SSH), NetworkX (graph/cycles), Rich (CLI output), Textual (TUI), PyYAML

## Monorepo structure
```
packages/
  netsleuth-core/        # Shared: SSH connection, Device/Neighbor models, Rich console
  netsleuth-loopfinder/  # Standalone loop detection tool (depends on netsleuth-core)
  netsleuth/             # Meta-package: CLI dispatcher + Textual TUI (depends on all tools)
loop_finder/             # LEGACY — kept for reference, superseded by packages/
```

## Installing & running

### All-in-one
```bash
pip install packages/netsleuth packages/netsleuth-core packages/netsleuth-loopfinder
netsleuth                                        # launches TUI
netsleuth loopfinder 192.168.1.1 -u admin        # CLI, skip TUI
netsleuth lf --mock topologies/simple_loop.yaml  # mock mode
```

### Standalone loop finder only
```bash
pip install packages/netsleuth-core packages/netsleuth-loopfinder
loop-finder 192.168.1.1 -u admin
loop-finder --mock topologies/simple_loop.yaml
```

## Building executables

### All-in-one (netsleuth.exe)
```bash
pip install packages/netsleuth packages/netsleuth-core packages/netsleuth-loopfinder
pyinstaller --onefile --name netsleuth --collect-all netmiko --collect-all rich --collect-all networkx --collect-all textual packages/netsleuth/netsleuth/entry.py
```

### Standalone loop finder (loop-finder.exe)
```bash
pip install packages/netsleuth-core packages/netsleuth-loopfinder
pyinstaller --onefile --name loop-finder --collect-all netmiko --collect-all rich --collect-all networkx packages/netsleuth-loopfinder/netsleuth_loopfinder/entry.py
```
Output in `dist/`. Do NOT commit `dist/` — it's in `.gitignore`.

## Adding a new tool
1. Create `packages/netsleuth-<toolname>/` with its own `pyproject.toml`
2. Add dependency on `netsleuth-core` for shared SSH/models
3. Register it as a subcommand in `packages/netsleuth/netsleuth/entry.py`
4. Add a screen in `packages/netsleuth/netsleuth/tui/app.py`
5. Add its package as a dependency in `packages/netsleuth/pyproject.toml`

## Working style
Use parallel subagents with `isolation: "worktree"` whenever tasks split across non-overlapping files or modules. Don't do sequential work when parallel is possible.
