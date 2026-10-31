"""
Crawl the switch network from a seed IP using CDP/LLDP neighbour data.

Switches are visited in parallel waves (one hop per wave). Only neighbours
that look like switches are crawled; phones, APs and hosts are kept as leaf
nodes in the topology but never SSH'd into.
"""

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from netmiko import NetmikoAuthenticationException, NetmikoTimeoutException

from netsleuth_core.models import Device, Neighbor
from netsleuth_core.ssh import open_device

from netsleuth_loopfinder.collect import RecordingConn, collect_device, save_record

# Re-exported for older imports.
__all__ = ["discover", "Device", "Neighbor"]


def _creds_sets(creds: dict, extra_creds: list[dict] | None) -> list[dict]:
    base = {
        "username": creds["username"],
        "password": creds.get("password", ""),
        "port": creds.get("port", 22),
        "key_file": creds.get("key_file"),
    }
    sets = [base]
    for ec in extra_creds or []:
        merged = dict(base)
        merged.update({k: v for k, v in ec.items() if v is not None})
        sets.append(merged)
    return sets


def _signature(device: Device) -> frozenset:
    from netsleuth_core.ports import canonical_port

    return frozenset((canonical_port(n.local_port), n.hostname.lower()) for n in device.neighbors)


def _visit(
    ip: str,
    hint: str,
    creds_sets: list[dict],
    collect_counters: bool,
    raw_dir: str | None,
    log: Callable[[str], None],
) -> Device:
    conn = None
    recorder = None
    device_type = hint
    try:
        conn, device_type, creds_idx = open_device(ip, creds_sets, hint, log)
        if creds_idx:
            log(f"[dim]  {ip}: logged in with fallback credentials #{creds_idx}[/dim]")
        recorder = RecordingConn(conn)
        device = collect_device(recorder, ip, device_type, collect_counters, log)
        return device
    except NetmikoAuthenticationException:
        return Device(hostname=ip, ip=ip, reachable=False, device_type=device_type,
                      error="authentication failed (all credential sets)")
    except NetmikoTimeoutException:
        return Device(hostname=ip, ip=ip, reachable=False, device_type=device_type,
                      error="SSH timeout")
    except Exception as exc:
        msg = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        return Device(hostname=ip, ip=ip, reachable=False, device_type=device_type, error=msg[:160])
    finally:
        if raw_dir and recorder is not None:
            try:
                save_record(raw_dir, ip, device_type, recorder)
            except Exception:
                pass
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass


def discover(
    seed_ip: str,
    creds: dict,
    max_depth: int = None,
    use_hint_for_all: bool = False,
    extra_creds: list[dict] = None,
    timeout_seconds: int = None,
    on_device_found: Callable[[str, str, int], None] | None = None,
    on_device_failed: Callable[[str, str], None] | None = None,
    log: Callable[[str], None] = lambda _m: None,
    workers: int = 6,
    collect_counters: bool = True,
    raw_dir: str | None = None,
) -> dict[str, Device]:
    """
    Discover the switch topology starting from *seed_ip*.

    Returns {name: Device} for every switch attempted (reachable or not).
    Names are hostnames, made unique with the IP if two switches share one
    (common with unconfigured switches all called "Switch").

    Args:
        creds:            username, password, device_type (or "auto"), port, key_file.
        max_depth:        Maximum hop depth from the seed (None = unlimited).
        use_hint_for_all: Use creds["device_type"] for every switch instead of
                          the per-neighbour CDP/LLDP hint.
        extra_creds:      Fallback credential dicts tried on auth failure.
        timeout_seconds:  Stop starting new waves after this long.
        on_device_found:  callable(hostname, ip, neighbor_count) per success.
        on_device_failed: callable(ip, reason) per failure.
        log:              callable(markup_str) for progress messages.
        workers:          Parallel SSH sessions.
        raw_dir:          Save every command's raw output here (for --replay).
    """
    creds_sets = _creds_sets(creds, extra_creds)
    seed_hint = creds.get("device_type", "auto")
    devices: dict[str, Device] = {}
    visited: set[str] = set()
    wave: list[tuple[str, str]] = [(seed_ip, seed_hint)]
    depth = 0
    started = time.monotonic()

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        while wave:
            if max_depth is not None and depth > max_depth:
                break
            if timeout_seconds is not None and time.monotonic() - started > timeout_seconds:
                log(f"[yellow]Discovery time limit ({timeout_seconds}s) reached - "
                    f"{len(wave)} switch(es) not visited[/yellow]")
                break

            for ip, _hint in wave:
                visited.add(ip)
            log(f"[cyan]Hop {depth}: connecting to {', '.join(ip for ip, _ in wave)}[/cyan]")
            futures = [
                (ip, pool.submit(_visit, ip, hint, creds_sets, collect_counters, raw_dir, log))
                for ip, hint in wave
            ]

            next_wave: list[tuple[str, str]] = []
            queued: set[str] = set()
            for ip, future in futures:
                device = future.result()
                name = device.hostname
                if name in devices and devices[name].ip != device.ip:
                    existing = devices[name]
                    if device.reachable and _signature(existing) == _signature(device):
                        # Same switch reached on a second management IP.
                        existing.alt_ips.append(device.ip)
                        log(f"[dim]  {ip} is {name} again (second management IP) - skipped[/dim]")
                        continue
                    name = f"{name} ({device.ip})"
                    device.hostname = name
                devices[name] = device

                if not device.reachable:
                    log(f"[red]  x {ip}: {device.error}[/red]")
                    if on_device_failed is not None:
                        on_device_failed(ip, device.error)
                    continue

                switches = [n for n in device.neighbors if n.role in ("switch", "unknown")]
                others = len(device.neighbors) - len(switches)
                log(f"[green]  + {name} ({ip}, {device.device_type}): "
                    f"{len(switches)} switch neighbour(s), {others} other device(s)[/green]")
                if on_device_found is not None:
                    on_device_found(name, ip, len(device.neighbors))

                for n in switches:
                    if n.ip and n.ip not in visited and n.ip not in queued:
                        queued.add(n.ip)
                        hint = seed_hint if use_hint_for_all else (n.device_type_hint or "auto")
                        next_wave.append((n.ip, hint))
                    elif not n.ip and n.role == "switch":
                        log(f"[yellow]  ! {name} {n.local_port} -> {n.hostname}: "
                            f"no management IP advertised, can't crawl it[/yellow]")

            wave = next_wave
            depth += 1

    return devices
