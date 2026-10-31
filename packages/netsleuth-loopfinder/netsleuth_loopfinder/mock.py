"""
Mock discovery module that loads a network topology from a YAML file and returns
``dict[str, Device]`` — the same type as ``discover()`` in ``discovery.py`` —
without performing any SSH connections.

Topology YAML format
--------------------
The YAML file must have a top-level ``devices`` key whose value is a mapping of
hostname strings to device objects.  Each device object has two keys:

``ip``
    The management IP address of the device (string).

``neighbors``
    A list of neighbor objects.  Each neighbor has:

    ``hostname``
        The hostname of the neighbouring device.
    ``local_port``
        The interface on *this* device that connects to the neighbour
        (e.g. ``GigabitEthernet0/1``).
    ``remote_port``
        The interface on the *neighbour* device that connects back to this one.
    ``ip``
        The management IP address of the neighbour (string, optional — defaults
        to an empty string if omitted).

Neighbour relationships are normally listed from both ends; a neighbour that
is only listed by one switch is treated as an unmanaged / unreachable device.

Optional per-device keys (to simulate live data):

``stp``            {port: FWD|BLK}  (if no device has ``stp``, the first port of
                   the first switch is blocked and the rest forward, as before)
``stp_mode``       enabled | disabled
``lags``           {member_port: lag_name}
``rates``          {port: inbound broadcast pkts/sec}
``logs``           raw log text, parsed like "show logging"
``reachable``      false to simulate a switch we couldn't log into

Optional per-neighbour keys: ``role`` (switch | endpoint) and ``platform``.

Example
-------
::

    devices:
      SW1:
        ip: 192.168.1.1
        neighbors:
          - hostname: SW2
            local_port: GigabitEthernet0/1
            remote_port: GigabitEthernet0/1
            ip: 192.168.1.2
          - hostname: SW3
            local_port: GigabitEthernet0/2
            remote_port: GigabitEthernet0/1
            ip: 192.168.1.3
      SW2:
        ip: 192.168.1.2
        neighbors:
          - hostname: SW1
            local_port: GigabitEthernet0/1
            remote_port: GigabitEthernet0/1
            ip: 192.168.1.1
"""

import os

import yaml

from netsleuth_core.models import Device, Neighbor
from netsleuth_core.platform import neighbor_role
from netsleuth_core.ports import canonical_port

from netsleuth_loopfinder.logparse import parse_logs

# Bundled topologies embedded directly so the exe works without any external files.
_BUNDLED_TOPOLOGIES = {
    "no_loop.yaml": {"devices": {"SW1": {"ip": "192.168.1.1", "neighbors": [{"hostname": "SW2", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.2"}, {"hostname": "SW3", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.3"}, {"hostname": "SW4", "local_port": "GigabitEthernet0/3", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.4"}]}, "SW2": {"ip": "192.168.1.2", "neighbors": [{"hostname": "SW1", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.1"}]}, "SW3": {"ip": "192.168.1.3", "neighbors": [{"hostname": "SW1", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.1"}]}, "SW4": {"ip": "192.168.1.4", "neighbors": [{"hostname": "SW1", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/3", "ip": "192.168.1.1"}]}}},
    "simple_loop.yaml": {"devices": {"SW1": {"ip": "192.168.1.1", "neighbors": [{"hostname": "SW2", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.2"}, {"hostname": "SW3", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.3"}]}, "SW2": {"ip": "192.168.1.2", "neighbors": [{"hostname": "SW1", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.1"}, {"hostname": "SW3", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.3"}]}, "SW3": {"ip": "192.168.1.3", "neighbors": [{"hostname": "SW2", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.2"}, {"hostname": "SW1", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.1"}]}}},
    "complex_loop.yaml": {"devices": {"SW1": {"ip": "192.168.1.1", "neighbors": [{"hostname": "SW2", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.2"}, {"hostname": "SW3", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.3"}]}, "SW2": {"ip": "192.168.1.2", "neighbors": [{"hostname": "SW1", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.1"}, {"hostname": "SW3", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.3"}, {"hostname": "SW4", "local_port": "GigabitEthernet0/3", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.4"}, {"hostname": "SW5", "local_port": "GigabitEthernet0/4", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.5"}]}, "SW3": {"ip": "192.168.1.3", "neighbors": [{"hostname": "SW2", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.2"}, {"hostname": "SW1", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.1"}]}, "SW4": {"ip": "192.168.1.4", "neighbors": [{"hostname": "SW2", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/3", "ip": "192.168.1.2"}, {"hostname": "SW5", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/1", "ip": "192.168.1.5"}]}, "SW5": {"ip": "192.168.1.5", "neighbors": [{"hostname": "SW4", "local_port": "GigabitEthernet0/1", "remote_port": "GigabitEthernet0/2", "ip": "192.168.1.4"}, {"hostname": "SW2", "local_port": "GigabitEthernet0/2", "remote_port": "GigabitEthernet0/4", "ip": "192.168.1.2"}]}}},
}


def _bundled_dir() -> str:
    import sys
    return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(__file__)), "topologies")


def _load_topology(topology_path: str) -> dict:
    """Load a topology file; fall back to the copies bundled into the exe."""
    candidates = [topology_path, os.path.join(_bundled_dir(), os.path.basename(topology_path))]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh)
    filename = os.path.basename(topology_path)
    if filename in _BUNDLED_TOPOLOGIES:
        return _BUNDLED_TOPOLOGIES[filename]
    raise FileNotFoundError(f"Topology file not found: {topology_path}")


def discover_mock(topology_path: str, log=lambda _m: None) -> dict[str, Device]:
    """
    Load a topology from *topology_path* (YAML) and return ``dict[str, Device]``
    shaped exactly like live discovery, without any SSH.

    :raises FileNotFoundError: If *topology_path* does not exist.
    :raises ValueError: If the YAML file is missing required fields.
    """
    data = _load_topology(topology_path)
    if not isinstance(data, dict) or "devices" not in data:
        raise ValueError(f"Topology file '{topology_path}' must contain a top-level 'devices' key.")

    devices: dict[str, Device] = {}
    for hostname, attrs in data["devices"].items():
        attrs = attrs or {}
        neighbors: list[Neighbor] = []
        for n in attrs.get("neighbors", []) or []:
            neighbor_hostname = n.get("hostname", "")
            if not neighbor_hostname:
                raise ValueError(f"Neighbour entry under '{hostname}' is missing a 'hostname' field.")
            nb = Neighbor(
                hostname=neighbor_hostname,
                local_port=n.get("local_port", ""),
                remote_port=n.get("remote_port", ""),
                ip=n.get("ip", ""),
                platform=n.get("platform", ""),
                capabilities=n.get("capabilities", ""),
            )
            nb.role = n.get("role") or neighbor_role(nb.capabilities, nb.platform, nb.hostname)
            if nb.role == "unknown":
                nb.role = "switch"
            neighbors.append(nb)

        device = Device(
            hostname=hostname,
            ip=attrs.get("ip", ""),
            neighbors=neighbors,
            reachable=attrs.get("reachable", True),
            device_type=attrs.get("device_type", "cisco_ios"),
            stp={canonical_port(p): str(s).upper() for p, s in (attrs.get("stp") or {}).items()},
            stp_mode=attrs.get("stp_mode", "enabled"),
            lags={canonical_port(p): lag for p, lag in (attrs.get("lags") or {}).items()},
            port_rates={canonical_port(p): float(r) for p, r in (attrs.get("rates") or {}).items()},
            rate_kind="mock",
            log_findings=parse_logs(attrs.get("logs", "") or ""),
            error="" if attrs.get("reachable", True) else "simulated: unreachable",
        )
        if not device.reachable:
            device.neighbors = []
        devices[hostname] = device
        log(f"[green]  Loaded {hostname} - {len(neighbors)} neighbour(s)[/green]")

    if not any(d.stp for d in devices.values()):
        # Legacy topologies: block the first port of the first switch.
        first = True
        for d in devices.values():
            for i, n in enumerate(d.neighbors):
                d.stp[canonical_port(n.local_port)] = "BLK" if first and i == 0 else "FWD"
            first = False

    log(f"[bold green]Mock discovery complete: {len(devices)} device(s) loaded.[/bold green]")
    return devices
