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

All neighbour relationships must be **bidirectional**: if SW1 lists SW2 as a
neighbour, SW2 must also list SW1.

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

import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from loop_finder.discovery import Device, Neighbor

console = Console()


def discover_mock(topology_path: str) -> dict[str, Device]:
    """
    Load a topology from *topology_path* (YAML) and return a ``dict[str, Device]``
    that mirrors what the real ``discover()`` function would return.

    Rich output is printed for each device so the user experience matches the
    live discovery workflow.

    :param topology_path: Path to a topology YAML file.
    :returns: Mapping of hostname -> :class:`~loop_finder.discovery.Device`.
    :raises FileNotFoundError: If *topology_path* does not exist.
    :raises ValueError: If the YAML file is missing required fields.
    """
    with open(topology_path, "r") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict) or "devices" not in data:
        raise ValueError(
            f"Topology file '{topology_path}' must contain a top-level 'devices' key."
        )

    raw_devices: dict = data["devices"]
    devices: dict[str, Device] = {}

    with Progress(
        SpinnerColumn(spinner_name="line"),
        TextColumn("{task.description}"),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Starting mock discovery...", total=None)

        for hostname, attrs in raw_devices.items():
            ip = attrs.get("ip", "")
            progress.update(task, description=f"Loading {hostname} (mock)...")

            raw_neighbors = attrs.get("neighbors", [])
            neighbors: list[Neighbor] = []
            for n in raw_neighbors:
                neighbor_hostname = n.get("hostname", "")
                if not neighbor_hostname:
                    raise ValueError(
                        f"Neighbour entry under '{hostname}' is missing a 'hostname' field."
                    )
                neighbors.append(
                    Neighbor(
                        hostname=neighbor_hostname,
                        local_port=n.get("local_port", ""),
                        remote_port=n.get("remote_port", ""),
                        ip=n.get("ip", ""),
                    )
                )

            device = Device(hostname=hostname, ip=ip, neighbors=neighbors)
            devices[hostname] = device
            progress.console.print(
                f"[green]  Loaded: {hostname} - {len(neighbors)} neighbour(s)[/green]"
            )

    console.print(
        f"[bold green]Mock discovery complete: {len(devices)} device(s) loaded.[/bold green]"
    )
    return devices
