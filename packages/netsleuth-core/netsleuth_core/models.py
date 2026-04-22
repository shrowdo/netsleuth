from dataclasses import dataclass, field


@dataclass
class Neighbor:
    hostname: str
    local_port: str
    remote_port: str
    ip: str = ""


@dataclass
class Device:
    hostname: str
    ip: str
    neighbors: list[Neighbor] = field(default_factory=list)
    reachable: bool = True
