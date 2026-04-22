from netsleuth_core.models import Device, Neighbor
from netsleuth_loopfinder.graph import build_graph, get_loop_edges
from netsleuth_loopfinder import stp


def test_get_loop_edges_for_two_node_cycle_keeps_both_orientations():
    devices = {
        "SW1": Device(
            hostname="SW1",
            ip="10.0.0.1",
            neighbors=[
                Neighbor(hostname="SW2", local_port="Gi0/1", remote_port="Gi0/1"),
                Neighbor(hostname="SW2", local_port="Gi0/2", remote_port="Gi0/2"),
            ],
        ),
        "SW2": Device(hostname="SW2", ip="10.0.0.2", neighbors=[]),
    }
    graph = build_graph(devices)

    edges = get_loop_edges(graph, ["SW1", "SW2"])

    assert len(edges) == 4
    assert {(e["from"], e["to"]) for e in edges} == {("SW1", "SW2"), ("SW2", "SW1")}
    assert {e["local_port"] for e in edges if e["from"] == "SW1"} == {"Gi0/1", "Gi0/2"}
    assert {e["local_port"] for e in edges if e["from"] == "SW2"} == {"Gi0/1", "Gi0/2"}


def test_build_graph_deduplicates_abbreviated_and_expanded_port_names():
    devices = {
        "SW1": Device(
            hostname="SW1",
            ip="10.0.0.1",
            neighbors=[Neighbor(hostname="SW2", local_port="Gi0/1", remote_port="Gi0/1")],
        ),
        "SW2": Device(
            hostname="SW2",
            ip="10.0.0.2",
            neighbors=[
                Neighbor(
                    hostname="SW1",
                    local_port="GigabitEthernet0/1",
                    remote_port="GigabitEthernet0/1",
                )
            ],
        ),
    }

    graph = build_graph(devices)

    assert graph.number_of_edges("SW1", "SW2") == 1


class _FakeConn:
    device_type = "arista_eos"

    def send_command(self, _):
        return ""

    def disconnect(self):
        return None


def test_get_stp_status_uses_detected_device_type(monkeypatch):
    captured = {}

    def fake_detect_device_type(**kwargs):
        return "arista_eos"

    def fake_connect(**kwargs):
        captured["device_type"] = kwargs["device_type"]
        return _FakeConn()

    monkeypatch.setattr(stp, "detect_device_type", fake_detect_device_type)
    monkeypatch.setattr(stp, "connect", fake_connect)
    monkeypatch.setattr(stp, "_parse_stp_output", lambda output: {"Ethernet1": "FWD"})

    devices = {"SW1": Device(hostname="SW1", ip="10.0.0.1", neighbors=[])}
    creds = {"username": "u", "password": "p", "device_type": "cisco_ios", "port": 22}

    result = stp.get_stp_status(devices, creds)

    assert captured["device_type"] == "arista_eos"
    assert result == {"SW1": {"Ethernet1": "FWD"}}


def test_get_stp_status_falls_back_to_configured_device_type(monkeypatch):
    captured = {}

    def fake_detect_device_type(**kwargs):
        return "cisco_ios"

    def fake_connect(**kwargs):
        captured["device_type"] = kwargs["device_type"]
        return _FakeConn()

    monkeypatch.setattr(stp, "detect_device_type", fake_detect_device_type)
    monkeypatch.setattr(stp, "connect", fake_connect)
    monkeypatch.setattr(stp, "_parse_stp_output", lambda output: {"Ethernet1": "FWD"})

    devices = {"SW1": Device(hostname="SW1", ip="10.0.0.1", neighbors=[])}
    creds = {"username": "u", "password": "p", "device_type": "juniper_junos", "port": 22}

    result = stp.get_stp_status(devices, creds)

    assert captured["device_type"] == "juniper_junos"
    assert result == {"SW1": {"Ethernet1": "FWD"}}
