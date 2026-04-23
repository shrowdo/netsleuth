import pytest
from netsleuth_core.models import Device, Neighbor
from netsleuth_loopfinder.graph import build_graph, get_loop_edges, suggest_remediation, find_loops
from netsleuth_loopfinder import stp
from netsleuth_loopfinder.logparse import parse_logs
from netsleuth_loopfinder.stp import _parse_stp_output_juniper, _parse_stp_output_huawei


def test_get_loop_edges_for_two_node_cycle_is_not_duplicated():
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

    assert len(edges) == 2
    assert {e["local_port"] for e in edges} == {"Gi0/1", "Gi0/2"}


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
    captured = []
    detect_calls = []

    def fake_detect_device_type(**kwargs):
        detect_calls.append(kwargs["ip"])
        return "arista_eos"

    def fake_connect(**kwargs):
        captured.append((kwargs["ip"], kwargs["device_type"]))
        return _FakeConn()

    monkeypatch.setattr(stp, "detect_device_type", fake_detect_device_type)
    monkeypatch.setattr(stp, "connect", fake_connect)
    monkeypatch.setattr(stp, "_parse_stp_output", lambda output: {"Ethernet1": "FWD"})

    devices = {
        "SW1": Device(hostname="SW1", ip="10.0.0.1", neighbors=[]),
        "SW2": Device(
            hostname="SW2",
            ip="10.0.0.2",
            neighbors=[],
            device_type="juniper_junos",
        ),
    }
    creds = {"username": "u", "password": "p", "device_type": "cisco_ios", "port": 22}

    result = stp.get_stp_status(devices, creds)

    assert detect_calls == ["10.0.0.1"]
    assert captured == [("10.0.0.1", "arista_eos"), ("10.0.0.2", "juniper_junos")]
    assert result == {"SW1": {"Ethernet1": "FWD"}, "SW2": {"Ethernet1": "FWD"}}


# ---------------------------------------------------------------------------
# parse_logs tests
# ---------------------------------------------------------------------------

_LOG_WITH_LOOP = """
Jan 1 00:01:00: %SW_MATM-4-MACFLAP_NOTIF: Host aabb.cc00.0001 in vlan 10 is flapping between port Gi0/1 and Gi0/2
Jan 1 00:01:01: %SW_MATM-4-MACFLAP_NOTIF: Host aabb.cc00.0001 in vlan 10 is flapping between port Gi0/1 and Gi0/2
Jan 1 00:01:02: %STORM_CONTROL-3-SHUTDOWN: A loop is detected on Gi0/2
Jan 1 00:01:03: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi0/1 with BPDU Guard enabled
Jan 1 00:01:04: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:05: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:06: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:07: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
Jan 1 00:01:08: %SPANTREE-5-TOPOTRAP: Topology Change Trap on vlan 1
"""

_LOG_CLEAN = """
Jan 1 00:00:01: %SYS-5-CONFIG_I: Configured from console by admin
Jan 1 00:00:02: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
"""


def test_parse_logs_detects_mac_flap_deduplicates():
    findings = parse_logs(_LOG_WITH_LOOP)
    assert len(findings.mac_flaps) == 1
    flap = findings.mac_flaps[0]
    assert flap["mac"] == "aabb.cc00.0001"
    assert flap["vlan"] == "10"
    assert set(flap["ports"]) == {"GigabitEthernet0/1", "GigabitEthernet0/2"}


def test_parse_logs_detects_storm_control():
    findings = parse_logs(_LOG_WITH_LOOP)
    assert len(findings.storm_shutdowns) == 1
    assert findings.storm_shutdowns[0]["port"] == "GigabitEthernet0/2"
    assert findings.storm_shutdowns[0]["action"] == "Shutdown"


def test_parse_logs_detects_bpdu_violation():
    findings = parse_logs(_LOG_WITH_LOOP)
    assert len(findings.bpdu_violations) == 1
    assert findings.bpdu_violations[0]["port"] == "GigabitEthernet0/1"
    assert findings.bpdu_violations[0]["type"] == "BLOCK_BPDUGUARD"


def test_parse_logs_detects_tcn_burst():
    findings = parse_logs(_LOG_WITH_LOOP)
    assert len(findings.tcn_bursts) == 1
    assert findings.tcn_bursts[0]["count"] == 5


def test_parse_logs_has_findings_true():
    assert parse_logs(_LOG_WITH_LOOP).has_findings is True


def test_parse_logs_clean_has_no_findings():
    findings = parse_logs(_LOG_CLEAN)
    assert findings.has_findings is False
    assert findings.mac_flaps == []
    assert findings.storm_shutdowns == []
    assert findings.bpdu_violations == []
    assert findings.tcn_bursts == []


def test_parse_logs_suspect_ports():
    findings = parse_logs(_LOG_WITH_LOOP)
    ports = findings.suspect_ports
    assert "GigabitEthernet0/1" in ports
    assert "GigabitEthernet0/2" in ports


# ---------------------------------------------------------------------------
# STP vendor parser tests
# ---------------------------------------------------------------------------

_JUNIPER_STP = """\
Interface    State         Role
ge-0/0/0.0   Forwarding    Designated
ge-0/0/1.0   Blocking      Root
ge-0/0/2.0   Learning      Alternate
"""

_HUAWEI_STP = """\
 MSTID  Port                        Role  STP State    Protection
 0      GigabitEthernet0/0/1        ROOT  FORWARDING   NONE
 0      GigabitEthernet0/0/2        DESI  BLOCKING     NONE
 0      GigabitEthernet0/0/3        ALTE  DISCARDING   NONE
"""


def test_parse_stp_output_juniper():
    ports = _parse_stp_output_juniper(_JUNIPER_STP)
    assert ports["ge-0/0/0.0"] == "FWD"
    assert ports["ge-0/0/1.0"] == "BLK"
    assert ports["ge-0/0/2.0"] == "LRN"


def test_parse_stp_output_huawei():
    ports = _parse_stp_output_huawei(_HUAWEI_STP)
    assert ports["GigabitEthernet0/0/1"] == "FWD"
    assert ports["GigabitEthernet0/0/2"] == "BLK"
    assert ports["GigabitEthernet0/0/3"] == "BLK"  # DISCARDING maps to BLK


# ---------------------------------------------------------------------------
# suggest_remediation tests
# ---------------------------------------------------------------------------

def _triangle_graph():
    """SW1-SW2-SW3-SW1 triangle (one 3-node loop)."""
    devices = {
        "SW1": Device("SW1", "10.0.0.1", [
            Neighbor("SW2", "Gi0/1", "Gi0/1"),
            Neighbor("SW3", "Gi0/2", "Gi0/1"),
        ]),
        "SW2": Device("SW2", "10.0.0.2", [
            Neighbor("SW1", "Gi0/1", "Gi0/1"),
            Neighbor("SW3", "Gi0/2", "Gi0/2"),
        ]),
        "SW3": Device("SW3", "10.0.0.3", [
            Neighbor("SW1", "Gi0/1", "Gi0/2"),
            Neighbor("SW2", "Gi0/2", "Gi0/2"),
        ]),
    }
    return build_graph(devices)


def test_suggest_remediation_single_loop():
    G = _triangle_graph()
    loops = find_loops(G)
    assert len(loops) == 1
    suggestions = suggest_remediation(G, loops)
    assert len(suggestions) == 1
    s = suggestions[0]
    assert s["loop"] == 1
    assert s["port"] != "?"
    assert s["disable_on"] in ("SW1", "SW2", "SW3")


def test_suggest_remediation_empty_loops():
    G = _triangle_graph()
    suggestions = suggest_remediation(G, [])
    assert suggestions == []


def test_suggest_remediation_overlapping_loops_picks_shared_edge():
    """Two loops sharing one edge — remediation should pick that edge."""
    # SW1-SW2-SW3 triangle + SW1-SW2 parallel link (two separate loops sharing SW1-SW2)
    devices = {
        "SW1": Device("SW1", "10.0.0.1", [
            Neighbor("SW2", "Gi0/1", "Gi0/1"),
            Neighbor("SW2", "Gi0/2", "Gi0/2"),  # parallel link
            Neighbor("SW3", "Gi0/3", "Gi0/1"),
        ]),
        "SW2": Device("SW2", "10.0.0.2", [
            Neighbor("SW1", "Gi0/1", "Gi0/1"),
            Neighbor("SW1", "Gi0/2", "Gi0/2"),
            Neighbor("SW3", "Gi0/3", "Gi0/2"),
        ]),
        "SW3": Device("SW3", "10.0.0.3", [
            Neighbor("SW1", "Gi0/1", "Gi0/3"),
            Neighbor("SW2", "Gi0/2", "Gi0/3"),
        ]),
    }
    G = build_graph(devices)
    loops = find_loops(G)
    assert len(loops) >= 2
    suggestions = suggest_remediation(G, loops)
    assert len(suggestions) == len(loops)
    # All suggestions must name a valid port (not "?")
    for s in suggestions:
        assert s["port"] != "?"
