"""Graph / STP evaluation / end-to-end tests."""

import json

from netsleuth_core.models import Device, Neighbor
from netsleuth_core.ports import canonical_port
from netsleuth_loopfinder.analysis import analyse, run_mock, run_replay
from netsleuth_loopfinder.collect import ReplayConn, collect_device
from netsleuth_loopfinder.graph import build_graph, evaluate_loop, find_loops

from tests_helpers import TOPOLOGIES  # noqa: F401  (path helper)


def _n(host, local, remote, ip="", role="switch"):
    return Neighbor(hostname=host, local_port=local, remote_port=remote, ip=ip, role=role)


def _dev(name, ip, neighbors, stp=None, lags=None, mode="enabled", reachable=True):
    return Device(name, ip, neighbors, reachable=reachable,
                  stp={canonical_port(k): v for k, v in (stp or {}).items()},
                  stp_mode=mode, lags={canonical_port(k): v for k, v in (lags or {}).items()})


def test_lacp_members_are_not_a_loop():
    devices = {
        "A": _dev("A", "10.0.0.1", [_n("B", "Gi1/0/49", "49", "10.0.0.2"), _n("B", "Gi1/0/50", "50", "10.0.0.2")],
                  stp={"Po1": "FWD"}, lags={"Gi1/0/49": "Po1", "Gi1/0/50": "Po1"}),
        "B": _dev("B", "10.0.0.2", [_n("A", "49", "Gi1/0/49", "10.0.0.1"), _n("A", "50", "Gi1/0/50", "10.0.0.1")],
                  stp={"Trk1": "FWD"}, lags={"49": "Trk1", "50": "Trk1"}),
    }
    G = build_graph(devices)
    assert G.number_of_edges("A", "B") == 1
    assert find_loops(G) == []


def test_parallel_links_without_lag_are_a_loop_blocked_on_far_side():
    devices = {
        "A": _dev("A", "10.0.0.1", [_n("B", "Gi0/1", "Gi0/1", "10.0.0.2"), _n("B", "Gi0/2", "Gi0/2", "10.0.0.2")],
                  stp={"Gi0/1": "FWD", "Gi0/2": "FWD"}),
        # The blocking port is on B's side - the old code only looked at A's.
        "B": _dev("B", "10.0.0.2", [_n("A", "Gi0/1", "Gi0/1", "10.0.0.1"), _n("A", "Gi0/2", "Gi0/2", "10.0.0.1")],
                  stp={"GigabitEthernet0/1": "FWD", "GigabitEthernet0/2": "BLK"}),
    }
    G = build_graph(devices)
    loops = find_loops(G)
    assert loops == [["A", "B"]]
    assert evaluate_loop(G, devices, loops[0])["status"] == "blocked"


def test_port_description_mismatch_does_not_double_count_a_cable():
    # B reports A's port as a description ("Uplink") rather than a port ID.
    devices = {
        "A": _dev("A", "10.0.0.1", [_n("B", "Gi0/1", "Gi0/24", "10.0.0.2")]),
        "B": _dev("B", "10.0.0.2", [_n("A", "Gi0/24", "Uplink", "10.0.0.1")]),
    }
    G = build_graph(devices)
    assert G.number_of_edges("A", "B") == 1
    assert find_loops(G) == []


def test_ring_active_when_every_port_forwards_and_ports_are_oriented():
    devices = {
        "A": _dev("A", "1.1.1.1", [_n("B", "1", "2", "1.1.1.2"), _n("C", "3", "4", "1.1.1.3")], stp={"1": "FWD", "3": "FWD"}),
        "B": _dev("B", "1.1.1.2", [_n("A", "2", "1", "1.1.1.1"), _n("C", "5", "6", "1.1.1.3")], stp={"2": "FWD", "5": "FWD"}),
        "C": _dev("C", "1.1.1.3", [_n("A", "4", "3", "1.1.1.1"), _n("B", "6", "5", "1.1.1.2")], stp={"4": "FWD", "6": "FWD"}),
    }
    G = build_graph(devices)
    loops = find_loops(G)
    assert len(loops) == 1
    ev = evaluate_loop(G, devices, loops[0])
    assert ev["status"] == "active"
    expected = {("A", "B"): ("1", "2"), ("B", "A"): ("2", "1"), ("A", "C"): ("3", "4"),
                ("C", "A"): ("4", "3"), ("B", "C"): ("5", "6"), ("C", "B"): ("6", "5")}
    for e in ev["edges"]:
        assert (e["local_port"], e["remote_port"]) == expected[(e["from"], e["to"])]


def test_unknown_when_a_switch_could_not_be_read():
    devices = {
        "A": _dev("A", "1.1.1.1", [_n("B", "1", "2", "1.1.1.2"), _n("C", "3", "4", "1.1.1.3")], stp={"1": "FWD", "3": "FWD"}),
        "B": _dev("B", "1.1.1.2", [_n("A", "2", "1", "1.1.1.1"), _n("C", "5", "6", "1.1.1.3")], stp={"2": "FWD", "5": "FWD"}),
    }
    # C is a switch we never logged into; B-C and A-C come only from A and B.
    G = build_graph(devices)
    loops = find_loops(G)
    assert len(loops) == 1
    assert evaluate_loop(G, devices, loops[0])["status"] == "unknown"


def test_unmanaged_device_on_two_switch_ports_is_an_active_loop():
    devices = {
        "A": _dev("A", "1.1.1.1", [_n("B", "1", "1", "1.1.1.2"), _n("DESK-PC", "10", "eth0", role="endpoint")],
                  stp={"1": "FWD", "10": "FWD"}),
        "B": _dev("B", "1.1.1.2", [_n("A", "1", "1", "1.1.1.1"), _n("DESK-PC", "20", "eth0", role="endpoint")],
                  stp={"1": "FWD", "20": "FWD"}),
    }
    result = analyse(devices)
    assert [l.status for l in result.loops] == ["active"]
    assert result.verdict[0] == "critical"


def test_stp_disabled_switch_makes_loop_active():
    devices = {
        "A": _dev("A", "1.1.1.1", [_n("A", "14", "22", "1.1.1.1"), _n("A", "22", "14", "1.1.1.1")], mode="disabled"),
    }
    result = analyse(devices)
    assert len(result.loops) == 1 and result.loops[0].status == "active"
    assert any("OFF" in f.title for f in result.findings)
    assert result.actions[0].commands  # tells you how to shut the port


def test_duplicate_hostnames_resolved_by_ip():
    devices = {
        "Switch": _dev("Switch", "1.1.1.1", [_n("Switch", "1", "1", "1.1.1.2")], stp={"1": "FWD"}),
        "Switch (1.1.1.2)": _dev("Switch (1.1.1.2)", "1.1.1.2", [_n("Switch", "1", "1", "1.1.1.1")], stp={"1": "FWD"}),
    }
    G = build_graph(devices)
    assert G.number_of_edges("Switch", "Switch (1.1.1.2)") == 1
    assert find_loops(G) == []


def test_mock_school_storm_end_to_end(tmp_path):
    result = run_mock(str(TOPOLOGIES / "school_storm.yaml"))
    assert result.verdict[0] == "critical"
    statuses = sorted(l.status for l in result.loops)
    assert statuses == ["active", "blocked"]  # LACP uplinks didn't create fake loops
    out = tmp_path / "r.json"
    result.write_json(str(out))
    assert json.loads(out.read_text())["verdict"]["level"] == "critical"


def test_legacy_mock_topologies_still_work():
    assert run_mock(str(TOPOLOGIES / "no_loop.yaml")).loops == []
    simple = run_mock(str(TOPOLOGIES / "simple_loop.yaml"))
    assert [l.status for l in simple.loops] == ["blocked"]


def test_replay_cisco_and_procurve_session(tmp_path):
    from test_parsers import (CISCO_COUNTERS, CISCO_ETHERCHANNEL, PROCURVE_BRIEF, PROCURVE_IFACES,
                              PROCURVE_LLDP_TABLE, PROCURVE_STP, PROCURVE_TRUNKS)

    core_lldp = """\
------------------------------------------------
Local Intf: Gi1/0/48
Chassis id: 001b.3f5c.2e00
Port id: 25
System Name: HP-ACCESS
System Description:
HP J9727A 2920-24G-PoE+ Switch, revision WB.16.10.0009
System Capabilities: B
Enabled Capabilities: B
Management Addresses:
    IP: 10.0.0.12
"""
    core_stp = """\
Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- ------
Gi1/0/48            Desg FWD 4         128.48   P2p
"""
    hp_detail = """\
  Local Port   : 25
  ChassisId    : 00 1b 3f 5c 2e 00
  PortId       : Gi1/0/48
  SysName      : CORE
  System Descr : Cisco IOS Software, C3850 Software
  System Capabilities Enabled    : bridge, router
     Address : 10.0.0.1
"""
    core = {"ip": "10.0.0.1", "device_type": "cisco_ios", "commands": [
        {"command": "__prompt__", "output": "CORE#", "t": 0},
        {"command": "show interfaces counters", "output": CISCO_COUNTERS, "t": 1},
        {"command": "show lldp neighbors detail", "output": core_lldp, "t": 2},
        {"command": "show spanning-tree", "output": core_stp, "t": 2},
        {"command": "show etherchannel summary", "output": CISCO_ETHERCHANNEL, "t": 3},
        {"command": "show interfaces counters", "output": CISCO_COUNTERS.replace("2000", "52000"), "t": 6},
    ]}
    hp = {"ip": "10.0.0.12", "device_type": "hp_procurve", "commands": [
        {"command": "__prompt__", "output": "HP-ACCESS#", "t": 0},
        {"command": "show lldp info remote-device", "output": PROCURVE_LLDP_TABLE, "t": 1},
        {"command": "show lldp info remote-device 25,48,5", "output": hp_detail, "t": 1},
        {"command": "show spanning-tree", "output": PROCURVE_STP, "t": 2},
        {"command": "show trunks", "output": PROCURVE_TRUNKS, "t": 2},
        {"command": "show interfaces brief", "output": PROCURVE_BRIEF, "t": 3},
        {"command": "show interfaces 1,14,49", "output": PROCURVE_IFACES, "t": 3},
    ]}
    d = collect_device(ReplayConn(core), "10.0.0.1", "cisco_ios")
    assert d.hostname == "CORE"
    assert d.port_rates[canonical_port("Gi1/0/1")] == 50000 / 5  # (52000-2000)/5s
    for rec in (core, hp):
        (tmp_path / f"{rec['ip']}.json").write_text(json.dumps(rec))
    result = run_replay(str(tmp_path))
    assert set(result.devices) == {"CORE", "HP-ACCESS"}
    assert result.graph.number_of_edges("CORE", "HP-ACCESS") == 1
    hot = {(h["device"], h["port"]): h for h in result.hot_ports}
    assert hot[("HP-ACCESS", "14")]["uplink"] is False
    assert any("Broadcast storm entering HP-ACCESS 14" in f.title for f in result.findings)
