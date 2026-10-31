"""
Integration test of the live SSH path (connect, autodetect, fallback creds,
parallel crawl, raw capture, replay) against fake Cisco switches on loopback.
"""

import socket

import pytest

from fake_switch import FakeSwitch
from netsleuth_loopfinder.analysis import ScanOptions, run_replay, run_scan

VERSION = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3\n{h} uptime is 1 week\n"


def _cdp(entries):
    out = []
    for host, ip, local, remote, platform, caps in entries:
        out.append(
            "-------------------------\n"
            f"Device ID: {host}\nEntry address(es): \n  IP address: {ip}\n"
            f"Platform: {platform},  Capabilities: {caps}\n"
            f"Interface: {local},  Port ID (outgoing port): {remote}\nHoldtime : 150 sec\n"
        )
    return "\n".join(out)


STP_HEAD = "Interface           Role Sts Cost      Prio.Nbr Type\n------------------- ---- --- --------- -------- -----\n"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def lab():
    port = _free_port()
    core = FakeSwitch("127.0.0.1", port, "CORE", {
        "show version": VERSION.format(h="CORE"),
        "show cdp neighbors detail": _cdp([
            ("ACCESS.school.local", "127.0.0.2", "GigabitEthernet1/0/1", "GigabitEthernet0/1", "cisco WS-C2960X", "Switch IGMP"),
            ("ACCESS.school.local", "127.0.0.2", "GigabitEthernet1/0/2", "GigabitEthernet0/2", "cisco WS-C2960X", "Switch IGMP"),
        ]),
        "show spanning-tree": STP_HEAD + "Gi1/0/1             Desg FWD 4         128.1    P2p\nGi1/0/2             Desg FWD 4         128.2    P2p\n",
        "show logging": "Log Buffer (4096 bytes):\n",
    })
    access = FakeSwitch("127.0.0.2", port, "ACCESS", {
        "show version": VERSION.format(h="ACCESS"),
        "show cdp neighbors detail": _cdp([
            ("CORE", "127.0.0.1", "GigabitEthernet0/1", "GigabitEthernet1/0/1", "cisco WS-C3850", "Router Switch IGMP"),
            ("CORE", "127.0.0.1", "GigabitEthernet0/2", "GigabitEthernet1/0/2", "cisco WS-C3850", "Router Switch IGMP"),
            ("SEP00AA00BB00CC", "127.0.0.3", "GigabitEthernet0/5", "Port 1", "Cisco IP Phone 7841", "Host Phone"),
        ]),
        # The second uplink is blocked by STP on the ACCESS side only.
        "show spanning-tree": STP_HEAD + "Gi0/1               Root FWD 4         128.1    P2p\nGi0/2               Altn BLK 4         128.2    P2p\nGi0/5               Desg FWD 4         128.5    P2p Edge\n",
        "show logging": "%SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.4455 in vlan 10 is flapping between port Gi0/5 and port Gi0/1\n",
    }, password="other")
    yield port, core, access
    core.close()
    access.close()


def test_live_crawl_detect_fallback_creds_and_replay(lab, tmp_path):
    port, core, access = lab
    raw = tmp_path / "run"
    logs = []
    result = run_scan(ScanOptions(
        seed_ip="127.0.0.1", username="admin", password="secret", port=port,
        extra_creds=[{"password": "other"}], collect_counters=False, raw_dir=str(raw),
    ), log=logs.append)

    assert set(result.devices) == {"CORE", "ACCESS"}, logs
    assert all(d.reachable for d in result.devices.values()), [d.error for d in result.devices.values()]
    assert result.devices["ACCESS"].device_type.startswith("cisco")
    # The phone was seen but never SSH'd into.
    assert "127.0.0.3" not in {d.ip for d in result.devices.values()}
    # Two uplinks without a port-channel = one redundant path, blocked on the ACCESS side.
    assert [l.status for l in result.loops] == ["blocked"]
    assert any("MAC flapping on ACCESS" in f.title for f in result.findings)
    assert (raw / "127.0.0.1.json").exists() and (raw / "127.0.0.2.txt").exists()
    assert (raw / "results.json").exists()

    replayed = run_replay(str(raw))
    assert set(replayed.devices) == {"CORE", "ACCESS"}
    assert [l.status for l in replayed.loops] == ["blocked"]


def test_wrong_password_reports_auth_failure(lab, tmp_path):
    port, _core, _access = lab
    result = run_scan(ScanOptions(seed_ip="127.0.0.1", username="admin", password="nope", port=port,
                                  device_type="cisco_ios", collect_counters=False))
    d = result.devices["127.0.0.1"]
    assert not d.reachable and "authentication" in d.error
