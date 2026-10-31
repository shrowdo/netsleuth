import struct

from netsleuth_loopfinder.listen import ListenStats

SRC = bytes.fromhex("001122334455")


def _tlv(t: int, value: bytes) -> bytes:
    return struct.pack("!H", (t << 9) | len(value)) + value


def lldp_frame() -> bytes:
    body = (
        _tlv(1, b"\x04" + bytes.fromhex("001b3f5c2e00"))
        + _tlv(2, b"\x05" + b"14")
        + _tlv(5, b"ACCESS-2")
        + _tlv(6, b"HP J9727A 2920-24G-PoE+ Switch, revision WB.16.10")
        + _tlv(8, bytes([5, 1, 10, 0, 0, 12, 2, 0, 0, 0, 1, 0]))
        + _tlv(0, b"")
    )
    return bytes.fromhex("0180c200000e") + SRC + b"\x88\xcc" + body


def cdp_frame() -> bytes:
    def t(kind, value):
        return struct.pack("!HH", kind, len(value) + 4) + value
    addr = struct.pack("!I", 1) + bytes([1, 1, 0xCC]) + struct.pack("!H", 4) + bytes([10, 0, 0, 1])
    cdp = b"\x02\xb4\x00\x00" + t(1, b"CORE") + t(2, addr) + t(3, b"GigabitEthernet1/0/5") + t(6, b"cisco WS-C3850")
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    payload = llc + cdp
    return bytes.fromhex("01000ccccccc") + SRC + struct.pack("!H", len(payload)) + payload


def bpdu_frame(tc: bool, root: bytes = bytes.fromhex("8000001b3f5c2e00")) -> bytes:
    bpdu = (b"\x00\x00\x02\x02" + bytes([0x01 if tc else 0x00]) + root
            + b"\x00\x00\x00\x04" + bytes.fromhex("8000001122334455") + b"\x80\x01"
            + b"\x00\x00\x14\x00\x02\x00\x0f\x00" + b"\x00")
    payload = b"\x42\x42\x03" + bpdu
    return bytes.fromhex("0180c2000000") + SRC + struct.pack("!H", len(payload)) + payload


def test_lldp_and_cdp_tell_you_where_you_are():
    s = ListenStats()
    s.feed(lldp_frame())
    s.feed(cdp_frame())
    peers = {p.protocol: p for p in s.peers.values()}
    assert (peers["LLDP"].name, peers["LLDP"].port, peers["LLDP"].ip) == ("ACCESS-2", "14", "10.0.0.12")
    assert (peers["CDP"].name, peers["CDP"].port, peers["CDP"].ip) == ("CORE", "GigabitEthernet1/0/5", "10.0.0.1")


def test_bpdu_topology_change_and_roots():
    s = ListenStats()
    for _ in range(3):
        s.feed(bpdu_frame(tc=True))
    s.feed(bpdu_frame(tc=False, root=bytes.fromhex("8000aaaaaaaaaaaa")))
    assert s.bpdus == 4 and s.tc_bpdus == 3 and len(s.roots) == 2


def test_storm_and_repeating_frames_detected():
    s = ListenStats(started=0.0, ended=2.0)
    arp = b"\xff" * 6 + SRC + b"\x08\x06" + b"\x00" * 28
    for _ in range(5000):
        s.feed(arp)
    levels = [lvl for lvl, _ in s.verdict()]
    texts = " ".join(t for _, t in s.verdict())
    assert levels.count("critical") == 2
    assert "Broadcast storm" in texts and "going round a loop" in texts


def test_quiet_port():
    s = ListenStats(started=0.0, ended=10.0)
    for i in range(30):
        s.feed(b"\xff" * 6 + SRC + b"\x08\x06" + bytes([i]) * 28)
    assert s.verdict()[0][0] == "ok"
