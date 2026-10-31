"""Parser tests against realistic vendor output."""

from netsleuth_core.platform import classify_platform, neighbor_role
from netsleuth_core.ports import canonical_port
from netsleuth_loopfinder import counters, neighbors as nb, stp
from netsleuth_loopfinder.logparse import parse_logs

# ---------------------------------------------------------------------------
# Cisco IOS
# ---------------------------------------------------------------------------

CISCO_CDP = """\
-------------------------
Device ID: ACCESS-1.school.local
Entry address(es):
  IP address: 10.0.0.11
Platform: cisco WS-C2960X-48FPD-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/49,  Port ID (outgoing port): GigabitEthernet1/0/52
Holdtime : 150 sec

Version :
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)

-------------------------
Device ID: SEP001122334455
Entry address(es):
  IP address: 10.1.5.20
Platform: Cisco IP Phone 7841,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Port 1
Holdtime : 170 sec

-------------------------
Device ID: AP-HALL
Entry address(es):
  IP address: 10.1.9.30
Platform: cisco AIR-AP2802I-E-K9,  Capabilities: Trans-Bridge Source-Route-Bridge IGMP
Interface: GigabitEthernet1/0/7,  Port ID (outgoing port): GigabitEthernet0
"""

CISCO_LLDP = """\
Capability codes:
    (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
    (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other
------------------------------------------------
Local Intf: Gi1/0/48
Chassis id: 001b.3f5c.2e00
Port id: 48
Port Description: 48
System Name: HP-ACCESS-3

System Description:
HP J9727A 2920-24G-PoE+ Switch, revision WB.16.10.0009, ROM WB.16.03 (/ws/swbuildm/rel_tacoma_qaoff/code/build/anm(swbuildm_rel_tacoma_qaoff_rel_tacoma))

Time remaining: 102 seconds
System Capabilities: B,R
Enabled Capabilities: B
Management Addresses:
    IP: 10.0.0.13
Auto Negotiation - supported, enabled

------------------------------------------------
Local Intf: Gi1/0/9
Chassis id: 0011.2233.4455
Port id: 0011.2233.4455
System Name: polycom-phone

System Capabilities: B,T
Enabled Capabilities: B,T
Management Addresses:
    IP: 10.1.5.88

Total entries displayed: 2
"""

CISCO_STP = """\
VLAN0001
  Spanning tree enabled protocol rstp
  Root ID    Priority    32769
             Address     001b.3f5c.2e00
  Bridge ID  Priority    32769  (priority 32768 sys-id-ext 1)

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Gi1/0/1             Desg FWD 4         128.1    P2p Edge
Gi1/0/48            Altn BLK 4         128.48   P2p
Po1                 Root FWD 3         128.488  P2p

VLAN0010
  Spanning tree enabled protocol rstp

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Gi1/0/1             Desg FWD 4         128.1    P2p Edge
Gi1/0/48            Desg FWD 4         128.48   P2p
Gi1/0/12            Desg BKN*4         128.12   P2p *LOOP_Inc
Po1                 Root FWD 3         128.488  P2p
"""

CISCO_ETHERCHANNEL = """\
Flags:  D - down        P - bundled in port-channel
Number of channel-groups in use: 2
Number of aggregators:           2

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
1      Po1(SU)         LACP      Gi1/0/49(P) Gi1/0/50(P)
2      Po2(SU)         LACP      Te1/1/1(P)  Te1/1/2(P)
                                 Te1/1/3(P)
"""

CISCO_COUNTERS = """\

Port            InOctets    InUcastPkts    InMcastPkts    InBcastPkts
Gi1/0/1        123456789        1000000          5000            2000
Gi1/0/2          1234567          12345            10               5
Po1           9999999999       88888888        777777          666666

Port           OutOctets   OutUcastPkts   OutMcastPkts   OutBcastPkts
Gi1/0/1        123456789        1000000          5000            2000
"""

CISCO_TCN = """\
 VLAN0001 is executing the rstp compatible Spanning Tree protocol
  Number of topology changes 4523 last change occurred 00:00:02 ago
          from GigabitEthernet1/0/12
 VLAN0010 is executing the rstp compatible Spanning Tree protocol
  Number of topology changes 3 last change occurred 2d04h ago
          from Port-channel1
"""


def test_cisco_cdp_roles_and_hints():
    ns = {n.hostname: n for n in nb.parse_cdp_detail(CISCO_CDP)}
    assert ns["ACCESS-1"].ip == "10.0.0.11"
    assert ns["ACCESS-1"].local_port == "GigabitEthernet1/0/49"
    assert ns["ACCESS-1"].remote_port == "GigabitEthernet1/0/52"
    assert ns["ACCESS-1"].role == "switch"
    assert ns["ACCESS-1"].device_type_hint == "cisco_ios"
    assert ns["SEP001122334455"].role == "endpoint"
    assert ns["AP-HALL"].role == "endpoint"


def test_cisco_lldp_local_intf_and_procurve_hint():
    ns = {n.hostname: n for n in nb.parse_lldp_detail(CISCO_LLDP)}
    hp = ns["HP-ACCESS-3"]
    assert hp.local_port == "GigabitEthernet1/0/48"
    assert hp.remote_port == "48"
    assert hp.ip == "10.0.0.13"
    assert hp.role == "switch"
    assert hp.device_type_hint == "hp_procurve"
    assert ns["polycom-phone"].role == "endpoint"


def test_cisco_stp_state_mid_line_and_per_vlan_merge():
    ports, mode = stp.parse_stp(CISCO_STP, "cisco_ios")
    assert mode == "enabled"
    assert ports[canonical_port("Gi1/0/1")] == "FWD"
    assert ports[canonical_port("Po1")] == "FWD"
    # Blocked in VLAN 1 but forwarding in VLAN 10.
    assert ports[canonical_port("Gi1/0/48")] == "PART"
    # Loop-inconsistent (BKN*) counts as blocked.
    assert ports[canonical_port("Gi1/0/12")] == "BLK"


def test_cisco_stp_disabled():
    _ports, mode = stp.parse_stp("No spanning tree instance exists.\n", "cisco_ios")
    assert mode == "disabled"


def test_cisco_etherchannel_including_wrapped_members():
    lags = stp.parse_cisco_lags(CISCO_ETHERCHANNEL)
    assert lags[canonical_port("Gi1/0/49")] == "Po1"
    assert lags[canonical_port("Te1/1/3")] == "Po2"
    assert canonical_port("Po1") not in lags


def test_cisco_counters_inbound_only():
    totals = counters.parse_cisco_counters(CISCO_COUNTERS)
    assert totals[canonical_port("Gi1/0/1")] == 7000
    assert totals[canonical_port("Po1")] == 777777 + 666666


def test_counter_rates():
    rates = counters.rates_from_samples({"a": 100, "b": 50}, {"a": 600, "b": 40}, 5.0)
    assert rates == {"a": 100.0}  # b went backwards (cleared) and is skipped


def test_cisco_tcn_source_port():
    tcn = stp.parse_cisco_tcn(CISCO_TCN)
    assert tcn[0]["count"] == 4523 and tcn[0]["age_s"] == 2
    assert tcn[0]["from_port"] == "GigabitEthernet1/0/12"
    assert tcn[1]["age_s"] == 2 * 86400 + 4 * 3600


# ---------------------------------------------------------------------------
# HP ProCurve / Aruba-OS
# ---------------------------------------------------------------------------

PROCURVE_LLDP_TABLE = """\
 LLDP Remote Devices Information

  LocalPort | ChassisId                 PortId PortDescr SysName
  --------- + ------------------------- ------ --------- ----------------------
  25        | 00 1b 3f 5c 2e 00         Gi1... Gigabi... CORE
  48        | 001b3f-5c2e00             48     48        HP-ACCESS-2
  5         | 00 11 22 33 44 55         00 ... Port 1    SEP001122334455
"""

PROCURVE_LLDP_DETAIL = """\
 LLDP Remote Device Information Detail

  Local Port   : 25
  ChassisType  : mac-address
  ChassisId    : 00 1b 3f 5c 2e 00
  PortType     : interface-name
  PortId       : Gi1/0/1
  SysName      : CORE
  System Descr : Cisco IOS Software, C3850 Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4
  PortDescr    : GigabitEthernet1/0/1

  System Capabilities Supported  : bridge, router
  System Capabilities Enabled    : bridge, router

  Remote Management Address
     Type    : ipv4
     Address : 10.0.0.1

 ------------------------------------------------------------------------------
  Local Port   : 5
  ChassisType  : network-address
  ChassisId    : 10.1.5.20
  PortType     : local
  PortId       : 1
  SysName      : SEP001122334455
  System Descr : Cisco IP Phone 7841
  System Capabilities Supported  : bridge, telephone
  System Capabilities Enabled    : bridge, telephone

  Remote Management Address
     Type    : ipv4
     Address : 10.1.5.20
"""

PROCURVE_STP = """\
 Multiple Spanning Trees (MST) Information

  STP Enabled   : Yes
  Force Version : MSTP-operation

  Topology Change Count  : 812
  Time Since Last Change : 3 secs

  Port  Type      Cost      Priority Role       State      Designated Bridge
  ----- --------- --------- -------- ---------- ---------- ------------------
  1     100/1000T 20000     128      Designated Forwarding 001b3f-aaaaaa
  2     100/1000T Auto      128      Disabled   Disabled
  25    SFP+SR    2000      128      Root       Forwarding 001b3f-5c2e00
  48    100/1000T 20000     128      Alternate  Blocking   001b3f-5c2e00
  Trk1            Auto      64       Designated Forwarding 001b3f-aaaaaa
"""

PROCURVE_STP_OFF = """\
 Multiple Spanning Trees (MST) Information

  STP Enabled   : No
"""

PROCURVE_TRUNKS = """\
 Load Balancing Method:  L3-based (default)

  Port | Name                             Type      | Group  Type
  ---- + -------------------------------- --------- + ------ --------
  49   |                                  SFP+SR    | Trk1   LACP
  50   |                                  SFP+SR    | Trk1   LACP
"""

PROCURVE_BRIEF = """\
 Status and Counters - Port Status

                          | Intrusion                           Flow  Bcast
  Port         Type       | Alert     Enabled Status Mode       Ctrl  Limit
  ------------ ---------- + --------- ------- ------ ---------- ----- ------
  1            100/1000T  | No        Yes     Up     1000FDx    off   0
  2            100/1000T  | No        Yes     Down   1000FDx    off   0
  14           100/1000T  | No        Yes     Up     1000FDx    off   0
  49                      | No        Yes     Up     10GigFD    off   0
"""

PROCURVE_IFACES = """\
 Status and Counters - Port Counters for port 1

  Name  :
  Link Status     : Up
  Totals (Since boot or last clear) :
   Bytes Rx        : 2,350,346,312        Bytes Tx        : 3,193,513,592
   Unicast Rx      : 23,416,235           Unicast Tx      : 25,016,612
   Bcast/Mcast Rx  : 2,091,341            Bcast/Mcast Tx  : 31,431,567
  Rates (5 minute weighted average) :
   Total Rx  (bps) : 1,135,976         Total Tx  (bps) : 1,196,792
   Unicast Rx (Pkts/sec) : 92          Unicast Tx (Pkts/sec) : 99
   B/Mcast Rx (Pkts/sec) : 6           B/Mcast Tx (Pkts/sec) : 42

 Status and Counters - Port Counters for port 14

  Rates (5 minute weighted average) :
   B/Mcast Rx (Pkts/sec) : 14,250      B/Mcast Tx (Pkts/sec) : 14,100
"""

PROCURVE_LOGS = """\
W 10/31/26 07:59:12 00332 FFI: port 14-Excessive Broadcasts. See help.
I 10/31/26 07:59:30 00436 loop-protect: port 14 disabled - loop detected (on port 14)
"""

PROCURVE_LOOP_PROTECT = """\
 Status and Counters - Loop Protect Information

  Transmit Interval (sec)        : 5
  Port Disable Timer (sec)       : 0 (Disabled)

        Loop      Loop   Loop     Time    Rx      Port
  Port  Protect   Detected Count   Since   Action  Status
  ----- --------- -------- ------  ------- ------- --------
  14   | Yes      Yes      3       12s     send-disable Down
  15   | Yes      No       0               send-disable Up
"""


def test_procurve_lldp_table_and_detail():
    assert nb.parse_procurve_lldp_ports(PROCURVE_LLDP_TABLE) == ["25", "48", "5"]
    ns = {n.hostname: n for n in nb.parse_procurve_lldp_detail(PROCURVE_LLDP_DETAIL)}
    core = ns["CORE"]
    assert core.local_port == "25" and core.remote_port == "GigabitEthernet1/0/1"
    assert core.ip == "10.0.0.1" and core.role == "switch"
    assert core.device_type_hint == "cisco_ios"
    assert ns["SEP001122334455"].role == "endpoint"


def test_procurve_stp_and_tcn():
    ports, mode = stp.parse_stp(PROCURVE_STP, "hp_procurve")
    assert mode == "enabled"
    assert ports["25"] == "FWD" and ports["48"] == "BLK" and ports["trk1"] == "FWD"
    assert "2" not in ports  # disabled ports aren't relevant
    tcn = stp.parse_procurve_tcn(PROCURVE_STP)
    assert tcn[0]["count"] == 812 and tcn[0]["age_s"] == 3
    assert stp.parse_stp(PROCURVE_STP_OFF, "hp_procurve")[1] == "disabled"


def test_procurve_trunks_ports_and_rates():
    assert stp.parse_procurve_trunks(PROCURVE_TRUNKS) == {"49": "Trk1", "50": "Trk1"}
    assert counters.parse_procurve_port_list(PROCURVE_BRIEF) == ["1", "14", "49"]
    rates = counters.parse_procurve_rates(PROCURVE_IFACES)
    assert rates == {"1": 6.0, "14": 14250.0}


def test_procurve_logs():
    f = parse_logs(PROCURVE_LOGS)
    assert f.storm_shutdowns[0]["port"] == "14"
    assert f.loop_detections[0]["port"] == "14"


def test_procurve_loop_protect_status():
    from netsleuth_loopfinder.collect import _disabled_ports

    class Conn:
        device_type = "hp_procurve"

        def send_command(self, cmd, **_):
            return PROCURVE_LOOP_PROTECT if cmd == "show loop-protect" else ""

    assert _disabled_ports(Conn(), "procurve") == [{"port": "14", "reason": "loop-protect (3 loops)"}]


# ---------------------------------------------------------------------------
# Aruba AOS-CX
# ---------------------------------------------------------------------------

AOSCX_LLDP = """\
LLDP Neighbor Information
=========================

Port                           : 1/1/49
Neighbor Entries               : 1
Neighbor Chassis-Name          : CORE-CX
Neighbor Chassis-Description   : Aruba JL659A 6300M 48SR5 CL6 PoE 4SFP56 Swch FL.10.09.1010
Neighbor Chassis-ID            : 38:21:c7:5d:21:00
Neighbor Management-Address    : 10.0.0.1
Neighbor System-Name           : CORE-CX
Neighbor System-Description    : Aruba JL659A 6300M 48SR5 CL6 PoE 4SFP56 Swch FL.10.09.1010
Neighbor Capabilities          : Bridge, Router
Neighbor Capabilities Enabled  : Bridge, Router
Neighbor Port-ID               : 1/1/52
TTL                            : 120
"""

AOSCX_LACP = """\
Actor details of all interfaces:
------------------------------------------------------------------------------
Intf    Aggr     Port  Port  State   System-ID         System Aggr Forwarding
        Name     Id    Pri                             Pri    Key  State
------------------------------------------------------------------------------
1/1/49  lag1     50    1     ALFNCD  38:21:c7:5d:21:00 65534  1    up
1/1/50  lag1     51    1     ALFNCD  38:21:c7:5d:21:00 65534  1    up
"""

AOSCX_IFACE = """\
Interface 1/1/1 is up
 Admin state is up
 Statistics                     RX                   TX                 Total
 -------------         -------------------- --------------------  --------------------
 Packets                          1000                 2000                  3000
   Unicast                         900                 1900                  2800
   Multicast                        60                   70                   130
   Broadcast                        40                   30                    70

Interface 1/1/2 is down
 Admin state is up
"""


def test_aoscx_lldp_lacp_counters():
    ns = nb.parse_aoscx_lldp_detail(AOSCX_LLDP)
    assert len(ns) == 1
    n = ns[0]
    assert (n.hostname, n.local_port, n.remote_port, n.ip) == ("CORE-CX", "1/1/49", "1/1/52", "10.0.0.1")
    assert n.role == "switch" and n.device_type_hint == "aruba_aoscx"
    assert stp.parse_aoscx_lags(AOSCX_LACP) == {"1/1/49": "lag1", "1/1/50": "lag1"}
    assert counters.parse_aoscx_counters(AOSCX_IFACE) == {"1/1/1": 100}


# ---------------------------------------------------------------------------
# Platform / role classification
# ---------------------------------------------------------------------------

def test_classify_platform():
    assert classify_platform("Aruba JL322A 2930M-48G-PoE+ Switch, revision WC.16.10.0011") == "hp_procurve"
    assert classify_platform("Aruba JL659A 6300M Swch FL.10.09.1010") == "aruba_aoscx"
    assert classify_platform("Cisco Nexus Operating System (NX-OS) Software") == "cisco_nxos"
    assert classify_platform("Cisco IOS XE Software, Version 16.12.4") == "cisco_xe"
    assert classify_platform("UniFi switch") == ""


def test_neighbor_roles():
    assert neighbor_role("B,T") == "endpoint"
    assert neighbor_role("B,W") == "endpoint"
    assert neighbor_role("B") == "switch"
    assert neighbor_role("Switch IGMP") == "switch"
    assert neighbor_role("R") == "endpoint"
    assert neighbor_role("") == "unknown"


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def test_cisco_storm_errdisable_and_loopback_logs():
    log = (
        "%STORM_CONTROL-3-SHUTDOWN: A packet storm was detected on Gi1/0/5. A packet filter action has been applied on the interface.\n"
        "%PM-4-ERR_DISABLE: loopback error detected on Gi1/0/6, putting Gi1/0/6 in err-disable state\n"
        "%ETHCNTR-3-LOOP_BACK_DETECTED: Loop-back detected on GigabitEthernet1/0/7.\n"
        "%L2FM-4-L2FM_MAC_MOVE: Mac 0011.2233.4455 in vlan 10 has moved from Eth1/1 to Eth1/2\n"
    )
    f = parse_logs(log)
    assert f.storm_shutdowns[0]["port"] == "GigabitEthernet1/0/5"
    ports = {d["port"] for d in f.loop_detections}
    assert {"GigabitEthernet1/0/6", "GigabitEthernet1/0/7"} <= ports
    assert f.mac_flaps[0]["ports"] == ["Ethernet1/1", "Ethernet1/2"]
