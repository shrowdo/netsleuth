import xml.etree.ElementTree as ET

import pytest

from netsleuth_core.models import Device
from netsleuth_loopfinder.analysis import analyse
from netsleuth_loopfinder.netgear_web import configuration, parse_device


def test_live_values_only_and_no_inferred_cable():
    identity = configuration('''<MASTER><DeviceBasicInfo><MacAddre>wrong</MacAddre>
        </DeviceBasicInfo></MASTER><DeviceConfiguration><DeviceBasicInfo>
        <MacAddre>e0:91:f5:1d:a5:4f</MacAddre><deviceDescription>GS724TS</deviceDescription>
        </DeviceBasicInfo></DeviceConfiguration>''')
    stp = ET.fromstring('''<DeviceConfiguration><SpanningTreeGlobalParam><enabled>1</enabled>
        </SpanningTreeGlobalParam><STP><DesignatedRoot><rootPortID>1/g22</rootPortID>
        </DesignatedRoot></STP></DeviceConfiguration>''')
    ports = ET.fromstring('''<DeviceConfiguration><InterfaceEntry><interfaceName>1/g23</interfaceName>
        <portState>5</portState></InterfaceEntry><InterfaceEntry><interfaceName>1/g24</interfaceName>
        <portState>2</portState></InterfaceEntry></DeviceConfiguration>''')
    fdb = ET.fromstring('''<DeviceConfiguration><ForwardingEntry><interfaceName>1/g23</interfaceName>
        <MACAddress>74:d4:dd:cc:78:28</MACAddress></ForwardingEntry></DeviceConfiguration>''')
    device = parse_device('10.254.197.147', identity, stp, ports, fdb)
    assert device.reachable and device.stp_mode == 'enabled'
    assert sorted(device.stp.values()) == ['BLK', 'FWD']
    assert device.evidence['identity']['MacAddre'] == 'e0:91:f5:1d:a5:4f'
    assert device.evidence['mac_table'][0]['MACAddress'] == '74:d4:dd:cc:78:28'
    result = analyse({device.hostname: device})
    assert not device.neighbors and result.graph.number_of_edges() == 0
    assert result.verdict[0] == 'warning'
    assert 'incomplete' in result.verdict[1].lower()
    assert not result.coverage_complete
    assert not any('No loop found' in a.text for a in result.actions)


def test_login_page_and_empty_identity_are_not_success():
    with pytest.raises(ValueError):
        configuration('<html>Login failure</html>')
    with pytest.raises(ValueError):
        parse_device('switch', *(ET.fromstring('<DeviceConfiguration/>') for _ in range(4)))


def test_failed_or_partial_coverage_never_claims_no_active_loop():
    assert 'no switch data' in analyse({}).verdict[1].lower()
    failed = Device('failed', '10.0.0.1', reachable=False)
    assert 'no switch data' in analyse({'failed': failed}).verdict[1].lower()
    good = Device('good', '10.0.0.2', stp_mode='enabled')
    assert 'incomplete' in analyse({'failed': failed, 'good': good}).verdict[1].lower()


def test_http_success_with_login_page_is_not_authenticated(monkeypatch):
    from netsleuth_loopfinder import netgear_web

    class Response:
        def __init__(self, text):
            self.text = text

        def raise_for_status(self):
            pass

    class Session:
        def __init__(self):
            self.proxies = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url, **kwargs):
            if '/wcd?' in url:
                return Response('<html>Login failure</html>')
            return Response('<input name="password$query" value="">')

        def post(self, url, **kwargs):
            return Response('<html>Login failure</html>')

    monkeypatch.setattr(netgear_web.requests, 'Session', Session)
    device = netgear_web.collect('10.0.0.1', 'test-only-value', counters=False)
    assert not device.reachable
    assert device.evidence == {}
    assert 'test-only-value' not in str(device)
