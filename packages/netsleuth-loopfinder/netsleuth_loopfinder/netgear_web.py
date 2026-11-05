"""Read-only GS724TS legacy web collector. Explicit opt-in; no inferred cables.

Only the authentication form is POSTed. Credentials and cookies stay in memory;
saved evidence contains parsed identity/STP/FDB/counters, never login responses.
"""
import re
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

import requests

from netsleuth_core.models import Device
from netsleuth_core.ports import canonical_port

QUERIES = {
    "identity": "{file=/System/Management/SystemInfo_master_745.xml}{DeviceBasicInfo}",
    "stp": "{file=/Switching/STP/STPConfiguration_master_745.xml}{STP}{SpanningTreeGlobalParam}",
    "ports": "{file=/Switching/STP/CSTPortConfig_master.xml}{STP&interfaceType=1&UnitID=1}",
    "fdb": "{file=/Switching/Address Table/AddressTable_master.xml}{ForwardingDatabase&Count=1000&filter=addressingType=3}",
    "counters": "{file=/Monitoring/RMON/RMON_Statistics_master.xml}{RMONStatistics&interfaceType=1&UnitID=1}",
}


class _Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and "name" in attrs:
            self.fields[attrs["name"]] = attrs.get("value", "")


def configuration(text):
    # MASTER contains UI templates, not live values. Never parse it as evidence.
    match = re.search(r"<DeviceConfiguration>.*?</DeviceConfiguration>", text, re.S)
    if not match:
        raise ValueError("No authenticated DeviceConfiguration returned")
    return ET.fromstring(match.group())


def parse_device(ip, identity, stp, ports, fdb):
    info = identity.find("DeviceBasicInfo")
    if info is None or not info.findtext("MacAddre"):
        raise ValueError("Authenticated switch identity missing")
    device = Device(info.findtext("deviceName") or ip, ip, device_type="netgear_web")
    enabled = stp.findtext("SpanningTreeGlobalParam/enabled")
    device.stp_mode = {"1": "enabled", "2": "disabled"}.get(enabled, "unknown")
    for row in ports.findall(".//InterfaceEntry"):
        port = row.findtext("interfaceName")
        if port:
            device.stp[canonical_port(port)] = {
                "1": "DIS", "2": "BLK", "3": "LIS", "4": "LRN", "5": "FWD"
            }.get(row.findtext("portState"), "UNK")
    root = stp.find(".//DesignatedRoot")
    device.evidence = {
        "identity": {k: info.findtext(k) for k in (
            "deviceDescription", "MacAddre", "firmwareVersion", "serialNumber")},
        "stp_root": {c.tag: c.text for c in root} if root is not None else {},
        "mac_table": [{c.tag: c.text for c in row} for row in fdb.findall(".//ForwardingEntry")],
    }
    device.collection_warnings.append(
        "Legacy web collection is limited to unit 1 identity, STP and FDB; "
        "neighbours, LAGs and logs are not collected. Topology/loop assessment is incomplete. "
        "A learned MAC identifies a direction, not a direct cable."
    )
    if not device.stp:
        device.collection_warnings.append("No per-port STP data returned")
    if len(device.evidence["mac_table"]) >= 1000:
        device.collection_warnings.append("MAC table reached the 1000-entry limit; may be truncated")
    return device


def counter_values(root):
    return {
        row.findtext("interfaceName"): (
            int(row.findtext("receiveBroadcastPacketCount", "0")) +
            int(row.findtext("receiveMulticastPacketCount", "0"))
        ) for row in root.findall(".//InterfaceStatisticsEntry")
        if row.findtext("interfaceName")
    }


def collect(target, password, proxy_url=None, counters=True):
    base = target if "://" in target else "http://" + target
    base = base.rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
        raise ValueError("Use an HTTP(S) switch address without embedded credentials")
    ip = parsed.hostname or target
    device = Device(ip, ip, reachable=False, device_type="netgear_web")
    with requests.Session() as session:
        session.trust_env = False
        if proxy_url:
            session.proxies.update({"http": proxy_url, "https": proxy_url})

        def get(path):
            response = session.get(base + path, timeout=12, allow_redirects=False)
            response.raise_for_status()
            return response.text

        def query(name):
            return configuration(get("/wcd?" + QUERIES[name]))

        try:
            form = _Form()
            form.feed(get("/config/log_off_page.htm"))
            if "password$query" not in form.fields:
                raise ValueError("Unsupported web interface; expected legacy GS724TS login form")
            form.fields.update({"userName$query": "$enab15$", "password$query": password})
            response = session.post(base + "/config/log_off_page.htm", data=form.fields,
                                    timeout=12, allow_redirects=False)
            response.raise_for_status()
            # A 200/302 alone does not establish authentication: require live identity.
            device = parse_device(ip, query("identity"), query("stp"), query("ports"), query("fdb"))
            if counters:
                before = counter_values(query("counters"))
                start = time.monotonic()
                time.sleep(5)
                after = counter_values(query("counters"))
                elapsed = time.monotonic() - start
                device.port_rates = {canonical_port(p): (after[p] - v) / elapsed
                                     for p, v in before.items() if p in after and after[p] >= v}
                device.rate_kind = "inbound broadcast+multicast packets/sec"
                if not before or not after:
                    device.collection_warnings.append("No broadcast counter samples returned")
        except (requests.RequestException, ValueError, ET.ParseError):
            if device.reachable:
                device.collection_warnings.append("An optional web query failed; collection is partial")
            else:
                # Never include raw requests exceptions: proxy URLs may contain credentials.
                device.error = "Legacy Netgear web collection failed: check access, login and supported model"
    return device
