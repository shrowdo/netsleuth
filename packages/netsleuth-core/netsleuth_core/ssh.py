import re

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoBaseException

from netsleuth_core.console import console

# When a user types a vendor shorthand (e.g. "aruba"), try these in order.
_DEVICE_TYPE_ALIASES: dict[str, list[str]] = {
    "aruba":   ["aruba_aoscx", "aruba_procurve", "aruba_osswitch", "aruba_os"],
    "hp":      ["hp_procurve", "hp_comware"],
    "juniper": ["juniper_junos", "juniper"],
    "huawei":  ["huawei_vrp", "huawei_vrpv8", "huawei"],
    "extreme": ["extreme_exos", "extreme_nos", "extreme_vsp"],
}


def connect(ip: str, username: str, password: str, device_type: str, port: int = 22, key_file: str = None) -> object:
    candidates = _DEVICE_TYPE_ALIASES.get(device_type.lower(), [device_type])

    last_err = None
    for dtype in candidates:
        params = {
            "device_type": dtype,
            "host": ip,
            "username": username,
            "password": password,
            "port": port,
        }
        if key_file:
            params["use_keys"] = True
            params["key_file"] = key_file
        try:
            conn = ConnectHandler(**params)
            if len(candidates) > 1:
                console.print(f"[dim]  Auto-detected device type: {dtype}[/dim]")
            return conn
        except (ValueError, NetmikoBaseException) as e:
            last_err = e
            continue

    raise last_err


def get_hostname(conn) -> str:
    output = conn.send_command("show version | include hostname|uptime")
    match = re.search(r"(\S+)\s+uptime", output)
    if match:
        return match.group(1)
    # fallback: use the prompt
    return conn.find_prompt().strip("#>")
