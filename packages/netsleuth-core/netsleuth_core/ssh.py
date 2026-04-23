import re
import socket

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoBaseException

from netsleuth_core.console import console

# Keyword patterns for banner-based fallback detection.
# Evaluated in order; first match wins.
_BANNER_PATTERNS: list[tuple[list[str], str]] = [
    (["ArubaOS", "Aruba"],          "aruba_aoscx"),
    (["ProCurve", "HP ProCurve"],   "hp_procurve"),
    (["comware", "H3C"],            "hp_comware"),
    (["JUNOS", "Juniper"],          "juniper_junos"),
    (["Arista", "EOS"],             "arista_eos"),
    (["Huawei", "VRP"],             "huawei_vrp"),
    (["ExtremeXOS", "EXOS"],        "extreme_exos"),
]


def detect_device_type(ip: str, port: int, username: str, password: str, key_file: str = None) -> str:
    """
    Probe a device and return its Netmiko device-type string.

    Strategy:
    1. Try Netmiko SSHDetect (autodetect).
    2. If that fails or returns None, open a raw TCP socket, read the SSH
       banner / login greeting, and match against known keyword patterns.
    3. If everything fails, return "cisco_ios" as a safe default.
    """
    # --- Step 1: Netmiko SSHDetect ---
    try:
        from netmiko import SSHDetect  # optional — may not exist in all versions

        params = {
            "device_type": "autodetect",
            "host": ip,
            "username": username,
            "password": password,
            "port": port,
        }
        if key_file:
            params["use_keys"] = True
            params["key_file"] = key_file

        guesser = SSHDetect(**params)
        result = guesser.autodetect()
        guesser.connection.disconnect()
        if result:
            return result
    except Exception:
        pass  # fall through to banner check

    # --- Step 2: Raw banner / prompt keyword matching ---
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            # Read up to 4 KB — enough to capture the SSH banner and any
            # pre-auth greeting that some devices send.
            banner_bytes = b""
            sock.settimeout(3)
            try:
                while len(banner_bytes) < 4096:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    banner_bytes += chunk
            except (socket.timeout, OSError):
                pass
            banner = banner_bytes.decode("utf-8", errors="replace")

        for keywords, device_type in _BANNER_PATTERNS:
            if any(kw in banner for kw in keywords):
                return device_type
    except Exception:
        pass

    # --- Step 3: Safe default ---
    return "cisco_ios"

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
    """
    Return the hostname of the connected device.

    Dispatches by ``conn.device_type`` to issue the right command for each
    vendor.  Every branch is wrapped in try/except so any command failure
    falls through to the universal prompt-based fallback.
    """
    device_type: str = getattr(conn, "device_type", "") or ""

    # --- Cisco IOS / XE / NX-OS / XR ---
    if any(dt in device_type for dt in ("cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr")):
        try:
            output = conn.send_command("show version | include hostname")
            match = re.search(r"(\S+)\s+uptime", output)
            if match:
                return match.group(1)
            # Some IOS versions don't print uptime in that line; try running-config
            output2 = conn.send_command("show running-config | include hostname")
            match2 = re.search(r"hostname\s+(\S+)", output2)
            if match2:
                return match2.group(1)
        except Exception:
            pass

    # --- Arista EOS ---
    elif "arista_eos" in device_type:
        try:
            output = conn.send_command("show hostname")
            lines = output.strip().splitlines()
            if lines and lines[0].strip():
                return lines[0].strip()
        except Exception:
            pass

    # --- Juniper JunOS ---
    elif "juniper" in device_type:
        try:
            output = conn.send_command("show version | match Hostname")
            match = re.search(r"Hostname:\s*(\S+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass

    # --- Aruba AOS-CX ---
    elif "aruba_aoscx" in device_type:
        try:
            output = conn.send_command("show system | include Hostname")
            match = re.search(r"Hostname\s*[:|]\s*(\S+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass

    # --- HP ProCurve / Aruba OS Switch / Aruba ProCurve ---
    elif any(dt in device_type for dt in ("hp_procurve", "aruba_osswitch", "aruba_procurve")):
        try:
            output = conn.send_command("show system-information")
            match = re.search(r"System Name\s*[:\.]+\s*(\S+)", output)
            if match:
                return match.group(1)
        except Exception:
            pass

    # --- Huawei VRP ---
    elif any(dt in device_type for dt in ("huawei_vrp", "huawei_vrpv8")):
        try:
            output = conn.send_command("display version")
            # Huawei prompt is <hostname> or [hostname]; try parsing the prompt directly.
            prompt = conn.find_prompt().strip()
            match = re.match(r"[<\[](.*?)[>\]]", prompt)
            if match:
                return match.group(1)
        except Exception:
            pass

    # --- Universal prompt-based fallback ---
    try:
        prompt = conn.find_prompt().strip()
        # Strip all common prompt trailer characters: #, >, <, [, ]
        return prompt.strip("#><[]")
    except Exception:
        return "unknown"
