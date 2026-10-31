import socket
from collections.abc import Callable

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoBaseException

from netsleuth_core.platform import classify_platform

# Switches under a broadcast storm have busy CPUs, so be patient.
CONN_TIMEOUT = 15
AUTH_TIMEOUT = 20
BANNER_TIMEOUT = 20
READ_TIMEOUT = 60

# Tried in order when a device's type can't be detected. Each is verified with
# "show version" after connecting, so a wrong guess gets corrected.
FALLBACK_TYPES = ["cisco_ios", "hp_procurve", "aruba_aoscx"]

# When a user types a vendor shorthand (e.g. "aruba"), try these in order.
_DEVICE_TYPE_ALIASES: dict[str, list[str]] = {
    "aruba":   ["aruba_aoscx", "hp_procurve"],
    "hp":      ["hp_procurve", "hp_comware"],
    "juniper": ["juniper_junos"],
    "huawei":  ["huawei"],
    "extreme": ["extreme_exos"],
}


def _params(ip: str, creds: dict, device_type: str) -> dict:
    params = {
        "device_type": device_type,
        "host": ip,
        "username": creds["username"],
        "password": creds.get("password", ""),
        "port": creds.get("port", 22),
        "conn_timeout": CONN_TIMEOUT,
        "auth_timeout": AUTH_TIMEOUT,
        "banner_timeout": BANNER_TIMEOUT,
    }
    if creds.get("key_file"):
        params["use_keys"] = True
        params["key_file"] = creds["key_file"]
    return params


def tcp_reachable(ip: str, port: int = 22, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def detect_device_type(ip: str, port: int, username: str, password: str, key_file: str = None) -> str:
    """
    Probe a device with Netmiko SSHDetect and return its device type, or ""
    if detection failed. Callers fall back to FALLBACK_TYPES.
    """
    try:
        from netmiko import SSHDetect

        params = _params(ip, {"username": username, "password": password,
                              "port": port, "key_file": key_file}, "autodetect")
        guesser = SSHDetect(**params)
        result = guesser.autodetect()
        guesser.connection.disconnect()
        return result or ""
    except Exception:
        return ""


def connect(ip: str, username: str, password: str, device_type: str, port: int = 22, key_file: str = None):
    """Connect with one device type (or a vendor shorthand from _DEVICE_TYPE_ALIASES)."""
    creds = {"username": username, "password": password, "port": port, "key_file": key_file}
    candidates = _DEVICE_TYPE_ALIASES.get(device_type.lower(), [device_type])
    last_err = None
    for dtype in candidates:
        try:
            return ConnectHandler(**_params(ip, creds, dtype))
        except (ValueError, NetmikoBaseException) as e:
            last_err = e
    raise last_err


def run(conn, command: str, read_timeout: float = READ_TIMEOUT) -> str:
    """Send a show command and return its output, or "" on any failure."""
    try:
        output = conn.send_command(command, read_timeout=read_timeout)
    except Exception:
        return ""
    if not isinstance(output, str):
        return ""
    # Treat CLI rejections as "no output" so parsers never see error text.
    lowered = output.lower()
    if any(marker in lowered for marker in (
        "invalid input", "% unrecognized", "invalid command", "unknown command",
        "syntax error", "error: unrecognized", "% incomplete command",
    )) and len(output) < 400:
        return ""
    return output


def _version_text(conn) -> str:
    device_type = getattr(conn, "device_type", "") or ""
    if device_type.startswith("huawei"):
        return run(conn, "display version", 30)
    return run(conn, "show version", 30)


def open_device(
    ip: str,
    creds_sets: list[dict],
    device_type_hint: str = "",
    log: Callable[[str], None] = lambda _m: None,
):
    """
    Connect to *ip*, working out the device type and credentials.

    Order: the hint (from CDP/LLDP or the user), then SSHDetect, then
    FALLBACK_TYPES. Each credential set is tried in turn on auth failure.
    When the type was guessed, "show version" confirms it and the session is
    reopened with the right driver if the guess was wrong.

    Returns (conn, device_type, creds_index). Raises the last error on failure.
    """
    primary = creds_sets[0]

    def _try_types(types: list[str], verify: bool):
        last_exc: Exception | None = None
        for dtype in types:
            for idx, creds in enumerate(creds_sets):
                try:
                    conn = ConnectHandler(**_params(ip, creds, dtype))
                except NetmikoAuthenticationException as exc:
                    last_exc = exc
                    continue
                except (ValueError, NetmikoBaseException, OSError) as exc:
                    last_exc = exc
                    break  # wrong driver or unreachable: next type, not next creds
                if verify:
                    actual = classify_platform(_version_text(conn))
                    if actual and actual != dtype and not (
                        actual.startswith("cisco_") and dtype.startswith("cisco_")
                    ):
                        log(f"[dim]  {ip}: looks like {actual}, not {dtype} - reconnecting[/dim]")
                        conn.disconnect()
                        conn = ConnectHandler(**_params(ip, creds, actual))
                        dtype = actual
                return conn, dtype, idx
            if isinstance(last_exc, NetmikoAuthenticationException):
                # Credentials are the problem, not the driver.
                raise last_exc
        raise last_exc or ConnectionError(f"Could not connect to {ip}")

    if device_type_hint and device_type_hint != "auto":
        hinted = _DEVICE_TYPE_ALIASES.get(device_type_hint.lower(), [device_type_hint])
        try:
            return _try_types(hinted, verify=False)
        except NetmikoAuthenticationException:
            raise
        except Exception as exc:
            log(f"[dim]  {ip}: {device_type_hint} driver failed ({type(exc).__name__}), trying detection[/dim]")

    if not tcp_reachable(ip, primary.get("port", 22)):
        raise ConnectionError(f"{ip} is not answering on TCP port {primary.get('port', 22)}")

    detected = detect_device_type(
        ip, primary.get("port", 22), primary["username"],
        primary.get("password", ""), primary.get("key_file"),
    )
    if detected:
        log(f"[dim]  {ip}: detected {detected}[/dim]")
        return _try_types([detected], verify=False)
    return _try_types(FALLBACK_TYPES, verify=True)


def get_hostname(conn) -> str:
    """Return the device hostname, taken from the CLI prompt."""
    try:
        prompt = conn.find_prompt().strip()
    except Exception:
        return ""
    device_type = getattr(conn, "device_type", "") or ""
    if device_type.startswith("juniper"):
        # user@host> or user@host#
        prompt = prompt.split("@", 1)[-1]
    if device_type.startswith("huawei"):
        prompt = prompt.strip("<>[]")
    return prompt.rstrip("#>$ ").strip("<>[]").strip()
