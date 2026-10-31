"""
A tiny fake SSH switch for integration tests: password auth, an interactive
shell with a "HOST#" prompt, and canned replies per command.
"""

import socket
import threading

import paramiko

_HOST_KEY = paramiko.RSAKey.generate(2048)


class _Server(paramiko.ServerInterface):
    def __init__(self, username, password):
        self.username, self.password = username, password
        self.shell = threading.Event()

    def check_auth_password(self, username, password):
        ok = username == self.username and password == self.password
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True


class FakeSwitch:
    def __init__(self, ip: str, port: int, hostname: str, replies: dict[str, str],
                 username="admin", password="secret"):
        self.ip, self.port, self.hostname = ip, port, hostname
        self.replies = replies
        self.username, self.password = username, password
        self.commands: list[str] = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((ip, port))
        self._sock.listen(20)
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass

    def _accept(self):
        while not self._stop:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _reply(self, cmd: str) -> str:
        if cmd in self.replies:
            return self.replies[cmd]
        for key, value in self.replies.items():
            if key.endswith("*") and cmd.startswith(key[:-1]):
                return value
        if cmd.startswith(("terminal ", "")) and (cmd.startswith("terminal") or not cmd):
            return ""
        return "                 ^\n% Invalid input detected at '^' marker.\n"

    def _handle(self, client):
        transport = paramiko.Transport(client)
        transport.add_server_key(_HOST_KEY)
        server = _Server(self.username, self.password)
        try:
            transport.start_server(server=server)
        except Exception:
            return
        chan = transport.accept(20)
        if chan is None:
            return
        server.shell.wait(10)
        prompt = f"{self.hostname}#"
        chan.send(f"\r\n{prompt}")
        buf = ""
        try:
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                buf += data.decode(errors="replace")
                while "\n" in buf or "\r" in buf:
                    idx = min(i for i in (buf.find("\n"), buf.find("\r")) if i >= 0)
                    line, buf = buf[:idx].strip(), buf[idx + 1:].lstrip("\r\n")
                    self.commands.append(line)
                    out = self._reply(line)
                    chan.send(f"{line}\r\n" + out.replace("\n", "\r\n") + f"\r\n{prompt}")
        except Exception:
            pass
        finally:
            transport.close()
