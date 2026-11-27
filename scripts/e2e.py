"""End-to-end test suite against the real `fucf` binary.

    python scripts/e2e.py [path-to-fucf]
    python scripts/e2e.py --tier baseline [path-to-fucf]
    python scripts/e2e.py --tier 1 --suite r1
    python scripts/e2e.py --list-tests
    python scripts/e2e.py --selftest

Preserves all 152 baseline checks (130 Windows / 152 Unix) and extends with
246 opaque-box 4-tier tests across R1-R5 (398 total checks).
"""
import argparse
import http.client
import http.server
import importlib
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

DEFAULT_BIN = os.path.join("target", "debug", "fucf.exe" if os.name == "nt" else "fucf")
BIN = DEFAULT_BIN
DNS, API, HTTP, HTTPS, ORIGIN, TCP_APP, UDP_APP = 15353, 18787, 18080, 18443, 18081, 18022, 18023
FRONT = 18480
SMTP, FAKEMX = 18025, 18026
TOKEN = "e2e-token"
# Nothing listens there: certificate orders must fail cleanly, and no real CA is ever contacted.
ACME = "http://127.0.0.1:9/directory"
checks = 0


def check(cond, what):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + what)
    if not cond:
        raise SystemExit(1)


class Origin(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        Origin.hits += 1
        body = f"origin path={self.path} host={self.headers['Host']} ip={self.headers.get('CF-Connecting-IP')}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def api(method, path, body=None, raw=None):
    c = http.client.HTTPConnection("127.0.0.1", API, timeout=10)
    data = raw if raw is not None else (json.dumps(body) if body is not None else None)
    c.request(method, "/client/v4" + path, body=data, headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    r = c.getresponse()
    out = json.loads(r.read())
    return r.status, out


def edge(path, host="example.test", method="GET", headers=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", HTTP, timeout=40)
    c.request(method, path, body=body, headers={"Host": host, **(headers or {})})
    r = c.getresponse()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read().decode("utf-8", "replace")


def dns_a(name):
    q = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, ("127.0.0.1", DNS))
    b = s.recv(4096)
    an = struct.unpack("!H", b[6:8])[0]
    return [socket.inet_ntoa(b[-4:])] if an else []


def dns_mx(name):
    q = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", 15, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(q, ("127.0.0.1", DNS))
    b = s.recv(4096)
    if not struct.unpack("!H", b[6:8])[0]:
        return []
    def skip_name(pos):
        while b[pos]:
            if b[pos] & 0xC0:
                return pos + 2
            pos += 1 + b[pos]
        return pos + 1
    at = skip_name(12) + 4  # question name + QTYPE/QCLASS
    at = skip_name(at)      # answer name
    pref = struct.unpack("!H", b[at + 10:at + 12])[0]
    at += 12                # TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) PREF(2)
    out = []
    while b[at]:
        if b[at] & 0xC0:
            at = struct.unpack("!H", b[at:at + 2])[0] & 0x3FFF
            continue
        out.append(b[at + 1:at + 1 + b[at]].decode())
        at += 1 + b[at]
    return [(pref, ".".join(out))]


class Relay:
    """A mail exchanger that takes everything and remembers it."""
    box = []

    def __init__(self, port):
        self.srv = socket.create_server(("127.0.0.1", port))
        self.srv.settimeout(0.5)
        self._stop = False
        def go():
            while not self._stop:
                try:
                    conn, _ = self.srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self.session, args=(conn,), daemon=True).start()
        threading.Thread(target=go, daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass

    @staticmethod
    def session(conn):
        f = conn.makefile("rwb")
        def w(line):
            f.write(line + b"\r\n")
            f.flush()
        w(b"220 relay.test ESMTP")
        env = {"from": "", "to": []}
        while True:
            line = f.readline()
            if not line:
                return
            u = line.decode("utf8", "replace").strip()
            c = u.split(":")[0].upper()
            if c == "MAIL FROM":
                env["from"] = u[u.index("<") + 1:u.index(">")]
            elif c == "RCPT TO":
                env["to"].append(u[u.index("<") + 1:u.index(">")])
            elif c == "DATA":
                w(b"354 go")
                body = b""
                while (l := f.readline()) not in (b".\r\n", b""):
                    body += l
                Relay.box.append({**env, "data": body.decode("utf8", "replace")})
                env = {"from": "", "to": []}
                w(b"250 taken")
                continue
            elif c == "QUIT":
                w(b"221 bye")
                return
            w(b"250 ok")


def smtp(lines, port=SMTP):
    """Say `lines` to fucf's SMTP listener; its replies."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=10)
    f = conn.makefile("rwb")
    def take():
        out = []
        while True:
            line = f.readline().decode("utf8", "replace").rstrip()
            out.append(line)
            if len(line) < 4 or line[3] == " ":
                return out
    replies = take()
    in_data = False
    for line in lines:
        f.write(line.encode() + b"\r\n")
        f.flush()
        if in_data:
            if line == ".":
                in_data = False
                replies += take()
            continue
        got = take()
        replies += got
        if got and got[-1].startswith("354"):
            in_data = True
    conn.close()
    return replies


def mail():
    """E-mail routing: rules through the API, mail through the SMTP listener,
    onward to the (fake) relay the node is configured with."""
    print("e-mail routing")
    zid = [z for z in api("GET", "/zones")[1]["result"] if z["name"] == "example.test"][0]["id"]
    st, r = api("GET", f"/zones/{zid}/email")
    check(st == 200 and r["result"]["enabled"] is False and r["result"]["rules"] == [], "mail routing starts off, without rules")
    needed = r["result"]["needed_records"]
    check(any(n["type"] == "MX" and n["content"] == "mx.cdn.test" for n in needed)
          and any(n["type"] == "TXT" and n["content"].startswith("v=spf1") for n in needed), "MX and SPF are suggested")
    for n in needed:
        st, r = api("POST", f"/zones/{zid}/dns_records", n)
        check(st == 200, f"{n['type']} record added")
    check(dns_mx("example.test") == [(10, "mx.cdn.test")], "MX resolves")
    st, r = api("GET", f"/zones/{zid}/email")
    check(r["result"]["needed_records"] == [] and r["result"]["mx"] == ["mx.cdn.test"], "with the records, nothing is missing")

    st, r = api("POST", f"/zones/{zid}/email/rules", {"address": "postmaster", "destinations": ["Owner@Mailbox.example"]})
    check(st == 200 and r["result"]["address"] == "postmaster@example.test", "a bare local part is an address at the zone")
    check(api("POST", f"/zones/{zid}/email/rules", {"address": "postmaster@example.test", "destinations": ["a@b.test"]})[0] == 409,
          "one rule per address")
    check(api("POST", f"/zones/{zid}/email/rules", {"address": "x", "destinations": ["someone@example.test"]})[0] == 400,
          "forwarding into the zone itself is refused")
    check(api("POST", f"/zones/{zid}/email/rules", {"address": "x", "destinations": ["no-address"]})[0] == 400
          and api("POST", f"/zones/{zid}/email/rules", {"address": "x@elsewhere.test", "destinations": ["a@b.test"]})[0] == 400,
          "bad destinations and foreign addresses are refused")
    api("POST", f"/zones/{zid}/email/rules", {"address": "junk", "action": "drop", "destinations": ["a@b.test"]})
    st, r = api("PATCH", f"/zones/{zid}/settings/email_routing", {"value": True})
    check(st == 200 and r["result"]["value"] is True, "mail routing on")

    said = smtp(["EHLO sender.test", "MAIL FROM:<alice@sender.test>", "RCPT TO:<postmaster@example.test>", "DATA",
                 "Subject: hi", "", "body", ".", "QUIT"])
    check(said[0].startswith("220 mx.cdn.test") and any(l.startswith("354") for l in said) and said[-1].startswith("221"), "a message is taken")
    check(said[-2].startswith("250 2.0.0"), "and passed on")
    got = Relay.box[-1] if Relay.box else {}
    check(got.get("from", "").startswith("srs0=") and got["from"].endswith("=sender.test=alice@example.test")
          and got.get("to") == ["Owner@mailbox.example"], "the relay got it, sender rewritten (SRS)")
    before = len(Relay.box)
    said = smtp(["EHLO x", "MAIL FROM:<a@b.test>", "RCPT TO:<nobody@example.test>", "RCPT TO:<junk@example.test>", "DATA", "x", "."])
    codes = [l[:3] for l in said]
    check("550" in codes and "250" in codes and len(Relay.box) == before, "unknown addresses refused, dropped mail taken and thrown away")
    api("POST", f"/zones/{zid}/email/rules", {"address": "*", "destinations": ["rest@mailbox.example"]})
    said = smtp(["EHLO x", "MAIL FROM:<a@b.test>", "RCPT TO:<anyone@example.test>", "DATA", "Subject: catch-all", "", "hi", ".", "QUIT"])
    check(said[-2].startswith("250 2.0.0") and Relay.box[-1].get("to") == ["rest@mailbox.example"], "catch-all forwards unmatched addresses")

    st, r = api("GET", "/email/status")
    acts = r["result"]["activity"]
    check(st == 200 and r["result"]["listening"] == f"127.0.0.1:{SMTP}" and r["result"]["hosts"] == ["mx.cdn.test"]
          and r["result"]["relay"] == f"127.0.0.1:{FAKEMX}", "mail status reports listener, hosts and relay")
    check(any(a["result"] == "forwarded" for a in acts) and any(a["result"] == "dropped" for a in acts), "activity is recorded")


def run_baseline(bin_path=None, keep_logs=False):
    global BIN, checks
    BIN = bin_path or DEFAULT_BIN
    checks = 0
    Origin.hits = 0
    Relay.box = []

    class _ReuseHTTPServer(http.server.ThreadingHTTPServer):
        allow_reuse_address = True

    origin_srv = _ReuseHTTPServer(("127.0.0.1", ORIGIN), Origin)
    threading.Thread(target=origin_srv.serve_forever, daemon=True).start()

    stop_echo = threading.Event()
    tcp_srv = socket.create_server(("127.0.0.1", ORIGIN + 100))
    tcp_srv.settimeout(0.5)
    udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_srv.bind(("127.0.0.1", ORIGIN + 100))
    udp_srv.settimeout(0.5)

    def tcp_echo():
        while not stop_echo.is_set():
            try:
                conn, _ = tcp_srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.sendall(b"echo:" + conn.recv(100))
            conn.close()

    def udp_echo():
        while not stop_echo.is_set():
            try:
                data, peer = udp_srv.recvfrom(100)
            except socket.timeout:
                continue
            except OSError:
                break
            udp_srv.sendto(b"echo:" + data, peer)

    threading.Thread(target=tcp_echo, daemon=True).start()
    threading.Thread(target=udp_echo, daemon=True).start()

    data_dir = tempfile.mkdtemp(prefix="fucf-e2e-")
    relay = Relay(FAKEMX)
    proc = subprocess.Popen(
        [BIN, "--dns-listen", f"127.0.0.1:{DNS}", "--api-listen", f"127.0.0.1:{API}", "--http-listen", f"127.0.0.1:{HTTP}",
         "--https-listen", f"127.0.0.1:{HTTPS}", "--spectrum-bind", "127.0.0.1", "--data-dir", data_dir, "--api-token", TOKEN,
         "--edge-ip", "203.0.113.10", "--acme-directory", ACME, "--h3-front-listen", f"127.0.0.1:{FRONT}",
         "--smtp-listen", f"127.0.0.1:{SMTP}", "--mail-relay", f"smtp://127.0.0.1:{FAKEMX}", "--mail-host", "mx.cdn.test"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok = False
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", API), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        run()
        mail()
        accounts()
        fleet(data_dir)
        releases()
        ok = True
        print(f"\nall {checks} baseline checks passed")
        return checks
    finally:
        proc.kill()
        proc.wait()
        stop_echo.set()
        relay.close()
        origin_srv.shutdown()
        origin_srv.server_close()
        tcp_srv.close()
        udp_srv.close()
        if keep_logs and not ok:
            print("  logs kept in", data_dir)
        else:
            shutil.rmtree(data_dir, ignore_errors=True)


def wait_for(what, probe, seconds=40):
    """Poll `probe` until it returns something truthy."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            got = probe()
            if got:
                return got
        except (OSError, KeyError, ValueError):
            pass
        time.sleep(0.5)
    check(False, what + " (timed out)")


def accounts():
    # The panel's accounts: the first administrator, passwords, roles, two-step
    # verification with backup codes, and what the fleet page is made of.
    import base64, hashlib, hmac
    print("panel accounts")

    def call(method, path, body=None, token=None):
        c = http.client.HTTPConnection("127.0.0.1", API, timeout=30)
        headers = {"Content-Type": "application/json", "User-Agent": "e2e/1"}
        if token:
            headers["Authorization"] = "Bearer " + token
        c.request(method, "/client/v4" + path, body=json.dumps(body) if body is not None else None, headers=headers)
        r = c.getresponse()
        out = json.loads(r.read())
        return r.status, out.get("result") or {}, (out.get("errors") or [{}])[0].get("code")

    def totp(secret, offset=0):
        key = base64.b32decode(secret + "=" * (-len(secret) % 8))
        mac = hmac.new(key, struct.pack(">Q", int(time.time()) // 30 + offset), hashlib.sha1).digest()
        at = mac[-1] & 15
        return "%06d" % ((struct.unpack(">I", mac[at:at + 4])[0] & 0x7FFFFFFF) % 1000000)

    st, r, _ = call("GET", "/auth/status")
    check(st == 200 and r["initialized"] is False, "a new panel says that it is not set up")
    setup = {"token": TOKEN, "email": "Owner@Example.test", "password": "a good password"}
    check(call("POST", "/auth/setup", {**setup, "token": "guess"})[0] == 403 and call("POST", "/auth/setup", {**setup, "password": "short"})[0] == 400
          and call("POST", "/auth/setup", {**setup, "email": "nobody"})[0] == 400, "setting it up takes the API token, an e-mail address and a real password")
    st, r, _ = call("POST", "/auth/setup", setup)
    owner = r.get("token", "")
    check(st == 200 and owner.startswith("fucf_s_") and r["user"]["email"] == "owner@example.test" and r["user"]["role"] == "admin", "the first account is an administrator, signed in at once")
    check(call("POST", "/auth/setup", setup)[0] == 409 and call("GET", "/auth/status")[1]["initialized"] is True, "... and that was the only time")
    st, me, _ = call("GET", "/account", token=owner)
    check(st == 200 and me["email"] == "owner@example.test" and len(me["sessions"]) == 1 and me["sessions"][0]["current"] and me["sessions"][0]["agent"] == "e2e/1"
          and call("GET", "/zones", token=owner)[0] == 200, "a session works like the token")
    check(call("GET", "/zones", token="fucf_s_made-up")[0] == 401 and call("GET", "/zones")[0] == 401 and api("GET", "/account")[1]["result"]["api_token"] is True,
          "anything else is refused; the API token still is what it was")
    check(call("POST", "/auth/login", {"email": "owner@example.test", "password": "wrong"})[2] == 2001
          and call("POST", "/auth/login", {"email": "nobody@example.test", "password": "a good password"})[2] == 2001, "wrong password and unknown address look the same")

    # users and roles
    st, r, _ = call("POST", "/users", {"email": "viewer@example.test", "role": "viewer"}, token=owner)
    made_up = r.get("password", "")
    check(st == 200 and len(made_up) == 20 and r["user"]["must_change_password"], "a new user gets a made-up password, shown once")
    viewer = call("POST", "/auth/login", {"email": "viewer@example.test", "password": made_up})[1]["token"]
    check(call("GET", "/zones", token=viewer)[0] == 403 and call("GET", "/zones", token=viewer)[2] == 2016,
          "a user with an initial password must change it before using the API")
    check(call("POST", "/account/password", {"current": made_up, "new": "viewer's own password"}, token=viewer)[0] == 200
          and call("POST", "/auth/login", {"email": "viewer@example.test", "password": made_up})[0] == 401
          and call("GET", "/account", token=viewer)[1]["must_change_password"] is False, "changing the initial password unlocks the account")
    check(call("GET", "/zones", token=viewer)[0] == 200 and call("POST", "/zones", {"name": "viewer.test"}, token=viewer)[0] == 403
          and call("GET", "/users", token=viewer)[0] == 403 and call("GET", "/audit", token=viewer)[0] == 403, "a viewer looks, and changes nothing")
    uid = [u for u in call("GET", "/users", token=owner)[1] if u["email"] == "viewer@example.test"][0]["id"]
    st, r, _ = call("PATCH", f"/users/{uid}", {"role": "editor"}, token=owner)
    check(st == 200 and r["user"]["role"] == "editor" and call("POST", "/zones", {"name": "editor.test"}, token=viewer)[0] == 200
          and call("POST", "/users", {"email": "x@example.test"}, token=viewer)[0] == 403
          and call("POST", "/nodes", {"name": "rogue", "ipv4": "203.0.113.99"}, token=viewer)[0] == 403
          and call("POST", "/fleet/local/actions", {"action": "purge_cache"}, token=viewer)[0] == 403,
          "an editor changes the configuration, not the users or the nodes")
    owner_id = me["id"]
    check(call("PATCH", f"/users/{owner_id}", {"role": "viewer"}, token=owner)[0] == 409 and call("DELETE", f"/users/{owner_id}", token=owner)[0] == 409, "the last administrator stays one")
    check(call("PATCH", f"/users/{uid}", {"disabled": True}, token=owner)[0] == 200 and call("GET", "/zones", token=viewer)[0] == 401
          and call("DELETE", f"/users/{uid}", token=owner)[0] == 200 and len(call("GET", "/users", token=owner)[1]) == 1, "disabling a user ends its sessions; deleting removes it")

    # two-step verification, and the backup codes that stand in for it
    check(call("POST", "/account/backup_codes", {"password": "a good password"}, token=owner)[0] == 409, "no backup codes without two-step verification")
    st, r, _ = call("POST", "/account/totp/begin", token=owner)
    secret = r.get("secret", "")
    check(st == 200 and r["uri"].startswith("otpauth://totp/fucloudflare:owner%40example.test?secret=" + secret) and r["qr_svg"].startswith("<?xml") and "<svg" in r["qr_svg"],
          "an authenticator app is set up from a secret, shown as a QR code")
    check(call("POST", "/account/totp/enable", {"code": "000000"}, token=owner)[0] == 401 and "token" in call("POST", "/auth/login", {"email": "owner@example.test", "password": "a good password"})[1],
          "it is not in force before a code from the app is shown")
    used = totp(secret)
    st, r, _ = call("POST", "/account/totp/enable", {"code": used}, token=owner)
    codes = r.get("backup_codes", [])
    check(st == 200 and len(set(codes)) == 10 and call("GET", "/account", token=owner)[1]["backup_codes_left"] == 10, "switching it on hands out ten backup codes")

    def ticket():
        r = call("POST", "/auth/login", {"email": "owner@example.test", "password": "a good password"})[1]
        return r["second_step"]["ticket"], r

    t, r = ticket()
    check("token" not in r and r["second_step"]["methods"] == ["totp", "backup_code"], "from then on the password alone does not sign in")
    # (the code that switched it on, not a new one: the clock may have moved on to the next)
    check(call("POST", "/auth/second_step", {"ticket": t, "code": "123456"})[2] == 2003 and call("POST", "/auth/second_step", {"ticket": t, "code": used})[2] == 2003,
          "a wrong code is refused, and so is one that was used before")
    st, r, _ = call("POST", "/auth/second_step", {"ticket": t, "code": totp(secret, 1)})
    check(st == 200 and call("GET", "/account", token=r["token"])[1]["sessions"][-1]["method"] == "password+totp", "the right code signs in")
    st, r, _ = call("POST", "/auth/second_step", {"ticket": ticket()[0], "backup_code": codes[4].upper()})
    check(st == 200 and r["token"].startswith("fucf_s_") and call("GET", "/account", token=owner)[1]["backup_codes_left"] == 9, "a backup code stands in for the code")
    check(call("POST", "/auth/second_step", {"ticket": ticket()[0], "backup_code": codes[4]})[2] == 2003, "... once")
    st, r, _ = call("POST", "/account/backup_codes", {"password": "a good password"}, token=owner)
    fresh = r.get("backup_codes", [])
    check(st == 200 and len(fresh) == 10 and not set(fresh) & set(codes) and call("POST", "/account/backup_codes", {"password": "wrong"}, token=owner)[0] == 403,
          "new backup codes at any time, for the password")
    check(call("POST", "/auth/second_step", {"ticket": ticket()[0], "backup_code": codes[0]})[2] == 2003
          and call("POST", "/auth/second_step", {"ticket": ticket()[0], "backup_code": fresh[0]})[0] == 200, "the old ones are void, the new ones work")
    check(call("POST", "/account/two_factor/disable", {"password": "a good password"}, token=owner)[0] == 200
          and "token" in call("POST", "/auth/login", {"email": "owner@example.test", "password": "a good password"})[1], "switched off, the password is enough again")

    # passkeys need a browser; what can be checked here is that the ceremonies start and nothing made up is taken
    st, r, _ = call("POST", "/account/passkeys/begin", token=owner)
    made_up_key = {"id": "AAAA", "client_data": "e30", "authenticator_data": "AAAA", "signature": "AAAA"}
    check(st == 200 and r["user"]["name"] == "owner@example.test" and r["algorithms"] == [-7, -257, -8] and len(call("POST", "/auth/passkey/begin", {})[1]["challenge"]) > 30
          and call("POST", "/auth/passkey/finish", made_up_key)[0] == 400, "passkey ceremonies start with a challenge; a made-up answer opens nothing")

    # sessions, the audit trail, the fleet page
    sessions = call("GET", "/account", token=owner)[1]["sessions"]
    other = [s for s in sessions if not s["current"]][0]["id"]
    check(len(sessions) >= 3 and call("DELETE", f"/account/sessions/{other}", token=owner)[0] == 200 and len(call("GET", "/account", token=owner)[1]["sessions"]) == len(sessions) - 1,
          "sessions are listed and can be ended one by one")
    actions = {e["action"] for e in call("GET", "/audit", token=owner)[1]}
    check({"user.create", "login", "login.failed", "password.change", "user.update", "user.delete", "two_factor.enable", "two_factor.disable", "backup_codes.regenerate"} <= actions,
          "what happened to accounts is on record")
    st, f, _ = call("GET", "/fleet", token=owner)
    own = [n for n in f["nodes"] if n["self"]][0]
    check(st == 200 and f["role"] == "peer" and own["role"] == "peer" and own["online"] and len(own["exe"]) == 64 and own["status"]["uptime_seconds"] >= 0
          and own["status"]["cache"]["max_bytes"] > 0 and any(l.startswith("dns 127.0.0.1") for l in own["status"]["listeners"]) and f["actions"] == ["restart", "purge_cache"]
          and f["release"]["enabled"] is False, "the fleet page knows this node in detail")
    edge("/a/keep.css")
    st, r, _ = call("POST", f"/fleet/{own['name']}/actions", {"action": "purge_cache"}, token=owner)
    check(st == 200 and "cache emptied" in r["message"] and call("GET", "/fleet", token=owner)[1]["nodes"][0]["status"]["cache"]["objects"] == 0
          and call("POST", f"/fleet/{own['name']}/actions", {"action": "format"}, token=owner)[0] == 400 and call("POST", "/fleet/nobody/actions", {"action": "restart"}, token=owner)[0] == 409,
          "a node can be told to empty its cache; nothing else is made up, nobody unknown is told")
    check(call("POST", "/account/logout", token=owner)[0] == 200 and call("GET", "/account", token=owner)[0] == 401, "signing out ends the session")


class Service:
    # Keeps a node running the way a service manager does: started again when it exits.
    def __init__(self, argv, env, log):
        self.argv, self.env, self.log, self.starts, self.stopping, self.proc = argv, env, open(log, "ab"), 0, False, None
        threading.Thread(target=self.keep, daemon=True).start()

    def keep(self):
        while not self.stopping:
            self.proc = subprocess.Popen(self.argv, env=self.env, stdout=self.log, stderr=self.log)
            self.starts += 1
            self.proc.wait()
            time.sleep(0.3)

    def stop(self):
        self.stopping = True
        if self.proc:
            self.proc.kill()
            self.proc.wait()


def releases():
    # Rolling updates of the binary itself: a primary and a replica take a
    # release one after the other; a release that does not run is given up
    # on; a release that is withdrawn is rolled back.
    if os.name == "nt":
        print("rolling updates: skipped (a process cannot replace itself in place on this platform)")
        return
    print("rolling updates, and going back when they fail")
    work = tempfile.mkdtemp(prefix="fucf-e2e-releases-")
    base = os.path.join(work, "fucf")
    if subprocess.run(["strip", "-o", base, BIN], capture_output=True).returncode != 0:
        shutil.copy(BIN, base)
    os.chmod(base, 0o755)

    def tool(*args):
        out = subprocess.run([base, *args], capture_output=True, text=True, check=True).stdout
        return dict(line.split("=", 1) for line in out.split())

    keys = tool("release-keygen")
    key_file = os.path.join(work, "key")
    with open(key_file, "w") as f:
        f.write(keys["private"])
    derived = subprocess.run([base, "release-pubkey", key_file], capture_output=True, text=True).stdout.strip()
    check(derived == keys["public"] and len(keys["public"]) == 43, "a release key pair is created; the public half follows from the private one")

    def release(name, data):
        path = os.path.join(work, name)
        with open(path, "wb") as f:
            f.write(data)
        signed = tool("release-sign", key_file, path)
        return data, signed["sha256"], signed["signature"]

    with open(base, "rb") as f:
        program = f.read()
    p_api, r_api = API + 2000, API + 3000
    env = {**os.environ, "FUCF_RELEASE_TRIAL": "3"}

    def node(name, api_port, offset, extra, key=keys["public"]):
        data_dir = os.path.join(work, name)
        os.mkdir(data_dir)
        argv = [base, "--dns-listen", f"127.0.0.1:{DNS + offset}", "--api-listen", f"127.0.0.1:{api_port}",
                "--http-listen", f"127.0.0.1:{HTTP + offset}", "--https-listen", "off", "--spectrum-bind", "127.0.0.1",
                "--data-dir", data_dir, "--api-token", TOKEN, "--acme-directory", ACME, "--node-name", name,
                f"--release-key={key}"] + extra
        return Service(argv, env, os.path.join(work, name + ".log"))

    def call(port, method, path, data=None):
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
            c.request(method, "/client/v4" + path, body=data, headers={"Authorization": "Bearer " + TOKEN})
            r = c.getresponse()
            return r.status, json.loads(r.read())
        except (OSError, http.client.HTTPException, ValueError):
            return 0, {}    # the node is starting over

    def exe(port):
        return (call(port, "GET", "/system")[1].get("result") or {}).get("exe")

    def status():
        return call(p_api, "GET", "/releases")[1].get("result") or {"rollout": None, "target": None, "nodes": []}

    def phase():
        return (status()["rollout"] or {}).get("phase")

    def submit(sha, sig, data):
        return call(p_api, "PUT", f"/releases/{sha}?signature={sig}", data)

    primary = node("au", p_api, 2000, [])
    replica = node("eu", r_api, 3000, ["--primary", f"http://127.0.0.1:{p_api}", "--role", "accelerate"])
    second = None
    ok = False
    try:
        wait_for("both nodes are up", lambda: exe(p_api) and exe(r_api))
        installed = exe(p_api)
        st = status()
        check(exe(r_api) == installed and st["enabled"] and not st["target"] and not st["on_trial"], "nodes say which binary they run")
        wait_for("the primary knows what its replica runs", lambda: [n for n in status()["nodes"] if n["name"] == "eu" and n["exe"] == installed])

        data1, sha1, sig1 = release("release-1", program + b"\n# release 1\n")
        check(submit(sha1, sig1[:-6] + "AAAAAA", data1)[0] == 400, "a release with a wrong signature is refused")
        check(submit(sha1, sig1, data1 + b"x")[0] == 400, "... and so is one that is not the binary that was signed")
        check(call(r_api, "PUT", f"/releases/{sha1}?signature={sig1}", data1)[0] == 409, "replicas take no uploads")
        code, out = submit(sha1, sig1, data1)
        check(code == 200 and out["result"]["target"]["sha256"] == sha1 and out["result"]["target"]["state"] == "rolling", "a signed release is accepted")
        wait_for("the replica takes the release first", lambda: exe(r_api) == sha1, 60)
        check(exe(p_api) == installed, "... while the primary keeps running what it ran")
        wait_for("then the primary, once the replica has passed its trial", lambda: exe(p_api) == sha1 and phase() == "done", 90)
        st = status()
        check(st["target"]["state"] == "done" and len(st["nodes"]) == 2 and all(n["on_release"] and n["trusted"] for n in st["nodes"]), "the whole fleet runs the release")
        check(primary.starts == 1 and replica.starts == 1, "the nodes replaced themselves in place")

        # a release that does not even start
        broken, sha_b, sig_b = release("broken", b"#!/bin/sh\nexit 3\n")
        check(submit(sha_b, sig_b, broken)[0] == 200, "a broken release is accepted too (it is properly signed)")
        wait_for("it is given up on after the replica tried it twice", lambda: phase() == "failed", 90)
        st = status()
        check("eu could not run the release" in st["rollout"]["reason"] and st["target"]["state"] == "failed", "the roll-out stopped at the first node")
        check(replica.starts == 3 and primary.starts == 1, "the primary was never touched")
        wait_for("the replica is back", lambda: exe(r_api) == sha1)
        check(exe(p_api) == sha1, "both nodes run the release from before")
        eu = [n for n in status()["nodes"] if n["name"] == "eu"][0]
        check(eu["rejected"] and not eu["on_release"] and eu["online"], "the primary knows which node could not run it")

        # a release that works, taken back by hand
        data2, sha2, sig2 = release("release-2", program + b"\n# release 2\n")
        check(submit(sha2, sig2, data2)[0] == 200, "the next release is accepted after a failed one")
        wait_for("it reaches the whole fleet", lambda: exe(r_api) == sha2 and exe(p_api) == sha2 and phase() == "done", 120)
        code, out = call(p_api, "DELETE", f"/releases/{sha2}")
        check(code == 200 and out["result"]["target"]["state"] == "failed", "a release can be withdrawn")
        wait_for("the replica goes back first", lambda: exe(r_api) == sha1, 60)
        wait_for("then the primary: the fleet is where it was", lambda: exe(p_api) == sha1 and phase() == "failed", 90)
        check(status()["rollout"]["reason"] == "withdrawn by the operator", "... and says why")
        check(call(p_api, "DELETE", f"/releases/{sha1}")[0] == 404, "only the fleet's release can be withdrawn")

        # submitted again, the same release gets another chance
        check(submit(sha2, sig2, data2)[0] == 200, "a withdrawn release can be submitted again")
        wait_for("and is taken again", lambda: exe(r_api) == sha2, 60)
        wait_for("by the whole fleet", lambda: exe(p_api) == sha2 and phase() == "done", 90)
        code, out = call(p_api, "DELETE", f"/releases/{sha2}?forget=true")
        check(code == 200 and out["result"]["target"] is None and exe(p_api) == sha2 and exe(r_api) == sha2, "forgetting a release leaves the nodes as they are")

        # a second replica that cannot take the release (it trusts another key):
        # the one that already took it goes back
        second = node("us", API + 4000, 4000, ["--primary", f"http://127.0.0.1:{p_api}", "--role", "accelerate"], key=tool("release-keygen")["public"])
        wait_for("a second replica joins", lambda: [n for n in status()["nodes"] if n["name"] == "us" and n["exe"] == installed])
        data3, sha3, sig3 = release("release-3", program + b"\n# release 3\n")
        starts = replica.starts
        check(submit(sha3, sig3, data3)[0] == 200, "another release is submitted")
        wait_for("the first replica takes it", lambda: exe(r_api) == sha3, 60)
        wait_for("the second one cannot: the roll-out has failed", lambda: phase() in ("rolling_back", "failed") and "us could not run the release" in status()["rollout"]["reason"], 90)
        wait_for("and the first replica goes back to what it ran before", lambda: exe(r_api) == sha2 and phase() == "failed", 90)
        check(exe(p_api) == sha2 and exe(API + 4000) == installed and replica.starts == starts, "a failed update leaves the whole fleet as it was")
        ok = True
    finally:
        primary.stop()
        replica.stop()
        if second:
            second.stop()
        if ok:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("  logs kept in", work)


def fleet(primary_dir):
    """A second instance as a read-only replica of the first one."""
    print("fleet: replica of the primary")
    r_api, r_http = API + 1000, HTTP + 1000
    data_dir = tempfile.mkdtemp(prefix="fucf-e2e-replica-")
    eu_node_id = api("POST", "/nodes", {"name": "eu", "ipv4": "203.0.113.11", "accel_hosts": ["*"]})[1]["result"]["id"]
    replica = subprocess.Popen(
        [BIN, "--dns-listen", f"127.0.0.1:{DNS + 1000}", "--api-listen", f"127.0.0.1:{r_api}", "--http-listen", f"127.0.0.1:{r_http}",
         "--https-listen", "off", "--spectrum-bind", "127.0.0.2", "--data-dir", data_dir, "--api-token", TOKEN,
         "--primary", f"http://127.0.0.1:{API}", "--role", "accelerate", "--node-name", "eu", "--acme-directory", ACME],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def rapi(method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", r_api, timeout=10)
        c.request(method, "/client/v4" + path, body=json.dumps(body) if body is not None else None,
                  headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, json.loads(r.read())

    def redge(path):
        c = http.client.HTTPConnection("127.0.0.1", r_http, timeout=20)
        c.request("GET", path, headers={"Host": "example.test"})
        r = c.getresponse()
        return r.status, r.read()

    try:
        zid = [z for z in api("GET", "/zones")[1]["result"] if z["name"] == "example.test"][0]["id"]
        wait_for("replica adopts the configuration", lambda: any(z["id"] == zid for z in rapi("GET", "/zones")[1]["result"]))
        check(rapi("GET", "/system")[1]["result"]["role"] == "accelerate", "replica reports its role")
        check(rapi("POST", "/zones", {"name": "nope.test"})[0] == 409, "replica refuses configuration changes")
        version = api("GET", "/system")[1]["result"]["version"]
        seen = wait_for("primary sees the replica", lambda: api("GET", "/system")[1]["result"]["replicas"].get("eu"))
        check(seen["online"] and bool(seen["version"]), "primary knows the replica is online")

        before = api("GET", f"/zones/{zid}/analytics")[1]["result"]["requests"]
        check(redge("/via-replica")[0] == 200, "replica serves traffic with the mirrored configuration")
        api("PATCH", f"/zones/{zid}/settings/waf", {"value": "block"})
        wait_for("setting change reaches the replica", lambda: redge("/.env")[0] == 403)
        hits = 3 + sum(1 for _ in range(3) if redge("/r/x.css"))

        def reported():
            a = api("GET", f"/zones/{zid}/analytics?since=1h")[1]["result"]
            eu = a["by_node"].get("eu", {})
            # (reports come in batches: wait for the one with the blocked request, too)
            return a if eu.get("requests", 0) >= hits and eu.get("threats", 0) >= 1 else None
        a = wait_for("replica traffic shows up in the primary's analytics", reported)
        check(a["requests"] >= before + hits and a["by_node"]["eu"]["threats"] >= 1 and len(a["series"]) == 60, "fleet-wide analytics, split by node")
        events = api("GET", f"/zones/{zid}/security/events")[1]["result"]
        check(any(e["node"] == "eu" and e["uri"] == "/.env" for e in events), "replica's security events reach the primary")
        st_own, own_r = rapi("GET", f"/zones/{zid}/analytics?since=1h")
        own = own_r["result"]
        check(st_own == 200 and own["requests"] == 0 and own["by_node"] == {}, "accelerate replica drains its local analytics outbox")
        totals = api("GET", "/analytics")[1]["result"]
        check(totals["zones"][zid]["name"] == "example.test" and totals["totals"]["requests"] >= a["requests"], "account-wide summary")

        # a purge on the primary empties the replica's cache too
        check(redge("/r/x.css")[0] == 200, "replica cache warm")
        before_ver = rapi("GET", "/system")[1]["result"]["version"]
        api("POST", f"/zones/{zid}/purge_cache", {"purge_everything": True})
        wait_for("purge replicated", lambda: rapi("GET", "/system")[1]["result"]["version"] != before_ver)
    finally:
        replica.terminate() if os.name != "nt" else replica.kill()
        replica.wait()
        shutil.rmtree(data_dir, ignore_errors=True)
        api("DELETE", f"/nodes/{eu_node_id}")

    # analytics and events survive a restart of the primary
    check(os.path.exists(os.path.join(primary_dir, "state.json")), "state file present")


def run():
    print("zone + DNS")
    st, z = api("POST", "/zones", {"name": "example.test"})
    zid = z["result"]["id"]
    check(st == 200 and z["result"]["settings"]["ssl"] == "flexible", "zone created with default settings")
    api("POST", f"/zones/{zid}/dns_records", {"type": "A", "name": "@", "content": "127.0.0.1", "proxied": True})
    check(dns_a("example.test") == ["203.0.113.10"], "proxied record resolves to the edge IP")

    print("CDN + origin rules")
    st, r = api("POST", f"/zones/{zid}/origin_rules", {"expression": "", "origin_port": ORIGIN})
    origin_rule = r["result"]["id"]
    check(st == 200, "origin rule created")
    st, h, body = edge("/page")
    check(st == 200 and "host=example.test ip=127.0.0.1" in body and h["cf-cache-status"] == "DYNAMIC", "request proxied to origin")
    check(edge("/a/style.css")[1]["cf-cache-status"] == "MISS" and edge("/a/style.css")[1]["cf-cache-status"] == "HIT", "static file cached")
    st, r = api("POST", f"/zones/{zid}/purge_cache", {"purge_everything": True})
    check(r["success"] and r["result"]["purged"] in (0, 1) and edge("/a/style.css")[1]["cf-cache-status"] == "MISS", "cache purged")
    # origin options on a proxied record: the origin is asked for another name than the visitor used
    st, r = api("POST", f"/zones/{zid}/dns_records", {"type": "A", "name": "saas", "content": "127.0.0.1", "proxied": True,
                                                      "origin": {"host_header": "App.Origin.test"}})
    saas = r["result"]["id"]
    check(st == 200 and r["result"]["origin"] == {"host_header": "app.origin.test"} and "host=app.origin.test" in edge("/page", host="saas.example.test")[2],
          "record with origin options: Host header of its own")
    st, r = api("PATCH", f"/zones/{zid}/dns_records/{saas}", {"origin": {"sni": "edge.cdn.test", "host_header": "app.origin.test"}})
    check(st == 200 and r["result"]["origin"]["sni"] == "edge.cdn.test" and r["result"]["content"] == "127.0.0.1"
          and edge("/page", host="saas.example.test")[0] == 525, "a server name for the origin means TLS (which this origin does not speak)")
    check(api("PATCH", f"/zones/{zid}/dns_records/{saas}", {"origin": {"sni": "edge.cdn.test", "scheme": "http"}})[0] == 400
          and api("POST", f"/zones/{zid}/dns_records", {"type": "TXT", "name": "t", "content": "x", "origin": {"sni": "a.test"}})[0] == 400,
          "origin options that make no sense are refused")
    st, r = api("PATCH", f"/zones/{zid}/dns_records/{saas}", {"origin": {}})
    check(st == 200 and r["result"]["origin"] is None and "host=saas.example.test" in edge("/page", host="saas.example.test")[2],
          "emptied, the record is reached the usual way again")
    api("DELETE", f"/zones/{zid}/dns_records/{saas}")
    st, r = api("PATCH", f"/zones/{zid}/origin_rules/{origin_rule}", {"host_header": "backend.internal"})
    check(st == 200 and "host=backend.internal" in edge("/page")[2], "origin rule patched: Host header override")
    check(edge("/", host="unknown.test")[0] == 404, "unknown host refused")

    print("WAF")
    check(edge("/?q=%3Cscript%3Ealert(1)%3C/script%3E")[0] == 403, "managed rule blocks XSS")
    st, r = api("POST", f"/zones/{zid}/firewall/rules", {"expression": 'http.request.uri.path contains "/admin"', "action": "block", "description": "no admin"})
    rule = r["result"]["id"]
    check(st == 200 and edge("/admin")[0] == 403, "custom firewall rule blocks")
    st, r = api("POST", f"/zones/{zid}/firewall/rules", {"expression": "nonsense ((", "action": "block"})
    check(st == 400 and not r["success"], "invalid expression rejected")
    api("DELETE", f"/zones/{zid}/firewall/rules/{rule}")
    check(edge("/admin")[0] == 200, "rule deleted")
    api("POST", f"/zones/{zid}/rate_limits", {"expression": 'http.request.uri.path eq "/login"', "threshold": 2, "period": 60})
    codes = [edge("/login")[0] for _ in range(4)]
    check(codes == [200, 200, 429, 429], f"rate limit enforced {codes}")
    st, r = api("GET", f"/zones/{zid}/security/events")
    sources = {e["source"] for e in r["result"]}
    check(sources == {"managed", "firewall", "ratelimit"}, "security events recorded")
    st, r = api("PATCH", f"/zones/{zid}/settings/waf", {"value": "off"})
    check(st == 200 and edge("/?q=%3Cscript%3E")[0] == 200, "managed rules switched off via settings")

    print("Workers")
    script = """export default { async fetch(request, env) {
        const url = new URL(request.url);
        if (url.pathname === "/w/origin") { const r = await fetch(request); const o = new Response(r.body, r); o.headers.set("x-worker", env.NAME); return o; }
        return Response.json({ hello: env.NAME, path: url.pathname });
    } }"""
    st, r = api("PUT", "/workers/scripts/demo", raw=script)
    check(st == 200 and r["result"]["id"] == "demo", "script uploaded")
    check(api("PUT", "/workers/scripts/broken", raw="export default {{{")[0] == 400, "syntax errors rejected at upload")
    api("PATCH", "/workers/scripts/demo/settings", {"vars": {"NAME": "fucf"}})
    st, r = api("POST", f"/zones/{zid}/workers/routes", {"pattern": "example.test/w/*", "script": "demo"})
    check(st == 200, "route created")
    st, h, body = edge("/w/json")
    check(st == 200 and json.loads(body) == {"hello": "fucf", "path": "/w/json"}, "worker generates a response")
    st, h, body = edge("/w/origin")
    check("origin path=/w/origin" in body and h.get("x-worker") == "fucf", "worker rewrites an origin response")
    check(api("DELETE", "/workers/scripts/demo")[0] == 409, "script in use cannot be deleted")

    print("Spectrum")
    st, r = api("POST", f"/zones/{zid}/spectrum/apps", {"protocol": f"tcp/{TCP_APP}", "dns": {"name": "ssh"}, "origin_direct": [f"tcp://127.0.0.1:{ORIGIN + 100}"]})
    check(st == 200 and r["result"]["dns"]["name"] == "ssh.example.test", "TCP app created")
    st, r = api("POST", f"/zones/{zid}/spectrum/apps", {"protocol": f"udp/{UDP_APP}", "dns": {"name": "game"}, "origin_direct": [f"udp://127.0.0.1:{ORIGIN + 100}"]})
    check(st == 200, "UDP app created")
    check(dns_a("ssh.example.test") == ["203.0.113.10"], "spectrum host name resolves to the edge")
    time.sleep(0.5)
    s = socket.create_connection(("127.0.0.1", TCP_APP), timeout=3)
    s.sendall(b"hi")
    check(s.recv(100) == b"echo:hi", "TCP forwarded")
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(3)
    u.sendto(b"yo", ("127.0.0.1", UDP_APP))
    check(u.recv(100) == b"echo:yo", "UDP forwarded")

    print("rules, HTTPS + HTTP/3, compression, analytics")
    st, r = api("POST", f"/zones/{zid}/redirect_rules", {"expression": 'http.request.uri.path eq "/old"', "target_url": "/new", "status_code": 301})
    st2, h, _ = edge("/old")
    check(st == 200 and st2 == 301 and h["location"] == "/new", "redirect rule")
    st, r = api("POST", f"/zones/{zid}/transform_rules", {"expression": "", "set_response_headers": {"X-Edge": "fucf"}})
    check(st == 200 and edge("/page")[1].get("x-edge") == "fucf", "transform rule sets a response header")
    st, r = api("POST", f"/zones/{zid}/cache_rules", {"expression": 'starts_with(http.request.uri.path, "/html/")', "cache": True, "edge_ttl": 60})
    check(st == 200 and [edge("/html/a")[1]["cf-cache-status"] for _ in range(2)] == ["MISS", "HIT"], "cache rule caches a dynamic path")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection("127.0.0.1", HTTPS, timeout=10, context=ctx)
    c.request("GET", "/secure", headers={"Host": "example.test"})
    r = c.getresponse()
    body = r.read().decode()
    check(r.status == 200 and "origin path=/secure" in body, "HTTPS with a generated certificate")
    check(r.getheader("alt-svc") == f'h3=":{HTTPS}"; ma=86400', "HTTPS responses advertise HTTP/3")
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.bind(("127.0.0.1", HTTPS))
        quic_bound = False
    except OSError:
        quic_bound = True
    u.close()
    check(quic_bound, "QUIC listener holds the UDP port")
    st, r = api("PUT", "/workers/scripts/big", raw='export default { fetch() { return new Response("x".repeat(4000), { headers: { "content-type": "text/html" } }); } }')
    api("POST", f"/zones/{zid}/workers/routes", {"pattern": "example.test/big", "script": "big"})
    st, h, _ = edge("/big", headers={"Accept-Encoding": "br, gzip"})
    check(h.get("content-encoding") == "br" and int(h["content-length"]) < 200, "brotli compression at the edge")
    st, r = api("GET", f"/zones/{zid}/analytics")
    a = r["result"]
    check(a["requests"] > 20 and a["threats"] >= 4 and a["cached"] >= 2 and a["status_2xx"] > 10, f"analytics {a['requests']} requests")

    print("ranges, zone settings, CNAME flattening")
    edge("/a/range.css")
    st, h, body = edge("/a/range.css", headers={"Range": "bytes=0-5"})
    check(st == 206 and h["cf-cache-status"] == "HIT" and h["content-range"].startswith("bytes 0-5/") and body == "origin", "byte range cut from the cached object")
    api("PATCH", f"/zones/{zid}/settings/security_level", {"value": "under_attack"})
    st, h, body = edge("/page")
    check(st == 403 and "Checking your browser" in body, "under attack mode challenges visitors")
    check(api("PATCH", f"/zones/{zid}/settings/security_level", {"value": "medium"})[0] == 200 and edge("/page")[0] == 200, "and is switched off again")
    api("PATCH", f"/zones/{zid}/settings/browser_cache_ttl", {"value": 600})
    check(edge("/a/range.css")[1]["cache-control"] == "public, max-age=600", "browser cache TTL applied to cached content")
    st, r = api("POST", "/zones", {"name": "apex.test"})
    st, r = api("POST", f"/zones/{r['result']['id']}/dns_records", {"type": "CNAME", "name": "@", "content": "localhost"})
    check(st == 200, "CNAME accepted at the zone apex")
    wait_for("apex CNAME flattened into its target's address", lambda: dns_a("apex.test") == ["127.0.0.1"])

    print("the edge's own endpoints")
    st, h, body = edge("/cdn-cgi/fucf-trace", headers={"User-Agent": "e2e/1"})
    trace = dict(line.split("=", 1) for line in body.splitlines())
    check(st == 200 and h["content-type"].startswith("text/plain") and trace["h"] == "example.test" and trace["ip"] == "127.0.0.1"
          and trace["http"] == "http/1.1" and trace["visit_scheme"] == "http" and trace["uag"] == "e2e/1" and trace["warp"] == "off"
          and trace["zone"] == "example.test" and trace["limit"] == "ok" and trace["ray"] == h["fucf-ray"], "trace describes the visitor")
    before = Origin.hits
    check(edge("/cdn-cgi/fucf-trace", host="unknown.test")[0] == 200, "trace works for any host")
    check(edge("/cdn-cgi/fucf-warp")[0] == 501 and edge("/cdn-cgi/fucf-warp/x", method="POST", body="y")[0] == 501, "the reserved endpoint is the edge's")
    check([edge(p)[0] for p in ("/cdn-cgi", "/cdn-cgi/", "/cdn-cgi/trace", "/cdn-cgi/anything/else")] == [404] * 4, "nothing else exists under /cdn-cgi")
    check(Origin.hits == before, "none of it reaches the origin")
    # HTTP/3 for real, and through a front (another QUIC server that passes its visitors on)
    out = subprocess.run([BIN, "h3-get", f"https://example.test:{HTTPS}/cdn-cgi/fucf-trace", "--connect", "127.0.0.1", "--insecure"],
                         capture_output=True, text=True, timeout=60).stdout
    check(out.startswith("HTTP/3.0 200") and "\nhttp=http/3\n" in out and "\ntls=TLSv1.3\n" in out, "the HTTP/3 probe gets its answer over QUIC")
    c = http.client.HTTPConnection("127.0.0.1", FRONT, timeout=10)
    c.request("GET", "/cdn-cgi/fucf-trace", headers={"Host": "example.test", "X-Forwarded-For": "10.1.1.1, 198.51.100.7", "X-Forwarded-Proto": "https"})
    r = c.getresponse()
    trace = dict(line.split("=", 1) for line in r.read().decode().splitlines())
    check(r.status == 200 and (trace["ip"], trace["http"], trace["visit_scheme"], trace["tls"]) == ("198.51.100.7", "http/3", "https", "TLSv1.3"),
          "visitors handed over by an HTTP/3 front are seen as they came")
    st, r = api("POST", "/warp/purge_cache", {"purge_everything": True})
    check(st == 200 and r["result"] == {"id": "cdn-cgi:fucf-warp", "purged": 0} and api("POST", "/warp/purge_cache", {})[0] == 400, "the reserved endpoint's cache can be purged")

    print("node traffic limits")
    st, r = api("POST", "/nodes", {"name": "solo", "ipv4": "203.0.113.10", "traffic_limit_gb": 0.000001})
    node = r["result"]
    check(st == 200 and node["traffic_period"] == "month" and node["traffic_reset_day"] == 1, "traffic limit set on this node")
    check(api("POST", "/nodes", {"name": "bad", "ipv4": "203.0.113.11", "traffic_dns_gb": 5, "traffic_limit_gb": 1})[0] == 400, "inconsistent limits refused")
    wait_for("a node over its allowance answers with the notice", lambda: edge("/page")[0] == 509)
    st, h, body = edge("/page")
    check(h["content-type"].startswith("text/html") and "DNS" in body and h.get("retry-after") == "300", "the notice tells visitors to check their DNS")
    st, h, body = edge("/cdn-cgi/limit/page.css")
    check(st == 509 and body == "", "the notice's resources are not served by the limited node")
    traffic = api("GET", "/nodes")[1]["result"][0]["traffic"]
    check(traffic["state"] == "limited" and traffic["used_bytes"] > 1000 and traffic["period_start"].endswith("-01T00:00:00Z"), "usage of the period shown per node")
    check(api("GET", "/zones")[0] == 200, "the management API is not affected")
    check(dns_a("example.test") == ["203.0.113.10"], "the only node is still answered by DNS")
    check(api("PATCH", f"/nodes/{node['id']}", {"traffic_limit_gb": None})[0] == 200, "limit removed")
    wait_for("the node serves again", lambda: edge("/page")[0] == 200)
    st, h, body = edge("/cdn-cgi/limit/page.css")
    check(st == 200 and h["content-type"].startswith("text/css"), "a node with allowance serves the notice's resources")
    check(api("DELETE", f"/nodes/{node['id']}")[0] == 200, "node removed")

    print("managed certificates")
    packs = f"/zones/{zid}/ssl/certificate_packs"
    st, r = api("POST", packs, {})
    pack = r["result"]
    check(st == 200 and pack["hosts"] == ["example.test", "*.example.test"] and pack["status"] == "pending" and "private_key" not in pack,
          "certificate ordered for the apex and its wildcard")
    check(api("POST", packs, {"hosts": ["www.other.test"]})[0] == 400, "names outside the zone refused")
    check(api("POST", packs, {"hosts": ["*.example.test"], "validation_method": "http"})[0] == 400, "wildcards need DNS validation")

    def failed():
        p = api("GET", f"{packs}/{pack['id']}")[1]["result"]
        return p if p["status"] == "failed" else None
    p = wait_for("order attempted", failed)
    check("cannot reach " + ACME in p["error"] and p["attempts"] == 1 and p["next_attempt"], "unreachable CA reported, retry scheduled")
    st, r = api("PATCH", f"{packs}/{pack['id']}")
    check(st == 200 and r["result"]["status"] == "pending" and r["result"]["next_attempt"] is None, "retry on request")
    check(api("DELETE", f"{packs}/{pack['id']}")[0] == 200 and api("GET", packs)[1]["result"] == [], "order withdrawn")

    print("misc")
    check(api("GET", f"/zones/{zid}/settings")[1]["result"][0]["id"] == "always_use_https", "settings listed")
    c = http.client.HTTPConnection("127.0.0.1", API, timeout=5)
    c.request("GET", "/client/v4/zones")
    r = c.getresponse()
    r.read()
    check(r.status == 401 and r.getheader("X-Frame-Options") == "DENY" and r.getheader("X-Content-Type-Options") == "nosniff"
          and r.getheader("Cache-Control") == "no-store", "API requires the token and sends security headers")
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    check(r.status == 200 and "frame-ancestors 'none'" in (r.getheader("Content-Security-Policy") or "")
          and r.getheader("X-Frame-Options") == "DENY", "panel sends CSP and anti-clickjacking headers")


def _cmd_list_tests():
    from e2e_tiers import load_all_tiers

    tests = load_all_tiers()
    print("Baseline checks (152 total: 130 Windows / 152 Linux):")
    print("  baseline/run       : 70 checks (Zone/DNS, CDN, WAF, Workers, Spectrum, Rules/H3, Limits, Certs, Misc)")
    print("  baseline/mail      : 18 checks (SMTP Email Routing + SRS)")
    print("  baseline/accounts  : 32 checks (Panel accounts, roles, TOTP, backup codes, audit, fleet)")
    print("  baseline/fleet     : 10 checks (Replica sync, analytics, events, cache purge)")
    print("  baseline/releases  : 22 checks (Unix-only rolling updates + rollback)")
    print("")
    by_tier = {"1": 0, "2": 0, "3": 0, "4": 0}
    for t in tests:
        by_tier[t.tier] += 1
        reqs = ",".join(t.reqs)
        tags = f" tags={','.join(t.tags)}" if t.tags else ""
        print(f"  {t.id}  tier={t.tier}  suite={t.suite:<4} reqs={reqs:<24}{tags}  {t.description}")
    print("")
    print(
        f"Counts: Tier 1={by_tier['1']}, Tier 2={by_tier['2']}, Tier 3={by_tier['3']}, Tier 4={by_tier['4']} "
        f"(new={len(tests)}, baseline=152, grand_total={len(tests) + 152})"
    )


def _cmd_selftest():
    from e2e_tiers.selftest import run_selftest

    rc = run_selftest()
    if rc != 0:
        return rc
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    for mod_name in ("bench_proxy", "ui_check"):
        mod_path = os.path.join(scripts_dir, f"{mod_name}.py")
        if os.path.exists(mod_path):
            mod = importlib.import_module(mod_name)
            if hasattr(mod, "run_selftest"):
                print(f"running {mod_name}.run_selftest()...")
                res = mod.run_selftest()
                if isinstance(res, dict):
                    if not res.get("passed"):
                        print(f"  FAIL {mod_name}.run_selftest(): {res}")
                        return 1
                    print(f"  ok   {mod_name}.run_selftest() passed ({len(res.get('checks', []))} checks)")
                elif res not in (0, None, True):
                    return 1
            else:
                p = subprocess.run([sys.executable, mod_path, "--selftest"], check=False)
                if p.returncode != 0:
                    return p.returncode
    return 0


def _run_tiers(bin_path, tier, suite, flt, keep_logs):
    from e2e_tiers import TestContext, select_tests

    run_base = (
        (tier in ("all", "baseline"))
        and (suite in ("all", "baseline"))
        and (not flt or "baseline" in flt.lower() or "t4-012" in flt.lower())
    )
    selected = [] if tier == "baseline" else select_tests(tier=tier, suite=suite, flt=flt)
    if tier == "all" and suite == "all" and not flt:
        # Avoid running baseline twice when T4-012 is included in Tier 4
        pass

    failed = []
    passed = 0
    if run_base:
        print("=== Running Preserved Baseline Checks ===")
        run_baseline(bin_path, keep_logs=keep_logs)
        passed += 1

    if selected:
        ctx = TestContext(bin_path, keep_logs=keep_logs)
        try:
            for tc in selected:
                if tc.id == "T4-012" and run_base:
                    print(f"  ok   {tc.id} (already executed baseline above)")
                    passed += 1
                    continue
                print(f"[{tc.id}] (tier={tc.tier} suite={tc.suite}) {tc.description}")
                try:
                    tc.fn(ctx)
                    print(f"  PASS {tc.id}")
                    passed += 1
                except Exception as exc:  # noqa: BLE001
                    print(f"  FAIL {tc.id}: {exc}")
                    failed.append((tc.id, str(exc)))
                    ctx.mark_failed()
        finally:
            ctx.close()

    print(f"\nSummary: {passed} passed, {len(failed)} failed")
    for tid, msg in failed:
        print(f"  FAILED {tid}: {msg}")
    return 1 if failed else 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="fucloudflare (fucf) E2E test runner")
    p.add_argument("bin_pos", nargs="?", default=None, help="Path to fucf binary")
    p.add_argument("--bin", dest="bin_opt", default=None, help="Path to fucf binary")
    p.add_argument("--tier", choices=["baseline", "1", "2", "3", "4", "all"], default="all")
    p.add_argument("--suite", choices=["all", "baseline", "r1", "r2", "r3", "r4", "r5", "ui", "bench"], default="all")
    p.add_argument("--filter", dest="flt", default=None, help="Filter tests by ID or substring")
    p.add_argument("--list-tests", action="store_true", help="List all registered tests and exit")
    p.add_argument("--selftest", action="store_true", help="Run offline helper/simulator self-tests")
    p.add_argument("--keep-logs", action="store_true", help="Keep temporary node logs on failure")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)

    if args.list_tests:
        _cmd_list_tests()
        return 0
    if args.selftest:
        return _cmd_selftest()

    bin_path = args.bin_opt or args.bin_pos or DEFAULT_BIN
    return _run_tiers(bin_path, args.tier, args.suite, args.flt, args.keep_logs)


if __name__ == "__main__":
    raise SystemExit(main())
