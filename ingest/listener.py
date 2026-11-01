"""Live syslog listener (Phase 4) — Laptop A.

Receives sshd log lines forwarded by the lab machines' rsyslog over TCP,
parses the authentication events, stores them in login_event, and scores
each one on arrival (near-real-time micro-event). Alerts appear in the
same ALERT table the dashboard reads.

Lab hosts/users are seeded from lab/lab_topology.json so sensitivities
and IP->host mapping are known. Unknown hosts/users are created on the fly.

Run (from the venv):   python ingest/listener.py [-v]
Listens on 0.0.0.0:5514 TCP (matches the rsyslog rule written by
lab/alpine-setup.sh:  authpriv.*  @@<laptop-A-ip>:5514).

-v / --verbose echoes every forwarded line before parsing — use it to confirm
plumbing with `logger -p authpriv.info test`, which is not an sshd event and so
is otherwise dropped silently.

sshd messages handled:
  Accepted password/publickey for <user> from <ip> port ...
  Failed   password        for [invalid user] <user> from <ip> port ...
"""
from __future__ import annotations
import json
import re
import socketserver
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "etl"))
sys.path.insert(0, str(ROOT / "detect"))
from common import connect              # noqa: E402
from score import score_incremental     # noqa: E402

HOST = "0.0.0.0"
PORT = 5514

# <pri>[version] <timestamp> hostname tag[pid]: message
# Both syslog timestamp styles are accepted: rsyslog's forward template is
# traditional RFC3164 ("Oct 31 20:18:42") on Alpine/older clients but
# high-precision RFC3339 ("2026-10-31T20:18:42.904904+00:00") on Ubuntu 22.04+
# (rsyslog 8.x). Matching only the first silently drops every real event.
_TS = (r"(?:\w{3}\s+\d+\s+\d+:\d+:\d+"
       r"|\d{4}-\d\d-\d\dT\d+:\d+:\d+(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)")
# groups -> (hostname, tag, message); the pid in tag[pid] is optional.
SYSLOG_RE = re.compile(rf"^(?:<\d+>)?(?:\d\s+)?{_TS}\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)$")
SSH_RE = re.compile(
    r"(Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port")


def load_topology(cur):
    topo = json.loads((ROOT / "lab" / "lab_topology.json").read_text())
    ip2host = {}
    for h in topo["hosts"]:
        cur.execute(
            """INSERT INTO host (host_id, hostname_hash, host_type, origin, ip_address, sensitivity)
               VALUES (%s, md5(%s), %s, 'lab', %s, %s)
               ON CONFLICT (host_id) DO UPDATE
                 SET sensitivity = EXCLUDED.sensitivity,
                     host_type   = EXCLUDED.host_type,
                     ip_address  = EXCLUDED.ip_address""",
            (h["host_id"], h["host_id"], h["host_type"], h["ip"], h["sensitivity"]),
        )
        ip2host[h["ip"]] = h["host_id"]
    for u in topo["users"]:
        cur.execute("INSERT INTO app_user (user_id, roles, origin) VALUES (%s,'LabUser','lab') "
                    "ON CONFLICT (user_id) DO NOTHING", (u,))
    return ip2host


def ensure_host(cur, host_id):
    cur.execute("INSERT INTO host (host_id, hostname_hash, origin) VALUES (%s, md5(%s), 'lab') "
                "ON CONFLICT (host_id) DO NOTHING", (host_id, host_id))


def ensure_user(cur, user_id):
    cur.execute("INSERT INTO app_user (user_id, roles, origin) VALUES (%s,'LabUser','lab') "
                "ON CONFLICT (user_id) DO NOTHING", (user_id,))


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        conn = connect()
        conn.autocommit = False
        cur = conn.cursor()
        ip2host = self.server.ip2host
        peer = self.client_address[0]
        print(f"[listener] connection from {peer}")
        try:
            for raw in self.rfile:
                # some relays NUL-terminate each frame as well as sending LF
                line = raw.decode("utf-8", "ignore").replace(chr(0), "").strip()
                if not line:
                    continue
                if self.server.verbose:
                    print(f"[raw ] {line}")
                m = SYSLOG_RE.match(line)
                if not m:
                    continue
                dst_host, tag, msg = m.group(1), m.group(2), m.group(3)
                if tag != "sshd":
                    continue
                s = SSH_RE.search(msg)
                if not s:
                    continue
                status, user, src_ip = s.group(1), s.group(2), s.group(3)
                success = (status == "Accepted")
                src_host = ip2host.get(src_ip, src_ip)   # fall back to the raw ip as a host

                ensure_host(cur, dst_host)
                ensure_host(cur, src_host)
                ensure_user(cur, user)
                cur.execute(
                    """INSERT INTO login_event
                         (ts, source_user_id, target_user_id, src_host_id, dst_host_id,
                          auth_type, success, logon_type, activity, source_event_ref, is_synthetic)
                       VALUES (%s,%s,%s,%s,%s,'ssh',%s,'remote','Logon',%s,FALSE)
                       RETURNING event_id""",
                    (datetime.now(), user, user, src_host, dst_host, success,
                     "LAB-" + uuid.uuid4().hex[:12]),
                )
                event_id = cur.fetchone()[0]
                conn.commit()

                flag = "OK " if success else "FAIL"
                print(f"[{flag}] {user}@{dst_host} from {src_host}  (event {event_id})")

                # score successful logons on arrival
                if success:
                    alert_id = score_incremental(cur, event_id)
                    conn.commit()
                    if alert_id:
                        cur.execute("SELECT score FROM alert WHERE alert_id=%s", (alert_id,))
                        sc = cur.fetchone()[0]
                        print(f"   *** ALERT #{alert_id}  score {int(sc)}  "
                              f"user {user} -> {dst_host} ***")
        finally:
            cur.close()
            conn.close()
            print(f"[listener] {peer} disconnected")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    verbose = False


def main():
    verbose = any(a in ("-v", "--verbose") for a in sys.argv[1:])
    with connect() as c, c.cursor() as cur:
        cur.execute("ALTER TABLE alert ADD COLUMN IF NOT EXISTS trigger_event_id BIGINT")
        ip2host = load_topology(cur)
        c.commit()
    print(f"[listener] seeded {len(ip2host)} lab hosts; listening on {HOST}:{PORT}"
          + ("  (verbose: echoing every forwarded line)" if verbose else ""))
    srv = Server((HOST, PORT), Handler)
    srv.ip2host = ip2host
    srv.verbose = verbose
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[listener] stopped")


if __name__ == "__main__":
    main()
