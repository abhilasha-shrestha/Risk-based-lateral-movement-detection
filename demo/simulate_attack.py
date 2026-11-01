"""Attack simulator (Phase 4) — single-laptop test + demo replay net.

Emits real sshd-format syslog lines to the listener over TCP, exactly as
a lab machine's rsyslog would. This lets you test the whole Laptop-A
pipeline (listener -> store -> score -> alert -> path) WITHOUT any VMs,
and is the fallback if the live VM network misbehaves on demo day.

The scripted attack mirrors attack/demo_runbook.md:
  1. (baseline)  alice logs into ws-01 from foothold          -> quiet
  2. (brute)     4x failed bob on ws-01, then success         -> failed_then_success
  3. (pivot)     bob ws-01 -> jump-01                          -> new host
  4. (loot)      bob jump-01 -> fileserver-01 (sensitive)      -> alert + multi-hop path

Run the listener first, then:
  python demo/simulate_attack.py --host localhost --speed 1.0
"""
from __future__ import annotations
import argparse
import json
import socket
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOPO = json.loads((ROOT / "lab" / "lab_topology.json").read_text())
IP = {h["host_id"]: h["ip"] for h in TOPO["hosts"]}


def syslog_line(host_id: str, msg: str) -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"<38>{ts} {host_id} sshd[{int(time.time()) % 90000}]: {msg}\n"


def accepted(dst, user, from_host):
    return syslog_line(dst, f"Accepted password for {user} from {IP[from_host]} port 50022 ssh2")


def failed(dst, user, from_host):
    return syslog_line(dst, f"Failed password for {user} from {IP[from_host]} port 50022 ssh2")


def build_script():
    s = []
    s.append(("baseline: alice logs into ws-01",       accepted("ws-01", "alice", "foothold")))
    for _ in range(4):
        s.append(("brute force: failed bob on ws-01",  failed("ws-01", "bob", "foothold")))
    s.append(("breach: bob accepted on ws-01",         accepted("ws-01", "bob", "foothold")))
    s.append(("pivot: bob ws-01 -> jump-01",           accepted("jump-01", "bob", "ws-01")))
    s.append(("loot: bob jump-01 -> fileserver-01",    accepted("fileserver-01", "bob", "jump-01")))
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--speed", type=float, default=1.0,
                    help="seconds between steps (0.5 = brisk demo)")
    args = ap.parse_args()

    script = build_script()
    with socket.create_connection((args.host, args.port)) as sk:
        for label, line in script:
            print(f">> {label}")
            sk.sendall(line.encode())
            time.sleep(max(0.05, args.speed))
    print("done — watch the listener output and the dashboard")


if __name__ == "__main__":
    main()
