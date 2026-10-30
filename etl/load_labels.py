"""Load ground-truth labels into redteam_label.

The answer files (answers/r4.2-1|2|3/*.csv) list each insider's malicious
events, one per line, prefixed by log type:
    logon,{uid},MM/DD/YYYY HH:MM:SS,USER,PC,Logon
We take the 'logon' rows (activity Logon) — those are the malicious
authentication events — and link them to login_event via the CERT uid.

scenario-3 (sysadmin logs in as his supervisor) is the primary, independent
ground truth for lateral movement. Scenarios 1 and 2 are also loaded.
"""
from __future__ import annotations
import argparse
import csv
import sys

from common import DATA, parse_ts, connect


def collect():
    """Return list of (ts, source, scenario, user_id, uid) for malicious logons."""
    ans = DATA / "answers"
    out = []
    per_folder = {}
    for folder in ("r4.2-1", "r4.2-2", "r4.2-3"):
        d = ans / folder
        if not d.exists():
            continue
        scen = folder.split("-")[-1]          # '1' / '2' / '3'
        src = f"cert-scenario-{scen}"
        cnt = 0
        for f in sorted(d.glob("*.csv")):
            with open(f, newline="", encoding="utf-8", errors="ignore") as fh:
                for row in csv.reader(fh):
                    if len(row) < 6 or row[0] != "logon" or row[5] != "Logon":
                        continue
                    uid, dt, user = row[1], row[2], row[3]
                    try:
                        ts = parse_ts(dt)
                    except ValueError:
                        continue
                    out.append((ts, src, scen, user, uid))
                    cnt += 1
        per_folder[folder] = cnt
    return out, per_folder


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--truncate", action="store_true",
                    help="empty redteam_label before loading (safe re-run)")
    args = ap.parse_args()

    labels, per_folder = collect()
    if not labels:
        sys.exit("no label rows found — check answers/ folder")
    print("malicious logon labels per scenario:", per_folder)
    print(f"total label rows: {len(labels)}")

    if args.dry_run:
        print("[dry-run] no DB write")
        return

    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM redteam_label")
        existing = cur.fetchone()[0]
        if existing and not args.truncate:
            print(f"ABORT: redteam_label already has {existing} rows. "
                  f"Re-run with --truncate to reload. (Would duplicate labels.)")
            return
        if existing and args.truncate:
            cur.execute("TRUNCATE redteam_label")
            conn.commit()
            print(f"truncated redteam_label ({existing} rows removed)")

        cur.executemany(
            """INSERT INTO redteam_label (ts, source, scenario, user_id, source_event_ref)
               VALUES (%s,%s,%s,%s,%s)""",
            labels,
        )
        conn.commit()
        # resolve event_id by matching the CERT uid
        cur.execute(
            """UPDATE redteam_label l
                 SET event_id = e.event_id
               FROM login_event e
               WHERE e.source_event_ref = l.source_event_ref
                 AND l.event_id IS NULL"""
        )
        conn.commit()
        cur.execute("SELECT count(*) FROM redteam_label")
        total = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM redteam_label WHERE event_id IS NOT NULL")
        linked = cur.fetchone()[0]
        cur.execute("SELECT count(DISTINCT user_id) FROM redteam_label")
        users = cur.fetchone()[0]
        print(f"redteam_label rows: {total}  |  linked to an event: {linked}  |  insiders: {users}")


if __name__ == "__main__":
    main()
