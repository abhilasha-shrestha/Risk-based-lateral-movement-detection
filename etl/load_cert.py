"""Load CERT logon.csv into login_event (the fact table).

- Loads only activity='Logon' rows (470,591) into login_event.
  Logoff rows are skipped in Phase 1.
- Derives the host set from every distinct pc in logon.csv.
- Inserts user/host stubs for any id not already present, so this loader
  is safe to run even if LDAP coverage is imperfect.
- Uses COPY (not INSERT) for the event rows — minutes vs. an hour.

In Phase 1 every event is a local interactive logon:
  source_user = target_user, src_host = dst_host, success = TRUE.
synthesize.py (Phase 2) later rewrites a fraction of these.

logon.csv columns: id,date,user,pc,activity
"""
from __future__ import annotations
import argparse
import csv
import sys

from common import DATA, parse_ts, connect


def logon_path():
    p = DATA / "r4.2" / "logon.csv"
    if not p.exists():
        sys.exit(f"missing {p}")
    return p


def scan(limit: int | None):
    """First pass: distinct hosts/users, row counts, date range, bad dates."""
    hosts, users = set(), set()
    n_logon = n_total = n_bad = 0
    tmin = tmax = None
    with open(logon_path(), newline="", encoding="utf-8", errors="ignore") as fh:
        for r in csv.DictReader(fh):
            n_total += 1
            if r["activity"] != "Logon":
                continue
            try:
                ts = parse_ts(r["date"])
            except ValueError:
                n_bad += 1
                continue
            n_logon += 1
            hosts.add(r["pc"])
            users.add(r["user"])
            tmin = ts if tmin is None or ts < tmin else tmin
            tmax = ts if tmax is None or ts > tmax else tmax
            if limit and n_logon >= limit:
                break
    return hosts, users, n_logon, n_total, n_bad, tmin, tmax


def event_rows(limit: int | None):
    """Yield tuples for COPY, Logon rows only."""
    n = 0
    with open(logon_path(), newline="", encoding="utf-8", errors="ignore") as fh:
        for r in csv.DictReader(fh):
            if r["activity"] != "Logon":
                continue
            try:
                ts = parse_ts(r["date"])
            except ValueError:
                continue
            user, pc, ref = r["user"], r["pc"], r["id"]
            # ts, source_user, target_user, src_host, dst_host, activity, ref
            yield (ts, user, user, pc, pc, "Logon", ref)
            n += 1
            if limit and n >= limit:
                break


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--truncate", action="store_true",
                    help="empty login_event before loading (safe re-run)")
    ap.add_argument("--limit", type=int, default=None,
                    help="load only the first N Logon rows (smoke test)")
    args = ap.parse_args()

    hosts, users, n_logon, n_total, n_bad, tmin, tmax = scan(args.limit)
    print(f"rows in file: {n_total}  |  Logon rows: {n_logon}  |  unparseable dates: {n_bad}")
    print(f"distinct hosts: {len(hosts)}  |  distinct users: {len(users)}")
    print(f"date range: {tmin}  ..  {tmax}")

    if args.dry_run:
        print("[dry-run] no DB write")
        return

    with connect() as conn, conn.cursor() as cur:
        # guard: COPY appends, so refuse to load on top of existing data
        cur.execute("SELECT count(*) FROM login_event")
        existing = cur.fetchone()[0]
        if existing and not args.truncate:
            print(f"ABORT: login_event already has {existing} rows. "
                  f"Re-run with --truncate to reload, or reset the DB with "
                  f"'docker compose down -v'. (COPY would duplicate the data.)")
            return
        if existing and args.truncate:
            cur.execute("TRUNCATE login_event")
            conn.commit()
            print(f"truncated login_event ({existing} rows removed)")

        # host set
        cur.executemany(
            "INSERT INTO host (host_id, hostname_hash) VALUES (%s, md5(%s)) "
            "ON CONFLICT (host_id) DO NOTHING",
            [(hid, hid) for hid in hosts],
        )
        # user stubs for any logon user missing from LDAP load
        cur.executemany(
            "INSERT INTO app_user (user_id, origin) VALUES (%s, 'CERT-logon-only') "
            "ON CONFLICT (user_id) DO NOTHING",
            [(uid,) for uid in users],
        )
        conn.commit()

        # COPY the events
        copy_sql = (
            "COPY login_event "
            "(ts, source_user_id, target_user_id, src_host_id, dst_host_id, "
            " activity, source_event_ref) FROM STDIN"
        )
        with cur.copy(copy_sql) as cp:
            for row in event_rows(args.limit):
                cp.write_row(row)
        conn.commit()

        # set first_seen = earliest logon per user
        cur.execute(
            "UPDATE app_user u SET first_seen = s.first_ts "
            "FROM (SELECT target_user_id, min(ts) first_ts "
            "      FROM login_event GROUP BY target_user_id) s "
            "WHERE u.user_id = s.target_user_id AND u.first_seen IS NULL"
        )
        conn.commit()

        cur.execute("SELECT count(*) FROM login_event")
        print(f"login_event rows now: {cur.fetchone()[0]}")
        cur.execute("SELECT count(*) FROM host")
        print(f"host rows now: {cur.fetchone()[0]}")


if __name__ == "__main__":
    main()
