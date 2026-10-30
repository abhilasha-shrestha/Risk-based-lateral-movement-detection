"""Load app_user from the 17 monthly LDAP snapshots.

A user present in month N but absent in month N+1 has been terminated;
terminated_date is set to the first-of-month they disappeared.
LDAP columns: employee_name,user_id,email,role,business_unit,
functional_unit,department,team,supervisor
"""
from __future__ import annotations
import argparse
import csv
import sys
from datetime import date
from pathlib import Path

from common import DATA, h, connect


def month_key(fname: str) -> str:
    # "2010-03.csv" -> "2010-03"
    return Path(fname).stem


def read_snapshots() -> tuple[dict, list[str]]:
    ldap_dir = DATA / "r4.2" / "LDAP"
    files = sorted(ldap_dir.glob("*.csv"))
    if not files:
        sys.exit(f"No LDAP files under {ldap_dir}")
    users: dict[str, dict] = {}
    present_by_month: dict[str, set] = {}
    months = [month_key(f.name) for f in files]

    for f in files:
        mk = month_key(f.name)
        present_by_month[mk] = set()
        with open(f, newline="", encoding="utf-8", errors="ignore") as fh:
            for r in csv.DictReader(fh):
                uid = r["user_id"]
                present_by_month[mk].add(uid)
                # keep the latest attributes we see for the user
                users[uid] = {
                    "user_id": uid,
                    "username_hash": h(r.get("employee_name")),
                    "roles": r.get("role"),
                    "email_hash": h(r.get("email")),
                    "business_unit": r.get("business_unit"),
                    "functional_unit": r.get("functional_unit"),
                    "department": r.get("department"),
                    "team": r.get("team"),
                    "supervisor": r.get("supervisor"),
                    "first_seen": users.get(uid, {}).get("first_seen", mk),
                }

    # terminated_date: first month a previously-present user goes missing
    last_month = months[-1]
    for uid, info in users.items():
        term = None
        was_present = False
        for mk in months:
            here = uid in present_by_month[mk]
            if was_present and not here:
                y, m = map(int, mk.split("-"))
                term = date(y, m, 1)
                break
            was_present = was_present or here
        # present in the final snapshot => still employed
        if uid in present_by_month[last_month]:
            term = None
        info["terminated_date"] = term
    return users, months


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report counts without touching the DB")
    args = ap.parse_args()

    users, months = read_snapshots()
    n_term = sum(1 for u in users.values() if u["terminated_date"])
    print(f"LDAP months: {len(months)} ({months[0]}..{months[-1]})")
    print(f"distinct users: {len(users)}  |  terminated: {n_term}")

    if args.dry_run:
        print("[dry-run] no DB write")
        return

    rows = [
        (u["user_id"], u["username_hash"], u["roles"], "CERT",
         u["email_hash"], u["business_unit"], u["functional_unit"],
         u["department"], u["team"], u["supervisor"], u["terminated_date"])
        for u in users.values()
    ]
    with connect() as conn, conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO app_user
                 (user_id, username_hash, roles, origin, email_hash,
                  business_unit, functional_unit, department, team,
                  supervisor, terminated_date)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (user_id) DO NOTHING""",
            rows,
        )
        conn.commit()
        cur.execute("SELECT count(*) FROM app_user")
        print(f"app_user rows now: {cur.fetchone()[0]}")


if __name__ == "__main__":
    main()
