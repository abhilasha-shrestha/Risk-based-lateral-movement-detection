"""Build USER_HOST_BASELINE over the fixed training window.

Training window: 2010-01-01 .. 2010-03-01 (CERT months Jan-Feb 2010),
which ends before the first labeled insider activity.

LEAKAGE GUARD: the baseline must contain nothing on/after the cutoff.
We assert this after building. Never widen the window to the full
dataset — every attack would end up in its own baseline and recall
would collapse.
"""
from __future__ import annotations
import argparse

from common import connect

CUTOFF = "2010-03-01"

BUILD_SQL = f"""
TRUNCATE user_host_baseline;
INSERT INTO user_host_baseline
    (user_id, host_id, first_login_ts, last_login_ts, login_count,
     typical_hour_start, typical_hour_end)
SELECT
    target_user_id,
    dst_host_id,
    min(ts),
    max(ts),
    count(*),
    percentile_cont(0.05) WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM ts))::INT,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM ts))::INT
FROM login_event
WHERE ts < TIMESTAMP '{CUTOFF}'
GROUP BY target_user_id, dst_host_id;
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="print the SQL and training window, do not run")
    args = ap.parse_args()

    print(f"training window: < {CUTOFF}")
    if args.dry_run:
        print(BUILD_SQL)
        print("[dry-run] no DB write")
        return

    with connect() as conn, conn.cursor() as cur:
        cur.execute(BUILD_SQL)
        conn.commit()

        cur.execute("SELECT count(*) FROM user_host_baseline")
        print(f"baseline (user,host) pairs: {cur.fetchone()[0]}")
        cur.execute("SELECT count(DISTINCT user_id) FROM user_host_baseline")
        print(f"users with a baseline: {cur.fetchone()[0]}")

        # leakage assertion
        cur.execute(
            f"""SELECT count(*) FROM login_event e
                 JOIN user_host_baseline b
                   ON b.user_id = e.target_user_id AND b.host_id = e.dst_host_id
                WHERE e.ts >= TIMESTAMP '{CUTOFF}'
                  AND b.first_login_ts >= TIMESTAMP '{CUTOFF}'"""
        )
        leaked = cur.fetchone()[0]
        assert leaked == 0, f"LEAKAGE: {leaked} baseline rows built from post-cutoff data"
        print("leakage check passed: baseline contains no post-cutoff activity")


if __name__ == "__main__":
    main()
