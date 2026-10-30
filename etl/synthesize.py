"""Seeded synthetic enrichment (Phase 2).

CERT logons lack failed logins, auth types, source hosts and credential
switching. This script layers those on, and injects multi-hop attack
campaigns — the only true multi-hop ground truth we have.

Idempotent: it first removes its own prior output (synthetic rows and
labels) and resets the enrichment columns, so re-running with the same
--seed reproduces the same database.

Everything synthetic is flagged: login_event.is_synthetic = TRUE for
generated rows; redteam_label.source = 'synthetic' for campaign labels.
The enrichment of REAL rows (auth_type, remote src_host) is deterministic
from the seed, so results stay reproducible but are clearly derived.
"""
from __future__ import annotations
import argparse
import random
from datetime import timedelta

from common import connect, CERT_TS_FMT  # noqa: F401

N_CAMPAIGNS = 20
N_HIGH_HOSTS = 30

# training cutoff — must match build_baseline.py / signals.py
CUTOFF_PY = "2010-03-01"
CUTOFF_SQL = "2010-03-01"


def reset(cur, seed):
    cur.execute("DELETE FROM redteam_label WHERE source = 'synthetic'")
    cur.execute("DELETE FROM login_event WHERE is_synthetic")
    cur.execute("UPDATE host SET sensitivity='low', host_type='workstation'")
    cur.execute(
        "UPDATE login_event SET logon_type='interactive', "
        "src_host_id=dst_host_id, source_user_id=target_user_id, auth_type=NULL "
        "WHERE NOT is_synthetic"
    )


def enrich(cur, seed):
    s = str(seed)
    # --- host sensitivity -------------------------------------------------
    cur.execute(
        """WITH ranked AS (
               SELECT host_id, abs(hashtext(%s || host_id)) AS hh FROM host
           )
           UPDATE host SET sensitivity='high', host_type='fileserver'
           WHERE host_id IN (SELECT host_id FROM ranked ORDER BY hh LIMIT %s)""",
        (s, N_HIGH_HOSTS),
    )
    # each ITAdmin's primary (most-used) machine -> medium
    cur.execute(
        """UPDATE host SET sensitivity='medium'
           WHERE sensitivity='low' AND host_id IN (
               SELECT DISTINCT ON (b.user_id) b.host_id
               FROM user_host_baseline b
               JOIN app_user u ON u.user_id = b.user_id
               WHERE u.roles = 'ITAdmin'
               ORDER BY b.user_id, b.login_count DESC)"""
    )
    # --- auth_type by host type ------------------------------------------
    cur.execute(
        """UPDATE login_event e SET auth_type =
               CASE h.host_type WHEN 'fileserver' THEN 'kerberos' ELSE 'ntlm' END
           FROM host h WHERE h.host_id = e.dst_host_id AND NOT e.is_synthetic"""
    )
    # --- remote logons (~15%): give them a real source host (edges) ------
    cur.execute(
        f"""WITH prev AS (
               SELECT event_id,
                      lag(dst_host_id) OVER (PARTITION BY target_user_id ORDER BY ts) AS prev_host
               FROM login_event WHERE NOT is_synthetic)
           UPDATE login_event e
              SET logon_type='remote', auth_type='ssh', src_host_id = p.prev_host
           FROM prev p
           WHERE p.event_id = e.event_id
             AND p.prev_host IS NOT NULL
             AND p.prev_host <> e.dst_host_id
             AND abs(hashtext('{s}remote' || e.source_event_ref)) % 100 < 15"""
    )
    # --- benign failed logins (~2% of post-cutoff successes, 2 fails) -----
    # 2 fails < FTS threshold of 3, so these are NOISE, not attacks.
    cur.execute(
        f"""INSERT INTO login_event
               (ts, source_user_id, target_user_id, src_host_id, dst_host_id,
                auth_type, success, logon_type, activity, source_event_ref, is_synthetic)
           SELECT e.ts - (k * interval '15 seconds'),
                  e.target_user_id, e.target_user_id, e.dst_host_id, e.dst_host_id,
                  'ntlm', FALSE, 'interactive', 'Logon',
                  'SYN-FAIL-' || e.event_id || '-' || k, TRUE
           FROM login_event e, generate_series(1,2) AS k
           WHERE NOT e.is_synthetic AND e.success AND e.ts >= TIMESTAMP '{CUTOFF_SQL}'
             AND abs(hashtext('{s}fail' || e.source_event_ref)) % 100 < 2"""
    )


def inject_campaigns(cur, rng):
    """20 multi-hop chains: brute-force entry, credential switch at hop 2,
    ending on a sensitive host, after-hours. Each hop is labeled."""
    cur.execute("SELECT host_id FROM host WHERE sensitivity='high'")
    high_hosts = [r[0] for r in cur.fetchall()]
    cur.execute("SELECT host_id FROM host WHERE sensitivity<>'high'")
    workstations = [r[0] for r in cur.fetchall()]
    # actors / victims: real users, excluding existing labeled insiders
    cur.execute(
        "SELECT user_id FROM app_user WHERE user_id NOT IN "
        "(SELECT DISTINCT user_id FROM redteam_label WHERE user_id IS NOT NULL)"
    )
    pool = [r[0] for r in cur.fetchall()]
    rng.shuffle(pool)

    rows, labels = [], []
    start_day = 120   # days after cutoff, keeps campaigns in the test period
    for c in range(N_CAMPAIGNS):
        attacker = pool[c]
        victim = pool[N_CAMPAIGNS + c]
        n_hops = rng.randint(4, 6)
        path = rng.sample(workstations, n_hops - 1) + [rng.choice(high_hosts)]
        # after-hours start, spread campaigns across the test window
        from datetime import datetime
        base = datetime.strptime(CUTOFF_PY, "%Y-%m-%d") + timedelta(
            days=start_day + c * 7, hours=rng.choice([22, 23, 0, 1, 2]),
            minutes=rng.randint(0, 59))
        t = base
        entry = path[0]
        # brute force: 4 failures then success at entry (fires failed_then_success)
        for k in range(4):
            rows.append((t - timedelta(seconds=30 * (4 - k)), attacker, attacker,
                         entry, entry, "ssh", False, "remote",
                         f"SYN-C{c}-BF{k}", True))
        for i, host in enumerate(path):
            acct = attacker if i == 0 else victim          # credential switch at hop>=1
            src = path[i - 1] if i > 0 else host
            ref = f"SYN-C{c}-H{i}"
            rows.append((t, attacker, acct, src, host, "ssh", True, "remote", ref, True))
            labels.append((t, "synthetic", "LM", acct, ref))
            t += timedelta(minutes=rng.randint(3, 12))

    cur.executemany(
        """INSERT INTO login_event
             (ts, source_user_id, target_user_id, src_host_id, dst_host_id,
              auth_type, success, logon_type, source_event_ref, is_synthetic)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        rows,
    )
    cur.executemany(
        """INSERT INTO redteam_label (ts, source, scenario, user_id, source_event_ref)
           VALUES (%s,%s,%s,%s,%s)""",
        labels,
    )
    # link synthetic labels to their events
    cur.execute(
        """UPDATE redteam_label l SET event_id = e.event_id
           FROM login_event e
           WHERE e.source_event_ref = l.source_event_ref
             AND l.source = 'synthetic' AND l.event_id IS NULL"""
    )
    return len(rows), len(labels)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    with connect() as conn, conn.cursor() as cur:
        reset(cur, args.seed)
        enrich(cur, args.seed)
        n_rows, n_labels = inject_campaigns(cur, rng)
        conn.commit()

        cur.execute("SELECT count(*) FROM login_event WHERE is_synthetic")
        syn = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM login_event WHERE NOT success")
        fails = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM login_event WHERE logon_type='remote'")
        remote = cur.fetchone()[0]
        cur.execute("SELECT sensitivity, count(*) FROM host GROUP BY sensitivity ORDER BY 1")
        sens = dict(cur.fetchall())
        cur.execute("SELECT count(*) FROM redteam_label WHERE source='synthetic' AND event_id IS NOT NULL")
        lbl = cur.fetchone()[0]

    print(f"seed={args.seed}")
    print(f"campaign rows inserted: {n_rows}  |  campaign labels linked: {lbl}/{n_labels}")
    print(f"total synthetic rows: {syn}  |  failed logons: {fails}  |  remote logons: {remote}")
    print(f"host sensitivity: {sens}")


if __name__ == "__main__":
    main()
