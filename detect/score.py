"""Scoring engine (Phase 2).

Scores every post-baseline successful logon in PostgreSQL, set-based.
For each event it computes the signals in signals.py, writes one
ALERT_REASON row per fired signal, and creates an ALERT when the capped
sum reaches THRESHOLD. Explainability is structural: an alert's score is
exactly the sum of its reason rows.

Idempotent: truncates alert / alert_reason / alert_path_hop first.
Run AFTER load_* and synthesize.py.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

# connect() lives in ../etl/common.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "etl"))
from common import connect                      # noqa: E402
import signals as S                             # noqa: E402


def damp(points_expr: str) -> str:
    """Wrap a points expression with ITAdmin damping (halved unless the
    destination is sensitive)."""
    return (f"CASE WHEN b.user_role = '{S.ADMIN_ROLE}' AND b.dst_sensitivity <> 'high' "
            f"THEN ({points_expr} * {S.ADMIN_DAMP})::int ELSE {points_expr} END")


def build_points_sql() -> str:
    w = S.WEIGHTS
    return f"""
CREATE TEMP TABLE tmp_pts ON COMMIT DROP AS
WITH base AS (
    SELECT e.event_id, e.ts, e.target_user_id AS uid, e.dst_host_id AS host,
           v.is_new_host, v.dst_sensitivity, v.is_credential_switch,
           v.is_after_termination, v.user_role, v.hour_of_day, e.source_user_id
    FROM login_event e
    JOIN v_login_enriched v ON v.event_id = e.event_id
    WHERE e.ts >= TIMESTAMP '{S.CUTOFF}' AND e.success
),
uhours AS (
    SELECT user_id, min(typical_hour_start) lo, max(typical_hour_end) hi
    FROM user_host_baseline GROUP BY user_id
),
rolehost AS (
    SELECT DISTINCT u.roles AS role, e.dst_host_id AS host
    FROM login_event e JOIN app_user u ON u.user_id = e.target_user_id
    WHERE e.ts < TIMESTAMP '{S.CUTOFF}'
),
rapid AS (
    SELECT e.event_id, count(DISTINCT e2.dst_host_id) AS hosts_win
    FROM base e
    JOIN login_event e2 ON e2.target_user_id = e.uid AND e2.success
         AND e2.ts <= e.ts AND e2.ts > e.ts - interval '{S.RAPID_WINDOW_MIN} min'
    GROUP BY e.event_id
),
fts AS (
    SELECT e.event_id, count(*) AS fails
    FROM base e
    JOIN login_event f ON f.target_user_id = e.uid AND f.dst_host_id = e.host
         AND NOT f.success AND f.ts <= e.ts
         AND f.ts > e.ts - interval '{S.FTS_WINDOW_MIN} min'
    GROUP BY e.event_id
),
gaps AS (
    SELECT event_id,
           ts - lag(ts) OVER (PARTITION BY target_user_id ORDER BY ts) AS gap
    FROM login_event WHERE success
)
SELECT b.event_id, b.ts, b.uid, s.signal, s.points, s.detail
FROM base b
LEFT JOIN uhours uh ON uh.user_id = b.uid
LEFT JOIN rapid  r  ON r.event_id = b.event_id
LEFT JOIN fts    f  ON f.event_id = b.event_id
LEFT JOIN gaps   g  ON g.event_id = b.event_id
CROSS JOIN LATERAL (VALUES
  ('new_host',
     CASE WHEN b.is_new_host THEN {damp(str(w['new_host']))} ELSE 0 END,
     'host ' || b.host || ' not in baseline for ' || b.uid),
  ('new_host_for_role',
     CASE WHEN b.is_new_host AND NOT EXISTS (
            SELECT 1 FROM rolehost rh WHERE rh.role = b.user_role AND rh.host = b.host)
          THEN {w['new_host_for_role']} ELSE 0 END,
     'no ' || COALESCE(b.user_role,'?') || ' has used ' || b.host),
  ('unusual_time',
     CASE WHEN uh.lo IS NOT NULL AND (b.hour_of_day < uh.lo OR b.hour_of_day > uh.hi)
          THEN {w['unusual_time']} ELSE 0 END,
     'hour ' || b.hour_of_day || ' outside ' || uh.lo || '-' || uh.hi),
  ('after_hours',
     CASE WHEN b.hour_of_day >= {S.AFTER_HOURS_START} OR b.hour_of_day < {S.AFTER_HOURS_END}
          THEN {w['after_hours']} ELSE 0 END,
     'after-hours logon at hour ' || b.hour_of_day),
  ('rapid_movement',
     CASE WHEN COALESCE(r.hosts_win,0) >= {S.RAPID_MIN_HOSTS}
          THEN {damp(str(w['rapid_movement']))} ELSE 0 END,
     COALESCE(r.hosts_win,0) || ' hosts in {S.RAPID_WINDOW_MIN} min'),
  ('failed_then_success',
     CASE WHEN COALESCE(f.fails,0) >= {S.FTS_MIN_FAILURES}
          THEN {w['failed_then_success']} ELSE 0 END,
     COALESCE(f.fails,0) || ' failures before success'),
  ('sensitive_destination',
     CASE WHEN b.dst_sensitivity = 'high' THEN {w['sensitive_destination']} ELSE 0 END,
     'destination ' || b.host || ' is sensitive'),
  ('credential_switch',
     CASE WHEN b.is_credential_switch THEN {w['credential_switch']} ELSE 0 END,
     'acting user ' || COALESCE(b.source_user_id,'?') || ' != account ' || b.uid),
  ('privilege_escalation',
     CASE WHEN b.user_role = '{S.ADMIN_ROLE}' AND b.is_credential_switch
          THEN {w['privilege_escalation']} ELSE 0 END,
     'use of an ' || '{S.ADMIN_ROLE}' || ' account by another user'),
  ('dormant_account',
     CASE WHEN g.gap > interval '{S.DORMANT_DAYS} days' THEN {w['dormant_account']} ELSE 0 END,
     'first logon after ' || COALESCE(EXTRACT(DAY FROM g.gap)::int::text,'?') || ' days'),
  ('terminated_user',
     CASE WHEN b.is_after_termination THEN {w['terminated_user']} ELSE 0 END,
     'logon after termination date')
) AS s(signal, points, detail)
WHERE s.points > 0;
"""


SCORE_AND_ALERT_SQL = f"""
TRUNCATE alert_path_hop, alert_reason, alert RESTART IDENTITY CASCADE;

WITH scored AS (
    SELECT event_id, ts, uid,
           LEAST({S.SCORE_CAP}, sum(points))::real AS score,
           (array_agg(signal ORDER BY points DESC))[1] AS top_signal
    FROM tmp_pts
    GROUP BY event_id, ts, uid
    HAVING sum(points) >= {S.THRESHOLD}
),
ins AS (
    INSERT INTO alert (detected_ts, causal_user_id, rule_triggered, score, trigger_event_id)
    SELECT ts, uid, top_signal, score, event_id FROM scored
    RETURNING alert_id, trigger_event_id
)
INSERT INTO alert_reason (alert_id, signal, points, detail)
SELECT i.alert_id, p.signal, p.points, p.detail
FROM ins i JOIN tmp_pts p ON p.event_id = i.trigger_event_id;
"""


def main() -> None:
    argparse.ArgumentParser().parse_args()  # no options yet

    # ALTER for a DB created before trigger_event_id existed
    with connect() as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE alert ADD COLUMN IF NOT EXISTS trigger_event_id BIGINT")
        conn.commit()

        cur.execute(build_points_sql())
        cur.execute(SCORE_AND_ALERT_SQL)
        conn.commit()

        report(cur)


def report(cur) -> None:
    cur.execute("SELECT count(*) FROM alert")
    n_alerts = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM alert a WHERE NOT EXISTS "
                "(SELECT 1 FROM alert_reason r WHERE r.alert_id=a.alert_id)")
    unexplained = cur.fetchone()[0]
    cur.execute("SELECT max(detected_ts)::date - min(detected_ts)::date FROM alert")
    span = cur.fetchone()[0] or 1
    per_day = n_alerts / max(span, 1)

    # scenario-3 recall (independent ground truth), user-level
    cur.execute("SELECT count(DISTINCT user_id) FROM redteam_label WHERE source='cert-scenario-3'")
    s3_total = cur.fetchone()[0]
    cur.execute("""SELECT count(DISTINCT l.user_id)
                   FROM redteam_label l JOIN alert a ON a.causal_user_id = l.user_id
                   WHERE l.source='cert-scenario-3'""")
    s3_hit = cur.fetchone()[0]

    # synthetic campaign recall, event-level + campaign-level
    cur.execute("SELECT count(*) FROM redteam_label WHERE source='synthetic' AND event_id IS NOT NULL")
    syn_total = cur.fetchone()[0]
    cur.execute("""SELECT count(*) FROM redteam_label l
                   WHERE l.source='synthetic'
                     AND EXISTS (SELECT 1 FROM alert a WHERE a.trigger_event_id = l.event_id)""")
    syn_hit = cur.fetchone()[0]
    cur.execute("""SELECT count(DISTINCT split_part(e.source_event_ref,'-',2))
                   FROM redteam_label l JOIN login_event e ON e.event_id=l.event_id
                   WHERE l.source='synthetic'
                     AND EXISTS (SELECT 1 FROM alert a WHERE a.trigger_event_id = l.event_id)""")
    camp_hit = cur.fetchone()[0]

    cur.execute("SELECT rule_triggered, count(*) FROM alert GROUP BY 1 ORDER BY 2 DESC")
    top = cur.fetchall()

    print("================ SCORING REPORT ================")
    print(f"alerts: {n_alerts}  |  unexplained (must be 0): {unexplained}")
    print(f"alert span: {span} days  |  avg alerts/day: {per_day:.1f}   [target < 50]")
    print(f"scenario-3 insiders alerted: {s3_hit}/{s3_total}   [target >= 7/10]")
    print(f"synthetic campaign hops alerted: {syn_hit}/{syn_total}")
    print(f"synthetic campaigns with >=1 hop alerted: {camp_hit}/20")
    print("top rule_triggered:", dict(top[:8]))


if __name__ == "__main__":
    main()
