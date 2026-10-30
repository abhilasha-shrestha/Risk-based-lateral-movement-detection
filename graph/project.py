"""Project ONE alert's neighbourhood from Postgres into Neo4j.

On-demand design: we never load all events into the graph. Given an
alert, we pull the acting user's movements in the 24 h before the alert
and MERGE them into a subgraph namespaced by `aid` (the alert_id). The
subgraph is a handful of Host nodes and the MOVE edges between them.

An edge is created wherever the actor's host changes between consecutive
logons — the user-mediated causal edge of IMPLEMENTATION_PLAN.md §2.2.
"""
from __future__ import annotations

# window before the alert to consider (Hopper's 24 h)
WINDOW_HOURS = 24

PULL_SQL = """
SELECT e.event_id, e.ts, e.dst_host_id, e.target_user_id,
       v.is_new_host, (v.dst_sensitivity = 'high') AS sensitive,
       v.is_credential_switch
FROM login_event e
JOIN v_login_enriched v ON v.event_id = e.event_id
WHERE e.source_user_id = %s AND e.success
  AND e.ts >  %s - make_interval(hours => %s)
  AND e.ts <= %s
ORDER BY e.ts
"""


def alert_context(cur, alert_id):
    """Return (actor, trigger_ts, dst_host) for an alert."""
    cur.execute(
        """SELECT e.source_user_id, e.ts, e.dst_host_id
           FROM alert a JOIN login_event e ON e.event_id = a.trigger_event_id
           WHERE a.alert_id = %s""",
        (alert_id,),
    )
    row = cur.fetchone()
    if not row:
        raise ValueError(f"alert {alert_id} has no trigger event")
    return row  # (actor, ts, dst_host)


def build_edges(cur, actor, trigger_ts):
    """Consecutive host changes of the actor in the window -> edge list."""
    cur.execute(PULL_SQL, (actor, trigger_ts, WINDOW_HOURS, trigger_ts))
    rows = cur.fetchall()
    edges, prev = [], None
    for ev_id, ts, host, acct, new_host, sensitive, switch in rows:
        if prev is not None and prev["host"] != host:
            edges.append({
                "src": prev["host"], "dst": host,
                "ts": ts.isoformat(), "event_id": ev_id, "acct": acct,
                "actor": actor, "sensitive": bool(sensitive),
                "new_host": bool(new_host), "switch": bool(switch),
            })
        prev = {"host": host}
    return edges


MERGE_CYPHER = """
UNWIND $edges AS e
MERGE (s:Host {host_id: e.src, aid: $aid})
MERGE (d:Host {host_id: e.dst, aid: $aid})
CREATE (s)-[:MOVE {ts: e.ts, event_id: e.event_id, acct: e.acct, actor: e.actor,
                   sensitive: e.sensitive, new_host: e.new_host, switch: e.switch}]->(d)
"""


def project(cur, session, alert_id):
    """Build the subgraph. Returns (dst_host, n_edges)."""
    actor, trigger_ts, dst_host = alert_context(cur, alert_id)
    edges = build_edges(cur, actor, trigger_ts)
    # clear any stale subgraph for this alert, then build fresh
    session.run("MATCH (n:Host {aid:$aid}) DETACH DELETE n", aid=alert_id)
    if edges:
        session.run(MERGE_CYPHER, edges=edges, aid=alert_id)
    return dst_host, len(edges)
