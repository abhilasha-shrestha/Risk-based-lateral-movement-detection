"""Reconstruct an alert's lateral-movement path with Neo4j, write it to
ALERT_PATH_HOP, apply the path-score bonus, and tear the subgraph down.

Run:  python reconstruct.py <alert_id> [<alert_id> ...]
      python reconstruct.py --campaigns      # all synthetic-campaign alerts
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "etl"))
from common import connect          # noqa: E402
from neo import get_driver          # noqa: E402
import project as P                 # noqa: E402

# longest time-ordered path ending at the alert's destination host
RECONSTRUCT_CYPHER = """
MATCH p = (a:Host {aid:$aid})-[r:MOVE*1..6]->(z:Host {aid:$aid, host_id:$dst})
WHERE ALL(i IN range(0, size(r)-2) WHERE r[i].ts < r[i+1].ts)
RETURN [n IN nodes(p) | n.host_id]       AS hosts,
       [x IN r | x.event_id]             AS events,
       [x IN r | x.switch]               AS switches,
       last(r).sensitive                 AS ends_sensitive,
       length(p)                         AS len
ORDER BY len DESC,
         reduce(s=0, x IN r | s + (CASE WHEN x.sensitive THEN 2 ELSE 0 END)
                                   + (CASE WHEN x.switch    THEN 2 ELSE 0 END)
                                   + (CASE WHEN x.new_host  THEN 1 ELSE 0 END)) DESC
LIMIT 1
"""


def path_bonus(n_hops, ends_sensitive, any_switch):
    bonus = 0
    if n_hops > 2:
        bonus += 10 * (n_hops - 2)      # +10 per hop beyond the second
    if ends_sensitive:
        bonus += 15
    if any_switch:
        bonus += 15
    return bonus


def reconstruct_alert(alert_id, cur, session):
    """Project -> traverse -> write hops -> score -> clean up.
    Returns a dict describing the path."""
    dst_host, n_edges = P.project(cur, session, alert_id)

    rec = None
    if n_edges:
        rec = session.run(RECONSTRUCT_CYPHER, aid=alert_id, dst=dst_host).single()

    # write hops
    cur.execute("DELETE FROM alert_path_hop WHERE alert_id = %s", (alert_id,))
    if rec and rec["events"]:
        hosts = rec["hosts"]
        events = rec["events"]
        any_switch = any(rec["switches"])
        ends_sensitive = bool(rec["ends_sensitive"])
        for order, ev in enumerate(events):
            cur.execute(
                "INSERT INTO alert_path_hop (alert_id, hop_order, event_id) VALUES (%s,%s,%s)",
                (alert_id, order, ev),
            )
        n_hops = len(events)
    else:
        # no movement chain: single-host path = just the trigger event
        cur.execute(
            "SELECT trigger_event_id FROM alert WHERE alert_id = %s", (alert_id,))
        trig = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO alert_path_hop (alert_id, hop_order, event_id) VALUES (%s,0,%s)",
            (alert_id, trig),
        )
        hosts, n_hops, any_switch, ends_sensitive = [dst_host], 0, False, False

    # path-score bonus
    bonus = path_bonus(n_hops, ends_sensitive, any_switch)
    if bonus:
        cur.execute(
            "UPDATE alert SET score = LEAST(100, score + %s) WHERE alert_id = %s",
            (bonus, alert_id),
        )

    # tear down the scratch subgraph — the on-demand guarantee
    session.run("MATCH (n:Host {aid:$aid}) DETACH DELETE n", aid=alert_id)

    return {"alert_id": alert_id, "hosts": hosts, "hops": n_hops,
            "bonus": bonus, "ends_sensitive": ends_sensitive}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("alert_ids", nargs="*", type=int)
    ap.add_argument("--campaigns", action="store_true",
                    help="reconstruct every alert on a synthetic-campaign event")
    args = ap.parse_args()

    with connect() as conn, conn.cursor() as cur, get_driver() as driver:
        ids = list(args.alert_ids)
        if args.campaigns:
            cur.execute(
                """SELECT DISTINCT a.alert_id
                   FROM alert a JOIN redteam_label l ON l.event_id = a.trigger_event_id
                   WHERE l.source = 'synthetic' ORDER BY a.alert_id""")
            ids += [r[0] for r in cur.fetchall()]
        if not ids:
            sys.exit("give alert ids or --campaigns")

        with driver.session() as session:
            for aid in ids:
                res = reconstruct_alert(aid, cur, session)
                conn.commit()
                chain = " -> ".join(res["hosts"])
                print(f"alert {aid}: {res['hops']} hops  (+{res['bonus']} bonus)  {chain}")

        # confirm the graph is empty at rest (on-demand proof)
        with driver.session() as session:
            left = session.run("MATCH (n:Host) RETURN count(n) AS c").single()["c"]
            print(f"Neo4j Host nodes at rest: {left}")


if __name__ == "__main__":
    main()
