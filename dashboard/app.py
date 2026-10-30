"""Analyst investigation dashboard (Phase 3).

Three views, per IMPLEMENTATION_PLAN.md Phase 3:
  1. Alert queue      — alerts by score, with the top reason inline
  2. Alert detail     — score breakdown (one bar per reason) + context
  3. Path view        — the reconstructed Host-A -> B -> C chain

The graph is built ON DEMAND: a path is reconstructed only when you open
an alert and click Reconstruct. Run with:
    streamlit run dashboard/app.py
"""
from __future__ import annotations
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "etl"))
sys.path.insert(0, str(ROOT / "graph"))
from common import connect          # noqa: E402
from neo import get_driver          # noqa: E402
import reconstruct as R             # noqa: E402

st.set_page_config(page_title="Lateral Movement Investigation", layout="wide")


def q(sql, params=None):
    with connect() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        cols = [c.name for c in cur.description]
        return pd.DataFrame(cur.fetchall(), columns=cols)


def run_reconstruct(alert_id: int):
    with connect() as conn, conn.cursor() as cur, get_driver() as driver:
        with driver.session() as session:
            res = R.reconstruct_alert(alert_id, cur, session)
        conn.commit()
    return res


# ---------------------------------------------------------------- sidebar
st.sidebar.title("Lateral Movement")
st.sidebar.caption("Risk-based investigation — CERT r4.2 + synthetic")
min_score = st.sidebar.slider("Minimum score", 50, 100, 50, 5)
only_truth = st.sidebar.checkbox("Only labeled (ground truth)", value=False)

st.sidebar.markdown("---")
st.sidebar.info("This tool scores events for **investigation**. "
                "A high score is a reason to look, not proof a person is malicious.")

# ---------------------------------------------------------------- queue
truth_join = (
    "JOIN redteam_label l ON l.event_id = a.trigger_event_id" if only_truth
    else "LEFT JOIN redteam_label l ON l.event_id = a.trigger_event_id"
)
queue = q(f"""
    SELECT a.alert_id, a.detected_ts, a.causal_user_id AS user,
           COALESCE(u.roles,'?') AS role, a.score, a.rule_triggered AS top_signal,
           (l.event_id IS NOT NULL) AS labeled,
           (SELECT count(*) FROM alert_path_hop h WHERE h.alert_id=a.alert_id) AS path_hops
    FROM alert a
    LEFT JOIN app_user u ON u.user_id = a.causal_user_id
    {truth_join}
    WHERE a.score >= %s
    GROUP BY a.alert_id, a.detected_ts, a.causal_user_id, u.roles, a.score,
             a.rule_triggered, l.event_id
    ORDER BY a.score DESC, a.detected_ts
    LIMIT 300
""", (min_score,))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts shown", len(queue))
c2.metric("Avg score", f"{queue['score'].mean():.0f}" if len(queue) else "—")
c3.metric("Labeled (TP)", int(queue["labeled"].sum()) if len(queue) else 0)
c4.metric("Neo4j nodes at rest", "0  (on-demand)")

st.subheader("Alert queue")
st.dataframe(queue, use_container_width=True, hide_index=True)

# ---------------------------------------------------------------- detail
st.subheader("Investigate an alert")
if len(queue):
    aid = st.selectbox("Alert", queue["alert_id"].tolist(),
                       format_func=lambda x: f"#{x}  (score "
                       f"{int(queue.loc[queue.alert_id==x,'score'].iloc[0])}, "
                       f"{queue.loc[queue.alert_id==x,'user'].iloc[0]})")

    head = q("""SELECT a.alert_id, a.detected_ts, a.causal_user_id, u.roles,
                       a.score, a.rule_triggered, a.trigger_event_id,
                       (SELECT source FROM redteam_label l
                         WHERE l.event_id=a.trigger_event_id LIMIT 1) AS label_source
                FROM alert a LEFT JOIN app_user u ON u.user_id=a.causal_user_id
                WHERE a.alert_id=%s""", (aid,)).iloc[0]

    left, right = st.columns([1, 1])
    with left:
        st.markdown(f"### Alert #{int(head.alert_id)} — score "
                    f"**{int(head.score)}/100**")
        st.write(f"**User:** {head.causal_user_id}  ({head.roles or '?'})")
        st.write(f"**When:** {head.detected_ts}")
        st.write(f"**Top signal:** {head.rule_triggered}")
        if head.label_source:
            st.success(f"Ground truth: labeled **{head.label_source}**")
        else:
            st.caption("Not in the ground-truth set (either a false positive "
                       "or an unlabeled real anomaly).")

        reasons = q("""SELECT signal, points, detail FROM alert_reason
                       WHERE alert_id=%s ORDER BY points DESC""", (aid,))
        st.markdown("**Why it fired (score breakdown):**")
        st.bar_chart(reasons.set_index("signal")["points"], horizontal=True)
        st.dataframe(reasons, use_container_width=True, hide_index=True)

    with right:
        st.markdown("### Attack path")
        if st.button("Reconstruct path (build subgraph in Neo4j)"):
            with st.spinner("Projecting ±24 h into Neo4j and traversing..."):
                res = run_reconstruct(int(aid))
            st.success(f"{res['hops']} hops, +{res['bonus']} path bonus")

        path = q("""SELECT h.hop_order, e.ts, e.src_host_id, e.dst_host_id,
                           e.source_user_id AS actor, e.target_user_id AS account,
                           ho.sensitivity
                    FROM alert_path_hop h
                    JOIN login_event e ON e.event_id=h.event_id
                    LEFT JOIN host ho ON ho.host_id=e.dst_host_id
                    WHERE h.alert_id=%s ORDER BY h.hop_order""", (aid,))
        if len(path):
            chain = []
            if path.iloc[0].src_host_id:
                chain.append(str(path.iloc[0].src_host_id))
            for _, r in path.iterrows():
                tag = " 🔑" if r.actor != r.account else ""
                sens = " ⚠️" if r.sensitivity == "high" else ""
                chain.append(f"{r.dst_host_id}{tag}{sens}")
            st.markdown("**" + "  →  ".join(chain) + "**")
            st.caption("🔑 = credential switch   ⚠️ = sensitive host")
            st.dataframe(path, use_container_width=True, hide_index=True)
        else:
            st.info("No path reconstructed yet — click the button above.")
else:
    st.info("No alerts at this score threshold.")
