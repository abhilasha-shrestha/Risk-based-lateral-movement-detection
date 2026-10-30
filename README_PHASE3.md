# Phase 3 — run guide (graph + dashboard)

Prereq: containers up and Phases 1-2 loaded (see README_PHASE1.md).
All commands from WSL, in the venv:

```bash
cd /mnt/c/Users/abhil/Desktop/DBMS && source .venv/bin/activate
```

## Reconstruct a path from the command line

```bash
cd graph
python reconstruct.py 941                 # one alert
python reconstruct.py --campaigns         # every synthetic-campaign alert
```

Each run projects only that alert's ±24 h into Neo4j, traverses it, writes
the hops to `alert_path_hop`, applies the path-score bonus, and deletes the
subgraph. It prints "Neo4j Host nodes at rest: 0" to prove the on-demand design.

## Run the dashboard

```bash
streamlit run dashboard/app.py
```

Open http://localhost:8501. Three things to show:
1. **Alert queue** — sorted by score, with the top signal and a labeled (TP) flag.
2. **Investigate an alert** — pick one; the score breakdown has one bar per reason.
3. **Attack path** — click *Reconstruct path*; the graph is built on demand and the
   chain appears (🔑 = credential switch, ⚠️ = sensitive host).

> The "Neo4j nodes at rest = 0" metric is the proof that the graph is on-demand:
> it holds one alert's neighbourhood only while you investigate, then tears it down.

## Handy

- Neo4j browser: http://localhost:7474 (run `MATCH (n) RETURN n` during a
  reconstruction to see a subgraph; it will be empty at rest).
- If `docker` is missing in WSL after a reboot, start Docker Desktop on Windows
  first, then `docker compose up -d`.
