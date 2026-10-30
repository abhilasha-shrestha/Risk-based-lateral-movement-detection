# Risk-Based Lateral Movement Investigation — Implementation Plan

**Course:** Experiential Learning (DBMS), 2026–27 · RVCE, Dept. of CSE
**Team:** Aarti Shirvante Pai (1RV24CS006), Abhilasha Shrestha (1RV24CS011)
**Duration:** 4 weeks · **Status:** draft v1 — edit freely

**How to use this file:** each phase has an *Exit criteria* block. Do not start the next
phase until those are ticked. If you fall behind, cut from the **Cut list** in §11, never
from the exit criteria.

---

## 0. Locked scope decisions

| # | Decision | Choice | Why |
|---|---|---|---|
| D1 | Timeline | 4 weeks | Fixed by submission date. Drives every cut below. |
| D2 | Primary dataset | CERT Insider Threat **r4.2** (your `archive.zip`) | Already downloaded. 470,591 logons, 1,000 users, 1,003 PCs, 17 months, with LDAP roles and a labeled answer key. |
| D3 | LANL auth dataset | **Excluded** | 7.2 GB download / 73 GB raw. No room in 4 weeks. Noted in the report as future work. |
| D4 | Zeek CSVs | **Excluded** | Network flows with no user column, no auth events, and zero Lateral Movement labels (only Discovery 2,086 / Reconnaissance 4,608). Cannot populate `LOGIN_EVENT`. |
| D5 | Lab network | 5 Alpine Linux VMs, SSH only | ~256 MB RAM each, fits VirtualBox on Laptop B. Real `/var/log/auth.log`. |
| D6 | Graph role | Neo4j is **on-demand only** | See §1. Postgres scores every event; Neo4j is built *only* for events that cross the alert threshold. |
| D7 | Synthetic data | Yes, seeded + documented | CERT structurally lacks failed logins, auth types and source hosts. See §2.3. |

---

## 1. Architecture

The system is a scoring pipeline with a graph **investigation** step hanging off the end.
This is the single most important design point in the project.

```
  Lab VMs (auth.log) ─┐
                      ├─► ingest ─► LOGIN_EVENT ─► baseline ─► SCORE every event
  CERT r4.2 (batch) ──┘            (PostgreSQL)   (Postgres)      (Postgres)
                                                                      │
                                                   score < T ─────────┤
                                                   (no alert, stop)   │
                                                                      │ score >= T
                                                                      ▼
                                                            create ALERT + reasons
                                                                      │
                                                                      ▼
                                              project ONLY this user's ±24 h events
                                                      into Neo4j as a subgraph
                                                                      │
                                                                      ▼
                                               Cypher traversal → multi-hop path
                                                                      │
                                                                      ▼
                                       write ALERT_PATH_HOP back to Postgres → dashboard
```

**Why the graph is on demand.** Loading all 470k events into Neo4j and keeping it in sync
doubles the storage, doubles the ingest code, and is dead weight — 99% of events are never
investigated. Instead, when an alert fires, we project a subgraph of a few hundred nodes
(that user's events in a 24 h window, plus hosts touched), traverse it, keep the path, and
discard the subgraph. Neo4j stays under a few thousand nodes at any moment and a laptop
handles it comfortably.

This also gives the report a genuine, defensible SQL-vs-NoSQL argument:
*set-based scoring over hundreds of thousands of rows is a relational job; variable-depth
path reconstruction over a small neighbourhood is a graph job.* That reads far better than
"we loaded the same data twice and timed it."

**Components**

| Layer | Choice | Runs on |
|---|---|---|
| Event store + scoring | PostgreSQL 16 | Laptop A (Docker/WSL2) |
| Investigation graph | Neo4j 5 Community | Laptop A (Docker/WSL2) |
| Ingest API | FastAPI (Python 3.11) | Laptop A |
| Dashboard | Streamlit | Laptop A |
| Target network | 5× Alpine VM, sshd + rsyslog | Laptop B (VirtualBox) |

---

## 2. Data

### 2.1 What to take from CERT r4.2

Stream these straight out of `archive.zip` with Python's `zipfile` — **do not extract the
archive**, it expands to ~16 GB and you only need ~58 MB of it.

| File | Size | Use |
|---|---|---|
| `r4.2/logon.csv` | 58 MB | `LOGIN_EVENT`. Fields: `id, date, user, pc, activity`. 470,591 `Logon` + 384,268 `Logoff`. |
| `r4.2/LDAP/*.csv` | 17 × ~140 KB | `USER`. Gives `role`, `business_unit`, `department`, `team`, `supervisor`. Monthly snapshots — a user missing from month *N+1* has been **terminated**, which is itself a signal. |
| `r4.2/device.csv` | 29 MB | Secondary signal (thumb-drive use) for scenarios 1 & 2. |
| `r4.2/file.csv` | 193 MB | Optional. File-copy-to-removable events. Load only if time allows. |
| `answers/insiders.csv` + `answers/r4.2-3/` | small | `REDTEAM_LABEL` ground truth. |

**Ignore** `http.csv` (14.5 GB) and `email.csv` (1.4 GB) entirely. They are not
authentication data and will eat your week.

**Ground truth.** The answer key has three scenarios:

| Folder | Scenario | Users | Relevance |
|---|---|---|---|
| `answers/r4.2-3/` | Sysadmin plants a keylogger, then **logs in as his supervisor** | 10 | **Primary.** This is credential misuse — exactly lateral movement. |
| `answers/r4.2-1/` | After-hours + removable drive + exfil, then leaves | 30 | Secondary (after-hours + device signals). |
| `answers/r4.2-2/` | Job hunting, then thumb-drive theft before leaving | 30 | Secondary. |

Scenario 4 in `scenarios.txt` ("logs into another user's machine and searches for files")
is also lateral movement, but is not present as a labeled folder in r4.2 — mention it in
the report, do not claim to evaluate on it.

### 2.2 The gap — read this before writing any DDL

CERT logons are *"user sat down at this PC"* events. They are **not** remote logins. This
is the central limitation of the project and the report must state it plainly.

| ER column | In CERT? | Resolution |
|---|---|---|
| `ts` | yes | direct |
| `target_user_id` | yes (`user`) | direct |
| `dst_host_id` | yes (`pc`) | direct |
| `success` | **no** — zero failed logins exist | synthesize (§2.3) |
| `auth_type` | **no** | synthesize from host type + time |
| `src_host_id` | **no** — no source host recorded | **derive** (below) + synthesize |
| `source_user_id` | **no** — no credential switching | synthesize on injected paths |
| `HOST.ip_address` | **no** | assign from a synthetic /16 |

**The derived edge.** Build a *user-mediated* causal edge: if user *u* is seen on `PC-A`
at `t1` and on `PC-B` at `t2`, with `0 < t2 − t1 ≤ Δ` (default **Δ = 24 h**, Hopper's
window), emit an edge `PC-A → PC-B` attributed to *u*. This is exactly Hopper's notion of
a causal path with the user as the pivot rather than a network connection. It is honest,
it is citable, and it is the backbone of path reconstruction.

Guard against the obvious false positive: a user's **assigned PC** appears in nearly every
chain. Exclude self-loops and down-weight edges that terminate on the user's own baseline
host.

### 2.3 Synthetic enrichment

One seeded script (`etl/synthesize.py`, fixed `--seed`) layers the missing fields on top of
real CERT events. Every synthetic field gets an `is_synthetic` flag in the DB so the report
can separate real from generated results.

1. **Failed logins.** Inject at a realistic base rate (~2% benign typos: 1–2 fails then
   success, same host, within 60 s). Separately inject brute-force bursts only inside
   injected attack campaigns.
2. **`auth_type`.** Assign `ssh` / `rdp` / `kerberos` / `ntlm` by host type and hour.
3. **`src_host_id`.** For ~15% of logons, mark the logon remote and set `src_host` to a
   host the user was recently on. The rest stay local (`src_host = dst_host`).
4. **`HOST.sensitivity`.** Promote ~3% of PCs to `high` (name them as DC / file server /
   DB server) and tag `ITAdmin`-owned machines as `medium`.
5. **Injected attack campaigns.** Generate **N = 20** multi-hop chains (4–6 hops, credential
   switch at hop 2, ending on a `high`-sensitivity host) at known timestamps against known
   users. These are the only true multi-hop ground truth you will have, since CERT has none.
   Record each in `REDTEAM_LABEL` with `source = 'synthetic'`.

> **Report honesty rule.** Precision/recall on the 20 injected chains is *optimistic* —
> you wrote both the attack and the detector. Report it separately from the CERT
> scenario-3 numbers, which are independent ground truth. Do not merge them into one score.

### 2.4 Rejected sources

- **Zeek CSVs** (`part-00000-*.csv`): no user field, no authentication, only Discovery and
  Reconnaissance labels. Cannot be mapped to `LOGIN_EVENT`. One line in the report.
- **LANL auth.txt**: right shape, wrong budget. Future work.

---

## 3. Changes to the ER model

Four changes. Make these in Week 1, before any DDL is final.

| # | Change | Reason |
|---|---|---|
| C1 | **Add `ALERT_REASON`** (`alert_id`, `signal`, `points`, `detail`) | "Explainable alerts" is your headline feature and the current ER has `score REAL` with nowhere to put the *why*. Without this table the explainability claim is unbacked. |
| C2 | **Add `HOST.sensitivity`** (`low`/`medium`/`high`) | "Sensitive-host awareness" is a listed feature with no column to read. |
| C3 | **Add `LOGIN_EVENT.logon_type`** (`interactive`/`remote`/`service`) | Separates RDP/SSH from service-account noise. Without it, service accounts dominate every alert list. |
| C4 | **Make `is_new_host` a view, not a stored column** | "New" is relative to a point in time. Stored, it goes stale the moment the baseline updates and will silently corrupt your recall numbers. Compute it at scoring time with `NOT EXISTS (SELECT 1 FROM USER_HOST_BASELINE ...)`. |

Also add `USER.terminated_date` (derivable from LDAP month-to-month disappearance) — a
logon after termination is one of the strongest single signals in the dataset.

Keep everything else from your diagram as-is. `ALERT.causal_user_id` matches Hopper's
"causal user" and `ALERT_PATH_HOP` with `hop_order` as a partial key is already correct.

---

## 4. Detection methodology

### 4.1 Baseline

Train `USER_HOST_BASELINE` on a **fixed training window** — CERT months **Jan–Feb 2010**
(first ~8 weeks) — and score everything after it.

> **Leakage warning.** Never build the baseline over the whole dataset and then score the
> same events. Every attack would be in its own baseline and recall would collapse. The
> training window must end before the first labeled insider activity.

Per `(user, host)` store: `first_login_ts`, `last_login_ts`, `login_count`,
`typical_hour_start`, `typical_hour_end` (5th/95th percentile of logon hour).
Also precompute per-user: set of known hosts, median logons/day, usual device count.

### 4.2 Signals and weights

Each firing signal writes one `ALERT_REASON` row. Weights are the starting point — tune
them in Week 4 against the validation split and record the final table in the report.

| Signal | Points | Condition |
|---|---|---|
| `new_host` | 25 | `(user, host)` absent from baseline |
| `new_host_for_role` | +10 | no user with the same LDAP role has ever used this host |
| `unusual_time` | 15 | hour outside the user's `typical_hour_start..end` |
| `after_hours` | +10 | 22:00–06:00 |
| `rapid_movement` | 20 | ≥3 distinct hosts within 60 min |
| `failed_then_success` | 25 | ≥3 failures then success within 15 min |
| `sensitive_destination` | 20 | `dst_host.sensitivity = 'high'` |
| `credential_switch` | 15 | `source_user_id <> target_user_id` |
| `privilege_escalation` | 20 | target user's role outranks source user's |
| `dormant_account` | 10 | no logon in the preceding 30 days |
| `terminated_user` | 30 | logon after `USER.terminated_date` |

**Score** = `LEAST(100, SUM(points))`. Cap at 100 so the dashboard scale is stable.

**Role-aware damping.** `ITAdmin` users legitimately touch many hosts. Multiply
`new_host` and `rapid_movement` by **0.5** when `role = 'ITAdmin'` *unless* the destination
is sensitive. This is the single change that will cut your false-positive rate most.

### 4.3 Alert threshold

Default **T = 50**. Do not treat this as fixed — produce the precision/recall curve across
T ∈ {30, 40, 50, 60, 70} in Week 4 and report **alerts per day** alongside recall, the way
Hopper does. "94% recall at 9 alerts/day" is a far stronger claim than raw accuracy on a
dataset this imbalanced.

### 4.4 Path reconstruction (on demand, Neo4j)

Triggered **only** when an alert fires.

1. Pull the causal user's events in `[alert_ts − 24 h, alert_ts]` from Postgres.
2. `MERGE` them into Neo4j: `(:Host)-[:LOGIN {ts, user, event_id, score}]->(:Host)`.
   Typically 50–400 nodes.
3. Traverse backwards from the alerting event to find the longest causal chain:

```cypher
MATCH path = (start:Host)-[r:LOGIN*1..6]->(end:Host {host_id: $dst_host})
WHERE ALL(i IN range(0, size(r)-2)
          WHERE (r[i]).ts < (r[i+1]).ts
            AND duration.inSeconds((r[i]).ts, (r[i+1]).ts).seconds <= 86400)
RETURN path
ORDER BY length(path) DESC, reduce(s = 0, x IN r | s + x.score) DESC
LIMIT 5
```

4. Write the best path to `ALERT_PATH_HOP` (`alert_id`, `hop_order`, `event_id`).
5. Delete the scratch subgraph (or namespace it by `alert_id` and expire it).

The monotonic-timestamp constraint is what makes this a *path through time* rather than
any walk in the graph. Get that right or you will reconstruct nonsense.

### 4.5 Path scoring

Final alert score = event score + path bonus:
`+10` per hop beyond the second, `+15` if the path ends on a sensitive host, `+15` if a
credential switch occurs mid-path. Re-cap at 100.

---

## 5. Phases

### Phase 1 — Week 1: Foundation and data in the database

**Goal:** every CERT logon queryable in Postgres with roles attached, and the baseline built.

- [ ] Docker Compose on Laptop A: `postgres:16`, `neo4j:5-community`. Pin versions, set
      a named volume, commit the compose file.
- [ ] Apply ER changes C1–C4 (§3). Write `schema/01_tables.sql`, `02_indexes.sql`.
- [ ] Indexes from day one: `(target_user_id, ts)`, `(dst_host_id, ts)`, `(ts)`.
      Partition `LOGIN_EVENT` by month — 17 monthly partitions. Cheap now, painful later.
- [ ] `etl/load_cert.py` — stream `logon.csv` from the zip, `COPY` into Postgres.
      Use `COPY`, not row-by-row `INSERT`; the difference is minutes vs. an hour.
- [ ] `etl/load_ldap.py` — build `USER` from the 17 monthly snapshots, derive
      `terminated_date` from disappearance.
- [ ] `etl/load_labels.py` — `answers/insiders.csv` + `r4.2-3/` into `REDTEAM_LABEL`.
- [ ] `etl/build_baseline.py` — `USER_HOST_BASELINE` over Jan–Feb 2010 only.

**Deliverables:** `docker-compose.yml`, `schema/*.sql`, `etl/*.py`, populated DB.

**Exit criteria**
- `SELECT count(*) FROM login_event` returns **470,591**.
- `SELECT count(*) FROM app_user` returns **1,000**; `host` returns **1,003**.
  (The ER entity USER is the table `app_user` — USER is a reserved word.)
- Baseline table is non-empty and contains **no** event after 2010-03-01.
- A per-user timeline query returns in **< 200 ms**.

**Risk:** CSV date format is `MM/DD/YYYY HH:MM:SS`. Parse explicitly; do not let Postgres
guess, or you will silently get day/month swapped and every time-based signal will be wrong.

---

### Phase 2 — Week 2: Synthetic enrichment and the scoring engine

**Goal:** every event has a score and a list of reasons.

- [ ] `etl/synthesize.py` (seeded) — failed logins, `auth_type`, `src_host_id`,
      `HOST.sensitivity`, `logon_type`. Flag every synthetic row.
- [ ] Inject the **20 multi-hop attack campaigns**; label them in `REDTEAM_LABEL`.
- [ ] `detect/signals.py` — one function per signal in §4.2, each returning
      `(fired: bool, points: int, detail: str)`.
- [ ] `detect/score.py` — run all signals, write `ALERT` + `ALERT_REASON` when `score >= T`.
- [ ] Apply the `ITAdmin` damping rule.
- [ ] Run across the full post-baseline period; record alert count per day.

**Deliverables:** scoring engine, populated `ALERT` / `ALERT_REASON`.

**Exit criteria**
- Every alert has **≥1** `ALERT_REASON` row — zero unexplained alerts.
- At least **7 of 10** scenario-3 insiders produce at least one alert.
- Alert volume is **< 50/day** average. If it is in the thousands, the weights or the
  `ITAdmin` damping are wrong — fix it here, not in Week 4.

**Risk:** this is the week most likely to overrun. If scoring is not working by Thursday,
drop signals `dormant_account` and `privilege_escalation` and move on.

---

### Phase 3 — Week 3: On-demand graph and dashboard

**Goal:** click an alert, see the attack path.

- [ ] `graph/project.py` — given `alert_id`, pull the ±24 h window and `MERGE` into Neo4j.
- [ ] `graph/reconstruct.py` — the Cypher in §4.4, write back to `ALERT_PATH_HOP`.
- [ ] Apply path scoring (§4.5).
- [ ] Streamlit dashboard, three views:
  1. **Alert queue** — sorted by score, with the top contributing reason shown inline.
  2. **Alert detail** — timeline, score breakdown bar (one bar per `ALERT_REASON`),
     affected user and hosts.
  3. **Path view** — the reconstructed chain `Host A → B → C` with timestamps.
- [ ] Teardown of scratch subgraphs after each investigation.

**Deliverables:** working investigation flow, dashboard.

**Exit criteria**
- An alert on an injected campaign reconstructs a path of the **correct length**.
- Path reconstruction completes in **< 2 s**.
- Neo4j holds **< 5,000 nodes** at rest — proof the on-demand design works.
- The score breakdown is legible to someone who has not read this document.

---

### Phase 4 — Week 4: Lab, live demo, evaluation, report

**Goal:** a demo that cannot fail, and numbers to put in the report.

> **Two-laptop split (locked).** Laptop B = the network under attack: it runs the 5
> VirtualBox VMs you log into **by hand** and ships `auth.log` to Laptop A. Laptop A = the
> detection system: Postgres, Neo4j and the dashboard. Keeping VirtualBox on its own laptop
> also sidesteps the WSL2 ↔ VirtualBox virtualisation conflict entirely, since the two never
> share a CPU.

**Lab (Laptop B) — days 1–2**
- [ ] 5 Alpine VMs in VirtualBox, Internal Network + host-only adapter, static IPs.
      Clone one golden image; do not build five by hand.
- [ ] `sshd` on all; one designated attacker foothold.
- [ ] Create demo accounts with **known** passwords: `alice` on `ws-01`, `bob` on
      `jump-01`/`fileserver-01`. You will type these yourself during the demo — no
      cracking tool is used.
- [ ] `rsyslog` forwards `auth.log` to Laptop A over TCP.
- [ ] `ingest/api.py` (FastAPI) parses sshd lines → `LOGIN_EVENT`, scores on arrival.

**Manual demo runbook — `attack/demo_runbook.md`**

The demo is performed by hand, not by a script. SSH records real failures and logins
whether you type them or a tool does, so typing is enough — and clearer for the audience.
Write the runbook as a numbered checklist you read from on the day:

1. `ssh alice@ws-01` (correct password) → baseline login, dashboard stays quiet (~5).
2. Log out, then on `ws-01` type a **wrong** password 3× then the correct one →
   fires `failed_then_success`.
3. From `ws-01`: `ssh bob@jump-01` (different user, unseen host) →
   fires `new_host` + `credential_switch`.
4. From `jump-01`: `ssh bob@fileserver-01` (sensitive host) → score crosses T, alert fires.
5. Open the alert on the dashboard → show the reconstructed path and the score breakdown.

> **Honesty note for the report/viva:** you type known passwords, so you are
> *demonstrating* the log signature of an attack, not performing a real break-in. The
> detector reads the log either way. State this plainly if asked.

**Replay safety net — day 2, non-negotiable**
- [ ] Record **your own manual run** to `demo/attack_replay.jsonl` (the ingest API logs
      every event it receives; keep one good run).
- [ ] `demo/replay.py --speed 10` feeds those events through the same ingest path.
- [ ] Rehearse the demo **from replay** so a broken VM network on the day costs you nothing.

**Evaluation — day 3**
- [ ] Precision / recall / alerts-per-day across T ∈ {30,40,50,60,70}.
- [ ] Report CERT scenario-3 results and injected-campaign results **in separate tables**.
- [ ] Small SQL-vs-graph comparison: recursive CTE in Postgres vs. the Cypher above, on the
      same subgraph, same machine, warm cache, 5 runs averaged. Include `EXPLAIN ANALYZE`.
- [ ] One index study: the same query with and without `(target_user_id, ts)`.

**Report and demo — days 4–5**
- [ ] Fill Requirements, Limitations and results tables; update the ER and schema diagrams
      with changes C1–C4.
- [ ] Rehearse the 10-minute run (§9) end to end, twice.

**Exit criteria**
- Live attack produces an alert with a reconstructed path in **< 10 s**.
- Replay mode produces the identical result with the VMs powered off.
- Results tables complete, with real and synthetic numbers separated.

---

## 6. Tooling

**Laptop A — analytics node** (WSL2 Ubuntu + Docker 29.4.1, both already installed)

| Tool | Version | Role |
|---|---|---|
| PostgreSQL | 16 | Event store, baseline, scoring, partitioning/index study |
| Neo4j | 5 Community | On-demand path reconstruction |
| Python | 3.11 (in container) | ETL, scoring, ingest |
| FastAPI + uvicorn | current | Log ingest endpoint |
| Streamlit | current | Analyst dashboard |
| psycopg | 3.x | Postgres driver (use its `COPY` support) |
| neo4j | 5.x driver | Cypher from Python |

> Run everything through Docker Compose inside WSL2. Do not install Postgres on Windows
> directly — path and locale issues will cost you a day you do not have.

**Laptop B — target network** (VirtualBox)

| Item | Spec |
|---|---|
| VMs | 5 × Alpine Linux 3.20, 1 vCPU, 256 MB, 2 GB disk |
| Roles | `attacker-foothold`, `ws-01`, `ws-02`, `jump-01`, `fileserver-01` (sensitive) |
| Services | `openssh-server`, `rsyslog` |
| Network | Internal Network (VM↔VM) + Host-only (→ Laptop A) |
| Total RAM | ~1.3 GB — comfortable on any laptop |

Laptops connect over the host-only adapter or plain LAN; fix Laptop A's IP in
`/etc/rsyslog.d/` on each VM.

---

## 7. Evaluation plan

| Metric | Why |
|---|---|
| Recall on CERT scenario-3 (10 users) | Independent ground truth. The number that matters. |
| Recall on 20 injected campaigns | Multi-hop path reconstruction. **Optimistic — label as such.** |
| Precision at T | With 470k events and ~70 insiders, raw accuracy is meaningless. |
| **Alerts per day** | The Hopper-comparable metric. An analyst cannot read 500 alerts/day. |
| Detection @ alert budget | Recall when capped at the top *k* alerts/day. |
| Path-length accuracy | Did the reconstructed chain match the injected one? |
| Query latency ± index | The DBMS contribution. |

Split: baseline Jan–Feb 2010 · tune weights on Mar–Aug 2010 · **report final numbers on
Sep 2010 – May 2011, touched once.**

---

## 8. Limitations — state these in the report

1. **CERT has no failed logins, no source host, and no credential switching.** The
   `success`, `src_host_id`, `source_user_id` and `auth_type` fields are synthetic.
   Any result depending on them is a result about our generator, not about CERT.
   **Measured consequence (Phase 2):** the scenario-3 credential-misuse logons score
   0/30 at the event level — logging in *as* the supervisor looks normal for the
   supervisor's account, and CERT never records who actually typed the password. We
   still catch 10/12 scenario-3 accounts via their *other* anomalies (after-hours,
   new host on their own logons), and the synthetic campaigns — where the acting user
   IS encoded — score 103/103 hops. This contrast is the clearest evidence of why the
   acting-user field is the crux of lateral-movement detection.
2. **Multi-hop ground truth is self-authored.** The 20 campaigns were written by us, so
   recall on them is optimistic and is reported separately.
3. **Host→host edges are derived, not observed.** They are user-mediated (§2.2), which is
   a weaker claim than an observed network connection.
4. **Scale is modest.** 470k events, not the millions the synopsis targets. LANL was cut
   for time; the partitioning and index work is built to extend to it.
5. **Hand-tuned weights.** Risk of overfitting to known scenarios; mitigated by the
   held-out split in §7 but not eliminated.
6. **Dense needles.** CERT r4.2 has an unrealistically high proportion of malicious
   activity (its own readme says so). Real-world precision would be worse.
7. **No ML baseline.** The GNN work in the literature review is cited for context, not
   reproduced.
8. **"Near real-time" means micro-batch** — a few seconds, not true stream processing.
9. **Neo4j Community, single instance.** No clustering; timing comparisons are
   single-node only.
10. **Ethics.** Usernames are hashed. The system scores events for *investigation* and
    never asserts that a person is malicious — this is stated in the dashboard UI too.

---

## 9. Demo script — 10 minutes

1. **(1 min)** Problem: one login looks normal, a chain does not.
2. **(2 min)** Dashboard on CERT data — alert queue, open a scenario-3 insider, show the
   score breakdown. *The sysadmin logging in as his supervisor.*
3. **(1 min)** Show a **suppressed** alert: an `ITAdmin` touching many hosts, scored low by
   the damping rule. This is what the examiner will ask about — pre-empt it.
4. **(3 min)** Live: work through `attack/demo_runbook.md` by hand on Laptop B — baseline
   login, failed-then-success, credential switch to `bob`, hop to the file server. Watch
   each step land on the dashboard before taking the next.
5. **(2 min)** Click it → Neo4j path `foothold → ws-01 → jump-01 → fileserver-01`.
   Point out that Neo4j is holding ~200 nodes, not 470,000.
6. **(1 min)** Numbers: recall, alerts/day, query latency ± index.

> If the VMs misbehave at step 4, run `demo/replay.py` and continue. Decide this in the
> first 5 seconds; do not debug on stage.

---

## 10. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Live demo network fails | **High** | Replay mode (records your manual run), built Week 4 day 2, rehearsed |
| Fat-finger a step live | Medium | Runbook is a read-from checklist; fall back to replay if a step won't land |
| Scoring floods with false positives | High | `ITAdmin` damping; tune in Week 2, not Week 4 |
| Week 2 overruns | Medium | Drop `dormant_account`, `privilege_escalation` |
| Date parsing silently wrong | Medium | Explicit format; assert min/max date after load |
| Baseline leakage inflates results | Medium | Fixed training window; assert no post-Mar-2010 rows |
| Neo4j subgraph not cleaned up | Low | Namespace by `alert_id`, drop after write-back |
| 7 GB zip handling | Low | Stream with `zipfile`, never extract |

---

## 11. Cut list — if you fall behind, cut in this order

1. `file.csv` ingest (device signals are enough for scenarios 1–2)
2. The index / `EXPLAIN ANALYZE` study (report content, not demo content)
3. Signals `dormant_account` and `privilege_escalation`
4. The SQL-vs-Cypher timing comparison
5. Scenarios 1 and 2 evaluation — keep scenario 3 only
6. Live VMs, demo from replay only — **last resort**

**Never cut:** the baseline training window, `ALERT_REASON`, or the replay safety net.

---

## 12. Repository layout

```
DBMS/
├── IMPLEMENTATION_PLAN.md        ← this file
├── docker-compose.yml
├── schema/                       # auto-run by Docker on first start
│   ├── 01_tables.sql
│   ├── 02_partitions.sql
│   ├── 03_indexes.sql
│   └── 04_views.sql
├── etl/
│   ├── load_cert.py              # streams logon.csv from the zip
│   ├── load_ldap.py
│   ├── load_labels.py
│   ├── build_baseline.py
│   └── synthesize.py             # seeded gap-filling + 20 campaigns
├── detect/
│   ├── signals.py
│   └── score.py
├── graph/
│   ├── project.py                # Postgres → Neo4j subgraph
│   └── reconstruct.py            # Cypher traversal → ALERT_PATH_HOP
├── ingest/
│   └── api.py                    # FastAPI, live auth.log
├── lab/
│   ├── alpine-setup.sh
│   └── rsyslog.conf
├── attack/
│   └── demo_runbook.md           # manual, step-by-step demo checklist
├── demo/
│   ├── attack_replay.jsonl
│   └── replay.py
├── dashboard/
│   └── app.py
└── eval/
    └── metrics.py
```
