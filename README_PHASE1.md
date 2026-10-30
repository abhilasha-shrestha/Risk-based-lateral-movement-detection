# Phase 1 — run guide

Everything runs from **WSL** (Ubuntu), in the shared project folder:

```bash
cd /mnt/c/Users/abhil/Desktop/DBMS
```

## 1. One-time setup

```bash
cp .env.example .env            # edit passwords if you like
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Start the databases

```bash
docker compose up -d            # starts postgres + neo4j
docker compose ps               # both should say "healthy"/"running"
```

The schema in `schema/*.sql` runs **automatically** the first time Postgres
starts (tables → partitions → indexes → views).

> If you ever change a file in `schema/`, the auto-run only happens on a fresh
> volume. Re-apply with a reset: `docker compose down -v && docker compose up -d`.

## 3. Load the data (order matters)

```bash
cd etl
python load_ldap.py             # app_user  (1000 users, 155 terminated)
python load_cert.py             # host + login_event (470,591 Logon rows)
python load_labels.py           # redteam_label (links to events by CERT id)
python build_baseline.py        # user_host_baseline (Jan-Feb 2010 only)
cd ..
```

Add `--dry-run` to any loader to parse and count **without** a database
(useful to sanity-check before the DB is up). `load_cert.py --limit 5000`
loads a small slice for a quick smoke test.

> **Re-running a loader.** `load_cert` and `load_labels` use append-style
> loads, so they **refuse to run twice** (that would duplicate the data —
> e.g. 470,591 → 941,182). To reload intentionally, pass `--truncate` to
> empty the table first, or reset everything with `docker compose down -v`.
> Rule of thumb: a count that is a clean multiple of the expected one
> (2×, 3×) means an accidental re-run, not a bad dataset.

## 4. Check the exit criteria

```bash
docker exec -it lmd-postgres psql -U lmd -d lateral -c "
  SELECT (SELECT count(*) FROM login_event)  AS login_events,
         (SELECT count(*) FROM app_user)     AS users,
         (SELECT count(*) FROM host)         AS hosts,
         (SELECT count(*) FROM user_host_baseline) AS baseline_pairs,
         (SELECT count(*) FROM redteam_label WHERE event_id IS NOT NULL) AS linked_labels;"
```

Expected: **login_events = 470591, users = 1000, hosts = 1003**, baseline_pairs > 0.

Per-user timeline (should return in well under 200 ms):

```bash
docker exec -it lmd-postgres psql -U lmd -d lateral -c "
  EXPLAIN ANALYZE
  SELECT ts, dst_host_id FROM login_event
  WHERE target_user_id = 'CCA0046' ORDER BY ts;"
```

## Useful

- Postgres shell: `docker exec -it lmd-postgres psql -U lmd -d lateral`
- Neo4j browser: http://localhost:7474  (user `neo4j`, pass from `.env`)
- Stop (keep data): `docker compose down`
- Reset everything: `docker compose down -v`

## What's validated so far

The parse/count layer is confirmed against the extracted CERT data
(470,591 Logon rows, 1000 users, 1003 hosts, 0 bad dates, 30 scenario-3
labels). The actual COPY into Postgres is step 3 above — run it once the
containers are up.
