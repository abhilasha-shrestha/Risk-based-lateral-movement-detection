-- =====================================================================
-- Risk-Based Lateral Movement Investigation — schema (tables)
-- Target: PostgreSQL 16
-- Maps the ER diagram. Deviations from the diagram are the agreed
-- changes C1-C4 (see IMPLEMENTATION_PLAN.md §3); each is marked below.
--
-- Naming note: the ER entity USER is created here as table `app_user`,
-- because USER is a reserved word in SQL. It is the same entity.
-- =====================================================================

-- ---------------------------------------------------------------------
-- USER  (ER: USER)   — enriched from CERT LDAP snapshots
-- ---------------------------------------------------------------------
CREATE TABLE app_user (
    user_id          VARCHAR(64)  PRIMARY KEY,          -- e.g. CEL0561
    username_hash    VARCHAR(255),                      -- sha256 of real name
    roles            VARCHAR(100),                      -- LDAP role, e.g. ITAdmin
    origin           VARCHAR(50)  DEFAULT 'CERT',
    first_seen       TIMESTAMP,
    -- extra context from LDAP, useful for role-aware scoring
    email_hash       VARCHAR(255),
    business_unit    VARCHAR(100),
    functional_unit  VARCHAR(100),
    department       VARCHAR(100),
    team             VARCHAR(100),
    supervisor       VARCHAR(255),
    terminated_date  DATE                                -- NULL = still employed
);

COMMENT ON COLUMN app_user.terminated_date IS
  'Derived: first LDAP month the user disappears. A logon after this date is a strong signal.';

-- ---------------------------------------------------------------------
-- HOST  (ER: HOST)
-- C2: added `sensitivity` to support sensitive-host awareness.
-- ---------------------------------------------------------------------
CREATE TABLE host (
    host_id        VARCHAR(64)  PRIMARY KEY,            -- e.g. PC-6056
    hostname_hash  VARCHAR(255),
    host_type      VARCHAR(50)  DEFAULT 'workstation',  -- workstation|server|dc|fileserver
    origin         VARCHAR(50)  DEFAULT 'CERT',
    ip_address     VARCHAR(45),                          -- filled by synthesize.py
    sensitivity    VARCHAR(10)  DEFAULT 'low'
                   CHECK (sensitivity IN ('low','medium','high'))   -- C2
);

-- ---------------------------------------------------------------------
-- USER_HOST_BASELINE  (ER: USER_HOST_BASELINE)
-- Built by build_baseline.py over the fixed training window only.
-- ---------------------------------------------------------------------
CREATE TABLE user_host_baseline (
    user_id            VARCHAR(64) REFERENCES app_user(user_id),
    host_id            VARCHAR(64) REFERENCES host(host_id),
    first_login_ts     TIMESTAMP,
    last_login_ts      TIMESTAMP,
    login_count        INTEGER,
    typical_hour_start INTEGER,                          -- 5th  pct of logon hour
    typical_hour_end   INTEGER,                          -- 95th pct of logon hour
    PRIMARY KEY (user_id, host_id)
);

-- ---------------------------------------------------------------------
-- LOGIN_EVENT  (ER: LOGIN_EVENT)   — the fact table
-- C3: added `logon_type`.
-- C4: `is_new_host` is NOT stored here; it is a view (04_views.sql),
--     because "new" is relative to a point in time.
-- Partitioned by month on ts (see 02_partitions.sql) for the
-- optimization/scalability study. PK must include the partition key.
--
-- event_id is a surrogate BIGINT. The original CERT id (e.g.
-- {X1D9-...}) is kept in source_event_ref — it is NOT globally unique
-- across CERT files (see r4.2/readme.txt errata), so it is not the PK.
-- ---------------------------------------------------------------------
CREATE TABLE login_event (
    event_id          BIGINT GENERATED ALWAYS AS IDENTITY,
    ts                TIMESTAMP   NOT NULL,
    source_user_id    VARCHAR(64) REFERENCES app_user(user_id),  -- = target until synthesized
    target_user_id    VARCHAR(64) REFERENCES app_user(user_id),
    src_host_id       VARCHAR(64) REFERENCES host(host_id),      -- = dst until synthesized
    dst_host_id       VARCHAR(64) REFERENCES host(host_id),
    auth_type         VARCHAR(50),                 -- ssh|rdp|kerberos|ntlm (synth)
    success           BOOLEAN     DEFAULT TRUE,     -- CERT has only successes
    logon_type        VARCHAR(20) DEFAULT 'interactive'          -- C3
                      CHECK (logon_type IN ('interactive','remote','service')),
    activity          VARCHAR(20) DEFAULT 'Logon',
    source_event_ref  TEXT,                         -- original CERT id
    is_synthetic      BOOLEAN     DEFAULT FALSE,     -- TRUE for generated rows/fields
    PRIMARY KEY (event_id, ts)
) PARTITION BY RANGE (ts);

-- ---------------------------------------------------------------------
-- ALERT  (ER: ALERT)
-- ---------------------------------------------------------------------
CREATE TABLE alert (
    alert_id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    detected_ts            TIMESTAMP,
    causal_user_id         VARCHAR(64) REFERENCES app_user(user_id),
    rule_triggered         VARCHAR(100),      -- the top-scoring signal
    score                  REAL,
    trigger_event_id       BIGINT,            -- the event that crossed the threshold
    confirmed_true_positive BOOLEAN
);

-- ---------------------------------------------------------------------
-- ALERT_REASON   — C1: NEW table. One row per signal that fired.
-- Backs the "explainable alerts" feature: the *why* behind a score.
-- ---------------------------------------------------------------------
CREATE TABLE alert_reason (
    reason_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id   BIGINT REFERENCES alert(alert_id) ON DELETE CASCADE,
    signal     VARCHAR(50),       -- e.g. new_host, failed_then_success
    points     INTEGER,
    detail     TEXT               -- human-readable, e.g. "host PC-8865 never seen for CCA0046"
);

-- ---------------------------------------------------------------------
-- ALERT_PATH_HOP  (ER: ALERT_PATH_HOP)
-- One row per hop of a reconstructed path. hop_order is the partial key.
-- event_id is a plain BIGINT (no FK): login_event is partitioned, so a
-- FK into it would need (event_id, ts). The link is enforced in code
-- and indexed here. Documented trade-off.
-- ---------------------------------------------------------------------
CREATE TABLE alert_path_hop (
    alert_id   BIGINT REFERENCES alert(alert_id) ON DELETE CASCADE,
    hop_order  INTEGER,
    event_id   BIGINT,
    PRIMARY KEY (alert_id, hop_order)
);

-- ---------------------------------------------------------------------
-- REDTEAM_LABEL  (ER: REDTEAM_LABEL)   — ground truth
-- source: 'cert-scenario-3' (real) or 'synthetic' (injected campaigns).
-- event_id resolved from source_event_ref after login_event is loaded.
-- ---------------------------------------------------------------------
CREATE TABLE redteam_label (
    label_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts                TIMESTAMP,
    source            VARCHAR(100),
    scenario          VARCHAR(20),
    user_id           VARCHAR(64) REFERENCES app_user(user_id),
    source_event_ref  TEXT,
    event_id          BIGINT              -- resolved link into login_event (nullable)
);
