-- =====================================================================
-- Indexes. Created on the partitioned parent, so they propagate to every
-- partition. These back the per-user and per-host timeline queries and
-- the index study in Phase 4.
-- =====================================================================

-- per-user timeline (the single most-used access path in scoring)
CREATE INDEX ix_login_target_ts ON login_event (target_user_id, ts);

-- per-host timeline (who touched this host, when)
CREATE INDEX ix_login_dst_ts    ON login_event (dst_host_id, ts);

-- global time scans / partition pruning helper
CREATE INDEX ix_login_ts        ON login_event (ts);

-- resolve CERT ids -> surrogate event_id (used by label linking)
CREATE INDEX ix_login_srcref    ON login_event (source_event_ref);

-- label and path lookups
CREATE INDEX ix_label_event     ON redteam_label (event_id);
CREATE INDEX ix_label_user      ON redteam_label (user_id);
CREATE INDEX ix_hop_event       ON alert_path_hop (event_id);
CREATE INDEX ix_reason_alert    ON alert_reason (alert_id);
CREATE INDEX ix_alert_user      ON alert (causal_user_id);
