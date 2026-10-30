-- =====================================================================
-- Views.
-- C4: is_new_host is computed here, not stored on login_event, because
-- "new" is relative to the baseline snapshot. If stored, it would go
-- stale the moment the baseline changed and silently corrupt recall.
-- =====================================================================

-- login_event enriched with point-in-time flags used by the scorer.
CREATE OR REPLACE VIEW v_login_enriched AS
SELECT
    e.event_id,
    e.ts,
    e.target_user_id,
    e.source_user_id,
    e.dst_host_id,
    e.src_host_id,
    e.auth_type,
    e.success,
    e.logon_type,
    e.is_synthetic,
    u.roles                          AS user_role,
    h.sensitivity                    AS dst_sensitivity,
    EXTRACT(HOUR FROM e.ts)::INT     AS hour_of_day,
    -- C4: new (user, host) pair not present in the baseline
    NOT EXISTS (
        SELECT 1 FROM user_host_baseline b
        WHERE b.user_id = e.target_user_id
          AND b.host_id = e.dst_host_id
    )                                AS is_new_host,
    -- credential switch: acting user differs from account used
    (e.source_user_id IS DISTINCT FROM e.target_user_id) AS is_credential_switch,
    -- logon after the user was terminated
    (u.terminated_date IS NOT NULL AND e.ts::date > u.terminated_date) AS is_after_termination
FROM login_event e
LEFT JOIN app_user u ON u.user_id = e.target_user_id
LEFT JOIN host     h ON h.host_id = e.dst_host_id;

-- convenience: labeled malicious events joined to their login_event
CREATE OR REPLACE VIEW v_labeled_events AS
SELECT l.label_id, l.source, l.scenario, l.user_id, l.event_id, e.ts, e.dst_host_id
FROM redteam_label l
LEFT JOIN login_event e ON e.event_id = l.event_id;
