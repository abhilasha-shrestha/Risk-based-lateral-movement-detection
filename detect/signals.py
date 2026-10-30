"""Scoring configuration — one place to tune every signal.

score.py reads these constants to build its SQL. Keeping them here means
Week-4 weight tuning touches a single file. Each weight is the points a
signal contributes; an event's score is the capped sum of fired signals.

See IMPLEMENTATION_PLAN.md §4.2 for the rationale behind each weight.
"""

# alert fires when an event's total score reaches this
THRESHOLD = 50

# cap so the dashboard scale stays 0..100
SCORE_CAP = 100

# baseline / training cutoff (must match build_baseline.py)
CUTOFF = "2010-03-01"

# per-signal points
WEIGHTS = {
    "new_host":              25,
    "new_host_for_role":     10,
    "unusual_time":          15,
    "after_hours":           10,
    "rapid_movement":        20,
    "failed_then_success":   25,
    "sensitive_destination": 20,
    "credential_switch":     15,
    "privilege_escalation":  20,
    "dormant_account":       10,
    "terminated_user":       30,
}

# thresholds for the sequence-based signals
RAPID_MIN_HOSTS   = 3      # distinct hosts ...
RAPID_WINDOW_MIN  = 60     # ... within this many minutes
FTS_MIN_FAILURES  = 3      # failed logons ...
FTS_WINDOW_MIN    = 15     # ... before a success, same user+host
DORMANT_DAYS      = 30     # gap since previous logon

# after-hours window: hour >= 22 OR hour < 6
AFTER_HOURS_START = 22
AFTER_HOURS_END   = 6

# role-aware damping: admins legitimately touch many hosts, so halve the
# host/movement signals for ITAdmin UNLESS the destination is sensitive.
ADMIN_ROLE   = "ITAdmin"
ADMIN_DAMP   = 0.5
