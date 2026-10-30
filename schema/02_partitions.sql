-- =====================================================================
-- Monthly partitions for login_event.
-- CERT r4.2 spans 2010-01 .. 2011-05. We cover 2010-01 .. 2011-06 and
-- add a DEFAULT partition so synthetic/out-of-range rows never fail to
-- insert.
-- =====================================================================

CREATE TABLE login_event_2010_01 PARTITION OF login_event FOR VALUES FROM ('2010-01-01') TO ('2010-02-01');
CREATE TABLE login_event_2010_02 PARTITION OF login_event FOR VALUES FROM ('2010-02-01') TO ('2010-03-01');
CREATE TABLE login_event_2010_03 PARTITION OF login_event FOR VALUES FROM ('2010-03-01') TO ('2010-04-01');
CREATE TABLE login_event_2010_04 PARTITION OF login_event FOR VALUES FROM ('2010-04-01') TO ('2010-05-01');
CREATE TABLE login_event_2010_05 PARTITION OF login_event FOR VALUES FROM ('2010-05-01') TO ('2010-06-01');
CREATE TABLE login_event_2010_06 PARTITION OF login_event FOR VALUES FROM ('2010-06-01') TO ('2010-07-01');
CREATE TABLE login_event_2010_07 PARTITION OF login_event FOR VALUES FROM ('2010-07-01') TO ('2010-08-01');
CREATE TABLE login_event_2010_08 PARTITION OF login_event FOR VALUES FROM ('2010-08-01') TO ('2010-09-01');
CREATE TABLE login_event_2010_09 PARTITION OF login_event FOR VALUES FROM ('2010-09-01') TO ('2010-10-01');
CREATE TABLE login_event_2010_10 PARTITION OF login_event FOR VALUES FROM ('2010-10-01') TO ('2010-11-01');
CREATE TABLE login_event_2010_11 PARTITION OF login_event FOR VALUES FROM ('2010-11-01') TO ('2010-12-01');
CREATE TABLE login_event_2010_12 PARTITION OF login_event FOR VALUES FROM ('2010-12-01') TO ('2011-01-01');
CREATE TABLE login_event_2011_01 PARTITION OF login_event FOR VALUES FROM ('2011-01-01') TO ('2011-02-01');
CREATE TABLE login_event_2011_02 PARTITION OF login_event FOR VALUES FROM ('2011-02-01') TO ('2011-03-01');
CREATE TABLE login_event_2011_03 PARTITION OF login_event FOR VALUES FROM ('2011-03-01') TO ('2011-04-01');
CREATE TABLE login_event_2011_04 PARTITION OF login_event FOR VALUES FROM ('2011-04-01') TO ('2011-05-01');
CREATE TABLE login_event_2011_05 PARTITION OF login_event FOR VALUES FROM ('2011-05-01') TO ('2011-06-01');
CREATE TABLE login_event_2011_06 PARTITION OF login_event FOR VALUES FROM ('2011-06-01') TO ('2011-07-01');

CREATE TABLE login_event_default PARTITION OF login_event DEFAULT;
