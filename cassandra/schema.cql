CREATE KEYSPACE IF NOT EXISTS sentinelflow
WITH replication = {'class': 'NetworkTopologyStrategy', 'dc1': 3};

USE sentinelflow;

CREATE TABLE IF NOT EXISTS events_by_user_day (
    user_id text,
    event_date date,
    event_time timestamp,
    event_id uuid,
    event_type text,
    device_id text,
    ip text,
    country text,
    bytes bigint,
    metadata text,
    PRIMARY KEY ((user_id, event_date), event_time, event_id)
) WITH CLUSTERING ORDER BY (event_time DESC);

CREATE TABLE IF NOT EXISTS events_by_ip_day (
    ip text,
    event_date date,
    event_time timestamp,
    event_id uuid,
    user_id text,
    device_id text,
    event_type text,
    country text,
    bytes bigint,
    metadata text,
    PRIMARY KEY ((ip, event_date), event_time, event_id)
) WITH CLUSTERING ORDER BY (event_time DESC);

CREATE TABLE IF NOT EXISTS events_by_device_day (
    device_id text,
    event_date date,
    event_time timestamp,
    event_id uuid,
    user_id text,
    ip text,
    event_type text,
    country text,
    bytes bigint,
    metadata text,
    PRIMARY KEY ((device_id, event_date), event_time, event_id)
) WITH CLUSTERING ORDER BY (event_time DESC);

CREATE TABLE IF NOT EXISTS alerts_by_user (
    user_id text,
    alert_time timestamp,
    alert_id uuid,
    risk_score double,
    reason text,
    window_start timestamp,
    window_end timestamp,
    PRIMARY KEY ((user_id), alert_time, alert_id)
) WITH CLUSTERING ORDER BY (alert_time DESC);

CREATE TABLE IF NOT EXISTS investigations_by_incident (
    incident_id uuid PRIMARY KEY,
    user_id text,
    created_at timestamp,
    severity text,
    confidence double,
    conclusion text,
    evidence text,
    recommended_actions text,
    agent_mode text
);

CREATE TABLE IF NOT EXISTS investigations_by_user (
    user_id text,
    created_at timestamp,
    incident_id uuid,
    severity text,
    confidence double,
    conclusion text,
    evidence text,
    recommended_actions text,
    agent_mode text,
    PRIMARY KEY ((user_id), created_at, incident_id)
) WITH CLUSTERING ORDER BY (created_at DESC);

CREATE TABLE IF NOT EXISTS agent_tool_calls_by_incident (
    incident_id uuid,
    started_at timestamp,
    call_id uuid,
    tool_name text,
    completed_at timestamp,
    duration_ms int,
    status text,
    input_json text,
    result_summary text,
    error text,
    PRIMARY KEY ((incident_id), started_at, call_id)
) WITH CLUSTERING ORDER BY (started_at ASC);
