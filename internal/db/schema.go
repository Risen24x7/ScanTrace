package db

// DDL is the complete schema for the ScanTrace SQLite database.
// Applied idempotently on Open() via the migration runner.
const DDL = `
-- scantrace schema v2
-- All timestamps are stored as RFC3339 strings (TEXT).
-- Arrays and blobs are stored as JSON-serialized TEXT.

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sensors (
    sensor_id       TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT '',
    public_ip       TEXT NOT NULL DEFAULT '',
    network_zone    TEXT NOT NULL DEFAULT '',
    location_tag    TEXT NOT NULL DEFAULT '',
    collector_type  TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT '',
    updated_at      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    first_seen      TEXT NOT NULL DEFAULT '',
    last_seen       TEXT NOT NULL DEFAULT '',
    sensor_id       TEXT NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,
    source_type     TEXT NOT NULL DEFAULT '',
    detector_type   TEXT NOT NULL DEFAULT '',
    event_type      TEXT NOT NULL DEFAULT '',
    src_ip          TEXT NOT NULL DEFAULT '',
    src_port        INTEGER NOT NULL DEFAULT 0,
    dst_ip          TEXT NOT NULL DEFAULT '',
    dst_port        INTEGER NOT NULL DEFAULT 0,
    protocol        TEXT NOT NULL DEFAULT '',
    transport       TEXT NOT NULL DEFAULT '',
    direction       TEXT NOT NULL DEFAULT '',
    raw_ref         TEXT NOT NULL DEFAULT '',
    pcap_ref        TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0.7,
    tags            TEXT NOT NULL DEFAULT '[]',
    notes           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_sensor_id ON events(sensor_id);
CREATE INDEX IF NOT EXISTS idx_events_dst_port  ON events(dst_port);

CREATE TABLE IF NOT EXISTS entities (
    entity_id           TEXT PRIMARY KEY,
    entity_type         TEXT NOT NULL DEFAULT 'ip',
    ip                  TEXT NOT NULL UNIQUE,
    asn                 TEXT NOT NULL DEFAULT '',
    as_name             TEXT NOT NULL DEFAULT '',
    provider            TEXT NOT NULL DEFAULT '',
    rdns                TEXT NOT NULL DEFAULT '',
    abuse_contact       TEXT NOT NULL DEFAULT '',
    geo_country         TEXT NOT NULL DEFAULT '',
    reputation_labels   TEXT NOT NULL DEFAULT '[]',
    last_enriched       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_entities_ip  ON entities(ip);
CREATE INDEX IF NOT EXISTS idx_entities_asn ON entities(asn);

CREATE TABLE IF NOT EXISTS cases (
    case_id             TEXT PRIMARY KEY,
    title               TEXT NOT NULL DEFAULT '',
    summary             TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'open',
    severity            TEXT NOT NULL DEFAULT 'medium',
    confidence          REAL NOT NULL DEFAULT 0.5,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    related_event_ids   TEXT NOT NULL DEFAULT '[]',
    related_entity_ids  TEXT NOT NULL DEFAULT '[]',
    timeline            TEXT NOT NULL DEFAULT '{}',
    artifacts           TEXT NOT NULL DEFAULT '{}',
    analyst_notes       TEXT NOT NULL DEFAULT '',
    report_exports      TEXT NOT NULL DEFAULT '{}',
    rule_type           TEXT NOT NULL DEFAULT '',
    src_ip              TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS case_entities (
    case_id   TEXT NOT NULL REFERENCES cases(case_id)   ON DELETE CASCADE,
    entity_id TEXT NOT NULL REFERENCES entities(entity_id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, entity_id)
);

-- known_devices: analyst-maintained registry of devices on monitored networks.
-- Keyed on ip OR mac (at least one must be non-empty).
-- trust_label: trusted | unknown | suspicious
-- auto_suppress: when true, the correlator skips case creation for this device.
CREATE TABLE IF NOT EXISTS known_devices (
    device_id       TEXT PRIMARY KEY,
    ip              TEXT NOT NULL DEFAULT '',
    mac             TEXT NOT NULL DEFAULT '',
    hostname        TEXT NOT NULL DEFAULT '',
    label           TEXT NOT NULL DEFAULT '',
    trust_label     TEXT NOT NULL DEFAULT 'unknown',
    network_zone    TEXT NOT NULL DEFAULT '',
    org_unit        TEXT NOT NULL DEFAULT '',
    owner           TEXT NOT NULL DEFAULT '',
    auto_suppress   INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL DEFAULT '',
    last_seen       TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT '',
    updated_at      TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_known_devices_ip  ON known_devices(ip)  WHERE ip  != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_known_devices_mac ON known_devices(mac) WHERE mac != '';
CREATE INDEX        IF NOT EXISTS idx_known_devices_trust ON known_devices(trust_label);

-- Migration: Add missing columns to existing cases table (v2 → v3 upgrade)
ALTER TABLE cases ADD COLUMN rule_type TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN src_ip TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_cases_severity   ON cases(severity);
CREATE INDEX IF NOT EXISTS idx_cases_status     ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);
CREATE INDEX IF NOT EXISTS idx_cases_rule_type  ON cases(rule_type);
CREATE INDEX IF NOT EXISTS idx_cases_src_ip     ON cases(src_ip);
CREATE INDEX IF NOT EXISTS idx_case_entities_case   ON case_entities(case_id);
CREATE INDEX IF NOT EXISTS idx_case_entities_entity ON case_entities(entity_id);

-- LLM telemetry: runs and review metadata (v4)
CREATE TABLE IF NOT EXISTS llm_runs (
    run_id           TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    call_type        TEXT NOT NULL DEFAULT '',
    model            TEXT NOT NULL DEFAULT '',
    max_tokens       INTEGER NOT NULL DEFAULT 0,
    temperature      REAL NOT NULL DEFAULT 0,
    top_p            REAL NOT NULL DEFAULT 0,
    disable_thinking INTEGER NOT NULL DEFAULT 0,
    stop_think       INTEGER NOT NULL DEFAULT 0,
    prompt_bytes     INTEGER NOT NULL DEFAULT 0,
    context_bytes    INTEGER NOT NULL DEFAULT 0,
    triage_bytes     INTEGER NOT NULL DEFAULT 0,
    actions_bytes    INTEGER NOT NULL DEFAULT 0,
    trim_enabled     INTEGER NOT NULL DEFAULT 0,
    trim_budget      INTEGER NOT NULL DEFAULT 0,
    trim_kept        INTEGER NOT NULL DEFAULT 0,
    trim_compressed  INTEGER NOT NULL DEFAULT 0,
    trim_dropped     INTEGER NOT NULL DEFAULT 0,
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'ok',
    error_message    TEXT NOT NULL DEFAULT '',
    case_id          TEXT NOT NULL DEFAULT '',
    channel_id       TEXT NOT NULL DEFAULT '',
    user_id          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_llm_runs_created_at ON llm_runs(created_at);
CREATE INDEX IF NOT EXISTS idx_llm_runs_call_type  ON llm_runs(call_type);
CREATE INDEX IF NOT EXISTS idx_llm_runs_case_id    ON llm_runs(case_id);

CREATE TABLE IF NOT EXISTS llm_review_meta (
    review_id             TEXT PRIMARY KEY,
    run_id                TEXT NOT NULL REFERENCES llm_runs(run_id) ON DELETE CASCADE,
    verdict               TEXT NOT NULL DEFAULT '',
    summary_words         INTEGER NOT NULL DEFAULT 0,
    details_bullets       INTEGER NOT NULL DEFAULT 0,
    assessment_sentences  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_llm_review_meta_run ON llm_review_meta(run_id);
`

// SchemaVersion is incremented whenever the DDL changes.
// The migration runner checks this before applying statements.
const SchemaVersion = 4