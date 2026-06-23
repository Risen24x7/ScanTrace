package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ---------------------------------------------------------------------------
// DB wraps *sql.DB with ScanTrace-specific helpers.
// ---------------------------------------------------------------------------

type DB struct {
	conn *sql.DB
	path string
}

// Open opens (or creates) the SQLite database at path, enables WAL mode,
// sets pragmas for safe concurrent access, and runs migrations.
func Open(path string) (*DB, error) {
// Ensure the directory exists
    dir := filepath.Dir(path)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create db directory: %w", err)
    }

	// The DSN embeds pragmas that must be set before any other statement.
	dsn := fmt.Sprintf(
		"file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on&_synchronous=NORMAL",
		path,
	)

	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.Open: sql.Open: %w", err)
	}

	// Limit to one writer at a time; SQLite WAL supports many concurrent readers.
	conn.SetMaxOpenConns(1)

	db := &DB{conn: conn, path: path}

	if err := db.ping(); err != nil {
		conn.Close()
		return nil, err
	}

	if err := db.RunMigrations(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("db.Open: migrations: %w", err)
	}

	return db, nil
}

// Close releases the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn exposes the underlying *sql.DB for ad-hoc queries.
func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) ping() error {
	if err := db.conn.Ping(); err != nil {
		return fmt.Errorf("db.ping: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

// RunMigrations applies the DDL if schema_version does not record the current version.
func (db *DB) RunMigrations() error {
    tx, err := db.conn.Begin()
    if err != nil {
        return err
    }
    defer func() {
        if err != nil {
            _ = tx.Rollback()
        }
    }()

    // Apply schema (CREATE TABLE IF NOT EXISTS is idempotent).
    for _, stmt := range splitStatements(DDL) {
        if _, err = tx.Exec(stmt); err != nil {
            return fmt.Errorf("RunMigrations: %w\nStatement: %s", err, stmt)
        }
    }

    // Record schema version in the table that actually exists (schema_version).
    // I updated the table name and the column names to match your schema.go
    _, err = tx.Exec(
        `INSERT OR REPLACE INTO schema_version(version, applied_at) VALUES(?, CURRENT_TIMESTAMP)`,
        SchemaVersion,
    )
    if err != nil {
        return err
    }

    return tx.Commit()
}

// SchemaVersionApplied returns the schema version stored in the DB.
func (db *DB) SchemaVersionApplied() (int, error) {
	var v int
	err := db.conn.QueryRow(
		`SELECT version FROM schema_version ORDER BY version DESC LIMIT 1`,
	).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return v, err
}

// splitStatements splits a multi-statement DDL string on ';'.
func splitStatements(ddl string) []string {
	raw := strings.Split(ddl, ";")
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// time helpers
// ---------------------------------------------------------------------------

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func mustParseTime(s string) time.Time {
	t, err := parseTime(s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ---------------------------------------------------------------------------
// StringSlice helpers for SQL scan
// ---------------------------------------------------------------------------

func marshalStringSlice(ss StringSlice) string {
	if ss == nil {
		return "[]"
	}
	b, _ := json.Marshal([]string(ss))
	return string(b)
}

func unmarshalStringSlice(s string) StringSlice {
	var out StringSlice
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// ===========================================================================
// SENSOR CRUD
// ===========================================================================

// InsertSensor inserts a new Sensor row. sensor_id must already be set (UUID v4).
func (db *DB) InsertSensor(s *Sensor) error {
	now := formatTime(time.Now().UTC())
	
	// Handle zero-value time initialization
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	if s.UpdatedAt.IsZero() {
		s.UpdatedAt = s.CreatedAt
	}

	_, err := db.conn.Exec(`
		INSERT INTO sensors
		  (sensor_id, hostname, platform, role, public_ip,
		   network_zone, location_tag, collector_type, version,
		   created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(sensor_id) DO UPDATE SET
		  hostname=excluded.hostname,
		  platform=excluded.platform,
		  role=excluded.role,
		  public_ip=excluded.public_ip,
		  network_zone=excluded.network_zone,
		  location_tag=excluded.location_tag,
		  collector_type=excluded.collector_type,
		  version=excluded.version,
		  updated_at=?`,
		s.SensorID, s.Hostname, s.Platform, s.Role, s.PublicIP,
		s.NetworkZone, s.LocationTag, s.CollectorType, s.Version,
		formatTime(s.CreatedAt), formatTime(s.UpdatedAt),
		now,
	)
	return err
}

// GetSensor retrieves a Sensor by sensor_id.
func (db *DB) GetSensor(sensorID string) (*Sensor, error) {
	row := db.conn.QueryRow(`
		SELECT sensor_id, hostname, platform, role, public_ip,
		       network_zone, location_tag, collector_type, version,
		       created_at, updated_at
		FROM sensors WHERE sensor_id = ?`, sensorID)
	return scanSensor(row)
}

// ListSensors returns all registered sensors.
func (db *DB) ListSensors() ([]*Sensor, error) {
	rows, err := db.conn.Query(`
		SELECT sensor_id, hostname, platform, role, public_ip,
		       network_zone, location_tag, collector_type, version,
		       created_at, updated_at
		FROM sensors ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Sensor
	for rows.Next() {
		s, err := scanSensor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteSensor removes a sensor and cascades to its events.
func (db *DB) DeleteSensor(sensorID string) error {
	_, err := db.conn.Exec(`DELETE FROM sensors WHERE sensor_id = ?`, sensorID)
	return err
}

type sensorScanner interface {
	Scan(dest ...any) error
}

func scanSensor(r sensorScanner) (*Sensor, error) {
	var s Sensor
	var createdAt, updatedAt string
	err := r.Scan(
		&s.SensorID, &s.Hostname, &s.Platform, &s.Role, &s.PublicIP,
		&s.NetworkZone, &s.LocationTag, &s.CollectorType, &s.Version,
		&createdAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt = mustParseTime(createdAt)
	s.UpdatedAt = mustParseTime(updatedAt)
	return &s, nil
}

// ===========================================================================
// EVENT CRUD
// ===========================================================================

// InsertEvent inserts a normalized Event. event_id must be set (UUID v4).
func (db *DB) InsertEvent(e *Event) error {
	_, err := db.conn.Exec(`
		INSERT INTO events
		  (event_id, timestamp, first_seen, last_seen, sensor_id,
		   source_type, detector_type, event_type,
		   src_ip, src_port, dst_ip, dst_port,
		   protocol, transport, direction,
		   raw_ref, pcap_ref, confidence, tags, notes)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(event_id) DO NOTHING`,
		e.EventID,
		formatTime(e.Timestamp),
		formatTime(e.FirstSeen),
		formatTime(e.LastSeen),
		e.SensorID,
		e.SourceType, e.DetectorType, e.EventType,
		e.SrcIP, e.SrcPort, e.DstIP, e.DstPort,
		e.Protocol, e.Transport, e.Direction,
		e.RawRef, e.PcapRef,
		e.Confidence,
		marshalStringSlice(e.Tags),
		e.Notes,
	)
	return err
}

// GetEvent retrieves an Event by event_id.
func (db *DB) GetEvent(eventID string) (*Event, error) {
	row := db.conn.QueryRow(`
		SELECT event_id, timestamp, first_seen, last_seen, sensor_id,
		       source_type, detector_type, event_type,
		       src_ip, src_port, dst_ip, dst_port,
		       protocol, transport, direction,
		       raw_ref, pcap_ref, confidence, tags, notes
		FROM events WHERE event_id = ?`, eventID)
	return scanEvent(row)
}

// ListEventsBySrcIP returns all events for a given source IP within an optional
// time window. Pass zero values for after/before to skip the window filter.
func (db *DB) ListEventsBySrcIP(srcIP string, after, before time.Time) ([]*Event, error) {
	query := `
		SELECT event_id, timestamp, first_seen, last_seen, sensor_id,
		       source_type, detector_type, event_type,
		       src_ip, src_port, dst_ip, dst_port,
		       protocol, transport, direction,
		       raw_ref, pcap_ref, confidence, tags, notes
		FROM events
		WHERE src_ip = ?`
	args := []any{srcIP}

	if !after.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, formatTime(after))
	}
	if !before.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, formatTime(before))
	}
	query += " ORDER BY timestamp ASC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// ListEvents returns events, newest first, with an optional limit.
func (db *DB) ListEvents(limit int) ([]*Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(`
		SELECT event_id, timestamp, first_seen, last_seen, sensor_id,
		       source_type, detector_type, event_type,
		       src_ip, src_port, dst_ip, dst_port,
		       protocol, transport, direction,
		       raw_ref, pcap_ref, confidence, tags, notes
		FROM events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// DeleteEvent removes a single event by ID.
func (db *DB) DeleteEvent(eventID string) error {
	_, err := db.conn.Exec(`DELETE FROM events WHERE event_id = ?`, eventID)
	return err
}

type eventScanner interface {
	Scan(dest ...any) error
}

func scanEvent(r eventScanner) (*Event, error) {
	var e Event
	var ts, fs, ls, tagsJSON string
	err := r.Scan(
		&e.EventID, &ts, &fs, &ls, &e.SensorID,
		&e.SourceType, &e.DetectorType, &e.EventType,
		&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort,
		&e.Protocol, &e.Transport, &e.Direction,
		&e.RawRef, &e.PcapRef, &e.Confidence, &tagsJSON, &e.Notes,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.Timestamp = mustParseTime(ts)
	e.FirstSeen = mustParseTime(fs)
	e.LastSeen = mustParseTime(ls)
	e.Tags = unmarshalStringSlice(tagsJSON)
	return &e, nil
}

func scanEvents(rows *sql.Rows) ([]*Event, error) {
	var out []*Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ===========================================================================
// ENTITY CRUD
// ===========================================================================

// UpsertEntity inserts or replaces an Entity keyed on ip.
func (db *DB) UpsertEntity(en *Entity) error {
	_, err := db.conn.Exec(`
		INSERT INTO entities
		  (entity_id, entity_type, ip, asn, as_name, provider,
		   rdns, abuse_contact, geo_country, reputation_labels, last_enriched)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET
		  entity_type=excluded.entity_type,
		  asn=excluded.asn,
		  as_name=excluded.as_name,
		  provider=excluded.provider,
		  rdns=excluded.rdns,
		  abuse_contact=excluded.abuse_contact,
		  geo_country=excluded.geo_country,
		  reputation_labels=excluded.reputation_labels,
		  last_enriched=excluded.last_enriched`,
		en.EntityID, en.EntityType, en.IP, en.ASN, en.ASName, en.Provider,
		en.RDNS, en.AbuseContact, en.GeoCountry,
		marshalStringSlice(en.ReputationLabels),
		formatTime(en.LastEnriched),
	)
	return err
}

// GetEntityByIP retrieves an Entity by its canonical IP address.
// Returns (nil, nil) if not found.
func (db *DB) GetEntityByIP(ip string) (*Entity, error) {
	row := db.conn.QueryRow(`
		SELECT entity_id, entity_type, ip, asn, as_name, provider,
		       rdns, abuse_contact, geo_country, reputation_labels, last_enriched
		FROM entities WHERE ip = ?`, ip)
	return scanEntity(row)
}

// GetEntity retrieves an Entity by entity_id.
func (db *DB) GetEntity(entityID string) (*Entity, error) {
	row := db.conn.QueryRow(`
		SELECT entity_id, entity_type, ip, asn, as_name, provider,
		       rdns, abuse_contact, geo_country, reputation_labels, last_enriched
		FROM entities WHERE entity_id = ?`, entityID)
	return scanEntity(row)
}

// ListEntities returns all enriched entities ordered by last_enriched desc.
func (db *DB) ListEntities(limit int) ([]*Entity, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(`
		SELECT entity_id, entity_type, ip, asn, as_name, provider,
		       rdns, abuse_contact, geo_country, reputation_labels, last_enriched
		FROM entities ORDER BY last_enriched DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Entity
	for rows.Next() {
		en, err := scanEntity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, en)
	}
	return out, rows.Err()
}

// DeleteEntity removes an entity by entity_id.
func (db *DB) DeleteEntity(entityID string) error {
	_, err := db.conn.Exec(`DELETE FROM entities WHERE entity_id = ?`, entityID)
	return err
}

type entityScanner interface {
	Scan(dest ...any) error
}

func scanEntity(r entityScanner) (*Entity, error) {
	var en Entity
	var repJSON, lastEnriched string
	err := r.Scan(
		&en.EntityID, &en.EntityType, &en.IP, &en.ASN, &en.ASName, &en.Provider,
		&en.RDNS, &en.AbuseContact, &en.GeoCountry, &repJSON, &lastEnriched,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	en.ReputationLabels = unmarshalStringSlice(repJSON)
	en.LastEnriched = mustParseTime(lastEnriched)
	return &en, nil
}

// GetEntityByValue is a helper for the MCP server to find an entity by IP or ID.
func (db *DB) GetEntityByValue(val string) (*Entity, error) {
    // Try to find by ID first, if not found, try by IP
    en, err := db.GetEntity(val)
    if err != nil || en != nil {
        return en, err
    }
    return db.GetEntityByIP(val)
}

// ===========================================================================
// CASE-ENTITY LINKING
// ===========================================================================

// LinkEntityToCase writes a row to case_entities and appends the entity_id to
// the case's related_entity_ids JSON column. Safe to call multiple times for
// the same pair (INSERT OR IGNORE).
func (db *DB) LinkEntityToCase(caseID, entityID string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Write the join row (idempotent).
	if _, err = tx.Exec(
		`INSERT OR IGNORE INTO case_entities(case_id, entity_id) VALUES(?,?)`,
		caseID, entityID,
	); err != nil {
		return fmt.Errorf("LinkEntityToCase: join insert: %w", err)
	}

	// Pull current related_entity_ids from the case.
	var raw string
	if err = tx.QueryRow(
		`SELECT related_entity_ids FROM cases WHERE case_id = ?`, caseID,
	).Scan(&raw); err != nil {
		return fmt.Errorf("LinkEntityToCase: read case: %w", err)
	}
	ids := unmarshalStringSlice(raw)

	// Append only if not already present.
	found := false
	for _, id := range ids {
		if id == entityID {
			found = true
			break
		}
	}
	if !found {
		ids = append(ids, entityID)
		if _, err = tx.Exec(
			`UPDATE cases SET related_entity_ids=?, updated_at=? WHERE case_id=?`,
			marshalStringSlice(ids), formatTime(time.Now().UTC()), caseID,
		); err != nil {
			return fmt.Errorf("LinkEntityToCase: update case: %w", err)
		}
	}

	return tx.Commit()
}

// GetEntitiesForCase returns all entities linked to a case via case_entities.
func (db *DB) GetEntitiesForCase(caseID string) ([]*Entity, error) {
	rows, err := db.conn.Query(`
		SELECT e.entity_id, e.entity_type, e.ip, e.asn, e.as_name, e.provider,
		       e.rdns, e.abuse_contact, e.geo_country, e.reputation_labels, e.last_enriched
		FROM entities e
		JOIN case_entities ce ON ce.entity_id = e.entity_id
		WHERE ce.case_id = ?`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Entity
	for rows.Next() {
		en, err := scanEntity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, en)
	}
	return out, rows.Err()
}

// ===========================================================================
// CASE CRUD
// ===========================================================================

// InsertCase inserts a new Case. case_id must be set (UUID v4).
func (db *DB) InsertCase(c *Case) error {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	_, err := db.conn.Exec(`
		INSERT INTO cases
		  (case_id, title, summary, status, severity, confidence,
		   created_at, updated_at,
		   related_event_ids, related_entity_ids,
		   timeline, artifacts, analyst_notes, report_exports)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(case_id) DO NOTHING`,
		c.CaseID, c.Title, c.Summary, c.Status, c.Severity, c.Confidence,
		formatTime(c.CreatedAt), formatTime(c.UpdatedAt),
		marshalStringSlice(c.RelatedEventIDs),
		marshalStringSlice(c.RelatedEntityIDs),
		c.Timeline, c.Artifacts,
		c.AnalystNotes,
		marshalStringSlice(c.ReportExports),
	)
	return err
}

// UpdateCase replaces mutable fields on an existing Case and bumps updated_at.
func (db *DB) UpdateCase(c *Case) error {
	c.UpdatedAt = time.Now().UTC()
	_, err := db.conn.Exec(`
		UPDATE cases SET
		  title=?, summary=?, status=?, severity=?, confidence=?,
		  updated_at=?,
		  related_event_ids=?, related_entity_ids=?,
		  timeline=?, artifacts=?, analyst_notes=?, report_exports=?
		WHERE case_id=?`,
		c.Title, c.Summary, c.Status, c.Severity, c.Confidence,
		formatTime(c.UpdatedAt),
		marshalStringSlice(c.RelatedEventIDs),
		marshalStringSlice(c.RelatedEntityIDs),
		c.Timeline, c.Artifacts,
		c.AnalystNotes,
		marshalStringSlice(c.ReportExports),
		c.CaseID,
	)
	return err
}

// GetCase retrieves a Case by case_id.
func (db *DB) GetCase(caseID string) (*Case, error) {
	row := db.conn.QueryRow(`
		SELECT case_id, title, summary, status, severity, confidence,
		       created_at, updated_at,
		       related_event_ids, related_entity_ids,
		       timeline, artifacts, analyst_notes, report_exports
		FROM cases WHERE case_id = ?`, caseID)
	return scanCase(row)
}

// ListCases returns cases ordered by created_at descending.
// severity filter is optional — pass "" to return all.
func (db *DB) ListCases(severity string, limit int) ([]*Case, error) {
	if limit <= 0 {
		limit = 50
	}

	var rows *sql.Rows
	var err error
	if severity != "" {
		rows, err = db.conn.Query(`
			SELECT case_id, title, summary, status, severity, confidence,
			       created_at, updated_at,
			       related_event_ids, related_entity_ids,
			       timeline, artifacts, analyst_notes, report_exports
			FROM cases WHERE severity = ?
			ORDER BY created_at DESC LIMIT ?`, severity, limit)
	} else {
		rows, err = db.conn.Query(`
			SELECT case_id, title, summary, status, severity, confidence,
			       created_at, updated_at,
			       related_event_ids, related_entity_ids,
			       timeline, artifacts, analyst_notes, report_exports
			FROM cases
			ORDER BY created_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Case
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCase removes a case by case_id.
func (db *DB) DeleteCase(caseID string) error {
	_, err := db.conn.Exec(`DELETE FROM cases WHERE case_id = ?`, caseID)
	return err
}

type caseScanner interface {
	Scan(dest ...any) error
}

func scanCase(r caseScanner) (*Case, error) {
	var c Case
	var createdAt, updatedAt string
	var relEvt, relEnt, repExp, artifacts string
	err := r.Scan(
		&c.CaseID, &c.Title, &c.Summary, &c.Status, &c.Severity, &c.Confidence,
		&createdAt, &updatedAt,
		&relEvt, &relEnt,
		&c.Timeline, &artifacts, &c.AnalystNotes, &repExp,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt = mustParseTime(createdAt)
	c.UpdatedAt = mustParseTime(updatedAt)
	c.RelatedEventIDs = unmarshalStringSlice(relEvt)
	c.RelatedEntityIDs = unmarshalStringSlice(relEnt)
	c.Artifacts = artifacts
	c.ReportExports = unmarshalStringSlice(repExp)
	return &c, nil
}
