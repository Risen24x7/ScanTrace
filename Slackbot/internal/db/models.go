package db

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// StringSlice — JSON-serializable []string stored as TEXT in SQLite
// ---------------------------------------------------------------------------

// StringSlice is a []string that marshals to/from JSON and satisfies
// the sql.Scanner and driver.Valuer interfaces for SQLite TEXT columns.
type StringSlice []string

// Scan implements sql.Scanner — called when reading from a TEXT column.
func (s *StringSlice) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*s = StringSlice{}
		return nil
	case string:
		return json.Unmarshal([]byte(v), s)
	case []byte:
		return json.Unmarshal(v, s)
	}
	return fmt.Errorf("StringSlice.Scan: unsupported source type %T", src)
}

// ---------------------------------------------------------------------------
// Sensor — source of observation
// ---------------------------------------------------------------------------

// Sensor represents a registered sensor that produces events.
type Sensor struct {
	SensorID      string    `json:"sensor_id"      db:"sensor_id"`
	Hostname      string    `json:"hostname"       db:"hostname"`
	Platform      string    `json:"platform"       db:"platform"`
	Role          string    `json:"role"           db:"role"`
	PublicIP      string    `json:"public_ip"      db:"public_ip"`
	NetworkZone   string    `json:"network_zone"   db:"network_zone"`
	LocationTag   string    `json:"location_tag"   db:"location_tag"`
	CollectorType string    `json:"collector_type" db:"collector_type"`
	Version       string    `json:"version"        db:"version"`
	CreatedAt     time.Time `json:"created_at"     db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"     db:"updated_at"`
}

// ---------------------------------------------------------------------------
// Event — one normalized observation record
// ---------------------------------------------------------------------------

// Event represents a single activity record after normalization.
// RawRef preserves the original payload so adapters remain reversible.
type Event struct {
	EventID      string      `json:"event_id"      db:"event_id"`
	Timestamp    time.Time   `json:"timestamp"     db:"timestamp"`
	FirstSeen    time.Time   `json:"first_seen"    db:"first_seen"`
	LastSeen     time.Time   `json:"last_seen"     db:"last_seen"`
	SensorID     string      `json:"sensor_id"     db:"sensor_id"`
	SourceType   string      `json:"source_type"   db:"source_type"`
	DetectorType string      `json:"detector_type" db:"detector_type"`
	EventType    string      `json:"event_type"    db:"event_type"`
	SrcIP        string      `json:"src_ip"        db:"src_ip"`
	SrcPort      int         `json:"src_port"      db:"src_port"`
	DstIP        string      `json:"dst_ip"        db:"dst_ip"`
	DstPort      int         `json:"dst_port"      db:"dst_port"`
	Protocol     string      `json:"protocol"      db:"protocol"`
	Transport    string      `json:"transport"     db:"transport"`
	Direction    string      `json:"direction"     db:"direction"`
	RawRef       string      `json:"raw_ref"       db:"raw_ref"`   // original payload JSON blob
	PcapRef      string      `json:"pcap_ref"      db:"pcap_ref"`  // optional pcap path/URI
	Confidence   float64     `json:"confidence"    db:"confidence"`
	Tags         StringSlice `json:"tags"          db:"tags"`      // stored as JSON TEXT
	Notes        string      `json:"notes"         db:"notes"`
}

// ---------------------------------------------------------------------------
// Entity — enriched infrastructure object derived from enrichment
// ---------------------------------------------------------------------------

// Entity represents a known external actor enriched from their source IP.
type Entity struct {
	EntityID         string      `json:"entity_id"         db:"entity_id"`
	EntityType       string      `json:"entity_type"       db:"entity_type"`
	IP               string      `json:"ip"                db:"ip"`
	ASN              string      `json:"asn"               db:"asn"`
	ASName           string      `json:"as_name"           db:"as_name"`
	Provider         string      `json:"provider"          db:"provider"`
	RDNS             string      `json:"rdns"              db:"rdns"`
	AbuseContact     string      `json:"abuse_contact"     db:"abuse_contact"`
	GeoCountry       string      `json:"geo_country"       db:"geo_country"`
	ReputationLabels StringSlice `json:"reputation_labels" db:"reputation_labels"` // JSON TEXT
	LastEnriched     time.Time   `json:"last_enriched"     db:"last_enriched"`
}

// ---------------------------------------------------------------------------
// Case — grouped investigation object
// ---------------------------------------------------------------------------

// Case represents a correlated investigation record that groups related
// events and entities into a reportable incident.
type Case struct {
	CaseID           string      `json:"case_id"            db:"case_id"`
	Title            string      `json:"title"              db:"title"`
	Summary          string      `json:"summary"            db:"summary"`
	Status           string      `json:"status"             db:"status"`    // open, closed, escalated
	Severity         string      `json:"severity"           db:"severity"`  // high, medium, low
	Confidence       float64     `json:"confidence"         db:"confidence"`
	CreatedAt        time.Time   `json:"created_at"         db:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"         db:"updated_at"`
	RelatedEventIDs  StringSlice `json:"related_event_ids"  db:"related_event_ids"`  // JSON TEXT
	RelatedEntityIDs StringSlice `json:"related_entity_ids" db:"related_entity_ids"` // JSON TEXT
	Timeline         string      `json:"timeline"           db:"timeline"`   // markdown or JSON blob
	Artifacts        string      `json:"artifacts"          db:"artifacts"`  // JSON blob — file paths/URIs
	AnalystNotes     string      `json:"analyst_notes"      db:"analyst_notes"`
	ReportExports    StringSlice `json:"report_exports"     db:"report_exports"` // file paths
}
