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
// Sensor
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
// Event
// ---------------------------------------------------------------------------

// Event represents a single normalized observation record.
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
	RawRef       string      `json:"raw_ref"       db:"raw_ref"`
	PcapRef      string      `json:"pcap_ref"      db:"pcap_ref"`
	Confidence   float64     `json:"confidence"    db:"confidence"`
	Tags         StringSlice `json:"tags"          db:"tags"`
	Notes        string      `json:"notes"         db:"notes"`
}

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

// Entity represents an enriched external actor derived from their source IP.
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
	ReputationLabels StringSlice `json:"reputation_labels" db:"reputation_labels"`
	LastEnriched     time.Time   `json:"last_enriched"     db:"last_enriched"`
}

// ---------------------------------------------------------------------------
// KnownDevice
// ---------------------------------------------------------------------------

// KnownDevice is an analyst-maintained registry entry for a device on a
// monitored network. Keyed on IP or MAC (at least one must be non-empty).
//
// TrustLabel values:
//
//	"trusted"    — known-good device; auto_suppress may silence low-severity cases
//	"unknown"    — seen on network but not yet classified (default)
//	"suspicious" — flagged for elevated scrutiny
type KnownDevice struct {
	DeviceID     string    `json:"device_id"     db:"device_id"`
	IP           string    `json:"ip"            db:"ip"`
	MAC          string    `json:"mac"           db:"mac"`
	Hostname     string    `json:"hostname"      db:"hostname"`
	Label        string    `json:"label"         db:"label"`        // human-readable name, e.g. "Corp Laptop — Alice"
	TrustLabel   string    `json:"trust_label"   db:"trust_label"` // trusted | unknown | suspicious
	NetworkZone  string    `json:"network_zone"  db:"network_zone"`
	OrgUnit      string    `json:"org_unit"      db:"org_unit"`
	Owner        string    `json:"owner"         db:"owner"`
	AutoSuppress bool      `json:"auto_suppress" db:"auto_suppress"`
	FirstSeen    time.Time `json:"first_seen"    db:"first_seen"`
	LastSeen     time.Time `json:"last_seen"     db:"last_seen"`
	Notes        string    `json:"notes"         db:"notes"`
	CreatedAt    time.Time `json:"created_at"    db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"    db:"updated_at"`
}

// ---------------------------------------------------------------------------
// Case
// ---------------------------------------------------------------------------

// Case represents a correlated investigation record grouping related
// events and entities into a reportable incident.
type Case struct {
	CaseID           string      `json:"case_id"            db:"case_id"`
	Title            string      `json:"title"              db:"title"`
	Summary          string      `json:"summary"            db:"summary"`
	Status           string      `json:"status"             db:"status"`
	Severity         string      `json:"severity"           db:"severity"`
	Confidence       float64     `json:"confidence"         db:"confidence"`
	CreatedAt        time.Time   `json:"created_at"         db:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"         db:"updated_at"`
	RelatedEventIDs  StringSlice `json:"related_event_ids"  db:"related_event_ids"`
	RelatedEntityIDs StringSlice `json:"related_entity_ids" db:"related_entity_ids"`
	Timeline         string      `json:"timeline"           db:"timeline"`
	Artifacts        string      `json:"artifacts"          db:"artifacts"`
	AnalystNotes     string      `json:"analyst_notes"      db:"analyst_notes"`
	ReportExports    StringSlice `json:"report_exports"     db:"report_exports"`
	RuleType         string      `json:"rule_type"          db:"rule_type"`
	SrcIP            string      `json:"src_ip"             db:"src_ip"`
}

// ---------------------------------------------------------------------------
// LLM telemetry
// ---------------------------------------------------------------------------

// LLMRun captures one call to the LLM backend.
type LLMRun struct {
	RunID           string    `json:"run_id"`
	CreatedAt       time.Time `json:"created_at"`
	CallType        string    `json:"call_type"`
	Model           string    `json:"model"`
	MaxTokens       int       `json:"max_tokens"`
	Temperature     float64   `json:"temperature"`
	TopP            float64   `json:"top_p"`
	DisableThinking bool      `json:"disable_thinking"`
	StopThink       bool      `json:"stop_think"`
	PromptBytes     int       `json:"prompt_bytes"`
	ContextBytes    int       `json:"context_bytes"`
	TriageBytes     int       `json:"triage_bytes"`
	ActionsBytes    int       `json:"actions_bytes"`
	TrimEnabled     bool      `json:"trim_enabled"`
	TrimBudget      int       `json:"trim_budget"`
	TrimKept        int       `json:"trim_kept"`
	TrimCompressed  int       `json:"trim_compressed"`
	TrimDropped     int       `json:"trim_dropped"`
	DurationMs      int64     `json:"duration_ms"`
	Status          string    `json:"status"`        // ok | error
	ErrorMessage    string    `json:"error_message"`
	CaseID          string    `json:"case_id"`
	ChannelID       string    `json:"channel_id"`
	UserID          string    `json:"user_id"`
}

// LLMReviewMeta stores structured facts parsed from an AskCase response.
type LLMReviewMeta struct {
	ReviewID            string `json:"review_id"`
	RunID               string `json:"run_id"`
	Verdict             string `json:"verdict"`
	SummaryWords        int    `json:"summary_words"`
	DetailsBullets      int    `json:"details_bullets"`
	AssessmentSentences int    `json:"assessment_sentences"`
}
