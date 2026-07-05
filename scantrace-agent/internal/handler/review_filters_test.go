package handler

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
)

const testWANIP = "24.20.77.75"

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	dir := t.TempDir()
	store, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.InsertSensor(&db.Sensor{SensorID: "s1", Hostname: "sensor-1"}); err != nil {
		t.Fatalf("InsertSensor: %v", err)
	}
	return &Handler{store: store, wanIP: testWANIP}
}

// insertCase writes a case with a single backing event and returns the case ID.
func insertCase(t *testing.T, h *Handler, caseID, severity, eventType, srcIP, dstIP string, dstPort int, protocol string, when time.Time) {
	t.Helper()
	evtID := caseID + "-evt"
	evt := &db.Event{
		EventID:   evtID,
		Timestamp: when,
		SensorID:  "s1",
		EventType: eventType,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  protocol,
	}
	if err := h.store.InsertEvent(evt); err != nil {
		t.Fatalf("InsertEvent(%s): %v", evtID, err)
	}
	c := &db.Case{
		CaseID:          caseID,
		Title:           "case " + caseID,
		Status:          "open",
		Severity:        severity,
		RelatedEventIDs: db.StringSlice{evtID},
		CreatedAt:       when,
		UpdatedAt:       when,
	}
	if err := h.store.InsertCase(c); err != nil {
		t.Fatalf("InsertCase(%s): %v", caseID, err)
	}
}

func caseIDs(cases []*db.Case) []string {
	out := make([]string, 0, len(cases))
	for _, c := range cases {
		out = append(out, c.CaseID)
	}
	return out
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestParseReviewAllFlagsValid(t *testing.T) {
	o, err := parseReviewAllFlags([]string{
		"--limit", "12", "--since", "72h", "--severity", "red,yellow",
		"--exclude-wan-only", "--dedupe",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.limit != 12 || !o.limitSet {
		t.Errorf("limit: want 12/set got %d/%v", o.limit, o.limitSet)
	}
	if o.since != 72*time.Hour || !o.sinceSet {
		t.Errorf("since: want 72h/set got %v/%v", o.since, o.sinceSet)
	}
	if !o.severities["high"] || !o.severities["medium"] || o.severities["low"] {
		t.Errorf("severities want {high,medium}: got %v", o.severities)
	}
	if !o.excludeWANOnly {
		t.Error("exclude-wan-only should be set")
	}
	if !o.dedupe {
		t.Error("dedupe should be set")
	}
}

func TestParseReviewAllFlagsEqualsForm(t *testing.T) {
	o, err := parseReviewAllFlags([]string{"--limit=5", "--since=7d", "--severity=green"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.limit != 5 {
		t.Errorf("limit: want 5 got %d", o.limit)
	}
	if o.since != 7*24*time.Hour {
		t.Errorf("since: want 168h got %v", o.since)
	}
	if !o.severities["low"] {
		t.Errorf("severity green should map to low: %v", o.severities)
	}
}

func TestParseReviewAllFlagsInvalid(t *testing.T) {
	bad := [][]string{
		{"--limit", "0"},
		{"--limit", "999"},
		{"--limit", "abc"},
		{"--since", "notaduration"},
		{"--severity", "purple"},
		{"--bogus", "x"},
		{"positional"},
	}
	for _, args := range bad {
		if _, err := parseReviewAllFlags(args); err == nil {
			t.Errorf("expected error for args %v", args)
		}
	}
}

func TestNormalizeSeverities(t *testing.T) {
	sevs, err := normalizeSeverities("red, yellow green")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sevs["high"] || !sevs["medium"] || !sevs["low"] {
		t.Errorf("want all three severities: %v", sevs)
	}
	if _, err := normalizeSeverities("mauve"); err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestParseFlexDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"2w":  2 * 7 * 24 * time.Hour,
		"90m": 90 * time.Minute,
	}
	for in, want := range cases {
		got, err := parseFlexDuration(in)
		if err != nil {
			t.Errorf("parseFlexDuration(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseFlexDuration(%q): want %v got %v", in, want, got)
		}
	}
	if _, err := parseFlexDuration("banana"); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestFilterReviewCasesSeverity(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now().UTC()
	insertCase(t, h, "A", "high", "wan_new_connection", "9.9.9.9", testWANIP, 443, "tcp", now)
	insertCase(t, h, "B", "medium", "port_scan", "8.8.8.8", "10.0.0.5", 22, "tcp", now)
	insertCase(t, h, "C", "low", "port_scan", "7.7.7.7", "10.0.0.6", 80, "tcp", now)

	cases, err := h.store.ListCases("", 200)
	if err != nil {
		t.Fatalf("ListCases: %v", err)
	}

	o, _ := parseReviewAllFlags([]string{"--severity", "red"})
	got := caseIDs(h.filterReviewCases(cases, o))
	if len(got) != 1 || !contains(got, "A") {
		t.Errorf("severity=red should keep only A, got %v", got)
	}
}

func TestFilterReviewCasesSince(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now().UTC()
	insertCase(t, h, "recent", "high", "port_scan", "9.9.9.9", "10.0.0.5", 22, "tcp", now.Add(-1*time.Hour))
	insertCase(t, h, "old", "high", "port_scan", "8.8.8.8", "10.0.0.6", 22, "tcp", now.Add(-10*24*time.Hour))

	cases, err := h.store.ListCases("", 200)
	if err != nil {
		t.Fatalf("ListCases: %v", err)
	}

	o, _ := parseReviewAllFlags([]string{"--since", "48h"})
	got := caseIDs(h.filterReviewCases(cases, o))
	if len(got) != 1 || !contains(got, "recent") {
		t.Errorf("since=48h should keep only recent, got %v", got)
	}
}

func TestFilterReviewCasesExcludeWANOnly(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now().UTC()
	// WAN-only: destination is the WAN edge.
	insertCase(t, h, "wan", "high", "wan_new_connection", "9.9.9.9", testWANIP, 443, "tcp", now)
	// Internal: destination is an internal host, not the WAN edge.
	insertCase(t, h, "internal", "high", "port_scan", "8.8.8.8", "10.0.0.5", 22, "tcp", now)

	cases, err := h.store.ListCases("", 200)
	if err != nil {
		t.Fatalf("ListCases: %v", err)
	}

	o, _ := parseReviewAllFlags([]string{"--exclude-wan-only"})
	got := caseIDs(h.filterReviewCases(cases, o))
	if len(got) != 1 || !contains(got, "internal") {
		t.Errorf("exclude-wan-only should keep only internal, got %v", got)
	}
}

func TestFilterReviewCasesDedupeKeepsMostRecent(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now().UTC()
	// Two cases sharing src/dst/port/proto -> dedupe to the most recent one.
	insertCase(t, h, "dup-old", "high", "port_scan", "1.1.1.1", "10.0.0.9", 22, "tcp", now.Add(-5*time.Hour))
	insertCase(t, h, "dup-new", "high", "port_scan", "1.1.1.1", "10.0.0.9", 22, "tcp", now.Add(-1*time.Hour))
	// A distinct case that must survive.
	insertCase(t, h, "other", "high", "port_scan", "2.2.2.2", "10.0.0.9", 80, "tcp", now)

	cases, err := h.store.ListCases("", 200)
	if err != nil {
		t.Fatalf("ListCases: %v", err)
	}

	o, _ := parseReviewAllFlags([]string{"--dedupe"})
	got := caseIDs(h.filterReviewCases(cases, o))
	if len(got) != 2 {
		t.Fatalf("dedupe should collapse to 2 cases, got %v", got)
	}
	if !contains(got, "dup-new") {
		t.Errorf("dedupe should keep the most recent (dup-new), got %v", got)
	}
	if contains(got, "dup-old") {
		t.Errorf("dedupe should drop the older duplicate (dup-old), got %v", got)
	}
	if !contains(got, "other") {
		t.Errorf("distinct case should survive, got %v", got)
	}
}
