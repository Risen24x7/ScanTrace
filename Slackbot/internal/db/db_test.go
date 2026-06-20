package db_test

import (
	"os"
	"testing"
	"time"

	"github.com/your-org/scantrace/internal/db"
)

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	f, err := os.CreateTemp("", "scantrace-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	d, err := db.Open(f.Name())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestMigrations(t *testing.T) {
	d := openTestDB(t)
	v, err := d.SchemaVersionApplied()
	if err != nil {
		t.Fatal(err)
	}
	if v != db.SchemaVersion {
		t.Fatalf("expected schema version %d, got %d", db.SchemaVersion, v)
	}
}

func TestSensorCRUD(t *testing.T) {
	d := openTestDB(t)

	s := &db.Sensor{
		SensorID:      "sensor-uuid-0001",
		Hostname:      "fw-edge-01",
		Platform:      "linux",
		Role:          "firewall",
		PublicIP:      "203.0.113.1",
		NetworkZone:   "dmz",
		LocationTag:   "eugene-or",
		CollectorType: "suricata_eve",
		Version:       "0.1.0",
	}

	if err := d.InsertSensor(s); err != nil {
		t.Fatalf("InsertSensor: %v", err)
	}

	got, err := d.GetSensor(s.SensorID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected sensor, got nil")
	}
	if got.Hostname != s.Hostname {
		t.Errorf("hostname mismatch: want %q got %q", s.Hostname, got.Hostname)
	}

	sensors, err := d.ListSensors()
	if err != nil {
		t.Fatal(err)
	}
	if len(sensors) != 1 {
		t.Fatalf("expected 1 sensor, got %d", len(sensors))
	}

	if err := d.DeleteSensor(s.SensorID); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetSensor(s.SensorID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestEventCRUD(t *testing.T) {
	d := openTestDB(t)

	// Sensor must exist first (FK constraint).
	s := &db.Sensor{SensorID: "sen-001", Hostname: "ids-01", Platform: "linux",
		CollectorType: "suricata_eve"}
	if err := d.InsertSensor(s); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	ev := &db.Event{
		EventID:      "evt-uuid-0001",
		Timestamp:    now,
		FirstSeen:    now,
		LastSeen:     now,
		SensorID:     "sen-001",
		SourceType:   "suricata_eve",
		DetectorType: "suricata",
		EventType:    "alert",
		SrcIP:        "185.220.101.45",
		SrcPort:      54321,
		DstIP:        "203.0.113.1",
		DstPort:      22,
		Protocol:     "TCP",
		Transport:    "tcp",
		Direction:    "inbound",
		RawRef:       `{"raw":"json"}`,
		Confidence:   0.9,
		Tags:         db.StringSlice{"port_scan", "ssh"},
	}

	if err := d.InsertEvent(ev); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}

	got, err := d.GetEvent(ev.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	if got.SrcIP != "185.220.101.45" {
		t.Errorf("src_ip mismatch: %q", got.SrcIP)
	}
	if len(got.Tags) != 2 {
		t.Errorf("tags: want 2, got %d", len(got.Tags))
	}

	evts, err := d.ListEventsBySrcIP("185.220.101.45", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 1 {
		t.Fatalf("want 1 event by src_ip, got %d", len(evts))
	}
}

func TestEntityCRUD(t *testing.T) {
	d := openTestDB(t)

	en := &db.Entity{
		EntityID:         "ent-uuid-0001",
		EntityType:       "ip",
		IP:               "185.220.101.45",
		ASN:              "AS4134",
		ASName:           "CHINANET-BACKBONE",
		Provider:         "China Telecom",
		RDNS:             "45.101.220.185.broad.gz.gd.dynamic.163data.com.cn",
		AbuseContact:     "abuse@chinatelecom.cn",
		GeoCountry:       "CN",
		ReputationLabels: db.StringSlice{},
		LastEnriched:     time.Now().UTC(),
	}

	if err := d.UpsertEntity(en); err != nil {
		t.Fatalf("UpsertEntity: %v", err)
	}

	got, err := d.GetEntityByIP("185.220.101.45")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("entity not found")
	}
	if got.ASN != "AS4134" {
		t.Errorf("ASN mismatch: %q", got.ASN)
	}

	// Upsert update path
	en.Provider = "China Telecom UPDATED"
	if err := d.UpsertEntity(en); err != nil {
		t.Fatal(err)
	}
	got2, _ := d.GetEntityByIP("185.220.101.45")
	if got2.Provider != "China Telecom UPDATED" {
		t.Error("upsert update did not persist")
	}
}

func TestCaseCRUD(t *testing.T) {
	d := openTestDB(t)

	c := &db.Case{
		CaseID:          "case-uuid-0001",
		Title:           "Repeated SSH scan — AS4134",
		Summary:         "47 inbound SSH probes from China Telecom over 6h window.",
		Status:          "open",
		Severity:        "high",
		Confidence:      0.95,
		RelatedEventIDs: db.StringSlice{"evt-uuid-0001"},
		RelatedEntityIDs: db.StringSlice{"ent-uuid-0001"},
		Timeline:        "| 2026-06-20T00:01:00Z | 22 | TCP | alert |",
		Artifacts:       `["case_case-uuid-0001.md","case_case-uuid-0001.json"]`,
		AnalystNotes:    "Likely automated botnet sweep.",
	}

	if err := d.InsertCase(c); err != nil {
		t.Fatalf("InsertCase: %v", err)
	}

	got, err := d.GetCase(c.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("case not found")
	}
	if got.Severity != "high" {
		t.Errorf("severity mismatch: %q", got.Severity)
	}

	got.AnalystNotes = "Confirmed botnet — AS4134 sweep."
	if err := d.UpdateCase(got); err != nil {
		t.Fatal(err)
	}

	got2, _ := d.GetCase(c.CaseID)
	if got2.AnalystNotes != "Confirmed botnet — AS4134 sweep." {
		t.Error("UpdateCase did not persist analyst_notes")
	}

	cases, err := d.ListCases("high", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("ListCases(high): want 1, got %d", len(cases))
	}

	if err := d.DeleteCase(c.CaseID); err != nil {
		t.Fatal(err)
	}
	got3, _ := d.GetCase(c.CaseID)
	if got3 != nil {
		t.Fatal("expected nil after delete")
	}
}
