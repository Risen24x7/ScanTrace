// ScanTrace CLI — Dead Reckoning Edition
//
// Usage:
//   scantrace ingest    --file <path> --adapter suricata|syslog|asus-syslog
//   scantrace correlate
//   scantrace cases     [--severity high|medium|low]
//   scantrace report    --case <case-id> [--format markdown|json|slack]
//
// Env:
//   SCANTRACE_DB         SQLite path (default: ./scantrace.db)
//   SCANTRACE_SENSOR_ID  sensor UUID (auto-created if unset)
//   SCANTRACE_ASUS_STATE path to Asus sensor-id state file (default: .asus-sensor-id)
//   IPINFO_TOKEN         ipinfo.io token (optional)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/collector"
	"github.com/Risen24x7/scantrace/internal/correlator"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/internal/enricher"
	"github.com/google/uuid"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	dbPath := envOrDefault("SCANTRACE_DB", "scantrace.db")
	sensorID := envOrDefault("SCANTRACE_SENSOR_ID", "")
	ipinfoToken := envOrDefault("IPINFO_TOKEN", "")

	store, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	if sensorID == "" {
		sensorID = ensureSensor(store)
	}

	switch os.Args[1] {
	case "ingest":
		cmdIngest(store, sensorID, ipinfoToken)
	case "correlate":
		cmdCorrelate(store)
	case "cases":
		cmdCases(store)
	case "report":
		cmdReport(store)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func cmdIngest(store *db.DB, sensorID, ipinfoToken string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	filePath := fs.String("file", "", "path to log file (use - for stdin)")
	adapterName := fs.String("adapter", "suricata", "suricata | syslog | asus-syslog")
	_ = fs.Parse(os.Args[2:])

	// asus-syslog needs its own sensor registration before the shared
	// Collector is constructed, because the sensor_id must exist in the DB
	// before any event referencing it can be inserted (FK constraint).
	if *adapterName == "asus-syslog" {
		cmdIngestAsus(store, *filePath)
		return
	}

	// --- shared Collector path for suricata / syslog ---
	var adapter collector.Adapter
	switch *adapterName {
	case "suricata":
		adapter = &collector.SuricataAdapter{}
	case "syslog":
		adapter = &collector.SyslogAdapter{}
	default:
		log.Fatalf("unknown adapter: %s (valid: suricata, syslog, asus-syslog)", *adapterName)
	}

	col := collector.New(store, sensorID)
	if *filePath == "" || *filePath == "-" {
		fmt.Fprintln(os.Stderr, "[ingest] reading from stdin (Ctrl+D to stop)...")
		col.TailFile(os.Stdin, adapter)
	} else {
		if err := col.IngestFile(*filePath, adapter); err != nil {
			log.Fatalf("ingest error: %v", err)
		}
	}

	enrich := enricher.New(store, enricher.WithToken(ipinfoToken))
	events, _ := store.ListEvents(500)
	result := enrich.EnrichEvents(events)
	fmt.Printf("[ingest] enriched %d unique source IPs\n", len(result))
}

// cmdIngestAsus handles the asus-syslog adapter path.
// It registers (or reuses) the Asus sensor, then drives the shared
// Collector.TailFile loop using AsusAdapter as the Adapter.
func cmdIngestAsus(store *db.DB, filePath string) {
	statePath := envOrDefault("SCANTRACE_ASUS_STATE", ".asus-sensor-id")

	asusSensorID, err := collector.RegisterAsusSensor(store, statePath)
	if err != nil {
		log.Fatalf("[asus-syslog] sensor registration failed: %v", err)
	}
	log.Printf("[asus-syslog] using sensor_id=%s", asusSensorID)

	// AsusAdapter now implements collector.Adapter via Parse().
	// The shared Collector handles scanning and DB insertion.
	adapter := collector.NewAsusAdapter(asusSensorID)
	col := collector.New(store, asusSensorID)

	if filePath == "" || filePath == "-" {
		fmt.Fprintln(os.Stderr, "[asus-syslog] reading from stdin — pipe with: sudo tail -F /var/log/asus-router.log")
		col.TailFile(os.Stdin, adapter)
	} else {
		if err := col.IngestFile(filePath, adapter); err != nil {
			log.Fatalf("[asus-syslog] ingest error: %v", err)
		}
	}

	fmt.Println("[asus-syslog] done — run: sqlite3 scantrace.db \"SELECT event_type, src_ip, dst_ip, dst_port FROM events WHERE source_type='asus_syslog' LIMIT 20;\"")
}

func cmdCorrelate(store *db.DB) {
	cfg := correlator.DefaultConfig()
	corr := correlator.New(store, cfg)
	cases, err := corr.Run()
	if err != nil {
		log.Fatalf("correlate error: %v", err)
	}
	if len(cases) == 0 {
		fmt.Println("[correlate] no new cases (threshold not reached)")
		return
	}
	fmt.Printf("[correlate] opened %d case(s)\n", len(cases))
	for _, c := range cases {
		fmt.Printf("  \u2022 [%s] %s  severity=%s  confidence=%.0f%%\n",
			c.CaseID[:8], c.Title, c.Severity, c.Confidence*100)
	}
}

func cmdCases(store *db.DB) {
	fs := flag.NewFlagSet("cases", flag.ExitOnError)
	severity := fs.String("severity", "", "high|medium|low")
	_ = fs.Parse(os.Args[2:])

	cases, err := store.ListCases(*severity, 50)
	if err != nil {
		log.Fatalf("list cases: %v", err)
	}
	if len(cases) == 0 {
		fmt.Println("No cases found.")
		return
	}
	fmt.Printf("%-38s  %-8s  %-8s  %-6s  %s\n", "CASE ID", "STATUS", "SEVERITY", "CONF", "TITLE")
	fmt.Println(strings.Repeat("-", 100))
	for _, c := range cases {
		fmt.Printf("%-38s  %-8s  %-8s  %5.0f%%  %s\n",
			c.CaseID, c.Status, c.Severity, c.Confidence*100, c.Title)
	}
}

func cmdReport(store *db.DB) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	caseID := fs.String("case", "", "case ID")
	format := fs.String("format", "markdown", "markdown|json|slack")
	_ = fs.Parse(os.Args[2:])

	if *caseID == "" {
		log.Fatal("--case is required")
	}

	builder := casebuilder.New(store)
	report, err := builder.BuildReport(*caseID)
	if err != nil {
		log.Fatalf("report error: %v", err)
	}

	switch *format {
	case "json":
		out, _ := report.ToJSON()
		fmt.Println(string(out))
	case "slack":
		out, _ := json.MarshalIndent(report.SlackBlock(), "", "  ")
		fmt.Println(string(out))
	default:
		fmt.Println(report.Markdown)
	}
}

func ensureSensor(store *db.DB) string {
	id := uuid.New().String()
	h, _ := os.Hostname()
	sensor := &db.Sensor{
		SensorID: id, Hostname: h, Platform: "linux",
		Role: "primary", CollectorType: "cli", Version: "0.1.0",
	}
	if err := store.InsertSensor(sensor); err != nil {
		log.Printf("[main] sensor registration error: %v", err)
	}
	log.Printf("[main] registered sensor id=%s hostname=%s", id, h)
	return id
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func printUsage() {
	fmt.Fprint(os.Stderr, `ScanTrace — Dead Reckoning Edition

Commands:
  ingest     --file <path> --adapter suricata|syslog|asus-syslog
  correlate
  cases      [--severity high|medium|low]
  report     --case <case-id> [--format markdown|json|slack]

Env:
  SCANTRACE_DB         SQLite path            (default: scantrace.db)
  SCANTRACE_SENSOR_ID  sensor UUID            (auto-created if unset)
  SCANTRACE_ASUS_STATE Asus sensor-id file    (default: .asus-sensor-id)
  IPINFO_TOKEN         ipinfo.io token        (optional)
`)
}
