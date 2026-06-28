// ScanTrace CLI — Dead Reckoning Edition
//
// Usage:
//   scantrace ingest    --file <path> --adapter suricata|syslog|asus-syslog
//   scantrace correlate
//   scantrace cases     [--severity high|medium|low]
//   scantrace report    --case <case-id> [--format markdown|json|slack]
//   scantrace serve     [--interval 5m] [--syslog-port 5140]
//   scantrace flush     [--source testdata]
//
// Env:
//   SCANTRACE_DB         SQLite path (default: ./scantrace.db)
//   SCANTRACE_SENSOR_ID  sensor UUID (auto-created if unset)
//   SCANTRACE_ASUS_STATE path to Asus sensor-id state file (default: .asus-sensor-id)
//   SCANTRACE_SYSLOG_PORT UDP port to receive router syslog (default: 5140, use 514 as root)
//   IPINFO_TOKEN         ipinfo.io token (optional)
//   SLACK_WEBHOOK_URL    Slack Incoming Webhook URL (optional — enables alert posting)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/collector"
	"github.com/Risen24x7/scantrace/internal/correlator"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/internal/enricher"
	"github.com/Risen24x7/scantrace/internal/slack"
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
	slackWebhook := envOrDefault("SLACK_WEBHOOK_URL", "")

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
		cmdCorrelate(store, slackWebhook)
	case "cases":
		cmdCases(store)
	case "report":
		cmdReport(store)
	case "serve":
		cmdServe(store, sensorID, ipinfoToken, slackWebhook)
	case "flush":
		cmdFlush(store)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// ingest
// ---------------------------------------------------------------------------

func cmdIngest(store *db.DB, sensorID, ipinfoToken string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	filePath := fs.String("file", "", "path to log file (use - for stdin)")
	adapterName := fs.String("adapter", "suricata", "suricata | syslog | asus-syslog")
	_ = fs.Parse(os.Args[2:])

	if *adapterName == "asus-syslog" {
		cmdIngestAsus(store, *filePath)
		return
	}

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

func cmdIngestAsus(store *db.DB, filePath string) {
	statePath := envOrDefault("SCANTRACE_ASUS_STATE", ".asus-sensor-id")

	asusSensorID, err := collector.RegisterAsusSensor(store, statePath)
	if err != nil {
		log.Fatalf("[asus-syslog] sensor registration failed: %v", err)
	}
	log.Printf("[asus-syslog] using sensor_id=%s", asusSensorID)

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

// ---------------------------------------------------------------------------
// correlate
// ---------------------------------------------------------------------------

func cmdCorrelate(store *db.DB, slackWebhook string) {
	cfg := correlator.DefaultConfig()
	corr := correlator.New(store, cfg)
	cases, err := corr.Run()
	if err != nil {
		log.Fatalf("correlate error: %v", err)
	}
	if len(cases) == 0 {
		fmt.Println("[correlate] no new cases (threshold not reached or all deduped)")
		return
	}
	fmt.Printf("[correlate] opened %d case(s)\n", len(cases))
	for _, c := range cases {
		fmt.Printf("  • [%s] %s  severity=%s  confidence=%.0f%%\n",
			c.CaseID[:8], c.Title, c.Severity, c.Confidence*100)
	}
	postAlerts(store, cases, slackWebhook)
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// serve — daemon loop with live UDP syslog receiver
// ---------------------------------------------------------------------------

func cmdServe(store *db.DB, sensorID, ipinfoToken, slackWebhook string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	intervalStr := fs.String("interval", "5m", "correlate interval (e.g. 1m, 5m, 15m)")
	syslogPort := fs.Int("syslog-port", syslogPortFromEnv(), "UDP port to receive router syslog (514 requires root, default 5140)")
	_ = fs.Parse(os.Args[2:])

	interval, err := time.ParseDuration(*intervalStr)
	if err != nil || interval < 10*time.Second {
		log.Fatalf("invalid --interval %q (min 10s)", *intervalStr)
	}

	slackClient := slack.New(slackWebhook)
	if slackClient.Enabled() {
		log.Printf("[serve] Slack alerts enabled")
	} else {
		log.Printf("[serve] Slack alerts disabled (set SLACK_WEBHOOK_URL to enable)")
	}
	log.Printf("[serve] starting — correlate interval=%s", interval)

	statePath := envOrDefault("SCANTRACE_ASUS_STATE", ".asus-sensor-id")
	asusSensorID, err := collector.RegisterAsusSensor(store, statePath)
	if err != nil {
		log.Printf("[serve] asus sensor registration failed: %v — continuing without syslog listener", err)
	} else {
		adapter := collector.NewAsusAdapter(asusSensorID)
		syslogSrv := collector.NewSyslogServer(*syslogPort, store, adapter)
		go func() {
			if err := syslogSrv.Listen(); err != nil {
				log.Printf("[syslog_server] fatal: %v", err)
				log.Printf("[syslog_server] TIP: run with sudo, or set SCANTRACE_SYSLOG_PORT=5140 and")
				log.Printf("[syslog_server] on your router set syslog port to 5140 instead of 514")
			}
		}()
		log.Printf("[serve] UDP syslog listener started on :%d", *syslogPort)
		log.Printf("[serve] point your router's syslog at %s:%d", getLocalIP(), *syslogPort)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	runCycle(store, slackWebhook)
	for range ticker.C {
		runCycle(store, slackWebhook)
	}
}

func runCycle(store *db.DB, slackWebhook string) {
	cfg := correlator.DefaultConfig()
	corr := correlator.New(store, cfg)
	cases, err := corr.Run()
	if err != nil {
		log.Printf("[serve] correlate error: %v", err)
		return
	}
	if len(cases) == 0 {
		log.Printf("[serve] cycle complete — no new cases")
		return
	}
	log.Printf("[serve] %d new case(s)", len(cases))
	postAlerts(store, cases, slackWebhook)
}

// ---------------------------------------------------------------------------
// flush
// ---------------------------------------------------------------------------

func cmdFlush(store *db.DB) {
	fs := flag.NewFlagSet("flush", flag.ExitOnError)
	source := fs.String("source", "testdata", "testdata = wipe RFC5737/test events and orphaned cases")
	_ = fs.Parse(os.Args[2:])

	switch *source {
	case "testdata":
		testPrefixes := []string{"192.0.2.", "198.51.100.", "203.0.113."}
		events, err := store.ListEvents(2000)
		if err != nil {
			log.Fatalf("flush: list events: %v", err)
		}
		evicted := 0
		for _, e := range events {
			for _, pfx := range testPrefixes {
				if strings.HasPrefix(e.SrcIP, pfx) || strings.HasPrefix(e.DstIP, pfx) {
					if err := store.DeleteEvent(e.EventID); err != nil {
						log.Printf("flush: delete event %s: %v", e.EventID[:8], err)
					} else {
						evicted++
					}
					break
				}
			}
		}
		cases, _ := store.ListCases("", 500)
		casesEvicted := 0
		for _, c := range cases {
			for _, pfx := range testPrefixes {
				if strings.Contains(c.Title, pfx[:len(pfx)-1]) || strings.Contains(c.Summary, pfx) {
					if err := store.DeleteCase(c.CaseID); err == nil {
						casesEvicted++
					}
					break
				}
			}
		}
		fmt.Printf("[flush] removed %d test events and %d test cases\n", evicted, casesEvicted)
	default:
		log.Fatalf("unknown flush source %q (valid: testdata)", *source)
	}
}

// ---------------------------------------------------------------------------
// Slack alert helper
// ---------------------------------------------------------------------------

func postAlerts(store *db.DB, cases []*db.Case, webhookURL string) {
	if webhookURL == "" {
		return
	}
	client := slack.New(webhookURL)
	builder := casebuilder.New(store)
	for _, cas := range cases {
		if cas.Severity == "low" {
			continue
		}
		report, err := builder.BuildReport(cas.CaseID)
		if err != nil {
			log.Printf("[alerts] BuildReport %s: %v", cas.CaseID[:8], err)
			continue
		}
		if err := client.PostBlock(report.SlackBlock()); err != nil {
			log.Printf("[alerts] Slack post failed for %s: %v", cas.CaseID[:8], err)
		} else {
			log.Printf("[alerts] posted case %s (%s) to Slack", cas.CaseID[:8], cas.Severity)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

func syslogPortFromEnv() int {
	if v := os.Getenv("SCANTRACE_SYSLOG_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			return p
		}
	}
	return 5140
}

func getLocalIP() string {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 80})
	if err != nil {
		return "<this-host>"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func printUsage() {
	fmt.Fprint(os.Stderr, `ScanTrace — Dead Reckoning Edition

Commands:
  ingest     --file <path> --adapter suricata|syslog|asus-syslog
  correlate
  cases      [--severity high|medium|low]
  report     --case <case-id> [--format markdown|json|slack]
  serve      [--interval 5m] [--syslog-port 5140]
  flush      [--source testdata]

Env:
  SCANTRACE_DB          SQLite path             (default: scantrace.db)
  SCANTRACE_SENSOR_ID   sensor UUID             (auto-created if unset)
  SCANTRACE_ASUS_STATE  Asus sensor-id file     (default: .asus-sensor-id)
  SCANTRACE_SYSLOG_PORT UDP syslog listen port  (default: 5140, use 514 as root)
  IPINFO_TOKEN          ipinfo.io token         (optional)
  SLACK_WEBHOOK_URL     Slack Incoming Webhook  (optional)
`)
}
