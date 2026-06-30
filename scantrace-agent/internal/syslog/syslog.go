// Package syslog provides a UDP syslog listener that ingests iptables kernel
// DROP lines forwarded from the gateway router and turns them into ScanTrace
// events and cases.
//
// Expected syslog line format (router sends RFC 3164 with kernel payload):
//
//	<134>Jun 28 15:28:29 router kernel: DROP IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=192.168.50.80 ... PROTO=TCP SPT=54321 DPT=22 ...
//
// The listener groups events by (src_ip, dst_port) into cases and calls
// Alerter.PostCaseAlert so a Slack message fires for every new case.
package syslog

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

// Alerter is the subset of handler.Handler that the syslog package needs.
// Using an interface keeps the import graph acyclic.
type Alerter interface {
	PostCaseAlert(c *db.Case)
}

// field extraction regexes — compiled once at init.
var (
	reIN    = regexp.MustCompile(`\bIN=(\S*)`)
	reSRC   = regexp.MustCompile(`\bSRC=(\S+)`)
	reDST   = regexp.MustCompile(`\bDST=(\S+)`)
	reSPT   = regexp.MustCompile(`\bSPT=(\d+)`)
	reDPT   = regexp.MustCompile(`\bDPT=(\d+)`)
	rePROTO = regexp.MustCompile(`\bPROTO=(\S+)`)
)

// parsedLine holds the fields extracted from one syslog message.
type parsedLine struct {
	iface   string
	srcIP   string
	dstIP   string
	srcPort int
	dstPort int
	proto   string
	rawLine string
}

// caseKey groups events into a single case: same external source + same targeted port.
type caseKey struct {
	srcIP   string
	dstPort int
}

// syslogSensorID is a stable UUID used for the syslog sensor row.
// Derived from the well-known namespace + "syslog_udp" so it never
// conflicts with CLI-registered sensors.
const syslogSensorID = "00000000-5359-4c4f-4700-000000000001"

// ensureSyslogSensor upserts the syslog sensor row so every event written by
// this package satisfies the events.sensor_id FOREIGN KEY constraint.
func ensureSyslogSensor(store *db.DB) error {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "router-syslog"
	}
	s := &db.Sensor{
		SensorID:      syslogSensorID,
		Hostname:      hostname,
		Platform:      "linux",
		Role:          "gateway",
		CollectorType: "syslog_udp",
		Version:       "1.0.0",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	return store.InsertSensor(s)
}

// Listen binds a UDP socket on addr (e.g. ":5140") and starts ingesting
// syslog lines. It blocks until the socket fails.
//
//   - store   — ScanTrace SQLite DB
//   - alerter — handler.Handler (or any Alerter); PostCaseAlert is called
//     whenever a new case is opened or an existing case gains events.
func Listen(addr string, store *db.DB, alerter Alerter) error {
	// Ensure the syslog sensor row exists before any event is written.
	if err := ensureSyslogSensor(store); err != nil {
		log.Printf("[syslog] WARNING: could not upsert syslog sensor: %v", err)
	}

	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("syslog.Listen: bind %s: %w", addr, err)
	}
	defer conn.Close()
	log.Printf("[syslog] listening on UDP %s", addr)

	// In-memory case index: caseKey → caseID.  Avoids a DB round-trip on every
	// packet while still persisting to SQLite for the Slack commands.
	caseIndex := make(map[caseKey]string)

	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("[syslog] read error: %v", err)
			continue
		}
		line := strings.TrimSpace(string(buf[:n]))
		if line == "" {
			continue
		}

		// Only handle iptables DROP lines.
		if !strings.Contains(line, "DROP") {
			continue
		}

		p, ok := parse(line)
		if !ok {
			continue
		}

		if err := ingest(p, store, alerter, caseIndex); err != nil {
			log.Printf("[syslog] ingest error: %v", err)
		}
	}
}

// parse extracts fields from an iptables syslog line.
// Returns (result, true) on success, (zero, false) if required fields are absent
// or the packet is broadcast/malformed noise.
func parse(line string) (parsedLine, bool) {
	extract := func(re *regexp.Regexp) string {
		m := re.FindStringSubmatch(line)
		if len(m) < 2 {
			return ""
		}
		return m[1]
	}

	srcIP := extract(reSRC)
	dstIP := extract(reDST)

	// Discard broadcast, unspecified, and malformed addresses.
	if srcIP == "" || srcIP == "0.0.0.0" {
		return parsedLine{}, false
	}
	if dstIP == "" || dstIP == "0.0.0.0" {
		return parsedLine{}, false
	}

	sptStr := extract(reSPT)
	dptStr := extract(reDPT)

	srcPort, _ := strconv.Atoi(sptStr)
	dstPort, _ := strconv.Atoi(dptStr)

	return parsedLine{
		iface:   extract(reIN),
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
		proto:   strings.ToUpper(extract(rePROTO)),
		rawLine: line,
	}, true
}

// ingest writes one event to the DB and creates/updates the parent case.
// Returns nil without writing anything if classifySeverity marks the port
// as noise (empty string return).
func ingest(p parsedLine, store *db.DB, alerter Alerter, caseIndex map[caseKey]string) error {
	// Discard ephemeral-port backscatter before touching the DB.
	if classifySeverity(p.dstPort) == "" {
		return nil
	}

	now := time.Now().UTC()

	// ── 1. Classify event type based on interface ──────────────────────────
	// wan_new_connection  → packet hit WAN interface, no port-forward matched
	// wan_forward         → packet was forwarded toward an internal host
	evtType := "wan_new_connection"
	if p.iface != "" && !strings.HasPrefix(p.iface, "eth") && !strings.HasPrefix(p.iface, "wan") {
		evtType = "wan_forward"
	}

	// ── 2. Store the raw event ─────────────────────────────────────────────
	evt := &db.Event{
		EventID:      uuid.NewString(),
		Timestamp:    now,
		FirstSeen:    now,
		LastSeen:     now,
		SensorID:     syslogSensorID,
		SourceType:   "syslog_udp",
		DetectorType: "iptables_drop",
		EventType:    evtType,
		SrcIP:        p.srcIP,
		SrcPort:      p.srcPort,
		DstIP:        p.dstIP,
		DstPort:      p.dstPort,
		Protocol:     p.proto,
		Transport:    p.proto,
		Direction:    "inbound",
		RawRef:       p.rawLine,
		Confidence:   0.8,
	}
	if err := store.InsertEvent(evt); err != nil {
		return fmt.Errorf("InsertEvent: %w", err)
	}

	// ── 3. Find or create parent case ──────────────────────────────────────
	key := caseKey{srcIP: p.srcIP, dstPort: p.dstPort}
	caseID, exists := caseIndex[key]

	if !exists {
		caseID = uuid.NewString()
		caseIndex[key] = caseID

		title := fmt.Sprintf("Inbound DROP: %s → port %d/%s", p.srcIP, p.dstPort, p.proto)
		if p.dstPort == 0 {
			title = fmt.Sprintf("Inbound DROP: %s (%s)", p.srcIP, p.proto)
		}

		c := &db.Case{
			CaseID:          caseID,
			Title:           title,
			Summary:         fmt.Sprintf("Syslog-ingested DROP event from %s targeting port %d.", p.srcIP, p.dstPort),
			Status:          "open",
			Severity:        classifySeverity(p.dstPort),
			Confidence:      0.8,
			RelatedEventIDs: db.StringSlice{evt.EventID},
		}
		if err := store.InsertCase(c); err != nil {
			return fmt.Errorf("InsertCase: %w", err)
		}

		log.Printf("[syslog] new case %s — %s", caseID[:8], title)
		go alerter.PostCaseAlert(c)
		return nil
	}

	// ── 4. Append event to existing case ───────────────────────────────────
	c, err := store.GetCase(caseID)
	if err != nil || c == nil {
		// Race: case was deleted externally; rebuild it.
		delete(caseIndex, key)
		return ingest(p, store, alerter, caseIndex)
	}

	c.RelatedEventIDs = append(c.RelatedEventIDs, evt.EventID)
	if err := store.UpdateCase(c); err != nil {
		return fmt.Errorf("UpdateCase: %w", err)
	}

	// Alert on significant growth milestones (5, 10, 25, 50, 100 …)
	n := len(c.RelatedEventIDs)
	if n == 5 || n == 10 || (n > 0 && n%25 == 0) {
		log.Printf("[syslog] case %s milestone: %d events", caseID[:8], n)
		go alerter.PostCaseAlert(c)
	}

	return nil
}

// classifySeverity maps destination port to a severity label.
//
// Returns "" for ephemeral/high ports (>= 32768) — these are almost always
// backscatter from spoofed SYNs or return traffic to closed ports and are
// not worth creating cases for.
func classifySeverity(dport int) string {
	// Ephemeral range — backscatter noise, discard silently.
	if dport >= 32768 {
		return ""
	}
	switch dport {
	case 22, 23, 3389, 5900, 5901, 4444, 8080, 8443, 9001:
		return "high"
	case 21, 25, 53, 110, 143, 443, 445, 3306, 5432, 6379, 27017:
		return "medium"
	default:
		return "low"
	}
}
