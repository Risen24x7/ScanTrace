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
//
// Roll-up architecture (burst suppression)
// -----------------------------------------
// HIGH severity cases (port 22/23/3389 etc.) are posted to Slack immediately.
// LOW/MEDIUM cases are held in a burst buffer for burstWindow seconds. When
// the buffer is flushed:
//   - 1 case buffered → emit as a normal single alert.
//   - 2+ cases, count >= burstThreshold → merge ALL buffered cases into one
//     ScanBurst case in the DB (individual stub cases are deleted to keep the
//     DB clean) then PostCaseAlert once for the rolled-up case.
//   - 2+ cases, count < burstThreshold → emit each individually.
//
// This preserves the "case-first" invariant: the DB always has exactly one
// case per alertable outcome, and Slack is triggered once per case.
package syslog

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

// Alerter is the subset of handler.Handler that the syslog package needs.
// Using an interface keeps the import graph acyclic.
type Alerter interface {
	PostCaseAlert(c *db.Case)
}

// ---------------------------------------------------------------------------
// Burst-suppression constants
// ---------------------------------------------------------------------------

const (
	// burstWindow is the hold time for LOW/MEDIUM cases before the buffer flushes.
	burstWindow = 90 * time.Second

	// burstThreshold: if >= this many cases accumulate in one window, merge them
	// into a single ScanBurst case instead of alerting individually.
	burstThreshold = 3

	// maxConcurrentAlerts limits the number of concurrent goroutines posting alerts
	// to prevent resource exhaustion if the alerter (Slack) is slow.
	maxConcurrentAlerts = 10
)

// ---------------------------------------------------------------------------
// Field extraction regexes — compiled once.
// ---------------------------------------------------------------------------

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

// caseKey groups events into a single case.
// srcSubnet is the /24 prefix of the source IP so that distributed subnet
// sweeps (e.g. 85.217.149.x) collapse into one case instead of one per IP.
type caseKey struct {
	srcSubnet string // first three octets, e.g. "85.217.149"
	dstPort   int
}

// subnetPrefix returns the /24 prefix of an IPv4 address string.
// e.g. "85.217.149.39" → "85.217.149"
func subnetPrefix(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return strings.Join(parts[:3], ".")
	}
	return ip
}

// syslogSensorID is a stable UUID used for the syslog sensor row.
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

// postAlertWithSem acquires the semaphore, launches a goroutine to post the alert,
// and releases the semaphore when done. This bounds concurrent alert goroutines.
func postAlertWithSem(alertSem chan struct{}, alerter Alerter, c *db.Case) {
	go func() {
		alertSem <- struct{}{}
		defer func() { <-alertSem }()
		alerter.PostCaseAlert(c)
	}()
}

// ---------------------------------------------------------------------------
// Burst buffer
// ---------------------------------------------------------------------------

// bufferedCase is a case held in the burst buffer pending flush.
type bufferedCase struct {
	c        *db.Case
	proto    string // protocol string for display ("TCP"/"UDP")
	srcIPs   []string // distinct source IPs seen in this case's events so far
}

// burstBuffer holds LOW/MEDIUM cases for up to burstWindow before deciding
// whether to emit them individually or merge them into a ScanBurst case.
type burstBuffer struct {
	mu    sync.Mutex
	items []*bufferedCase
}

func (b *burstBuffer) add(bc *bufferedCase) {
	b.mu.Lock()
	b.items = append(b.items, bc)
	b.mu.Unlock()
}

// drain atomically removes and returns all buffered cases.
func (b *burstBuffer) drain() []*bufferedCase {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.items
	b.items = nil
	return out
}

// ---------------------------------------------------------------------------
// Listen — main entry point
// ---------------------------------------------------------------------------

// Listen binds a UDP socket on addr (e.g. ":5140") and starts ingesting
// syslog lines. It blocks until the socket fails.
func Listen(addr string, store *db.DB, alerter Alerter) error {
	if err := ensureSyslogSensor(store); err != nil {
		log.Printf("[syslog] WARNING: could not upsert syslog sensor: %v", err)
	}

	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("syslog.Listen: bind %s: %w", addr, err)
	}
	defer conn.Close()
	log.Printf("[syslog] listening on UDP %s", addr)

	caseIndex := make(map[caseKey]string)
	buf := &burstBuffer{}

	// alertSem limits concurrent alert goroutines to prevent resource exhaustion
	alertSem := make(chan struct{}, maxConcurrentAlerts)

	// Flush ticker — runs every burstWindow, decides merge vs. individual emit.
	ticker := time.NewTicker(burstWindow)
	go func() {
		for range ticker.C {
			flushBurst(store, alerter, buf, alertSem)
		}
	}()
	defer ticker.Stop()

	pkt := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(pkt)
		if err != nil {
			log.Printf("[syslog] read error: %v", err)
			continue
		}
		// Warn if packet is close to buffer size (possible truncation)
		if n > 65520 {
			log.Printf("[syslog] WARNING: packet size %d bytes near buffer limit, possible truncation", n)
		}
		line := strings.TrimSpace(string(pkt[:n]))
		if line == "" {
			continue
		}
		if !strings.Contains(line, "DROP") {
			continue
		}

		p, ok := parse(line)
		if !ok {
			continue
		}

		if err := ingest(p, store, alerter, caseIndex, buf, alertSem); err != nil {
			log.Printf("[syslog] ingest error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------

// parse extracts fields from an iptables syslog line.
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

	if srcIP == "" || srcIP == "0.0.0.0" {
		return parsedLine{}, false
	}
	if dstIP == "" || dstIP == "0.0.0.0" {
		return parsedLine{}, false
	}

	srcPort, _ := strconv.Atoi(extract(reSPT))
	dstPort, _ := strconv.Atoi(extract(reDPT))

	// GRE (proto 47), ICMP encap, and other non-TCP/UDP protocols produce no
	// SPT/DPT fields — both parse as 0. Discard them.
	if srcPort == 0 && dstPort == 0 {
		return parsedLine{}, false
	}

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

// ---------------------------------------------------------------------------
// ingest
// ---------------------------------------------------------------------------

// ingest writes one event to the DB and creates/updates the parent case.
// HIGH severity cases bypass the burst buffer and alert immediately.
// LOW/MEDIUM cases are queued in the burst buffer for deferred roll-up.
func ingest(p parsedLine, store *db.DB, alerter Alerter, caseIndex map[caseKey]string, buf *burstBuffer, alertSem chan struct{}) error {
	sev := classifySeverity(p.dstPort)
	if sev == "" {
		// Ephemeral port (>= 32768) — backscatter noise, discard.
		return nil
	}

	now := time.Now().UTC()

	evtType := "wan_new_connection"
	if p.iface != "" && !strings.HasPrefix(p.iface, "eth") && !strings.HasPrefix(p.iface, "wan") {
		evtType = "wan_forward"
	}

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

	// ── Find or create parent case ───────────────────────────────────────────
	key := caseKey{srcSubnet: subnetPrefix(p.srcIP), dstPort: p.dstPort}
	caseID, exists := caseIndex[key]

	if !exists {
		caseID = uuid.NewString()
		caseIndex[key] = caseID

		subnet := key.srcSubnet + ".0/24"
		title := fmt.Sprintf("Inbound DROP: %s → port %d/%s", subnet, p.dstPort, p.proto)

		c := &db.Case{
			CaseID:          caseID,
			Title:           title,
			Summary:         fmt.Sprintf("Syslog-ingested DROP events from %s targeting port %d. First seen from %s.", subnet, p.dstPort, p.srcIP),
			Status:          "open",
			Severity:        sev,
			Confidence:      0.8,
			RelatedEventIDs: db.StringSlice{evt.EventID},
			CreatedAt:       now,
			UpdatedAt:       now,
			RuleType:        "syslog_drop",
			SrcIP:           p.srcIP,
		}
		if err := store.InsertCase(c); err != nil {
			return fmt.Errorf("InsertCase: %w", err)
		}

		log.Printf("[syslog] new case %s — %s", caseID[:8], title)

		if sev == "high" {
			// HIGH severity: bypass buffer, alert immediately.
			log.Printf("[syslog] HIGH severity — alerting immediately for case %s", caseID[:8])
			postAlertWithSem(alertSem, alerter, c)
		} else {
			// LOW/MEDIUM: queue in burst buffer; the ticker will decide.
			buf.add(&bufferedCase{
				c:      c,
				proto:  p.proto,
				srcIPs: []string{p.srcIP},
			})
		}
		return nil
	}

	// ── Append event to existing case ───────────────────────────────────────
	c, err := store.GetCase(caseID)
	if err != nil || c == nil {
		delete(caseIndex, key)
		return ingest(p, store, alerter, caseIndex, buf, alertSem)
	}

	c.RelatedEventIDs = append(c.RelatedEventIDs, evt.EventID)
	c.UpdatedAt = now
	if err := store.UpdateCase(c); err != nil {
		return fmt.Errorf("UpdateCase: %w", err)
	}

	n := len(c.RelatedEventIDs)
	if n == 5 || n == 10 || (n > 0 && n%25 == 0) {
		log.Printf("[syslog] case %s milestone: %d events", caseID[:8], n)
		postAlertWithSem(alertSem, alerter, c)
	}

	return nil
}

// ---------------------------------------------------------------------------
// flushBurst — called by the ticker every burstWindow
// ---------------------------------------------------------------------------

// flushBurst drains the burst buffer and decides:
//   - < burstThreshold cases → alert each individually (small bursts are fine).
//   - >= burstThreshold cases → merge into one ScanBurst case, delete stubs,
//     insert the rolled-up case, and alert once.
func flushBurst(store *db.DB, alerter Alerter, buf *burstBuffer, alertSem chan struct{}) {
	items := buf.drain()
	if len(items) == 0 {
		return
	}

	log.Printf("[syslog] burst flush: %d buffered cases", len(items))

	if len(items) < burstThreshold {
		// Small burst — alert individually; no merge needed.
		for _, bc := range items {
			postAlertWithSem(alertSem, alerter, bc.c)
		}
		return
	}

	// ── Merge into ScanBurst case ────────────────────────────────────────────
	var (
		allEventIDs db.StringSlice
		uniqueSrcIPs  = make(map[string]bool)
		uniquePorts   = make(map[int]bool)
		uniqueProtos  = make(map[string]bool)
		highestSev    = "low"
		oldCaseIDs  []string
	)

	sevRank := map[string]int{"low": 0, "medium": 1, "high": 2}

	for _, bc := range items {
		for _, eid := range bc.c.RelatedEventIDs {
			allEventIDs = append(allEventIDs, eid)
		}
		for _, ip := range bc.srcIPs {
			uniqueSrcIPs[ip] = true
		}
		// Extract port from title: "Inbound DROP: x.x.x.0/24 → port 8181/TCP"
		var port int
		fmt.Sscanf(bc.c.Title, "Inbound DROP: %*s → port %d", &port)
		if port > 0 {
			uniquePorts[port] = true
		}
		if bc.proto != "" {
			uniqueProtos[bc.proto] = true
		}
		if sevRank[bc.c.Severity] > sevRank[highestSev] {
			highestSev = bc.c.Severity
		}
		oldCaseIDs = append(oldCaseIDs, bc.c.CaseID)
	}

	// Build a human-readable port list for the title.
	ports := make([]int, 0, len(uniquePorts))
	for p := range uniquePorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	portStrs := make([]string, 0, len(ports))
	for _, p := range ports {
		portStrs = append(portStrs, strconv.Itoa(p))
	}

	srcCount := len(uniqueSrcIPs)
	portCount := len(uniquePorts)

	protos := make([]string, 0, len(uniqueProtos))
	for pr := range uniqueProtos {
		protos = append(protos, pr)
	}
	sort.Strings(protos)
	protoStr := strings.Join(protos, "/")
	if protoStr == "" {
		protoStr = "TCP"
	}

	title := fmt.Sprintf(
		"[Scan Burst] %d sources, %d ports/%s — internet background scan",
		srcCount, portCount, protoStr,
	)
	summary := fmt.Sprintf(
		"Rolled-up scan burst: %d distinct source IPs across %d unique ports (%s) in a %s window. "+
			"Ports targeted: %s. Individual cases merged: %d. This is internet background radiation — "+
			"no action required unless a specific source appears in threat intelligence.",
		srcCount, portCount, protoStr, burstWindow,
		strings.Join(portStrs, ", "),
		len(items),
	)

	burstCase := &db.Case{
		CaseID:          uuid.NewString(),
		Title:           title,
		Summary:         summary,
		Status:          "open",
		Severity:        highestSev,
		Confidence:      0.6, // lower confidence — bulk noise pattern
		RelatedEventIDs: allEventIDs,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		AnalystNotes:    fmt.Sprintf("rule=scan_burst type=bulk_inbound_drop merged_cases=%d", len(items)),
		RuleType:        "bulk_inbound_drop",
		SrcIP:           items[0].c.SrcIP,
	}

	if err := store.InsertCase(burstCase); err != nil {
		log.Printf("[syslog] burst merge: InsertCase failed: %v — falling back to individual alerts", err)
		for _, bc := range items {
			go alerter.PostCaseAlert(bc.c)
		}
		return
	}

	// Delete the individual stub cases now that the burst case owns all events.
	for _, id := range oldCaseIDs {
		if err := store.DeleteCase(id); err != nil {
			log.Printf("[syslog] burst merge: could not delete stub case %s: %v", id[:8], err)
			// Non-fatal — the burst case is canonical; stubs will be orphaned.
		}
	}

	log.Printf("[syslog] burst merged %d cases → %s (%s, %d sources, ports: %s)",
		len(items), burstCase.CaseID[:8], highestSev, srcCount, strings.Join(portStrs, ","))

	postAlertWithSem(alertSem, alerter, burstCase)
}

// ---------------------------------------------------------------------------
// classifySeverity
// ---------------------------------------------------------------------------

// classifySeverity maps destination port to a severity label.
// Returns "" for ephemeral ports (>= 32768) — backscatter noise, discard.
func classifySeverity(dport int) string {
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
