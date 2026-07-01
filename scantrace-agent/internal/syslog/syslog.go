// Package syslog provides a UDP syslog listener that ingests iptables kernel
// DROP lines forwarded from the gateway router and turns them into ScanTrace
// events and cases.
//
// Expected syslog line format (router sends RFC 3164 with kernel payload):
//
//	<134>Jun 28 15:28:29 router kernel: DROP IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=192.168.50.80 ... PROTO=TCP SPT=54321 DPT=22 ...
//
// Roll-up / burst-suppression architecture
// -----------------------------------------
// HIGH severity cases (port 22/23/3389/5938/8080/8088/etc.) bypass the burst
// buffer and trigger an immediate Slack alert so real intrusion probes are
// never delayed.
//
// LOW/MEDIUM cases are held in a burst buffer for burstWindow (90 s). When the
// ticker fires flushBurst:
//
//	< burstThreshold cases  → alert each individually (small clusters are fine).
//	>= burstThreshold cases → merge ALL buffered cases into one ScanBurst case
//	                          in the DB, delete the stub cases, call PostCaseAlert
//	                          exactly once for the rolled-up case.
//
// INFO suppression (Gemini threshold-based alerting)
// ---------------------------------------------------
// A merged ScanBurst that touches NO port in knownPorts (the union of high+
// medium sets derived from the router's actual port-forwarding table) is
// classified severity="info" and NOT posted to Slack. It is still written to
// the DB for audit completeness. This eliminates pure background radiation
// (e.g. scanners hitting random high ports you don't forward) from the Slack
// channel entirely.
//
// Goroutine safety
// ----------------
// The ingest goroutine (ReadFrom loop) and the ticker goroutine (flushBurst)
// are the only two writers to burstBuffer. All buffer mutations go through
// burstBuffer.mu. flushBurst calls drainLocked() which keeps mu held through
// the entire drain-and-return so no add() can sneak in mid-drain.
//
// Orphaned-event invariant
// ------------------------
// The events table has NO case_id foreign key. Events are linked to cases only
// via the cases.related_event_ids JSON blob. DeleteCase therefore drops only
// the cases row; all event rows remain intact and are re-owned by the new
// ScanBurst case through its own RelatedEventIDs list. No orphaned events.
//
// Max-events cap
// --------------
// A single case that keeps receiving appends is closed once it reaches
// burstMaxEvents (50). The caseIndex entry is evicted so the next event opens
// a fresh case, preventing unbounded case growth during long-running scans.
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
type Alerter interface {
	PostCaseAlert(c *db.Case)
}

// ---------------------------------------------------------------------------
// Tuning constants
// ---------------------------------------------------------------------------

const (
	burstWindow    = 90 * time.Second
	burstThreshold = 3
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

type parsedLine struct {
	iface   string
	srcIP   string
	dstIP   string
	srcPort int
	dstPort int
	proto   string
	rawLine string
}

// caseKey groups events into a single case by /24 source subnet + dst port.
type caseKey struct {
	srcSubnet string
	dstPort   int
}

func subnetPrefix(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return strings.Join(parts[:3], ".")
	}
	return ip
}

const syslogSensorID = "00000000-5359-4c4f-4700-000000000001"

func ensureSyslogSensor(store *db.DB) error {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "router-syslog"
	}
	return store.InsertSensor(&db.Sensor{
		SensorID:      syslogSensorID,
		Hostname:      hostname,
		Platform:      "linux",
		Role:          "gateway",
		CollectorType: "syslog_udp",
		Version:       "1.0.0",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	})
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
// dstPort is stored directly (not re-parsed from Title) to avoid
// UTF-8 arrow parsing bugs in fmt.Sscanf.
type bufferedCase struct {
	c       *db.Case
	proto   string
	srcIPs  []string
	dstPort int // the actual destination port for this case
}

type burstBuffer struct {
	mu    sync.Mutex
	items []*bufferedCase
}

func (b *burstBuffer) add(bc *bufferedCase) {
	b.mu.Lock()
	b.items = append(b.items, bc)
	b.mu.Unlock()
}

// drainLocked atomically removes and returns all buffered cases.
// CALLER MUST hold b.mu before calling.
func (b *burstBuffer) drainLocked() []*bufferedCase {
	out := b.items
	b.items = nil
	return out
}

// ---------------------------------------------------------------------------
// Listen
// ---------------------------------------------------------------------------

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
		if line == "" || !strings.Contains(line, "DROP") {
			continue
		}
		p, ok := parse(line)
		if !ok {
			continue
		}

		if err := ingest(p, store, alerter, caseIndex, buf); err != nil {
			log.Printf("[syslog] ingest error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------

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
	if srcIP == "" || srcIP == "0.0.0.0" || dstIP == "" || dstIP == "0.0.0.0" {
		return parsedLine{}, false
	}

	srcPort, _ := strconv.Atoi(extract(reSPT))
	dstPort, _ := strconv.Atoi(extract(reDPT))
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
func ingest(p parsedLine, store *db.DB, alerter Alerter, caseIndex map[caseKey]string, buf *burstBuffer) error {
	sev := classifySeverity(p.dstPort)
	if sev == "" {
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

	key := caseKey{srcSubnet: subnetPrefix(p.srcIP), dstPort: p.dstPort}
	caseID, exists := caseIndex[key]

	if !exists {
		caseID = uuid.NewString()
		caseIndex[key] = caseID

		subnet := key.srcSubnet + ".0/24"
		title := fmt.Sprintf("Inbound DROP: %s -> port %d/%s", subnet, p.dstPort, p.proto)

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

		log.Printf("[syslog] new case %s -- %s", caseID[:8], title)

		if sev == "high" {
			// HIGH severity: bypass buffer, alert immediately.
			log.Printf("[syslog] HIGH severity — alerting immediately for case %s", caseID[:8])
			go alerter.PostCaseAlert(c)
		} else {
			// dstPort stored directly — no title re-parsing needed in flushBurst.
			buf.add(&bufferedCase{c: c, proto: p.proto, srcIPs: []string{p.srcIP}, dstPort: p.dstPort})
		}
		return nil
	}

	// Append event to existing case.
	c, err := store.GetCase(caseID)
	if err != nil || c == nil {
		delete(caseIndex, key)
		return ingest(p, store, alerter, caseIndex, buf, alertSem)
	}

	c.RelatedEventIDs = append(c.RelatedEventIDs, evt.EventID)
	c.UpdatedAt = now

	// Max-events cap: close and evict when a case gets too large.
	if len(c.RelatedEventIDs) >= burstMaxEvents {
		c.Status = "closed"
		c.AnalystNotes = fmt.Sprintf("%s | capped at %d events on %s",
			c.AnalystNotes, burstMaxEvents, now.Format(time.RFC3339))
		if err := store.UpdateCase(c); err != nil {
			return fmt.Errorf("UpdateCase (cap): %w", err)
		}
		delete(caseIndex, key)
		log.Printf("[syslog] case %s capped at %d events, closed", caseID[:8], burstMaxEvents)
		return nil
	}

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
// flushBurst
// ---------------------------------------------------------------------------

// flushBurst drains the burst buffer and decides:
//   - < burstThreshold cases → alert each individually (small bursts are fine).
//   - >= burstThreshold cases → merge into one ScanBurst case, delete stubs,
//     insert the rolled-up case, and alert once.
func flushBurst(store *db.DB, alerter Alerter, buf *burstBuffer) {
	items := buf.drain()
	if len(items) == 0 {
		return
	}

	log.Printf("[syslog] burst flush: %d buffered cases", len(items))

	if len(items) < burstThreshold {
		for _, bc := range items {
			postAlertWithSem(alertSem, alerter, bc.c)
		}
		return
	}

	// Merge into ScanBurst case.
	var (
		allEventIDs  db.StringSlice
		uniqueSrcIPs = make(map[string]bool)
		uniquePorts  = make(map[int]bool)
		uniqueProtos = make(map[string]bool)
		highestSev   = "low"
		oldCaseIDs   []string
	)

	sevRank := map[string]int{"low": 0, "medium": 1, "high": 2}

	for _, bc := range items {
		for _, eid := range bc.c.RelatedEventIDs {
			allEventIDs = append(allEventIDs, eid)
		}
		for _, ip := range bc.srcIPs {
			uniqueSrcIPs[ip] = true
		}
		// Use stored dstPort — no fmt.Sscanf title re-parsing (fixes port=0 bug).
		if bc.dstPort > 0 {
			uniquePorts[bc.dstPort] = true
		}
		if bc.proto != "" {
			uniqueProtos[bc.proto] = true
		}
		if sevRank[bc.c.Severity] > sevRank[highestSev] {
			highestSev = bc.c.Severity
		}
		oldCaseIDs = append(oldCaseIDs, bc.c.CaseID)
	}

	ports := make([]int, 0, len(uniquePorts))
	for p := range uniquePorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	portStrs := make([]string, 0, len(ports))
	for _, p := range ports {
		portStrs = append(portStrs, strconv.Itoa(p))
	}

	protos := make([]string, 0, len(uniqueProtos))
	for pr := range uniqueProtos {
		protos = append(protos, pr)
	}
	sort.Strings(protos)
	protoStr := strings.Join(protos, "/")
	if protoStr == "" {
		protoStr = "TCP"
	}

	srcCount := len(uniqueSrcIPs)
	portCount := len(uniquePorts)

	// Determine final severity — suppress to "info" if no known port targeted.
	finalSev := burstSeverity(uniquePorts, highestSev)

	title := fmt.Sprintf(
		"[Scan Burst] %d sources, %d ports/%s -- internet background scan",
		srcCount, portCount, protoStr,
	)
	summary := fmt.Sprintf(
		"Rolled-up scan burst: %d distinct source IPs across %d unique ports (%s) in a %s window. "+
			"Ports targeted: %s. Individual cases merged: %d.",
		srcCount, portCount, protoStr, burstWindow,
		strings.Join(portStrs, ", "),
		len(items),
	)
	if finalSev == "info" {
		summary += " No forwarded/known ports targeted -- pure internet background radiation, Slack suppressed."
	} else {
		summary += " At least one known service port targeted -- review recommended."
	}

	now := time.Now().UTC()
	burstCase := &db.Case{
		CaseID:          uuid.NewString(),
		Title:           title,
		Summary:         summary,
		Status:          "open",
		Severity:        finalSev,
		Confidence:      0.6,
		RelatedEventIDs: allEventIDs,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		AnalystNotes:    fmt.Sprintf("rule=scan_burst type=bulk_inbound_drop merged_cases=%d", len(items)),
	}

	if err := store.InsertCase(burstCase); err != nil {
		log.Printf("[syslog] burst merge: InsertCase failed: %v -- falling back to individual alerts", err)
		for _, bc := range items {
			go alerter.PostCaseAlert(bc.c)
		}
		return
	}

	// Delete stub cases.
	// Safe: events table has NO case_id FK. DeleteCase drops only the cases row.
	// burstCase.RelatedEventIDs owns all event references going forward.
	for _, id := range oldCaseIDs {
		if err := store.DeleteCase(id); err != nil {
			log.Printf("[syslog] burst merge: could not delete stub case %s: %v", id[:8], err)
		}
	}

	if finalSev == "info" {
		// Pure background radiation — written to DB for audit, not posted to Slack.
		log.Printf("[syslog] burst INFO (no known ports): %s suppressed from Slack", burstCase.CaseID[:8])
		return
	}

	log.Printf("[syslog] burst merged %d cases -> %s (%s, %d sources, ports: %s)",
		len(items), burstCase.CaseID[:8], finalSev, srcCount, strings.Join(portStrs, ","))

	postAlertWithSem(alertSem, alerter, burstCase)
}
