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
// HIGH severity cases (port 22/23/3389/etc.) bypass the burst buffer and
// trigger an immediate Slack alert so real intrusion probes are never delayed.
//
// LOW/MEDIUM cases are held in a burst buffer for burstWindow (90 s). When the
// ticker fires flushBurst:
//
//	< burstThreshold cases  → alert each individually (small clusters are fine).
//	>= burstThreshold cases → merge ALL buffered cases into one ScanBurst case
//	                          in the DB, delete the stub cases, call PostCaseAlert
//	                          exactly once for the rolled-up case.
//
// Goroutine safety
// ----------------
// The ingest goroutine (ReadFrom loop) and the ticker goroutine (flushBurst)
// are the only two writers to burstBuffer. All buffer mutations go through
// burstBuffer.mu. flushBurst holds the lock for the ENTIRE drain-and-merge
// sequence via drainLocked() to prevent a race between draining and a
// concurrent add() from ingest.
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
// A single ScanBurst case that keeps receiving appends (e.g. a scan that runs
// for hours) is closed once it reaches burstMaxEvents (50). The case is marked
// status="closed" and the caseIndex entry is deleted so the next event opens a
// fresh case, preventing an unmanageably large case file.
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
	// burstWindow is the hold time for LOW/MEDIUM cases before the buffer flushes.
	burstWindow = 90 * time.Second

	// burstThreshold: if >= this many LOW/MEDIUM cases accumulate in one window,
	// merge them into a single ScanBurst case.
	burstThreshold = 3

	// burstMaxEvents caps the total related_event_ids on any single case (burst
	// or individual). When a case reaches this limit it is closed and the
	// caseIndex entry is evicted so the next event starts a new case.
	burstMaxEvents = 50
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
	srcSubnet string
	dstPort   int
}

// subnetPrefix returns the /24 prefix of an IPv4 address string.
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

// ---------------------------------------------------------------------------
// Burst buffer
// ---------------------------------------------------------------------------

// bufferedCase is a case held in the burst buffer pending flush.
type bufferedCase struct {
	c      *db.Case
	proto  string
	srcIPs []string
}

// burstBuffer holds LOW/MEDIUM cases for up to burstWindow.
//
// Concurrency model: add() is called from the ingest goroutine (ReadFrom
// loop); flushBurst() is called from the ticker goroutine. Both hold mu
// before touching items. flushBurst calls drainLocked() which keeps mu held
// through the entire drain-and-return so no add() can sneak in between the
// length check and the nil-reset.
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
// CALLER MUST hold b.mu before calling and release it after.
func (b *burstBuffer) drainLocked() []*bufferedCase {
	out := b.items
	b.items = nil
	return out
}

// ---------------------------------------------------------------------------
// Listen — main entry point
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

	ticker := time.NewTicker(burstWindow)
	go func() {
		for range ticker.C {
			flushBurst(store, alerter, buf)
		}
	}()
	defer ticker.Stop()

	pkt := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(pkt)
		if err != nil {
			log.Printf("[syslog] read error: %v", err)
			continue
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
		// ── Create new case ──────────────────────────────────────────────────
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
		}
		if err := store.InsertCase(c); err != nil {
			return fmt.Errorf("InsertCase: %w", err)
		}

		log.Printf("[syslog] new case %s — %s", caseID[:8], title)

		if sev == "high" {
			log.Printf("[syslog] HIGH severity — alerting immediately for case %s", caseID[:8])
			go alerter.PostCaseAlert(c)
		} else {
			buf.add(&bufferedCase{c: c, proto: p.proto, srcIPs: []string{p.srcIP}})
		}
		return nil
	}

	// ── Append event to existing case ────────────────────────────────────────
	c, err := store.GetCase(caseID)
	if err != nil || c == nil {
		delete(caseIndex, key)
		return ingest(p, store, alerter, caseIndex, buf)
	}

	c.RelatedEventIDs = append(c.RelatedEventIDs, evt.EventID)
	c.UpdatedAt = now

	// ── Max-events cap: close this case and evict so the next event starts fresh.
	// This prevents a single long-running scan from producing an unmanageably
	// large case. The events remain intact in the events table; only this case
	// row is capped.
	if len(c.RelatedEventIDs) >= burstMaxEvents {
		c.Status = "closed"
		c.AnalystNotes = fmt.Sprintf("%s | capped at %d events on %s",
			c.AnalystNotes, burstMaxEvents, now.Format(time.RFC3339))
		if err := store.UpdateCase(c); err != nil {
			return fmt.Errorf("UpdateCase (cap): %w", err)
		}
		delete(caseIndex, key) // evict — next event will open a new case
		log.Printf("[syslog] case %s capped at %d events, closed", caseID[:8], burstMaxEvents)
		return nil
	}

	if err := store.UpdateCase(c); err != nil {
		return fmt.Errorf("UpdateCase: %w", err)
	}

	n := len(c.RelatedEventIDs)
	if n == 5 || n == 10 || (n > 0 && n%25 == 0) {
		log.Printf("[syslog] case %s milestone: %d events", caseID[:8], n)
		go alerter.PostCaseAlert(c)
	}

	return nil
}

// ---------------------------------------------------------------------------
// flushBurst — called by the ticker every burstWindow
// ---------------------------------------------------------------------------

// flushBurst drains the burst buffer under the mutex for its entire execution
// and decides whether to merge or emit individually.
//
// Mutex protocol:
//
//	Lock is acquired before drainLocked() and held until items is fully copied
//	into local variables. The lock is released before any DB or network I/O
//	(InsertCase, DeleteCase, PostCaseAlert) to avoid holding it across slow ops.
func flushBurst(store *db.DB, alerter Alerter, buf *burstBuffer) {
	// Drain atomically.
	buf.mu.Lock()
	items := buf.drainLocked()
	buf.mu.Unlock()
	// Lock is now released. All subsequent work is local to this goroutine.

	if len(items) == 0 {
		return
	}

	log.Printf("[syslog] burst flush: %d buffered cases", len(items))

	if len(items) < burstThreshold {
		for _, bc := range items {
			go alerter.PostCaseAlert(bc.c)
		}
		return
	}

	// ── Merge into ScanBurst case ─────────────────────────────────────────────
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

	now := time.Now().UTC()
	burstCase := &db.Case{
		CaseID:          uuid.NewString(),
		Title:           title,
		Summary:         summary,
		Status:          "open",
		Severity:        highestSev,
		Confidence:      0.6,
		RelatedEventIDs: allEventIDs,
		CreatedAt:       now,
		UpdatedAt:       now,
		AnalystNotes: fmt.Sprintf(
			"rule=scan_burst type=bulk_inbound_drop merged_cases=%d stub_ids=%s",
			len(items),
			strings.Join(oldCaseIDs, ","),
		),
	}

	if err := store.InsertCase(burstCase); err != nil {
		log.Printf("[syslog] burst merge: InsertCase failed: %v — falling back to individual alerts", err)
		for _, bc := range items {
			go alerter.PostCaseAlert(bc.c)
		}
		return
	}

	// Delete stub cases. Safe because:
	//   - events table has NO case_id FK — events are not deleted.
	//   - burstCase.RelatedEventIDs now owns all event references.
	//   - If DeleteCase fails for a stub, log and continue — the burst case
	//     is already the canonical record; the stub is simply an orphaned row.
	for _, id := range oldCaseIDs {
		if err := store.DeleteCase(id); err != nil {
			log.Printf("[syslog] burst merge: could not delete stub case %s: %v", id[:8], err)
		}
	}

	log.Printf("[syslog] burst merged %d cases → %s (%s, %d sources, ports: %s)",
		len(items), burstCase.CaseID[:8], highestSev, srcCount, strings.Join(portStrs, ","))

	go alerter.PostCaseAlert(burstCase)
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
