// Package collector ingests raw log lines and writes normalized Events to the DB.
// Adapters provided:
//   - SuricataAdapter: parses Suricata EVE JSON
//   - SyslogAdapter:   parses generic firewall syslog (iptables/pf/ASA)
//   - AsusAdapter:     parses AsusWRT syslog (RFC 3339 and BSD formats)
package collector

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

// ErrSkip is returned by an Adapter.Parse implementation when the line is
// well-formed but intentionally not tracked (e.g. a non-security process on
// an Asus router, or a Suricata event_type we don't care about).
// TailFile silently drops these; only unexpected errors are logged.
var ErrSkip = errors.New("skip")

// skipErr wraps ErrSkip with context without allocating on the hot path.
type skipErr struct{ msg string }

func (e *skipErr) Error() string { return e.msg }
func (e *skipErr) Is(target error) bool { return target == ErrSkip }

// Skip returns a sentinel error that causes TailFile to silently discard the
// current line. Use it inside Adapter.Parse for expected non-events.
func Skip(msg string) error { return &skipErr{msg: msg} }

type Collector struct {
	store    *db.DB
	sensorID string
}

func New(store *db.DB, sensorID string) *Collector {
	return &Collector{store: store, sensorID: sensorID}
}

func (c *Collector) TailFile(r io.Reader, adapter Adapter) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		evt, err := adapter.Parse(line)
		if err != nil {
			if !errors.Is(err, ErrSkip) {
				log.Printf("[collector] parse error: %v", err)
			}
			continue
		}
		evt.SensorID = c.sensorID
		if err := c.store.InsertEvent(evt); err != nil {
			log.Printf("[collector] insert error: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[collector] scanner error: %v", err)
	}
}

func (c *Collector) IngestFile(path string, adapter Adapter) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("collector.IngestFile: %w", err)
	}
	defer f.Close()
	c.TailFile(f, adapter)
	return nil
}

type Adapter interface {
	Parse(line string) (*db.Event, error)
}

// ---------------------------------------------------------------------------
// SuricataAdapter
// ---------------------------------------------------------------------------

type SuricataEVE struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     *struct {
		Signature string `json:"signature"`
		Category  string `json:"category"`
		Severity  int    `json:"severity"`
	} `json:"alert,omitempty"`
}

type SuricataAdapter struct{}

func (a *SuricataAdapter) Parse(line string) (*db.Event, error) {
	var eve SuricataEVE
	if err := json.Unmarshal([]byte(line), &eve); err != nil {
		return nil, fmt.Errorf("suricata: json unmarshal: %w", err)
	}
	switch eve.EventType {
	case "alert", "flow", "anomaly", "scan":
	default:
		return nil, Skip(fmt.Sprintf("suricata: event_type=%s", eve.EventType))
	}
	ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", eve.Timestamp)
	if err != nil {
		ts = time.Now().UTC()
	}
	tags := db.StringSlice{}
	notes := ""
	if eve.Alert != nil {
		tags = append(tags, eve.Alert.Category)
		notes = eve.Alert.Signature
	}
	return &db.Event{
		EventID:      uuid.New().String(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SourceType:   "suricata",
		DetectorType: "eve-json",
		EventType:    eve.EventType,
		SrcIP:        eve.SrcIP,
		SrcPort:      eve.SrcPort,
		DstIP:        eve.DestIP,
		DstPort:      eve.DestPort,
		Protocol:     strings.ToLower(eve.Proto),
		Transport:    strings.ToLower(eve.Proto),
		Direction:    "inbound",
		RawRef:       line,
		Confidence:   0.80,
		Tags:         tags,
		Notes:        notes,
	}, nil
}

// ---------------------------------------------------------------------------
// SyslogAdapter
// ---------------------------------------------------------------------------

type SyslogAdapter struct{}

func (a *SyslogAdapter) Parse(line string) (*db.Event, error) {
	lower := strings.ToLower(line)
	if !strings.ContainsAny(lower, "drop block deny reject") {
		return nil, Skip("syslog: no deny keyword")
	}
	srcIP, dstIP, srcPort, dstPort, proto := extractSyslogFields(line)
	if srcIP == "" {
		return nil, fmt.Errorf("syslog: could not extract src_ip")
	}
	ts := time.Now().UTC()
	if len(line) > 15 {
		if t, err := time.Parse("Jan  2 15:04:05", line[:15]); err == nil {
			ts = t.UTC()
		}
	}
	return &db.Event{
		EventID:      uuid.New().String(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SourceType:   "syslog",
		DetectorType: "firewall",
		EventType:    "blocked",
		SrcIP:        srcIP,
		SrcPort:      srcPort,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Protocol:     proto,
		Transport:    proto,
		Direction:    "inbound",
		RawRef:       line,
		Confidence:   0.65,
		Tags:         db.StringSlice{"firewall-block"},
	}, nil
}

func extractSyslogFields(line string) (srcIP, dstIP string, srcPort, dstPort int, proto string) {
	fields := strings.Fields(line)
	for _, f := range fields {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.ToLower(kv[0]), kv[1]
		switch k {
		case "src":
			if net.ParseIP(v) != nil {
				srcIP = v
			}
		case "dst":
			if net.ParseIP(v) != nil {
				dstIP = v
			}
		case "spt":
			if p, err := strconv.Atoi(v); err == nil {
				srcPort = p
			}
		case "dpt":
			if p, err := strconv.Atoi(v); err == nil {
				dstPort = p
			}
		case "proto", "protocol":
			proto = strings.ToLower(v)
		}
	}
	if srcIP == "" {
		for _, f := range fields {
			if net.ParseIP(f) != nil {
				if srcIP == "" {
					srcIP = f
				} else if dstIP == "" {
					dstIP = f
					break
				}
			}
		}
	}
	if proto == "" {
		proto = "tcp"
	}
	return
}
