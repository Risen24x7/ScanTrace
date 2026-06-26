// collector/asus_syslog.go
package collector

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Risen24x7/scantrace/internal/db"
)

// SourceTypeAsus is the source_type tag written to every Event this adapter produces.
const SourceTypeAsus = "asus_syslog"

// ---------------------------------------------------------------------------
// Compiled regexes
// ---------------------------------------------------------------------------

var (
	// Matches both RFC 3339 (BE96U) and BSD syslog (older firmware) headers.
	// m[1]=timestamp  m[2]=process  m[3]=body
	reHeader = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})` +
			`\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)$`,
	)

	// iptables LOG target: DROP / ACCEPT / REJECT
	reNetfilter = regexp.MustCompile(
		`(?i)(DROP|ACCEPT|REJECT)\s+IN=(\S*)\s+OUT=(\S*)\s+.*?SRC=(\S+)\s+DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?`,
	)

	// dnsmasq-dhcp: DHCPACK(br0) 192.168.50.42 aa:bb:cc:dd:ee:ff [hostname]
	reDHCP = regexp.MustCompile(
		`(?i)(DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPNAK|DHCPREQUEST)\S*\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f:]{17})(?:\s+(\S+))?`,
	)

	// hostapd: STA aa:bb:cc:dd:ee:ff ... associated / disassociated / etc.
	reHostapd = regexp.MustCompile(
		`(?i)STA\s+([0-9a-f:]{17})\s+.*?(associated|disassociated|deauthenticated|authenticated)`,
	)

	// WAN IP change
	reWANIP = regexp.MustCompile(
		`WAN[_\s](?:Connection[:\s]+)?(?:IP|ip)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
	)
)

// ---------------------------------------------------------------------------
// AsusAdapter
// ---------------------------------------------------------------------------

// AsusAdapter parses AsusWRT syslog lines. Implements collector.Adapter.
type AsusAdapter struct {
	SensorID string
	year     int
}

func NewAsusAdapter(sensorID string) *AsusAdapter {
	return &AsusAdapter{SensorID: sensorID, year: time.Now().Year()}
}

// Parse implements collector.Adapter.
// Returns ErrSkip (via Skip()) for well-formed but non-security lines so
// TailFile suppresses them without logging.
func (a *AsusAdapter) Parse(line string) (*db.Event, error) {
	if a.year == 0 {
		a.year = time.Now().Year()
	}
	evt, err := a.parseLine(line)
	if err != nil {
		return nil, err
	}
	if evt == nil {
		// Well-formed header but not a tracked process — silent skip.
		return nil, Skip("non-security process")
	}
	if evt.SensorID == "" {
		evt.SensorID = a.SensorID
	}
	return evt, nil
}

// ---------------------------------------------------------------------------
// Bulk ingestion helpers
// ---------------------------------------------------------------------------

func (a *AsusAdapter) IngestReader(database *db.DB, r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		evt, err := a.Parse(line)
		if err != nil {
			if !isSkip(err) {
				log.Printf("[asus_syslog] parse error: %v", err)
			}
			continue
		}
		if err := database.InsertEvent(evt); err != nil {
			log.Printf("[asus_syslog] db.InsertEvent: %v", err)
			continue
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("asus_syslog: scanner: %w", err)
	}
	return count, nil
}

func (a *AsusAdapter) IngestFile(database *db.DB, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("asus_syslog: open %q: %w", path, err)
	}
	defer f.Close()
	return a.IngestReader(database, f)
}

// ---------------------------------------------------------------------------
// Line parser
// ---------------------------------------------------------------------------

func (a *AsusAdapter) parseLine(line string) (*db.Event, error) {
	m := reHeader.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("no syslog header match")
	}
	rawTime := m[1]
	process := m[2]
	body := m[3]

	ts, err := a.parseTimestamp(rawTime)
	if err != nil {
		return nil, fmt.Errorf("timestamp parse: %w", err)
	}

	switch {
	case strings.HasPrefix(process, "kernel"):
		return a.parseNetfilter(ts, body, line)
	case strings.HasPrefix(process, "dnsmasq"):
		return a.parseDHCP(ts, body, line)
	case strings.HasPrefix(process, "hostapd"):
		return a.parseHostapd(ts, body, line)
	case strings.Contains(body, "WAN") && strings.Contains(body, "IP"):
		return a.parseWANIP(ts, body, line)
	}

	return nil, nil // well-formed but not a tracked process
}

// ---------------------------------------------------------------------------
// Sub-parsers
// ---------------------------------------------------------------------------

func (a *AsusAdapter) parseNetfilter(ts time.Time, body, raw string) (*db.Event, error) {
	m := reNetfilter.FindStringSubmatch(body)
	if m == nil {
		return nil, nil
	}
	action := strings.ToUpper(m[1])
	srcIP := m[4]
	dstIP := m[5]
	proto := strings.ToUpper(m[6])
	dstPort := 0
	if m[7] != "" {
		dstPort, _ = strconv.Atoi(m[7])
	}
	tags := db.StringSlice{"firewall_" + strings.ToLower(action)}
	if action == "DROP" || action == "REJECT" {
		tags = append(tags, "blocked")
	}
	return &db.Event{
		EventID:      uuid.NewString(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     a.SensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "firewall",
		EventType:    "netfilter_" + strings.ToLower(action),
		SrcIP:        srcIP,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Protocol:     proto,
		Transport:    proto,
		Direction:    inferDirection(srcIP, dstIP),
		RawRef:       raw,
		Confidence:   0.8,
		Tags:         tags,
	}, nil
}

func (a *AsusAdapter) parseDHCP(ts time.Time, body, raw string) (*db.Event, error) {
	m := reDHCP.FindStringSubmatch(body)
	if m == nil {
		return nil, nil
	}
	msgType := m[1]
	clientIP := m[2]
	mac := m[3]
	hostname := ""
	if len(m) > 4 {
		hostname = strings.TrimSpace(m[4])
	}
	notes := fmt.Sprintf("mac=%s", mac)
	if hostname != "" {
		notes += fmt.Sprintf(" hostname=%s", hostname)
	}
	return &db.Event{
		EventID:      uuid.NewString(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     a.SensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "dhcp",
		EventType:    "dhcp_" + strings.ToLower(msgType),
		SrcIP:        clientIP,
		Protocol:     "UDP",
		Transport:    "UDP",
		Direction:    "internal",
		RawRef:       raw,
		Confidence:   0.9,
		Tags:         db.StringSlice{"dhcp", "lan_device"},
		Notes:        notes,
	}, nil
}

func (a *AsusAdapter) parseHostapd(ts time.Time, body, raw string) (*db.Event, error) {
	m := reHostapd.FindStringSubmatch(body)
	if m == nil {
		return nil, nil
	}
	mac := m[1]
	action := m[2]
	return &db.Event{
		EventID:      uuid.NewString(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     a.SensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "wifi",
		EventType:    "wifi_" + strings.ToLower(action),
		Protocol:     "802.11",
		Direction:    "internal",
		RawRef:       raw,
		Confidence:   0.85,
		Tags:         db.StringSlice{"wifi", "lan_device"},
		Notes:        fmt.Sprintf("mac=%s action=%s", mac, action),
	}, nil
}

func (a *AsusAdapter) parseWANIP(ts time.Time, body, raw string) (*db.Event, error) {
	m := reWANIP.FindStringSubmatch(body)
	if m == nil {
		return nil, nil
	}
	wanIP := m[1]
	return &db.Event{
		EventID:      uuid.NewString(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     a.SensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "wan",
		EventType:    "wan_ip_change",
		SrcIP:        wanIP,
		Direction:    "outbound",
		RawRef:       raw,
		Confidence:   1.0,
		Tags:         db.StringSlice{"wan", "ip_change"},
		Notes:        fmt.Sprintf("new_wan_ip=%s", wanIP),
	}, nil
}

// ---------------------------------------------------------------------------
// Timestamp parsing
// ---------------------------------------------------------------------------

func (a *AsusAdapter) parseTimestamp(s string) (time.Time, error) {
	// RFC 3339 (BE96U): 2026-06-25T20:38:19+00:00
	if len(s) > 10 && s[4] == '-' {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("RFC3339 parse %q: %w", s, err)
		}
		return t.UTC(), nil
	}
	// BSD syslog (older firmware): Jun 25 20:05:01
	s = strings.Join(strings.Fields(s), " ")
	candidate := fmt.Sprintf("%s %d", s, a.year)
	t, err := time.ParseInLocation("Jan 2 15:04:05 2006", candidate, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("BSD parse %q: %w", s, err)
	}
	if t.After(time.Now().Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// Sensor registration
// ---------------------------------------------------------------------------

func RegisterAsusSensor(database *db.DB, stateFile string) (string, error) {
	if id, err := loadSensorID(stateFile); err == nil && id != "" {
		return id, nil
	}
	hostname, _ := os.Hostname()
	s := &db.Sensor{
		SensorID:      uuid.NewString(),
		Hostname:      hostname,
		Platform:      "linux",
		Role:          "gateway_syslog",
		NetworkZone:   "home_lan",
		LocationTag:   "asus_router",
		CollectorType: SourceTypeAsus,
		Version:       "1.0.0",
	}
	if err := database.InsertSensor(s); err != nil {
		return "", fmt.Errorf("RegisterAsusSensor: InsertSensor: %w", err)
	}
	if err := saveSensorID(stateFile, s.SensorID); err != nil {
		log.Printf("[asus_syslog] warning: could not save sensor_id to %q: %v", stateFile, err)
	}
	log.Printf("[asus_syslog] registered sensor %s", s.SensorID)
	return s.SensorID, nil
}

func loadSensorID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("empty")
	}
	return id, nil
}

func saveSensorID(path, id string) error {
	return os.WriteFile(path, []byte(id+"\n"), 0600)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isSkip(err error) bool {
	return errors.Is(err, ErrSkip)
}

func inferDirection(src, dst string) string {
	srcPriv := isPrivate(src)
	dstPriv := isPrivate(dst)
	switch {
	case !srcPriv && dstPriv:
		return "inbound"
	case srcPriv && !dstPriv:
		return "outbound"
	case srcPriv && dstPriv:
		return "internal"
	default:
		return "unknown"
	}
}

func isPrivate(ip string) bool {
	if ip == "" {
		return false
	}
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") ||
		isPrivate172(ip)
}

func isPrivate172(ip string) bool {
	parts := strings.SplitN(ip, ".", 4)
	if len(parts) < 2 || parts[0] != "172" {
		return false
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return n >= 16 && n <= 31
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\u2026"
}
