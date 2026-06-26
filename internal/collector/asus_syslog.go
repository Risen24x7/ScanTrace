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

	"github.com/Risen24x7/ScanTrace/internal/db"
)

// SourceTypeAsus is the source_type tag written to every Event this adapter produces.
const SourceTypeAsus = "asus_syslog"

// SyslogTimeLayout is the standard BSD syslog timestamp used by AsusWRT.
// Example: "Jun 25 20:05:01"
const SyslogTimeLayout = "Jan  2 15:04:05"

// ---------------------------------------------------------------------------
// Compiled regexes — compiled once at package init, reused per line.
// ---------------------------------------------------------------------------

var (
	// Jun 25 20:05:01 hostname kernel: ...
	reHeader = regexp.MustCompile(
		`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(\S+):\s+(.*)$`,
	)

	// kernel: DROP / ACCEPT lines from iptables LOG target
	// IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP ... DPT=22 ...
	reNetfilter = regexp.MustCompile(
		`(?i)(DROP|ACCEPT|REJECT)\s+IN=(\S*)\s+OUT=(\S*)\s+.*?SRC=(\S+)\s+DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?`,
	)

	// dnsmasq-dhcp: DHCPACK / DHCPDISCOVER / DHCPOFFER / DHCPNAK
	// DHCPACK(br0) 192.168.50.42 aa:bb:cc:dd:ee:ff hostname
	reDHCP = regexp.MustCompile(
		`(DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPNAK|DHCPREQUEST)\S*\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f:]{17})(?:\s+(\S+))?`,
	)

	// hostapd: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated
	reHostapd = regexp.MustCompile(
		`STA\s+([0-9a-f:]{17})\s+.*?(associated|disassociated|deauthenticated|authenticated)`,
	)

	// WAN IP change: "WAN Connection: WAN_IP=1.2.3.4"  (varies by firmware)
	reWANIP = regexp.MustCompile(
		`WAN[_\s](?:Connection[:\s]+)?(?:IP|ip)[=:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
	)
)

// ---------------------------------------------------------------------------
// AsusAdapter reads syslog lines and emits db.Event values.
// ---------------------------------------------------------------------------

// AsusAdapter parses AsusWRT syslog lines and writes Events to the database.
type AsusAdapter struct {
	db       *db.DB
	sensorID string
	hostname string // value read from syslog header; set on first line
	year     int    // inferred year (syslog BSD format omits year)
}

// NewAsusAdapter returns an adapter bound to the given DB and pre-registered sensor.
// Call RegisterAsussSensor first to obtain sensorID.
func NewAsusAdapter(database *db.DB, sensorID string) *AsusAdapter {
	return &AsusAdapter{
		db:       database,
		sensorID: sensorID,
		year:     time.Now().Year(),
	}
}

// Ingest reads lines from r until EOF or error, parses each line, and
// writes recognized events to the DB. Unknown / malformed lines are logged
// at debug level and skipped — they never cause Ingest to return an error.
// Returns the count of events successfully written.
func (a *AsusAdapter) Ingest(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	count := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		evt, err := a.parseLine(line)
		if err != nil {
			log.Printf("[asus_syslog] skip: %v — %q", err, truncate(line, 120))
			continue
		}
		if evt == nil {
			// Recognized header but event_type is not security-relevant — skip silently.
			continue
		}

		if err := a.db.InsertEvent(evt); err != nil {
			log.Printf("[asus_syslog] db.InsertEvent error: %v", err)
			continue
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("asus_syslog: scanner: %w", err)
	}
	return count, nil
}

// IngestFile opens path and calls Ingest. Convenience wrapper for CLI use.
func (a *AsusAdapter) IngestFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("asus_syslog: open %q: %w", path, err)
	}
	defer f.Close()
	return a.Ingest(f)
}

// ---------------------------------------------------------------------------
// Line parser
// ---------------------------------------------------------------------------

// parseLine parses a single syslog line. Returns:
//   - (event, nil)  — recognized, security-relevant line
//   - (nil, nil)    — recognized header but not a tracked event type
//   - (nil, err)    — malformed header; caller logs and skips
func (a *AsusAdapter) parseLine(line string) (*db.Event, error) {
	m := reHeader.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("no syslog header match")
	}

	rawTime := m[1]
	process := m[2] // e.g. "kernel", "dnsmasq-dhcp", "hostapd"
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

	return nil, nil // not a tracked process
}

// ---------------------------------------------------------------------------
// Sub-parsers
// ---------------------------------------------------------------------------

func (a *AsusAdapter) parseNetfilter(ts time.Time, body, raw string) (*db.Event, error) {
	m := reNetfilter.FindStringSubmatch(body)
	if m == nil {
		return nil, nil // kernel line but not a netfilter LOG line
	}

	action := strings.ToUpper(m[1]) // DROP, ACCEPT, REJECT
	// m[2] = IN iface, m[3] = OUT iface
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
		SensorID:     a.sensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "firewall",
		EventType:    "netfilter_" + strings.ToLower(action),
		SrcIP:        srcIP,
		SrcPort:      0,
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

	msgType := m[1] // DHCPACK, DHCPDISCOVER, etc.
	clientIP := m[2]
	mac := m[3]
	hostname := ""
	if len(m) > 4 {
		hostname = m[4]
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
		SensorID:     a.sensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "dhcp",
		EventType:    "dhcp_" + strings.ToLower(msgType),
		SrcIP:        clientIP,
		SrcPort:      0,
		DstIP:        "",
		DstPort:      0,
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
	action := m[2] // associated, disassociated, etc.

	return &db.Event{
		EventID:      uuid.NewString(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     a.sensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "wifi",
		EventType:    "wifi_" + strings.ToLower(action),
		SrcIP:        "",
		SrcPort:      0,
		DstIP:        "",
		DstPort:      0,
		Protocol:     "802.11",
		Transport:    "",
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
		SensorID:     a.sensorID,
		SourceType:   SourceTypeAsus,
		DetectorType: "wan",
		EventType:    "wan_ip_change",
		SrcIP:        wanIP,
		SrcPort:      0,
		DstIP:        "",
		DstPort:      0,
		Protocol:     "",
		Transport:    "",
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

// parseTimestamp parses the BSD syslog time prefix ("Jan  2 15:04:05").
// Syslog omits the year — we inject the current year and handle the
// Dec→Jan rollover so a log file spanning year-end doesn't produce
// timestamps 12 months in the future.
func (a *AsusAdapter) parseTimestamp(s string) (time.Time, error) {
	// Normalize double-space padding in single-digit days ("Jun  5" → "Jun  5")
	s = strings.Join(strings.Fields(s), " ")
	candidate := fmt.Sprintf("%s %d", s, a.year)
	layout := "Jan 2 15:04:05 2006"

	t, err := time.ParseInLocation(layout, candidate, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("parseTimestamp %q: %w", s, err)
	}

	// If the parsed time is more than 24h in the future, it's a Dec→Jan rollover.
	if t.After(time.Now().Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// Sensor registration
// ---------------------------------------------------------------------------

// RegisterAsusSensor ensures a sensor record exists for the Asus syslog source.
// It is idempotent — safe to call on every startup.
// Returns the sensor_id (either newly created or loaded from the state file at stateFile).
func RegisterAsusSensor(database *db.DB, stateFile string) (string, error) {
	// Try to load a previously assigned sensor_id from the state file.
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

// inferDirection returns "inbound", "outbound", or "internal" based on
// whether src/dst IPs are RFC-1918 private ranges.
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

// isPrivate returns true for RFC-1918 and loopback addresses.
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
	return s[:n] + "…"
}