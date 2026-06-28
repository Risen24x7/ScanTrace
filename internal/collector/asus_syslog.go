// Package collector — Asus router syslog adapter.
//
// Parses raw syslog lines from an Asus router (ASUSWRT / Merlin firmware) and
// emits normalized Event records.
//
// Supported timestamp formats:
//   RFC3339:  2026-06-25T20:05:01+00:00 hostname process[pid]: body
//   BSD:      Jun 25 20:05:01 hostname process[pid]: body
//
// Supported message families:
//   • DHCP (dnsmasq-dhcp)   — dhcp_dhcprequest, dhcp_dhcpack, dhcp_dhcpnak
//   • Wi-Fi (hostapd)       — wifi_associated, wifi_disassociated, wifi_deauthenticated
//   • Netfilter / iptables  — netfilter_drop, netfilter_reject, netfilter_accept
//   • WAN new connections   — wan_new_connection (WAN_NEW_ACCEPT, eth0 NEW)
//   • WAN port-forwards     — wan_forward (WAN_FWD, eth0→br0 NEW)
//   • Connection tracking   — conn_attempt
//   • Firewall block        — firewall_block
package collector

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

var (
	// RFC3339 timestamp prefix — produced by BE96U / Merlin firmware.
	// Example: "2026-06-25T20:38:19+00:00 hostname process: body"
	ts3339RE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+`)

	// BSD syslog timestamp prefix — produced by older ASUSWRT firmware.
	// Example: "Jun 25 20:05:01 hostname process: body"
	tsBSDRE = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+`)

	// DHCP — dnsmasq-dhcp lines
	// Example: "... dnsmasq-dhcp[8492]: DHCPACK(br0) 192.168.50.238 70:f0:88:2d:db:1e"
	dhcpRE = regexp.MustCompile(
		`dnsmasq-dhcp\[\d+\]:\s+(DHCPREQUEST|DHCPACK|DHCPNAK|DHCPOFFER|DHCPDISCOVER)` +
			`(?:\(\S+\))?\s+(\S+)(?:\s+(\S+))?(?:\s+(\S+))?`,
	)

	// Wi-Fi — hostapd lines (BE96U real format)
	// Example: "... hostapd: wl2.1: STA fe:5d:8f:1d:ef:46 IEEE 802.11: associated (aid 2)"
	// Example: "... hostapd: wl1.1: STA fe:5d:8f:1d:ef:46 IEEE 802.11: disassociated"
	hostapdRE = regexp.MustCompile(
		`hostapd:\s+\S+:\s+STA\s+(\S+)\s+IEEE\s+802\.11:\s+(\S+)`,
	)

	// Netfilter — iptables LOG target (DROP, REJECT, ACCEPT, BLOCK)
	// Example: "... kernel: DROP IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=185.220.101.45 DST=192.168.50.1 ... PROTO=TCP SPT=54321 DPT=22 ..."
	netfilterRE = regexp.MustCompile(
		`kernel:\s+(DROP|REJECT|ACCEPT|BLOCK)\s+IN=(\S*)\s+OUT=(\S*)\s+` +
			`(?:MAC=\S+\s+)?SRC=(\S+)\s+DST=(\S+)` +
			`.*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?`,
	)

	// WAN_NEW_ACCEPT — inbound connection that reached an open port on the router
	wanAcceptRE = regexp.MustCompile(
		`kernel:\s+WAN_NEW_ACCEPT\s+IN=(\S+)\s+OUT=\S*\s+` +
			`(?:MAC=\S+\s+)?SRC=(\S+)\s+DST=(\S+)` +
			`.*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?`,
	)

	// WAN_FWD — inbound connection forwarded to an internal host
	wanFwdRE = regexp.MustCompile(
		`kernel:\s+WAN_FWD\s+IN=(\S+)\s+OUT=(\S+)\s+` +
			`(?:MAC=\S+\s+)?SRC=(\S+)\s+DST=(\S+)` +
			`.*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?`,
	)

	// Firewall block — rc_service / firewall log format
	firewallRE = regexp.MustCompile(
		`(?:rc_service|firewall)[^:]*:.*?(?:BLOCK|DROP|REJECT)\s+SRC=(\S+)\s+DST=(\S+)(?:.*?DPT=(\d+))?`,
	)

	// Connection tracking — [CONN] NEW
	connRE = regexp.MustCompile(
		`\[CONN\]\s+NEW\s+SRC=(\S+)\s+DST=(\S+)\s+PROTO=(\S+)(?:.*?DPT=(\d+))?`,
	)

	// wlceventd lines — non-security, always skip
	wlceventdRE = regexp.MustCompile(`wlceventd:`)
)

// ---------------------------------------------------------------------------
// Sentinel for lines with no parseable timestamp/process prefix
// ---------------------------------------------------------------------------

// ErrMalformed is returned for lines that have no recognizable syslog structure.
var ErrMalformed = fmt.Errorf("asus_syslog: malformed line")

// ---------------------------------------------------------------------------
// inferDirection classifies traffic direction based on src/dst RFC1918 membership.
//
//   external → internal  = inbound
//   internal → external  = outbound
//   internal → internal  = internal
//   external → external  = unknown
func inferDirection(srcIP, dstIP string) string {
	srcPriv := isPrivate(srcIP)
	dstPriv := isPrivate(dstIP)
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

// isPrivate reports whether ipStr is an RFC1918/loopback/link-local address.
func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// RegisterAsusSensor ensures a stable sensor UUID is persisted in statePath
// and registered in the DB. It is safe to call on every startup.
func RegisterAsusSensor(store *db.DB, statePath string) (string, error) {
	// Try to read existing ID from state file.
	if data, err := os.ReadFile(statePath); err == nil {
		sensorID := strings.TrimSpace(string(data))
		if sensorID != "" {
			return sensorID, nil
		}
	}

	// Generate a new UUID and persist it.
	sensorID := uuid.New().String()
	if err := os.WriteFile(statePath, []byte(sensorID+"\n"), 0o600); err != nil {
		// Non-fatal: we'll use the UUID in-memory.
		fmt.Printf("[asus] warning: could not write sensor state file %s: %v\n", statePath, err)
	}

	h, _ := os.Hostname()
	sensor := &db.Sensor{
		SensorID:      sensorID,
		Hostname:      h,
		Platform:      "asus",
		Role:          "router",
		CollectorType: "asus_syslog",
		Version:       "0.1.0",
	}
	if err := store.InsertSensor(sensor); err != nil {
		return "", fmt.Errorf("RegisterAsusSensor: InsertSensor: %w", err)
	}
	return sensorID, nil
}

// ---------------------------------------------------------------------------
// AsusParser
// ---------------------------------------------------------------------------

// AsusParser parses raw ASUSWRT syslog lines into normalized Event records.
type AsusParser struct {
	SensorID string
	Year     int // injected so tests are deterministic; 0 = time.Now().Year()
}

// NewAsusAdapter returns an AsusParser ready for use with SyslogServer or TailFile.
func NewAsusAdapter(sensorID string) *AsusParser {
	return &AsusParser{SensorID: sensorID}
}

// Parse converts a single syslog line into an Event.
//
// Returns:
//   - (event, nil)       — line matched and produced a security event
//   - (nil, ErrSkip)     — line is well-formed but intentionally not tracked
//   - (nil, ErrMalformed)— line has no recognizable syslog structure at all
func (p *AsusParser) Parse(line string) (*db.Event, error) {
	// Skip wlceventd noise before any other check.
	if wlceventdRE.MatchString(line) {
		return nil, Skip("wlceventd: non-security")
	}

	// Require a recognizable syslog prefix (RFC3339 or BSD timestamp).
	if !ts3339RE.MatchString(line) && !tsBSDRE.MatchString(line) {
		return nil, ErrMalformed
	}

	ts := p.extractTimestamp(line)

	switch {
	case dhcpRE.MatchString(line):
		return p.parseDHCP(line, ts)
	case hostapdRE.MatchString(line):
		return p.parseHostapd(line, ts)
	case wanAcceptRE.MatchString(line):
		return p.parseWANAccept(line, ts)
	case wanFwdRE.MatchString(line):
		return p.parseWANFwd(line, ts)
	case netfilterRE.MatchString(line):
		return p.parseNetfilter(line, ts)
	case firewallRE.MatchString(line):
		return p.parseFirewall(line, ts)
	case connRE.MatchString(line):
		return p.parseConn(line, ts)
	}
	// Well-formed syslog line but no pattern matched — skip silently.
	return nil, Skip("asus_syslog: unrecognized process")
}

func (p *AsusParser) extractTimestamp(line string) time.Time {
	// RFC3339 with timezone offset (BE96U default)
	if m := ts3339RE.FindStringSubmatch(line); m != nil {
		for _, layout := range []string{
			"2006-01-02T15:04:05-07:00",
			"2006-01-02T15:04:05+00:00",
			"2006-01-02T15:04:05Z07:00",
		} {
			if t, err := time.Parse(layout, m[1]); err == nil {
				return t.UTC()
			}
		}
	}
	// BSD timestamp — inject current year
	year := p.Year
	if year == 0 {
		year = time.Now().Year()
	}
	if m := tsBSDRE.FindStringSubmatch(line); m != nil {
		raw := fmt.Sprintf("%s %d", m[1], year)
		for _, layout := range []string{"Jan _2 15:04:05 2006", "Jan  2 15:04:05 2006"} {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Now().UTC()
}

// parseDHCP handles dnsmasq-dhcp lines.
// Notes field: "mac=<mac>" so tests can assert strings.Contains(evt.Notes, "mac=").
func (p *AsusParser) parseDHCP(line string, ts time.Time) (*db.Event, error) {
	m := dhcpRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	// m[1]=msgType m[2]=field1 m[3]=field2(opt) m[4]=hostname(opt)
	msgType := strings.ToLower(m[1])
	f1, f2 := m[2], ""
	if len(m) > 3 {
		f2 = m[3]
	}

	// Determine which field is IP and which is MAC.
	ip, mac := f1, f2
	if net.ParseIP(f1) == nil && net.ParseIP(f2) != nil {
		ip, mac = f2, f1
	}

	notes := ""
	if mac != "" {
		notes = "mac=" + mac
	}

	return &db.Event{
		EventID:    uuid.New().String(),
		Timestamp:  ts,
		FirstSeen:  ts,
		LastSeen:   ts,
		SensorID:   p.SensorID,
		SourceType: "asus_syslog",
		EventType:  "dhcp_" + msgType,
		SrcIP:      ip,
		Notes:      notes,
	}, nil
}

// parseHostapd handles hostapd Wi-Fi association/disassociation lines.
// Notes field: "mac=<mac>" so tests can assert strings.Contains(evt.Notes, "mac=").
func (p *AsusParser) parseHostapd(line string, ts time.Time) (*db.Event, error) {
	m := hostapdRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	mac := m[1]
	action := strings.ToLower(m[2])

	evtType := "wifi_" + action

	return &db.Event{
		EventID:    uuid.New().String(),
		Timestamp:  ts,
		FirstSeen:  ts,
		LastSeen:   ts,
		SensorID:   p.SensorID,
		SourceType: "asus_syslog",
		EventType:  evtType,
		SrcIP:      mac, // MAC stored in SrcIP until DHCP assigns an IP
		Notes:      "mac=" + mac,
	}, nil
}

// parseNetfilter handles iptables LOG lines (DROP, REJECT, ACCEPT, BLOCK).
func (p *AsusParser) parseNetfilter(line string, ts time.Time) (*db.Event, error) {
	m := netfilterRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	// m[1]=action m[2]=in m[3]=out m[4]=srcIP m[5]=dstIP m[6]=proto m[7]=spt m[8]=dpt
	action := strings.ToLower(m[1])
	srcIP := m[4]
	dstIP := m[5]
	proto := strings.ToUpper(m[6])
	srcPort := 0
	if m[7] != "" {
		srcPort, _ = strconv.Atoi(m[7])
	}
	dstPort := 0
	if m[8] != "" {
		dstPort, _ = strconv.Atoi(m[8])
	}

	evtType := "netfilter_" + action
	dir := inferDirection(srcIP, dstIP)

	tags := db.StringSlice{}
	if action == "drop" || action == "reject" || action == "block" {
		tags = append(tags, "blocked", "firewall_drop")
	}

	return &db.Event{
		EventID:      uuid.New().String(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     p.SensorID,
		SourceType:   "asus_syslog",
		DetectorType: "netfilter",
		EventType:    evtType,
		SrcIP:        srcIP,
		SrcPort:      srcPort,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Protocol:     proto,
		Direction:    dir,
		RawRef:       line,
		Tags:         tags,
	}, nil
}

func (p *AsusParser) parseWANAccept(line string, ts time.Time) (*db.Event, error) {
	m := wanAcceptRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	// m[1]=iface m[2]=srcIP m[3]=dstIP m[4]=proto m[5]=spt m[6]=dpt
	srcIP := m[2]
	dstIP := m[3]
	proto := strings.ToUpper(m[4])
	srcPort := 0
	if m[5] != "" {
		srcPort, _ = strconv.Atoi(m[5])
	}
	dstPort := 0
	if m[6] != "" {
		dstPort, _ = strconv.Atoi(m[6])
	}
	return &db.Event{
		EventID:      uuid.New().String(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     p.SensorID,
		SourceType:   "asus_syslog",
		DetectorType: "netfilter",
		EventType:    "wan_new_connection",
		SrcIP:        srcIP,
		SrcPort:      srcPort,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Protocol:     proto,
		Direction:    "inbound",
		RawRef:       line,
	}, nil
}

func (p *AsusParser) parseWANFwd(line string, ts time.Time) (*db.Event, error) {
	m := wanFwdRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	// m[1]=inIface m[2]=outIface m[3]=srcIP m[4]=dstIP m[5]=proto m[6]=spt m[7]=dpt
	srcIP := m[3]
	dstIP := m[4]
	proto := strings.ToUpper(m[5])
	srcPort := 0
	if m[6] != "" {
		srcPort, _ = strconv.Atoi(m[6])
	}
	dstPort := 0
	if m[7] != "" {
		dstPort, _ = strconv.Atoi(m[7])
	}
	return &db.Event{
		EventID:      uuid.New().String(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     p.SensorID,
		SourceType:   "asus_syslog",
		DetectorType: "netfilter",
		EventType:    "wan_forward",
		SrcIP:        srcIP,
		SrcPort:      srcPort,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Protocol:     proto,
		Direction:    "inbound",
		RawRef:       line,
	}, nil
}

func (p *AsusParser) parseFirewall(line string, ts time.Time) (*db.Event, error) {
	m := firewallRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	srcIP := m[1]
	dstIP := m[2]
	dstPort := 0
	if len(m) > 3 && m[3] != "" {
		dstPort, _ = strconv.Atoi(m[3])
	}
	return &db.Event{
		EventID:      uuid.New().String(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     p.SensorID,
		SourceType:   "asus_syslog",
		DetectorType: "firewall",
		EventType:    "firewall_block",
		SrcIP:        srcIP,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Direction:    inferDirection(srcIP, dstIP),
		RawRef:       line,
	}, nil
}

func (p *AsusParser) parseConn(line string, ts time.Time) (*db.Event, error) {
	m := connRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	srcIP := m[1]
	dstIP := m[2]
	proto := strings.ToUpper(m[3])
	dstPort := 0
	if len(m) > 4 && m[4] != "" {
		dstPort, _ = strconv.Atoi(m[4])
	}
	return &db.Event{
		EventID:      uuid.New().String(),
		Timestamp:    ts,
		FirstSeen:    ts,
		LastSeen:     ts,
		SensorID:     p.SensorID,
		SourceType:   "asus_syslog",
		DetectorType: "conntrack",
		EventType:    "conn_attempt",
		SrcIP:        srcIP,
		DstIP:        dstIP,
		DstPort:      dstPort,
		Protocol:     proto,
		Direction:    inferDirection(srcIP, dstIP),
		RawRef:       line,
	}, nil
}
