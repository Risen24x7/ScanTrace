// Package collector — Asus router syslog adapter.
//
// Parses raw syslog lines from an Asus router (ASUSWRT / Merlin) and emits
// normalized Event records. Supported message families:
//
//	• DHCP (dnsmasq-dhcp)  — dhcp_dhcprequest, dhcp_dhcpack, dhcp_dhcpnak
//	• Wi-Fi (wlceventd)    — wifi_associated, wifi_disassociated, wifi_deauthenticated
//	• Netfilter / iptables — netfilter_drop, netfilter_reject (⚠ primary inbound scan source)
//	• Connection tracking  — conn_attempt, conn_established (when enabled)
//	• Firewall block       — firewall_drop, firewall_block
package collector

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Regex patterns for each log family
// ---------------------------------------------------------------------------

var (
	// DHCP — dnsmasq-dhcp lines
	// Example: "Jun 28 14:28:01 dnsmasq-dhcp[1234]: DHCPREQUEST(br0) 192.168.50.238 fe:5d:8f:1d:ef:46"
	dhcpRE = regexp.MustCompile(
		`dnsmasq-dhcp\[\d+\]:\s+(DHCPREQUEST|DHCPACK|DHCPNAK|DHCPOFFER|DHCPDISCOVER)` +
			`(?:\(\S+\))?\s+(\S+)(?:\s+(\S+))?`,
	)

	// Wi-Fi — wlceventd lines
	// Example: "Jun 28 14:29:00 wlceventd: fe:5d:8f:1d:ef:46 Associated at eth6"
	wifiRE = regexp.MustCompile(
		`wlceventd[^:]*:\s+(\S+)\s+(Associated|Disassociated|Authenticated|Deauthenticated|Disconnected)`,
	)

	// Netfilter DROP/REJECT — iptables LOG target
	// Example: "Jun 28 15:01:22 kernel: DROP IN=eth0 OUT= SRC=24.20.77.75 DST=192.168.50.1 ... PROTO=TCP SPT=54321 DPT=22"
	netfilterRE = regexp.MustCompile(
		`kernel:\s+(DROP|REJECT|BLOCK)\s+IN=\S*\s+OUT=\S*\s+SRC=(\S+)\s+DST=(\S+)` +
			`.*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?`,
	)

	// Firewall block — ASUSWRT firewall log format
	// Example: "Jun 28 15:01:22 rc_service: nflog BLOCK SRC=24.20.77.75 DST=192.168.50.1 DPT=443"
	firewallRE = regexp.MustCompile(
		`(?:rc_service|firewall)[^:]*:.*?(?:BLOCK|DROP|REJECT)\s+SRC=(\S+)\s+DST=(\S+)(?:.*?DPT=(\d+))?`,
	)

	// Connection attempt — ASUSWRT connection tracking
	// Example: "Jun 28 15:01:22 kernel: [CONN] NEW SRC=24.20.77.75 DST=192.168.50.1 PROTO=TCP DPT=8080"
	connRE = regexp.MustCompile(
		`\[CONN\]\s+NEW\s+SRC=(\S+)\s+DST=(\S+)\s+PROTO=(\S+)(?:.*?DPT=(\d+))?`,
	)

	// Timestamp prefix present on most syslog lines
	// Example: "Jun 28 14:28:01 ..."
	timestampRE = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+`)
)

// ---------------------------------------------------------------------------
// AsusParser
// ---------------------------------------------------------------------------

// AsusParser parses raw ASUSWRT syslog lines into normalized Event records.
type AsusParser struct {
	SensorID string
	Year     int // injected so tests are deterministic; 0 = time.Now().Year()
}

// Parse converts a single syslog line into an Event.
// Returns (nil, nil) for lines that don't match any known pattern.
func (p *AsusParser) Parse(line string) (*db.Event, error) {
	ts := p.extractTimestamp(line)

	switch {
	case dhcpRE.MatchString(line):
		return p.parseDHCP(line, ts)
	case wifiRE.MatchString(line):
		return p.parseWifi(line, ts)
	case netfilterRE.MatchString(line):
		return p.parseNetfilter(line, ts)
	case firewallRE.MatchString(line):
		return p.parseFirewall(line, ts)
	case connRE.MatchString(line):
		return p.parseConn(line, ts)
	}
	return nil, nil
}

func (p *AsusParser) extractTimestamp(line string) time.Time {
	year := p.Year
	if year == 0 {
		year = time.Now().Year()
	}
	if m := timestampRE.FindStringSubmatch(line); m != nil {
		raw := fmt.Sprintf("%s %d", m[1], year)
		if t, err := time.Parse("Jan _2 15:04:05 2006", raw); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse("Jan  2 15:04:05 2006", raw); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func (p *AsusParser) parseDHCP(line string, ts time.Time) (*db.Event, error) {
	m := dhcpRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	msgType := strings.ToLower(m[1])
	ip := m[2]
	mac := ""
	if len(m) > 3 {
		mac = m[3]
	}
	if net.ParseIP(ip) == nil {
		ip, mac = mac, ip // some firmware reverses the order
	}
	evt := &db.Event{
		EventID:    uuid.New().String(),
		Timestamp:  ts,
		FirstSeen:  ts,
		LastSeen:   ts,
		SensorID:   p.SensorID,
		SourceType: "asus_syslog",
		EventType:  "dhcp_" + msgType,
		SrcIP:      ip,
		Notes:      mac,
	}
	return evt, nil
}

func (p *AsusParser) parseWifi(line string, ts time.Time) (*db.Event, error) {
	m := wifiRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	mac := m[1]
	action := strings.ToLower(m[2])
	evtType := "wifi_" + action
	evt := &db.Event{
		EventID:    uuid.New().String(),
		Timestamp:  ts,
		FirstSeen:  ts,
		LastSeen:   ts,
		SensorID:   p.SensorID,
		SourceType: "asus_syslog",
		EventType:  evtType,
		SrcIP:      mac, // MAC stored in SrcIP for Wi-Fi events — no IP assigned yet
	}
	return evt, nil
}

// parseNetfilter handles iptables LOG target lines.
// These are the MOST IMPORTANT events for detecting external port scans —
// every dropped inbound packet from an external IP lands here.
func (p *AsusParser) parseNetfilter(line string, ts time.Time) (*db.Event, error) {
	m := netfilterRE.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	action := strings.ToLower(m[1]) // drop | reject | block
	srcIP := m[2]
	dstIP := m[3]
	proto := strings.ToUpper(m[4])

	srcPort := 0
	if len(m) > 5 && m[5] != "" {
		srcPort, _ = strconv.Atoi(m[5])
	}
	dstPort := 0
	if len(m) > 6 && m[6] != "" {
		dstPort, _ = strconv.Atoi(m[6])
	}

	evtType := "netfilter_" + action

	evt := &db.Event{
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
		Direction:    "inbound",
		RawRef:       line,
	}
	return evt, nil
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
	evt := &db.Event{
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
		Direction:    "inbound",
		RawRef:       line,
	}
	return evt, nil
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
	evt := &db.Event{
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
		Direction:    "inbound",
		RawRef:       line,
	}
	return evt, nil
}
