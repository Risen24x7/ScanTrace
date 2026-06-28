// Package collector — Asus router syslog adapter.
//
// Parses raw syslog lines from an Asus router (ASUSWRT / Merlin) and emits
// normalized Event records. Supported message families:
//
//	• DHCP (dnsmasq-dhcp)  — dhcp_dhcprequest, dhcp_dhcpack, dhcp_dhcpnak
//	• Wi-Fi (wlceventd)    — wifi_associated, wifi_disassociated, wifi_deauthenticated
//	• Netfilter / iptables — netfilter_drop, netfilter_reject (legacy DROP prefix)
//	• WAN new connections  — wan_new_connection (WAN_NEW_ACCEPT prefix, eth0 NEW)
//	• WAN port-forwards    — wan_forward (WAN_FWD prefix, eth0→br0 NEW)
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

	// Netfilter DROP/REJECT — legacy iptables LOG target with bare DROP/REJECT prefix
	// Example: "Jun 28 15:01:22 kernel: DROP IN=eth0 OUT= SRC=24.20.77.75 DST=192.168.50.1 ... PROTO=TCP SPT=54321 DPT=22"
	netfilterRE = regexp.MustCompile(
		`kernel:\s+(DROP|REJECT|BLOCK)\s+IN=\S*\s+OUT=\S*\s+SRC=(\S+)\s+DST=(\S+)` +
			`.*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?`,
	)

	// WAN new connection — iptables LOG with WAN_NEW_ACCEPT prefix (eth0, state NEW)
	// These are inbound WAN connections that reached an open port on the router.
	// Example: "Jun 28 16:01:14 kernel: WAN_NEW_ACCEPT IN=eth0 OUT= MAC=... SRC=198.235.24.117 DST=24.20.77.75 LEN=44 ... PROTO=TCP SPT=52336 DPT=7777 ..."
	wanAcceptRE = regexp.MustCompile(
		`kernel:\s+WAN_NEW_ACCEPT\s+IN=(\S+)\s+OUT=\S*\s+` +
			`(?:MAC=\S+\s+)?SRC=(\S+)\s+DST=(\S+)` +
			`.*?PROTO=(\S+)(?:.*?SPT=(\d+))?(?:.*?DPT=(\d+))?`,
	)

	// WAN forward — iptables LOG with WAN_FWD prefix (eth0→br0, state NEW)
	// These are inbound WAN connections forwarded to an internal host via port-forward rules.
	// Example: "Jun 28 16:01:20 kernel: WAN_FWD IN=eth0 OUT=br0 MAC=... SRC=134.122.125.153 DST=192.168.50.10 LEN=60 ... PROTO=TCP SPT=34028 DPT=25565 ..."
	wanFwdRE = regexp.MustCompile(
		`kernel:\s+WAN_FWD\s+IN=(\S+)\s+OUT=(\S+)\s+` +
			`(?:MAC=\S+\s+)?SRC=(\S+)\s+DST=(\S+)` +
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

// parseWANAccept handles WAN_NEW_ACCEPT iptables LOG lines.
// These are inbound WAN connections that reached an open port on the router itself.
// Highest severity — something on the router answered.
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

// parseWANFwd handles WAN_FWD iptables LOG lines.
// These are inbound WAN connections forwarded to an internal host via port-forward rules.
// SrcIP is the external scanner, DstIP is the internal host being hit.
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

// parseNetfilter handles legacy iptables LOG target lines with bare DROP/REJECT prefix.
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
	}, nil
}
