// Package correlator — named detection rules.
//
// Each Rule inspects a fully-built IPCluster and returns a RuleMatch when the
// cluster satisfies the rule's criteria. Rules are stateless and pure so they
// can be tested independently of the DB.
package correlator

import (
	"fmt"
	"strings"
	"time"
)

// RuleMatch describes which rule fired and why.
type RuleMatch struct {
	RuleName    string
	RuleType    string // inbound_scan | port_scan | repeated_drop | new_device | generic_scan
	Description string
}

// Rule is a single detection rule over an IPCluster.
type Rule interface {
	Eval(cl *IPCluster) *RuleMatch
}

// ---------------------------------------------------------------------------
// ExternalScanRule — an EXTERNAL IP (non-RFC1918) touches N+ distinct
// destination ports on internal hosts.
// ---------------------------------------------------------------------------

func isExternal(ip string) bool {
	if ip == "" {
		return false
	}
	for _, prefix := range []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"127.",
		"169.254.",
		"0.0.0.0",
		"::1",
	} {
		if strings.HasPrefix(ip, prefix) {
			return false
		}
	}
	return true
}

// scanEventTypes is the set of event types that count as inbound connection
// attempts for external scan detection. Includes WAN router event types.
var scanEventTypes = map[string]bool{
	"netfilter_drop":    true,
	"netfilter_reject":  true,
	"ids_alert":         true,
	"suricata_alert":    true,
	"blocked":           true,
	"conn_attempt":      true,
	"tcp_syn":           true,
	"firewall_drop":     true,
	"firewall_block":    true,
	"portscan_detected": true,
	// ASUS BE96U WAN events
	"wan_new_connection": true,
	"wan_forward":        true,
}

type ExternalScanRule struct {
	// MinPorts is the minimum number of distinct destination ports before the
	// rule fires. Set to 1 so every unique external inbound hit generates a case.
	MinPorts int
}

func (r *ExternalScanRule) Eval(cl *IPCluster) *RuleMatch {
	if !isExternal(cl.SrcIP) {
		return nil
	}
	min := r.MinPorts
	if min == 0 {
		min = 1
	}

	scanEvents := 0
	scanPorts := make(map[int]bool)
	for _, e := range cl.Events {
		if scanEventTypes[e.EventType] {
			scanEvents++
			if e.DstPort > 0 {
				scanPorts[e.DstPort] = true
			}
		}
	}

	// Any external IP touching any port is anomalous.
	for _, e := range cl.Events {
		if e.DstPort > 0 {
			scanPorts[e.DstPort] = true
		}
	}

	if scanEvents == 0 {
		return nil
	}

	if len(scanPorts) < min {
		// Still fire if we have scan events but no port info (e.g. IGMP)
		if scanEvents == 0 {
			return nil
		}
	}

	portList := make([]string, 0, len(scanPorts))
	for p := range scanPorts {
		portList = append(portList, fmt.Sprintf("%d", p))
	}

	return &RuleMatch{
		RuleName: "inbound_scan",
		RuleType: "inbound_scan",
		Description: fmt.Sprintf(
			"External IP %s probed %d ports [%s] (%d events)",
			cl.SrcIP, len(scanPorts), strings.Join(portList, ", "), scanEvents,
		),
	}
}

// ---------------------------------------------------------------------------
// PortScanRule — N distinct destination ports from the same src IP.
// ---------------------------------------------------------------------------

type PortScanRule struct {
	MinPorts int
	Window   time.Duration
}

func (r *PortScanRule) Eval(cl *IPCluster) *RuleMatch {
	if isExternal(cl.SrcIP) {
		return nil
	}
	min := r.MinPorts
	if min == 0 {
		min = 5
	}
	if len(cl.Ports) >= min {
		return &RuleMatch{
			RuleName:    "port_scan",
			RuleType:    "port_scan",
			Description: fmt.Sprintf("%s touched %d distinct ports (%d events)", cl.SrcIP, len(cl.Ports), len(cl.Events)),
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// RepeatedDropRule — same src IP hit the DROP rule N+ times.
// ---------------------------------------------------------------------------

type RepeatedDropRule struct {
	MinDrops int
}

func (r *RepeatedDropRule) Eval(cl *IPCluster) *RuleMatch {
	min := r.MinDrops
	if min == 0 {
		min = 3
	}
	drops := 0
	for _, e := range cl.Events {
		switch e.EventType {
		case "netfilter_drop", "netfilter_reject",
			"ids_alert", "blocked", "firewall_drop", "firewall_block":
			drops++
		}
	}
	if drops >= min {
		return &RuleMatch{
			RuleName:    "repeated_drop",
			RuleType:    "repeated_drop",
			Description: fmt.Sprintf("%s was blocked %d times", cl.SrcIP, drops),
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// NewDeviceRule — fires when a new MAC appears on the network.
// ---------------------------------------------------------------------------

type NewDeviceRule struct{}

func (r *NewDeviceRule) Eval(cl *IPCluster) *RuleMatch {
	if isExternal(cl.SrcIP) {
		return nil
	}
	for _, e := range cl.Events {
		switch e.EventType {
		case "dhcp_dhcpack", "wifi_associated", "wifi_authenticated":
			return &RuleMatch{
				RuleName:    "new_device",
				RuleType:    "new_device",
				Description: fmt.Sprintf("New device seen at %s (%s)", cl.SrcIP, e.EventType),
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// DefaultRules returns the standard rule set.
// ---------------------------------------------------------------------------

func DefaultRules() []Rule {
	return []Rule{
		&ExternalScanRule{MinPorts: 1},
		&PortScanRule{MinPorts: 5},
		&RepeatedDropRule{MinDrops: 3},
		&NewDeviceRule{},
	}
}
