// Package correlator — named detection rules.
//
// Each Rule inspects a fully-built IPCluster and returns a RuleMatch when the
// cluster satisfies the rule's criteria. Rules are stateless and pure so they
// can be tested independently of the DB.
//
// Special sentinel:
//   RuleType == "suppressed" means the correlator should skip case creation
//   entirely for this cluster. CloudSuppressRule uses this to eliminate
//   well-known hyperscaler probes to the WAN gateway interface.
package correlator

import (
	"fmt"
	"strings"
	"time"
)

// RuleMatch describes which rule fired and why.
type RuleMatch struct {
	RuleName    string
	RuleType    string // inbound_scan | port_scan | repeated_drop | new_device | generic_scan | suppressed
	Description string
}

// Rule is a single detection rule over an IPCluster.
type Rule interface {
	Eval(cl *IPCluster) *RuleMatch
}

// ---------------------------------------------------------------------------
// CloudSuppressRule — suppresses single-event clusters from well-known
// hyperscaler ASNs hitting only the WAN gateway interface on common ports.
// ---------------------------------------------------------------------------

// knownCloudASNs is the set of ASN strings (as returned by ipinfo.io org
// field prefix, e.g. "AS8075") belonging to major cloud/CDN providers whose
// routine internet probing should not generate cases.
var knownCloudASNs = map[string]string{
	// Microsoft / Azure
	"AS8075": "Microsoft",
	"AS8069": "Microsoft",
	"AS8070": "Microsoft",
	"AS8071": "Microsoft",
	"AS8072": "Microsoft",
	"AS8073": "Microsoft",
	"AS8074": "Microsoft",
	"AS3598": "Microsoft",
	// Google / GCP
	"AS15169": "Google",
	"AS396982": "Google",
	// Amazon / AWS
	"AS16509": "Amazon",
	"AS14618": "Amazon",
	// Cloudflare
	"AS13335": "Cloudflare",
	// Akamai
	"AS20940": "Akamai",
	"AS16625": "Akamai",
	"AS21342": "Akamai",
	// Meta
	"AS32934": "Meta",
	// Apple
	"AS714":   "Apple",
	"AS6185":  "Apple",
	// Fastly
	"AS54113": "Fastly",
}

// wellKnownGatewayPorts are ports that a WAN router legitimately receives
// unsolicited packets on from internet hosts as part of normal internet noise.
// Traffic to these ports from cloud ASNs is not actionable.
var wellKnownGatewayPorts = map[int]bool{
	22:   true, // SSH brute-force noise (drop rule fires, not alarming from cloud)
	53:   true, // DNS — common misconfigured resolver probes
	80:   true, // HTTP
	443:  true, // HTTPS
	8080: true, // Alt HTTP
	8443: true, // Alt HTTPS
	123:  true, // NTP
	0:    true, // ICMP / proto-only events
}

// EntityASNFunc is an optional callback the CloudSuppressRule uses to look up
// the ASN for a src IP. It mirrors db.DB.GetEntityByIP without importing db.
type EntityASNFunc func(ip string) (asn string, ok bool)

// CloudSuppressRule suppresses cases where:
//  1. The cluster has only 1 event (transient probe, not a pattern), OR
//     all events target the WAN gateway (.1 address) on a well-known port.
//  2. The source resolves to a known hyperscaler ASN.
//
// It returns a sentinel RuleMatch with RuleType="suppressed" so the
// correlator's Run() can skip openCase without logging a false alert.
type CloudSuppressRule struct {
	// LookupASN is optional. If nil, ASN-based suppression is skipped and
	// only the structural (single-event + gateway-port) check applies.
	LookupASN EntityASNFunc
}

func (r *CloudSuppressRule) Eval(cl *IPCluster) *RuleMatch {
	if !isExternal(cl.SrcIP) {
		return nil
	}

	// Structural check: all events target the WAN gateway on a common port.
	if !allEventsToGateway(cl) {
		return nil
	}

	// If we have an ASN lookup, require it to be a known cloud ASN.
	// If no lookup is provided, suppress anyway (gateway-port heuristic alone
	// is sufficient for 53/80/443 from any single-event cluster).
	if r.LookupASN != nil {
		asn, ok := r.LookupASN(cl.SrcIP)
		if !ok {
			// Entity not in DB yet — do not suppress; let the case open so
			// the inline enricher fills in the ASN for next time.
			return nil
		}
		provider, known := knownCloudASNs[asn]
		if !known {
			return nil
		}
		return &RuleMatch{
			RuleName: "cloud_suppress",
			RuleType: "suppressed",
			Description: fmt.Sprintf(
				"Suppressed: %s (%s %s) — WAN gateway probe on common port, not actionable",
				cl.SrcIP, provider, asn,
			),
		}
	}

	// No ASN lookup wired — suppress single-event gateway probes on well-known
	// ports as pure structural noise (internet background radiation).
	if len(cl.Events) == 1 && isSingleEventWANProbe(cl) {
		return &RuleMatch{
			RuleName:    "cloud_suppress",
			RuleType:    "suppressed",
			Description: fmt.Sprintf("Suppressed: %s — single-event WAN gateway probe on well-known port", cl.SrcIP),
		}
	}

	return nil
}

// allEventsToGateway returns true when every event in the cluster targets
// a WAN gateway IP (ends in .1) on a well-known port.
func allEventsToGateway(cl *IPCluster) bool {
	if len(cl.Events) == 0 {
		return false
	}
	for _, e := range cl.Events {
		if !isGatewayIP(e.DstIP) {
			return false
		}
		if !wellKnownGatewayPorts[e.DstPort] {
			return false
		}
	}
	return true
}

// isGatewayIP returns true for IPs that look like a router's WAN or LAN
// gateway interface: x.x.x.1, or common gateway addresses.
func isGatewayIP(ip string) bool {
	if ip == "" {
		return false
	}
	// Ends in .1 — covers 192.168.1.1, 10.0.0.1, 172.x.x.1, etc.
	if strings.HasSuffix(ip, ".1") {
		return true
	}
	// Also catch common .254 gateway addresses (some ISP CPE uses these).
	if strings.HasSuffix(ip, ".254") {
		return true
	}
	return false
}

// isSingleEventWANProbe returns true when the cluster is a 1-event probe
// to a gateway IP on a well-known port.
func isSingleEventWANProbe(cl *IPCluster) bool {
	if len(cl.Events) != 1 {
		return false
	}
	e := cl.Events[0]
	return isGatewayIP(e.DstIP) && wellKnownGatewayPorts[e.DstPort]
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
// CloudSuppressRule is always first so it short-circuits before any
// detection rule runs on known-benign hyperscaler traffic.
// ---------------------------------------------------------------------------

func DefaultRules() []Rule {
	return []Rule{
		&CloudSuppressRule{}, // must be first — sentinel suppressor
		&ExternalScanRule{MinPorts: 1},
		&PortScanRule{MinPorts: 5},
		&RepeatedDropRule{MinDrops: 3},
		&NewDeviceRule{},
	}
}
