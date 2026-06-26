// Package correlator — named detection rules.
//
// Each Rule inspects a fully-built IPCluster and returns a RuleMatch when the
// cluster satisfies the rule's criteria. Rules are stateless and pure so they
// can be tested independently of the DB.
package correlator

import (
	"fmt"
	"time"
)

// RuleMatch describes which rule fired and why.
type RuleMatch struct {
	RuleName    string
	RuleType    string // port_scan | repeated_drop | new_device | generic_scan
	Description string
}

// Rule is a single detection rule over an IPCluster.
type Rule interface {
	Eval(cl *IPCluster) *RuleMatch
}

// ---------------------------------------------------------------------------
// PortScanRule — N distinct destination ports from the same src IP.
// ---------------------------------------------------------------------------

type PortScanRule struct {
	MinPorts int // default 5
	Window   time.Duration
}

func (r *PortScanRule) Eval(cl *IPCluster) *RuleMatch {
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
	MinDrops int // default 3
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
			"ids_alert", "blocked":
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
// NewDeviceRule — fires once when a cluster contains a first-ever DHCP or
// WiFi association event (new MAC on the network).
// ---------------------------------------------------------------------------

type NewDeviceRule struct{}

func (r *NewDeviceRule) Eval(cl *IPCluster) *RuleMatch {
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
// DefaultRules returns the standard rule set used by the correlator.
// ---------------------------------------------------------------------------

func DefaultRules() []Rule {
	return []Rule{
		&PortScanRule{MinPorts: 5},
		&RepeatedDropRule{MinDrops: 3},
		&NewDeviceRule{},
	}
}
