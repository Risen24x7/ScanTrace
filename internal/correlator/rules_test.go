package correlator

import (
	"testing"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
)

func makeEvent(eventType string, dstPort int) *db.Event {
	return &db.Event{
		EventID:   "test-" + eventType,
		EventType: eventType,
		SrcIP:     "1.2.3.4",
		DstPort:   dstPort,
		Timestamp: time.Now(),
	}
}

func makeCluster(events []*db.Event) *IPCluster {
	cl := &IPCluster{
		SrcIP:     "1.2.3.4",
		Ports:     make(map[int]int),
		Protocols: make(map[string]int),
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		Events:    events,
	}
	for _, e := range events {
		cl.Ports[e.DstPort]++
	}
	return cl
}

func TestPortScanRule(t *testing.T) {
	events := []*db.Event{
		makeEvent("netfilter_drop", 22),
		makeEvent("netfilter_drop", 80),
		makeEvent("netfilter_drop", 443),
		makeEvent("netfilter_drop", 8080),
		makeEvent("netfilter_drop", 3389),
	}
	cl := makeCluster(events)
	rule := &PortScanRule{MinPorts: 5}
	m := rule.Eval(cl)
	if m == nil {
		t.Fatal("expected port_scan match, got nil")
	}
	if m.RuleType != "port_scan" {
		t.Errorf("expected port_scan, got %s", m.RuleType)
	}
}

func TestPortScanRule_BelowThreshold(t *testing.T) {
	events := []*db.Event{
		makeEvent("netfilter_drop", 22),
		makeEvent("netfilter_drop", 80),
	}
	cl := makeCluster(events)
	rule := &PortScanRule{MinPorts: 5}
	if m := rule.Eval(cl); m != nil {
		t.Errorf("expected nil, got match: %+v", m)
	}
}

func TestRepeatedDropRule(t *testing.T) {
	events := []*db.Event{
		makeEvent("netfilter_drop", 22),
		makeEvent("netfilter_drop", 22),
		makeEvent("netfilter_drop", 22),
	}
	cl := makeCluster(events)
	rule := &RepeatedDropRule{MinDrops: 3}
	m := rule.Eval(cl)
	if m == nil {
		t.Fatal("expected repeated_drop match, got nil")
	}
	if m.RuleType != "repeated_drop" {
		t.Errorf("expected repeated_drop, got %s", m.RuleType)
	}
}

func TestNewDeviceRule(t *testing.T) {
	events := []*db.Event{
		{EventID: "e1", EventType: "dhcp_dhcpack", SrcIP: "192.168.1.50", Timestamp: time.Now()},
	}
	cl := makeCluster(events)
	cl.SrcIP = "192.168.1.50"
	rule := &NewDeviceRule{}
	m := rule.Eval(cl)
	if m == nil {
		t.Fatal("expected new_device match, got nil")
	}
	if m.RuleType != "new_device" {
		t.Errorf("expected new_device, got %s", m.RuleType)
	}
}
