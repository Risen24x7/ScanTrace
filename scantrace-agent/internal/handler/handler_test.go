package handler

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"no args", "", nil},
		{"single token", "cases", []string{"cases"}},
		{"multiple spaces collapse", "report    abc12345", []string{"report", "abc12345"}},
		{"leading and trailing spaces", "  cases  ", []string{"cases"}},
		{
			"quoted value with space",
			`adddevice 192.168.50.4 label="Plex Server" trust=trusted`,
			[]string{"adddevice", "192.168.50.4", "label=Plex Server", "trust=trusted"},
		},
		{
			"quoted value only",
			`"Corp Laptop"`,
			[]string{"Corp Laptop"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitArgs(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitArgs(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestClassifyDst(t *testing.T) {
	const wan = "203.0.113.5"
	// api and store are unused by classifyDst — only wanIP and eventType matter.
	h := &Handler{wanIP: wan}

	tests := []struct {
		name      string
		dstIP     string
		eventType string
		wantEdge  bool
		wantLabel bool // true if a non-empty label is expected
	}{
		{"wan_new_connection is always WAN edge", "10.0.0.9", "wan_new_connection", true, true},
		{"wan_new_connection edge even when dst==wanIP", wan, "wan_new_connection", true, true},
		{"wan_forward with dst==wanIP is WAN edge", wan, "wan_forward", true, true},
		{"wan_forward with dst!=wanIP is internal", "192.168.50.10", "wan_forward", false, false},
		{"default type with dst==wanIP is WAN edge", wan, "port_scan", true, true},
		{"default type with dst!=wanIP is internal", "192.168.50.10", "port_scan", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, isEdge := h.classifyDst(tt.dstIP, tt.eventType)
			if isEdge != tt.wantEdge {
				t.Errorf("classifyDst(%q, %q) isWANEdge = %v, want %v",
					tt.dstIP, tt.eventType, isEdge, tt.wantEdge)
			}
			if gotLabel := label != ""; gotLabel != tt.wantLabel {
				t.Errorf("classifyDst(%q, %q) label=%q, want non-empty=%v",
					tt.dstIP, tt.eventType, label, tt.wantLabel)
			}
		})
	}

	// With no WAN IP configured, wan_forward/default never classify as WAN edge.
	hNoWAN := &Handler{}
	if _, edge := hNoWAN.classifyDst("203.0.113.5", "wan_forward"); edge {
		t.Errorf("classifyDst with empty wanIP should not be WAN edge for wan_forward")
	}
	if label, edge := hNoWAN.classifyDst("10.0.0.1", "wan_new_connection"); !edge || label == "" {
		t.Errorf("wan_new_connection should be WAN edge regardless of wanIP; got edge=%v label=%q", edge, label)
	}
}
