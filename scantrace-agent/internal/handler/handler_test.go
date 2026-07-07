package handler

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	cases := []struct{
		in string
		out []string
	}{
		{"", nil},
		{"adddevice 192.168.1.2", []string{"adddevice", "192.168.1.2"}},
		{"adddevice   192.168.1.2", []string{"adddevice", "192.168.1.2"}},
		{"adddevice 192.168.1.2 label=\"Plex Server\" trust=suspicious", []string{"adddevice", "192.168.1.2", "label=Plex Server", "trust=suspicious"}},
	}
	for _, c := range cases {
		got := splitArgs(c.in)
		if !reflect.DeepEqual(got, c.out) {
			t.Fatalf("splitArgs(%q) got %#v want %#v", c.in, got, c.out)
		}
	}
}

func TestClassifyDst(t *testing.T) {
	h := &Handler{wanIP: "24.20.77.75"}
	label, edge := h.classifyDst("24.20.77.75", "wan_new_connection")
	if !edge || label == "" {
		t.Fatalf("expected WAN edge for wan_new_connection")
	}
	label, edge = h.classifyDst("24.20.77.75", "wan_forward")
	if !edge || label == "" {
		t.Fatalf("expected WAN edge for wan_forward with dst==wanIP")
	}
	label, edge = h.classifyDst("24.20.77.75", "other")
	if !edge || label == "" {
		t.Fatalf("expected WAN edge for default with dst==wanIP")
	}
	label, edge = h.classifyDst("10.0.0.5", "wan_forward")
	if edge || label != "" {
		t.Fatalf("expected non-edge for wan_forward with dst!=wanIP")
	}
	label, edge = h.classifyDst("10.0.0.5", "other")
	if edge || label != "" {
		t.Fatalf("expected non-edge for default with dst!=wanIP")
	}
	label, edge = h.classifyDst("10.0.0.5", "wan_new_connection")
	if !edge || label == "" {
		t.Fatalf("expected WAN edge for wan_new_connection regardless of dst")
	}
}
