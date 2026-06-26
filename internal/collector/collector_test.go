package collector

import (
	"strings"
	"testing"
)

// All test fixtures use the real BE96U RFC 3339 timestamp format:
//   2026-06-25T20:38:19+00:00 hostname process[pid]: body

func TestAsusAdapter_NetfilterDrop(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `2026-06-25T20:05:01+00:00 Rzn-BE96U kernel: DROP IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=185.220.101.45 DST=192.168.50.1 LEN=40 TOS=0x00 PREC=0x00 TTL=238 ID=54321 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.SrcIP != "185.220.101.45" {
		t.Errorf("SrcIP: got %q, want 185.220.101.45", evt.SrcIP)
	}
	if evt.DstPort != 22 {
		t.Errorf("DstPort: got %d, want 22", evt.DstPort)
	}
	if evt.Protocol != "TCP" {
		t.Errorf("Protocol: got %q, want TCP", evt.Protocol)
	}
	if evt.EventType != "netfilter_drop" {
		t.Errorf("EventType: got %q, want netfilter_drop", evt.EventType)
	}
	if evt.Direction != "inbound" {
		t.Errorf("Direction: got %q, want inbound", evt.Direction)
	}
	hasTag := func(tag string) bool {
		for _, tg := range evt.Tags {
			if tg == tag {
				return true
			}
		}
		return false
	}
	if !hasTag("blocked") {
		t.Error("expected tag 'blocked'")
	}
	if !hasTag("firewall_drop") {
		t.Error("expected tag 'firewall_drop'")
	}
}

func TestAsusAdapter_NetfilterAccept(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `2026-06-25T20:05:02+00:00 Rzn-BE96U kernel: ACCEPT IN=eth0 OUT=br0 MAC=aa:bb:cc:dd:ee:ff SRC=8.8.8.8 DST=192.168.50.10 LEN=60 PROTO=TCP SPT=443 DPT=54321 WINDOW=65535`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.EventType != "netfilter_accept" {
		t.Errorf("EventType: got %q, want netfilter_accept", evt.EventType)
	}
}

func TestAsusAdapter_DHCP(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	// Real line from BE96U (no hostname, trailing space trimmed)
	line := `2026-06-25T20:39:31+00:00 Rzn-BE96U-0422D0F-C dnsmasq-dhcp[8492]: DHCPACK(br0) 192.168.50.238 70:f0:88:2d:db:1e`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.SrcIP != "192.168.50.238" {
		t.Errorf("SrcIP: got %q, want 192.168.50.238", evt.SrcIP)
	}
	if evt.EventType != "dhcp_dhcpack" {
		t.Errorf("EventType: got %q, want dhcp_dhcpack", evt.EventType)
	}
	if !strings.Contains(evt.Notes, "mac=70:f0:88:2d:db:1e") {
		t.Errorf("Notes missing mac: %q", evt.Notes)
	}
}

func TestAsusAdapter_Hostapd(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	// Real line from BE96U
	line := `2026-06-25T20:38:19+00:00 Rzn-BE96U-0422D0F-C hostapd: wl2.1: STA fe:5d:8f:1d:ef:46 IEEE 802.11: associated (aid 2)`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.EventType != "wifi_associated" {
		t.Errorf("EventType: got %q, want wifi_associated", evt.EventType)
	}
	if !strings.Contains(evt.Notes, "mac=fe:5d:8f:1d:ef:46") {
		t.Errorf("Notes missing mac: %q", evt.Notes)
	}
}

func TestAsusAdapter_HostapdDisassociated(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `2026-06-25T20:38:20+00:00 Rzn-BE96U-0422D0F-C hostapd: wl1.1: STA fe:5d:8f:1d:ef:46 IEEE 802.11: disassociated`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.EventType != "wifi_disassociated" {
		t.Errorf("EventType: got %q, want wifi_disassociated", evt.EventType)
	}
}

func TestAsusAdapter_UnknownProcess(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	// wlceventd lines should be skipped (non-security)
	line := `2026-06-25T20:38:19+00:00 Rzn-BE96U-0422D0F-C wlceventd: wlceventd_proc_event(695): wl2.1: ReAssoc FE:5D:8F:1D:EF:46, status: Successful (0), rssi:-61`

	evt, err := a.Parse(line)
	if err == nil && evt == nil {
		t.Error("expected skip sentinel error for non-security line")
	}
	if evt != nil {
		t.Errorf("expected no event for wlceventd line, got %+v", evt)
	}
}

func TestAsusAdapter_MalformedLine(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `this is not a syslog line at all`

	evt, err := a.Parse(line)
	if err == nil {
		t.Error("expected error for malformed line")
	}
	if evt != nil {
		t.Errorf("expected nil event for malformed line, got %+v", evt)
	}
}

// BSDTimestamp tests backward-compat with older firmware.
func TestAsusAdapter_BSDTimestamp(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `Jun 25 20:05:01 router dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.50.42 aa:bb:cc:dd:ee:ff mylaptop`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("BSD timestamp: unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("BSD timestamp: expected event, got nil")
	}
	if evt.EventType != "dhcp_dhcpack" {
		t.Errorf("EventType: got %q, want dhcp_dhcpack", evt.EventType)
	}
}

func TestInferDirection(t *testing.T) {
	cases := []struct {
		src, dst string
		want     string
	}{
		{"185.220.101.45", "192.168.50.1", "inbound"},
		{"192.168.50.10", "8.8.8.8", "outbound"},
		{"192.168.50.10", "192.168.50.1", "internal"},
		{"10.0.0.5", "172.16.0.1", "internal"},
		{"1.2.3.4", "5.6.7.8", "unknown"},
	}
	for _, tc := range cases {
		got := inferDirection(tc.src, tc.dst)
		if got != tc.want {
			t.Errorf("inferDirection(%q, %q) = %q, want %q", tc.src, tc.dst, got, tc.want)
		}
	}
}
