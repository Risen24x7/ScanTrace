package collector

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// AsusAdapter unit tests
// ---------------------------------------------------------------------------

func TestAsusAdapter_NetfilterDrop(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `Jun 25 20:05:01 router kernel: DROP IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=185.220.101.45 DST=192.168.50.1 LEN=40 TOS=0x00 PREC=0x00 TTL=238 ID=54321 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.SrcIP != "185.220.101.45" {
		t.Errorf("SrcIP: got %q, want %q", evt.SrcIP, "185.220.101.45")
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
	line := `Jun 25 20:05:02 router kernel: ACCEPT IN=eth0 OUT=br0 MAC=aa:bb:cc:dd:ee:ff SRC=8.8.8.8 DST=192.168.50.10 LEN=60 PROTO=TCP SPT=443 DPT=54321 WINDOW=65535`

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
	line := `Jun 25 20:06:00 router dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.50.42 aa:bb:cc:dd:ee:ff mylaptop`

	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt == nil {
		t.Fatal("expected event, got nil")
	}
	if evt.SrcIP != "192.168.50.42" {
		t.Errorf("SrcIP: got %q, want 192.168.50.42", evt.SrcIP)
	}
	if evt.EventType != "dhcp_dhcpack" {
		t.Errorf("EventType: got %q, want dhcp_dhcpack", evt.EventType)
	}
	if !strings.Contains(evt.Notes, "mac=aa:bb:cc:dd:ee:ff") {
		t.Errorf("Notes missing mac: %q", evt.Notes)
	}
	if !strings.Contains(evt.Notes, "hostname=mylaptop") {
		t.Errorf("Notes missing hostname: %q", evt.Notes)
	}
}

func TestAsusAdapter_Hostapd(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `Jun 25 20:07:00 router hostapd: wl0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated`

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
}

func TestAsusAdapter_UnknownLine(t *testing.T) {
	a := NewAsusAdapter("test-sensor-id")
	line := `Jun 25 20:08:00 router crond[5678]: crond: USER root pid 1234 cmd /usr/bin/ntpcheck.sh`

	evt, err := a.Parse(line)
	// crond lines should return a non-nil error (skip sentinel), not a nil error with a nil event
	if err == nil && evt == nil {
		t.Error("expected skip sentinel error for non-security line, got (nil, nil)")
	}
	if evt != nil {
		t.Errorf("expected no event for crond line, got %+v", evt)
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
