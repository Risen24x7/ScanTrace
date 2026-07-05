package handler

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseExportBlocklistFlagsDefaults(t *testing.T) {
	o, err := parseExportBlocklistFlags(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.limit != exportDefaultLimit {
		t.Errorf("default limit: want %d got %d", exportDefaultLimit, o.limit)
	}
	if o.since != exportDefaultSince {
		t.Errorf("default since: want %v got %v", exportDefaultSince, o.since)
	}
	if !o.wanOnly {
		t.Error("default wan-only should be true")
	}
	if o.format != "txt" {
		t.Errorf("default format: want txt got %q", o.format)
	}
	if !o.severities["high"] || !o.severities["medium"] || o.severities["low"] {
		t.Errorf("default severities want {high,medium}: got %v", o.severities)
	}
}

func TestParseExportBlocklistFlags(t *testing.T) {
	o, err := parseExportBlocklistFlags([]string{
		"--limit", "12", "--since", "72h", "--severity", "red,yellow",
		"--group-cidr", "--format", "csv", "--wan-only=false",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.limit != 12 {
		t.Errorf("limit: want 12 got %d", o.limit)
	}
	if o.since != 72*time.Hour {
		t.Errorf("since: want 72h got %v", o.since)
	}
	if !o.groupCIDR {
		t.Error("group-cidr should be set")
	}
	if o.format != "csv" {
		t.Errorf("format: want csv got %q", o.format)
	}
	if o.wanOnly {
		t.Error("wan-only should be false")
	}
}

func TestParseExportBlocklistLimitCap(t *testing.T) {
	o, err := parseExportBlocklistFlags([]string{"--limit=9999"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.limit != exportMaxLimit {
		t.Errorf("limit should be capped at %d, got %d", exportMaxLimit, o.limit)
	}
}

func TestParseExportBlocklistInvalid(t *testing.T) {
	bad := [][]string{
		{"--format", "xml"},
		{"--limit", "0"},
		{"--limit", "abc"},
		{"--since", "banana"},
		{"--severity", "purple"},
		{"positional"},
		{"--unknown", "x"},
	}
	for _, args := range bad {
		if _, err := parseExportBlocklistFlags(args); err == nil {
			t.Errorf("expected error for args %v", args)
		}
	}
}

func TestBuildBlocklistLinesDedupe(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	raw := []blocklistEntry{
		{IP: "1.2.3.4", Time: base},
		{IP: "1.2.3.4", Time: base.Add(2 * time.Hour)}, // more recent dupe
		{IP: "5.6.7.8", Time: base},
		{IP: "", Time: base}, // empty ignored
	}
	lines := buildBlocklistLines(raw, false, 0)
	if len(lines) != 2 {
		t.Fatalf("want 2 deduped lines, got %d: %+v", len(lines), lines)
	}
	for _, l := range lines {
		if l.Value == "1.2.3.4" && !l.LastSeen.Equal(base.Add(2*time.Hour)) {
			t.Errorf("dedupe should keep most recent time, got %v", l.LastSeen)
		}
	}
}

func TestBuildBlocklistLinesGroupingThreshold(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	// Three IPs share 10.0.0.0/24 -> should aggregate.
	// Two IPs share 172.16.5.0/24 -> below threshold, stay as singles.
	raw := []blocklistEntry{
		{IP: "10.0.0.1", Time: base},
		{IP: "10.0.0.2", Time: base.Add(time.Hour)},
		{IP: "10.0.0.3", Time: base.Add(2 * time.Hour)},
		{IP: "172.16.5.9", Time: base},
		{IP: "172.16.5.10", Time: base},
	}
	lines := buildBlocklistLines(raw, true, 0)

	var cidrCount, singleCount int
	var sawGroup bool
	for _, l := range lines {
		if l.IsCIDR {
			cidrCount++
			if l.Value == "10.0.0.0/24" {
				sawGroup = true
				if l.Count != 3 {
					t.Errorf("group count: want 3 got %d", l.Count)
				}
			}
		} else {
			singleCount++
		}
	}
	if !sawGroup {
		t.Error("expected 10.0.0.0/24 aggregate")
	}
	if cidrCount != 1 {
		t.Errorf("want exactly 1 CIDR line, got %d", cidrCount)
	}
	if singleCount != 2 {
		t.Errorf("want 2 single lines (below-threshold /24), got %d", singleCount)
	}
	// CIDR should sort first (preferred larger group).
	if !lines[0].IsCIDR {
		t.Errorf("expected CIDR aggregate to sort first, got %+v", lines[0])
	}
}

func TestBuildBlocklistLinesGroupingIPv6(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	raw := []blocklistEntry{
		{IP: "2001:db8:abcd:1::1", Time: base},
		{IP: "2001:db8:abcd:1::2", Time: base},
		{IP: "2001:db8:abcd:1::3", Time: base},
	}
	lines := buildBlocklistLines(raw, true, 0)
	if len(lines) != 1 || !lines[0].IsCIDR || lines[0].Value != "2001:db8:abcd:1::/64" {
		t.Fatalf("want single /64 aggregate, got %+v", lines)
	}
}

func TestBuildBlocklistLinesLimit(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	var raw []blocklistEntry
	for i := 0; i < 10; i++ {
		raw = append(raw, blocklistEntry{
			IP:   "203.0.113." + strconv.Itoa(i),
			Time: base.Add(time.Duration(i) * time.Hour),
		})
	}
	lines := buildBlocklistLines(raw, false, 4)
	if len(lines) != 4 {
		t.Fatalf("limit not enforced: want 4 got %d", len(lines))
	}
	// Most recent should come first.
	if lines[0].Value != "203.0.113.9" {
		t.Errorf("want most-recent IP first, got %q", lines[0].Value)
	}
}

func TestFormatBlocklist(t *testing.T) {
	lines := []blocklistLine{
		{Value: "1.2.3.4", Count: 1, LastSeen: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
		{Value: "10.0.0.0/24", IsCIDR: true, Count: 3, LastSeen: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
	}
	if got := formatBlocklist(lines, "txt"); got != "1.2.3.4\n10.0.0.0/24\n" {
		t.Errorf("txt format mismatch: %q", got)
	}
	csv := formatBlocklist(lines, "csv")
	if wantPrefix := "ip_or_cidr,count,last_seen\n"; len(csv) < len(wantPrefix) || csv[:len(wantPrefix)] != wantPrefix {
		t.Errorf("csv header missing: %q", csv)
	}
	ipset := formatBlocklist(lines, "ipset")
	if !strings.Contains(ipset, "add scantrace-blocklist 1.2.3.4") {
		t.Errorf("ipset format missing add line: %q", ipset)
	}
}

func TestCIDRPrefix(t *testing.T) {
	if p, ok := cidrPrefix("192.168.1.55"); !ok || p != "192.168.1.0/24" {
		t.Errorf("ipv4 prefix: got %q ok=%v", p, ok)
	}
	if p, ok := cidrPrefix("2001:db8:1:2::abcd"); !ok || p != "2001:db8:1:2::/64" {
		t.Errorf("ipv6 prefix: got %q ok=%v", p, ok)
	}
	if _, ok := cidrPrefix("not-an-ip"); ok {
		t.Error("expected failure for invalid IP")
	}
}
