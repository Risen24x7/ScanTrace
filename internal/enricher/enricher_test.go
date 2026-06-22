package enricher

import (
	"testing"
)

func TestIsPrivate(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.5.5", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
	}
	for _, c := range cases {
		got := isPrivate(c.ip)
		if got != c.private {
			t.Errorf("isPrivate(%s) = %v, want %v", c.ip, got, c.private)
		}
	}
}

func TestIPInfoASNParsing(t *testing.T) {
	r := &ipInfoResponse{Org: "AS15169 Google LLC"}
	if r.ASN() != "AS15169" {
		t.Errorf("ASN() = %s, want AS15169", r.ASN())
	}
	if r.OrgName() != "Google LLC" {
		t.Errorf("OrgName() = %s, want Google LLC", r.OrgName())
	}
}

func TestStubEntityNeverNil(t *testing.T) {
	e := stubEntity("1.2.3.4", "test")
	if e == nil {
		t.Fatal("stubEntity returned nil")
	}
	if e.IP != "1.2.3.4" {
		t.Errorf("IP = %s, want 1.2.3.4", e.IP)
	}
}
