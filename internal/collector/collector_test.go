package collector

import (
	"testing"
)

func TestSuricataAdapterParse(t *testing.T) {
	line := `{"timestamp":"2026-06-20T10:00:00.000000-0700","event_type":"alert","src_ip":"1.2.3.4","src_port":54321,"dest_ip":"10.0.0.1","dest_port":22,"proto":"TCP","alert":{"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}`
	a := &SuricataAdapter{}
	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt.SrcIP != "1.2.3.4" {
		t.Errorf("expected src_ip=1.2.3.4, got %s", evt.SrcIP)
	}
	if evt.DstPort != 22 {
		t.Errorf("expected dst_port=22, got %d", evt.DstPort)
	}
}

func TestSyslogAdapterParse(t *testing.T) {
	line := `Jun 20 22:00:01 fw kernel: [UFW BLOCK] IN=eth0 SRC=5.6.7.8 DST=192.168.1.1 PROTO=TCP SPT=44512 DPT=443`
	a := &SyslogAdapter{}
	evt, err := a.Parse(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if evt.SrcIP != "5.6.7.8" {
		t.Errorf("expected src_ip=5.6.7.8, got %s", evt.SrcIP)
	}
}

func TestSuricataSkipsNonScanEvents(t *testing.T) {
	line := `{"timestamp":"2026-06-20T10:00:00.000000-0700","event_type":"dns","src_ip":"1.2.3.4","src_port":53,"dest_ip":"10.0.0.1","dest_port":53,"proto":"UDP"}`
	a := &SuricataAdapter{}
	_, err := a.Parse(line)
	if err == nil {
		t.Error("expected skip error for dns event_type, got nil")
	}
}
