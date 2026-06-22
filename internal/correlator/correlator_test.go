package correlator

import (
	"testing"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
)

func makeEvent(ip string, dstPort int, ts time.Time) *db.Event {
	return &db.Event{SrcIP: ip, DstPort: dstPort, Protocol: "tcp", Timestamp: ts}
}

func TestCluster(t *testing.T) {
	c := &Correlator{config: DefaultConfig()}
	now := time.Now().UTC()
	events := []*db.Event{
		makeEvent("1.2.3.4", 22, now),
		makeEvent("1.2.3.4", 80, now.Add(time.Minute)),
		makeEvent("1.2.3.4", 443, now.Add(2*time.Minute)),
		makeEvent("5.6.7.8", 22, now),
	}
	clusters := c.cluster(events)
	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(clusters))
	}
	cl := clusters["1.2.3.4"]
	if cl == nil {
		t.Fatal("missing cluster for 1.2.3.4")
	}
	if len(cl.Events) != 3 {
		t.Errorf("expected 3 events for 1.2.3.4, got %d", len(cl.Events))
	}
}

func TestScoreAndSeverity(t *testing.T) {
	cl := &IPCluster{
		Ports:  map[int]int{22: 3, 80: 2, 443: 1, 8080: 1, 3389: 1},
		Events: make([]*db.Event, 10),
	}
	cl.Score = cl.computeScore()
	if cl.Score <= 0 {
		t.Error("score should be > 0")
	}
	t.Logf("score=%.4f severity=%s", cl.Score, cl.Severity())
}
