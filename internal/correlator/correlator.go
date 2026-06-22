// Package correlator groups Events into Cases by src_ip within a rolling time window.
package correlator

import (
	"fmt"
	"log"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

const (
	DefaultWindow    = 15 * time.Minute
	DefaultThreshold = 3
	DefaultMaxEvents = 500
)

type Config struct {
	Window    time.Duration
	Threshold int
	MaxEvents int
}

func DefaultConfig() Config {
	return Config{Window: DefaultWindow, Threshold: DefaultThreshold, MaxEvents: DefaultMaxEvents}
}

type Correlator struct {
	store  *db.DB
	config Config
}

func New(store *db.DB, cfg Config) *Correlator {
	return &Correlator{store: store, config: cfg}
}

type IPCluster struct {
	SrcIP     string
	Events    []*db.Event
	Ports     map[int]int
	Protocols map[string]int
	FirstSeen time.Time
	LastSeen  time.Time
	Score     float64
}

func (c *IPCluster) computeScore() float64 {
	if len(c.Events) == 0 {
		return 0
	}
	portDiversity := float64(len(c.Ports))
	base := float64(len(c.Events))
	raw := (base * portDiversity) / (base + portDiversity + 1)
	if raw > 1.0 {
		raw = 1.0
	}
	return raw
}

func (c *IPCluster) Severity() string {
	switch {
	case c.Score >= 0.75:
		return "high"
	case c.Score >= 0.45:
		return "medium"
	default:
		return "low"
	}
}

func (c *Correlator) Run() ([]*db.Case, error) {
	since := time.Now().UTC().Add(-c.config.Window)
	events, err := c.store.ListEvents(c.config.MaxEvents)
	if err != nil {
		return nil, fmt.Errorf("correlator.Run: list events: %w", err)
	}
	var windowed []*db.Event
	for _, e := range events {
		if e.Timestamp.After(since) {
			windowed = append(windowed, e)
		}
	}
	clusters := c.cluster(windowed)
	var cases []*db.Case
	for _, cl := range clusters {
		if len(cl.Events) < c.config.Threshold {
			continue
		}
		cl.Score = cl.computeScore()
		cas, err := c.openOrUpdateCase(cl)
		if err != nil {
			log.Printf("[correlator] case error for %s: %v", cl.SrcIP, err)
			continue
		}
		cases = append(cases, cas)
	}
	return cases, nil
}

func (c *Correlator) cluster(events []*db.Event) map[string]*IPCluster {
	out := make(map[string]*IPCluster)
	for _, e := range events {
		cl, ok := out[e.SrcIP]
		if !ok {
			cl = &IPCluster{
				SrcIP:     e.SrcIP,
				Ports:     make(map[int]int),
				Protocols: make(map[string]int),
				FirstSeen: e.Timestamp,
				LastSeen:  e.Timestamp,
			}
			out[e.SrcIP] = cl
		}
		cl.Events = append(cl.Events, e)
		cl.Ports[e.DstPort]++
		cl.Protocols[e.Protocol]++
		if e.Timestamp.Before(cl.FirstSeen) {
			cl.FirstSeen = e.Timestamp
		}
		if e.Timestamp.After(cl.LastSeen) {
			cl.LastSeen = e.Timestamp
		}
	}
	return out
}

func (c *Correlator) openOrUpdateCase(cl *IPCluster) (*db.Case, error) {
	eventIDs := make(db.StringSlice, 0, len(cl.Events))
	for _, e := range cl.Events {
		eventIDs = append(eventIDs, e.EventID)
	}
	cas := &db.Case{
		CaseID:          uuid.New().String(),
		Title:           fmt.Sprintf("Scan activity from %s", cl.SrcIP),
		Summary:         buildSummary(cl),
		Status:          "open",
		Severity:        cl.Severity(),
		Confidence:      cl.Score,
		CreatedAt:       cl.FirstSeen,
		UpdatedAt:       time.Now().UTC(),
		RelatedEventIDs: eventIDs,
	}
	if err := c.store.InsertCase(cas); err != nil {
		return nil, err
	}
	return cas, nil
}

func buildSummary(cl *IPCluster) string {
	ports := []string{}
	for p := range cl.Ports {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	return fmt.Sprintf(
		"**Source IP:** %s\n**Observations:** %d events over %s\n**Ports touched:** %s\n**First seen:** %s\n**Last seen:** %s\n**Confidence:** %.2f\n**Severity:** %s",
		cl.SrcIP, len(cl.Events), cl.LastSeen.Sub(cl.FirstSeen).Round(time.Second),
		joinStrings(ports, ", "),
		cl.FirstSeen.Format(time.RFC3339), cl.LastSeen.Format(time.RFC3339),
		cl.Score, cl.Severity(),
	)
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}
