// Package correlator groups Events into Cases by src_ip within a rolling time window
// and evaluates named detection rules against each cluster.
package correlator

import (
	"fmt"
	"log"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/google/uuid"
)

const (
	DefaultWindow    = 72 * time.Hour
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
	rules  []Rule
}

func New(store *db.DB, cfg Config) *Correlator {
	return &Correlator{store: store, config: cfg, rules: DefaultRules()}
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

// Run clusters events in the window, evaluates rules, and opens/updates Cases.
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

		// Evaluate named rules; take the first match (highest priority first).
		var match *RuleMatch
		for _, rule := range c.rules {
			if m := rule.Eval(cl); m != nil {
				match = m
				break
			}
		}

		cas, err := c.openOrUpdateCase(cl, match)
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

func (c *Correlator) openOrUpdateCase(cl *IPCluster, match *RuleMatch) (*db.Case, error) {
	eventIDs := make(db.StringSlice, 0, len(cl.Events))
	for _, e := range cl.Events {
		eventIDs = append(eventIDs, e.EventID)
	}

	title := fmt.Sprintf("Scan activity from %s", cl.SrcIP)
	ruleName := "generic_scan"
	ruleType := "generic_scan"
	if match != nil {
		title = fmt.Sprintf("[%s] %s", match.RuleName, cl.SrcIP)
		ruleName = match.RuleName
		ruleType = match.RuleType
	}

	cas := &db.Case{
		CaseID:          uuid.New().String(),
		Title:           title,
		Summary:         buildSummary(cl, match),
		Status:          "open",
		Severity:        cl.Severity(),
		Confidence:      cl.Score,
		CreatedAt:       cl.FirstSeen,
		UpdatedAt:       time.Now().UTC(),
		RelatedEventIDs: eventIDs,
		AnalystNotes:    fmt.Sprintf("rule=%s type=%s", ruleName, ruleType),
	}
	if err := c.store.InsertCase(cas); err != nil {
		return nil, err
	}

	if entity, err := c.store.GetEntityByIP(cl.SrcIP); err == nil && entity != nil {
		if linkErr := c.store.LinkEntityToCase(cas.CaseID, entity.EntityID); linkErr != nil {
			log.Printf("[correlator] entity link failed for case %s / ip %s: %v",
				cas.CaseID[:8], cl.SrcIP, linkErr)
		}
	}

	return cas, nil
}

func buildSummary(cl *IPCluster, match *RuleMatch) string {
	ports := []string{}
	for p := range cl.Ports {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	base := fmt.Sprintf(
		"**Source IP:** %s\n**Observations:** %d events over %s\n**Ports touched:** %s\n**First seen:** %s\n**Last seen:** %s\n**Confidence:** %.2f\n**Severity:** %s",
		cl.SrcIP, len(cl.Events), cl.LastSeen.Sub(cl.FirstSeen).Round(time.Second),
		joinStrings(ports, ", "),
		cl.FirstSeen.Format(time.RFC3339), cl.LastSeen.Format(time.RFC3339),
		cl.Score, cl.Severity(),
	)
	if match != nil {
		base += fmt.Sprintf("\n**Rule:** %s — %s", match.RuleName, match.Description)
	}
	return base
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
