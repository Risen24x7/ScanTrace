// Package ingestmetrics posts periodic "Ingestion Status" summaries to Slack
// for demo visibility so hackathon judges can watch the ingest flow.
//
// It is intentionally isolated from the case-alerting path: it posts ONLY to a
// hardcoded demo channel supplied by the caller and never touches normal alert
// channel selection. If the Slack client, bot token, or channel is missing the
// manager disables itself gracefully (it logs a warning and never panics).
package ingestmetrics

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/slack-go/slack"
)

// SyslogSnapshot is a point-in-time copy of the syslog ingest counters.
type SyslogSnapshot struct {
	LinesReceived uint64
	LinesParsed   uint64
	LinesSkipped  uint64
}

// SyslogMetricsProvider is implemented by anything that can report ingest
// totals (e.g. a small adapter over the syslog package's Snapshot()).
type SyslogMetricsProvider interface {
	Snapshot() SyslogSnapshot
}

// slackPoster is the subset of *slack.Client that the manager needs. Keeping it
// as an interface makes the nil-client guard explicit and the manager testable.
type slackPoster interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
}

const (
	// DefaultInterval is used when metrics are enabled but no interval is set.
	DefaultInterval = 30 * time.Second

	// initialDelay is how soon after Start() the first status is posted.
	initialDelay = 5 * time.Second
)

// Manager posts periodic ingestion status summaries to a fixed Slack channel.
type Manager struct {
	client    slackPoster
	channelID string
	interval  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
	src       SyslogMetricsProvider

	last     SyslogSnapshot
	hasLast  bool
	disabled bool
}

// NewManager builds a Manager. If client is nil, channelID is empty, or src is
// nil, the manager is created in a disabled state: Start() logs a clear warning
// and does nothing (no goroutine, no panic).
func NewManager(client *slack.Client, channelID string, interval time.Duration, src SyslogMetricsProvider) *Manager {
	m := &Manager{
		channelID: channelID,
		interval:  interval,
		stopCh:    make(chan struct{}),
		src:       src,
	}
	if m.interval <= 0 {
		m.interval = DefaultInterval
	}
	if client == nil || channelID == "" || src == nil {
		m.disabled = true
	} else {
		m.client = client
	}
	return m
}

// Start launches the background poster. If the manager is disabled it logs a
// clear warning and returns without starting a goroutine.
func (m *Manager) Start() {
	if m.disabled {
		log.Printf("[ingestmetrics] disabled: missing Slack client, bot token, or channel — ingestion status posting is OFF")
		return
	}
	log.Printf("[ingestmetrics] enabled: posting ingestion status to channel %s every %s (first post in ~%s)",
		m.channelID, m.interval, initialDelay)

	m.wg.Add(1)
	go m.run()
}

func (m *Manager) run() {
	defer m.wg.Done()

	// Initial post within a few seconds of startup.
	initial := time.NewTimer(initialDelay)
	defer initial.Stop()

	select {
	case <-initial.C:
		m.postOnce()
	case <-m.stopCh:
		return
	}

	// Then every interval.
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.postOnce()
		case <-m.stopCh:
			return
		}
	}
}

// Stop signals the poster to exit and waits for it to finish. Safe to call even
// when the manager is disabled or already stopped.
func (m *Manager) Stop() {
	if m.disabled {
		return
	}
	select {
	case <-m.stopCh:
		// already closed
	default:
		close(m.stopCh)
	}
	m.wg.Wait()
}

// deltaClamp returns cur-prev, clamped at 0 to tolerate counter resets/wrap.
func deltaClamp(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

// skipRate returns LinesSkipped/(LinesParsed+LinesSkipped) as a percentage.
func skipRate(parsed, skipped uint64) float64 {
	denom := parsed + skipped
	if denom == 0 {
		return 0
	}
	return float64(skipped) / float64(denom) * 100.0
}

func (m *Manager) postOnce() {
	if m.client == nil {
		log.Printf("[ingestmetrics] no Slack client available — stopping poster")
		return
	}

	cur := m.src.Snapshot()
	text := m.formatStatus(cur)

	if _, _, err := m.client.PostMessage(m.channelID, slack.MsgOptionText(text, false)); err != nil {
		log.Printf("[ingestmetrics] post to %s failed: %v", m.channelID, err)
		// Leave last unchanged so the next delta is measured from the last
		// successfully-reported totals.
		return
	}

	m.last = cur
	m.hasLast = true
}

// formatStatus renders a concise plain-text status message. On the first post
// (no prior snapshot) deltas are shown as N/A and only totals are meaningful.
func (m *Manager) formatStatus(cur SyslogSnapshot) string {
	rate := skipRate(cur.LinesParsed, cur.LinesSkipped)

	dRecv, dParsed, dSkipped := "N/A", "N/A", "N/A"
	if m.hasLast {
		dRecv = fmt.Sprintf("+%d", deltaClamp(cur.LinesReceived, m.last.LinesReceived))
		dParsed = fmt.Sprintf("+%d", deltaClamp(cur.LinesParsed, m.last.LinesParsed))
		dSkipped = fmt.Sprintf("+%d", deltaClamp(cur.LinesSkipped, m.last.LinesSkipped))
	}

	return fmt.Sprintf(
		":satellite: *ScanTrace Ingestion Status*\n"+
			"• Lines received: *%d* (since last: %s)\n"+
			"• Lines parsed: *%d* (since last: %s)\n"+
			"• Lines skipped: *%d* (since last: %s)\n"+
			"• Skip rate: *%.2f%%*",
		cur.LinesReceived, dRecv,
		cur.LinesParsed, dParsed,
		cur.LinesSkipped, dSkipped,
		rate,
	)
}
