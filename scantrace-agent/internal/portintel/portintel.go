// Package portintel provides a SQLite-backed port hit registry for ScanTrace.
//
// It persists every (port, sourceIP) observation seen by the agent so that
// long-term trends survive restarts. The data is used for two purposes:
//
//  1. LLM context injection — when a case targets a port that has been hit by
//     many unique IPs or is trending up, a [PORT INTEL ADVISORY] block is
//     injected into the prompt so the model can produce a more accurate verdict.
//
//  2. /scantrace port-trends Slack command — shows a ranked table of the most
//     targeted ports over the last 7 days, with unique-IP count, total hit count,
//     and trend direction vs the prior 7-day window.
package portintel

import (
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS port_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    port       INTEGER NOT NULL,
    src_ip     TEXT    NOT NULL,
    src_asn    TEXT    NOT NULL DEFAULT '',
    src_org    TEXT    NOT NULL DEFAULT '',
    src_country TEXT   NOT NULL DEFAULT '',
    event_type TEXT    NOT NULL DEFAULT 'wan_new_connection',
    seen_at    DATETIME NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_port_hits_port    ON port_hits(port);
CREATE INDEX IF NOT EXISTS idx_port_hits_seen_at ON port_hits(seen_at);
CREATE INDEX IF NOT EXISTS idx_port_hits_src_ip  ON port_hits(src_ip);
`

// HitRecord is a single observation tuple passed from handler to RecordHit.
type HitRecord struct {
	Port       int
	SrcIP      string
	SrcASN     string
	SrcOrg     string
	SrcCountry string
	EventType  string
}

// Store is a persistent port hit registry backed by SQLite.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and
// applies the schema.
func Open(path string) (*Store, error) {
	if path == "" {
		path = "/opt/scantrace/portintel.db"
	}
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("portintel: open %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("portintel: schema: %w", err)
	}
	log.Printf("[portintel] store opened: %s", path)
	return &Store{db: db}, nil
}

// RecordHit records a single port observation. Non-fatal — logs on error.
func (s *Store) RecordHit(port int, srcIP, srcASN, srcOrg, srcCountry, eventType string) {
	if port <= 0 {
		return
	}
	_, err := s.db.Exec(
		`INSERT INTO port_hits (port, src_ip, src_asn, src_org, src_country, event_type, seen_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
		port, srcIP, srcASN, srcOrg, srcCountry, eventType,
	)
	if err != nil {
		log.Printf("[portintel] RecordHit error port=%d src=%s: %v", port, srcIP, err)
	}
}

// PortSummary holds aggregated stats for a single port.
type PortSummary struct {
	Port       int
	HitCount   int      // total raw hits in window
	UniqueIPs  int      // distinct source IPs
	UniqueASNs int      // distinct ASNs (campaign breadth indicator)
	FirstSeen  time.Time
	LastSeen   time.Time
	PrevHits   int      // hit count in prior window (for trend)
	TrendPct   float64  // (HitCount - PrevHits) / max(PrevHits,1) * 100
	TopOrgs    []string // up to 3 most common org names
}

// TrendArrow returns a Slack-friendly trend indicator.
func (p PortSummary) TrendArrow() string {
	switch {
	case p.PrevHits == 0 && p.HitCount > 0:
		return "🆕 NEW"
	case p.TrendPct >= 50:
		return "🔺 UP +" + pctStr(p.TrendPct)
	case p.TrendPct <= -30:
		return "🔻 DOWN " + pctStr(p.TrendPct)
	default:
		return "➖ STABLE"
	}
}

func pctStr(f float64) string {
	if f >= 0 {
		return fmt.Sprintf("%.0f%%", f)
	}
	return fmt.Sprintf("%.0f%%", f)
}

// TopPorts returns aggregated stats for the top N most-hit ports in the last
// windowDays days. Results are sorted by HitCount descending.
func (s *Store) TopPorts(windowDays, limit int) ([]PortSummary, error) {
	if windowDays <= 0 {
		windowDays = 7
	}
	if limit <= 0 {
		limit = 20
	}

	cutCurrent := time.Now().AddDate(0, 0, -windowDays)
	cutPrev := cutCurrent.AddDate(0, 0, -windowDays)

	// Current window: per-port hit count + unique IPs + unique ASNs + first/last seen.
	rows, err := s.db.Query(`
		SELECT
			port,
			COUNT(*) AS hit_count,
			COUNT(DISTINCT src_ip) AS unique_ips,
			COUNT(DISTINCT src_asn) AS unique_asns,
			MIN(seen_at) AS first_seen,
			MAX(seen_at) AS last_seen
		FROM port_hits
		WHERE seen_at >= ?
		GROUP BY port
		ORDER BY hit_count DESC
		LIMIT ?`,
		cutCurrent.Format(time.DateTime), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("portintel: TopPorts query: %w", err)
	}
	defer rows.Close()

	var summaries []PortSummary
	for rows.Next() {
		var ps PortSummary
		var first, last string
		if err := rows.Scan(&ps.Port, &ps.HitCount, &ps.UniqueIPs, &ps.UniqueASNs, &first, &last); err != nil {
			continue
		}
		ps.FirstSeen, _ = time.Parse(time.DateTime, first)
		ps.LastSeen, _ = time.Parse(time.DateTime, last)
		summaries = append(summaries, ps)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Prior window hits for trend calculation.
	prevRows, err := s.db.Query(`
		SELECT port, COUNT(*) AS hit_count
		FROM port_hits
		WHERE seen_at >= ? AND seen_at < ?
		GROUP BY port`,
		cutPrev.Format(time.DateTime), cutCurrent.Format(time.DateTime),
	)
	if err == nil {
		prevMap := make(map[int]int)
		for prevRows.Next() {
			var port, cnt int
			if prevRows.Scan(&port, &cnt) == nil {
				prevMap[port] = cnt
			}
		}
		prevRows.Close()
		for i := range summaries {
			summaries[i].PrevHits = prevMap[summaries[i].Port]
			prev := summaries[i].PrevHits
			if prev == 0 {
				prev = 1
			}
			summaries[i].TrendPct = float64(summaries[i].HitCount-summaries[i].PrevHits) / float64(prev) * 100
		}
	}

	// Top orgs per port (up to 3).
	for i, ps := range summaries {
		orgs, _ := s.topOrgsForPort(ps.Port, cutCurrent, 3)
		summaries[i].TopOrgs = orgs
	}

	return summaries, nil
}

func (s *Store) topOrgsForPort(port int, since time.Time, limit int) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT src_org, COUNT(*) AS cnt
		FROM port_hits
		WHERE port = ? AND seen_at >= ? AND src_org != ''
		GROUP BY src_org
		ORDER BY cnt DESC
		LIMIT ?`,
		port, since.Format(time.DateTime), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var org string
		var cnt int
		if rows.Scan(&org, &cnt) == nil {
			out = append(out, org)
		}
	}
	return out, rows.Err()
}

// PortAdvisory returns an advisory string for a set of ports to inject into
// the LLM context. Only ports with significant activity are included.
// Returns an empty string if nothing noteworthy.
func (s *Store) PortAdvisory(ports []int, windowDays int) string {
	if len(ports) == 0 {
		return ""
	}
	if windowDays <= 0 {
		windowDays = 7
	}
	cutCurrent := time.Now().AddDate(0, 0, -windowDays)

	type entry struct {
		port      int
		hits      int
		uniqueIPs int
	}
	var entries []entry
	for _, port := range ports {
		var hits, uips int
		s.db.QueryRow(
			`SELECT COUNT(*), COUNT(DISTINCT src_ip) FROM port_hits WHERE port = ? AND seen_at >= ?`,
			port, cutCurrent.Format(time.DateTime),
		).Scan(&hits, &uips)
		if hits >= 2 || uips >= 2 {
			entries = append(entries, entry{port, hits, uips})
		}
	}
	if len(entries) == 0 {
		return ""
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].hits > entries[j].hits })

	var sb strings.Builder
	sb.WriteString("[PORT INTEL ADVISORY — last " + fmt.Sprintf("%d", windowDays) + " days]\n")
	for _, e := range entries {
		campaign := "single-source vertical probe"
		if e.uniqueIPs >= 5 {
			campaign = "coordinated horizontal campaign across " + fmt.Sprintf("%d", e.uniqueIPs) + " unique source IPs"
		} else if e.uniqueIPs >= 2 {
			campaign = "multi-source probe across " + fmt.Sprintf("%d", e.uniqueIPs) + " unique source IPs"
		}
		sb.WriteString(fmt.Sprintf(
			"- Port %d: %d hits, %d unique source IPs — %s\n",
			e.port, e.hits, e.uniqueIPs, campaign,
		))
	}
	return sb.String()
}

// BehaviorSummary classifies the global scanning behavior visible in the store
// over the last windowDays days.
type BehaviorSummary struct {
	HorizontalCampaigns int // ports hit by 5+ unique IPs
	VerticalProbes      int // single-IP hitting 3+ ports in short succession
	NewPorts            int // ports with zero prior-window hits
}

// GlobalBehavior returns a high-level behavior summary for the Slack report.
func (s *Store) GlobalBehavior(windowDays int) BehaviorSummary {
	tops, err := s.TopPorts(windowDays, 100)
	if err != nil {
		return BehaviorSummary{}
	}
	var bs BehaviorSummary
	for _, ps := range tops {
		if ps.UniqueIPs >= 5 {
			bs.HorizontalCampaigns++
		}
		if ps.PrevHits == 0 && ps.HitCount > 0 {
			bs.NewPorts++
		}
	}
	// Vertical probe detection: count IPs that hit 3+ distinct ports.
	rows, err := s.db.Query(`
		SELECT src_ip, COUNT(DISTINCT port) AS pc
		FROM port_hits
		WHERE seen_at >= ?
		GROUP BY src_ip
		HAVING pc >= 3`,
		time.Now().AddDate(0, 0, -windowDays).Format(time.DateTime),
	)
	if err == nil {
		for rows.Next() {
			bs.VerticalProbes++
		}
		rows.Close()
	}
	return bs
}
