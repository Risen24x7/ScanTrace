// Package threat provides local threat-feed lookups for ScanTrace.
//
// It loads two feed files on startup (refreshed nightly by cron):
//
//	/opt/scantrace/ipsum.txt  — stamparm/ipsum aggregated blocklist (scored)
//	/opt/scantrace/tor-exits.txt — Tor Project bulk exit list
//
// Files are reloaded every 12 hours automatically. If a file is absent the
// lookup for that feed gracefully returns a zero score.
package threat

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultIPSumPath   = "/opt/scantrace/ipsum.txt"
	DefaultTorExitPath = "/opt/scantrace/tor-exits.txt"

	// MaliciousThreshold is the minimum IPSum score to label a source IP as
	// confirmed malicious. IPSum scores reflect how many independent blocklists
	// flagged the IP (max ~30). Score >= 5 means at least 5 separate feeds agree.
	MaliciousThreshold = 5

	reloadInterval = 12 * time.Hour
)

// Score holds the result of a threat-feed lookup for a single IP.
type Score struct {
	IPSumScore int  // 0 = not listed; >=MaliciousThreshold = confirmed malicious
	IsTorExit  bool // true if the IP is an active Tor exit node
}

// IsConfirmedMalicious returns true when the IPSum score meets the threshold.
func (s Score) IsConfirmedMalicious() bool {
	return s.IPSumScore >= MaliciousThreshold
}

// Tag returns a short human-readable label for use in triage context.
func (s Score) Tag() string {
	switch {
	case s.IsConfirmedMalicious() && s.IsTorExit:
		return "⚠️ CONFIRMED MALICIOUS + TOR EXIT (IPSum score: " + itoa(s.IPSumScore) + ")"
	case s.IsConfirmedMalicious():
		return "⚠️ CONFIRMED MALICIOUS (IPSum score: " + itoa(s.IPSumScore) + ")"
	case s.IsTorExit:
		return "🧅 TOR EXIT NODE — anonymized source"
	default:
		return ""
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// Enricher holds in-memory copies of the threat feeds and refreshes them
// periodically from disk.
type Enricher struct {
	ipSumPath   string
	torExitPath string

	mu       sync.RWMutex
	ipsum    map[string]int  // ip -> score
	torExits map[string]bool // ip -> true
}

// New creates an Enricher, loads both feed files immediately, and starts the
// background reload ticker. Missing files are logged as warnings, not errors.
func New(ipSumPath, torExitPath string) *Enricher {
	if ipSumPath == "" {
		ipSumPath = DefaultIPSumPath
	}
	if torExitPath == "" {
		torExitPath = DefaultTorExitPath
	}
	e := &Enricher{
		ipSumPath:   ipSumPath,
		torExitPath: torExitPath,
		ipsum:       make(map[string]int),
		torExits:    make(map[string]bool),
	}
	e.reload()
	go e.reloadLoop()
	return e
}

// Lookup returns the threat score for a given IP.
func (e *Enricher) Lookup(ip string) Score {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Score{
		IPSumScore: e.ipsum[ip],
		IsTorExit:  e.torExits[ip],
	}
}

// LookupMany returns scores for a slice of IPs. Only IPs with a non-zero score
// are included in the result map.
func (e *Enricher) LookupMany(ips []string) map[string]Score {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]Score, len(ips))
	for _, ip := range ips {
		s := Score{
			IPSumScore: e.ipsum[ip],
			IsTorExit:  e.torExits[ip],
		}
		if s.IPSumScore > 0 || s.IsTorExit {
			out[ip] = s
		}
	}
	return out
}

func (e *Enricher) reloadLoop() {
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	for range ticker.C {
		e.reload()
	}
}

func (e *Enricher) reload() {
	ipsum := loadIPSum(e.ipSumPath)
	tor := loadTorExits(e.torExitPath)

	e.mu.Lock()
	e.ipsum = ipsum
	e.torExits = tor
	e.mu.Unlock()

	log.Printf("[threat] feeds loaded: ipsum=%d IPs, tor-exits=%d IPs", len(ipsum), len(tor))
}

// loadIPSum parses stamparm/ipsum format:
//
//	# comment
//	<ip>\t<score>
func loadIPSum(path string) map[string]int {
	out := make(map[string]int)
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[threat] ipsum open error: %v", err)
		}
		return out
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		score, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		out[fields[0]] = score
	}
	return out
}

// loadTorExits parses the Tor Project bulk exit list — one IP per line.
func loadTorExits(path string) map[string]bool {
	out := make(map[string]bool)
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[threat] tor-exits open error: %v", err)
		}
		return out
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "ExitAddress") {
			continue
		}
		// Tor bulk list format: "ExitAddress <ip> <date>" OR just bare IP
		fields := strings.Fields(line)
		out[fields[0]] = true
	}
	return out
}
