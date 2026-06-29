// Package threatfeed provides lightweight, local-first threat intelligence
// lookups with zero external API calls at query time.
//
// ipsum.go ingests the IPSum aggregated blocklist
// (https://github.com/stamparm/ipsum) — a two-column flat file where each
// line is "<ip>\t<count>" and count is the number of third-party threat feeds
// that have blacklisted the IP (max ~30).
//
// The list is refreshed on startup (and optionally via SIGHUP / make feeds).
// All lookups are O(1) map reads — no disk I/O at query time.
package threatfeed

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// IPSumURL is the raw flat-file from the stamparm/ipsum GitHub repo.
	// Updated daily by the upstream maintainer.
	IPSumURL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

	// IPSumTimeout is the HTTP deadline for the initial fetch.
	IPSumTimeout = 30 * time.Second

	// ScoreNoise is the upper bound for internet background noise.
	ScoreNoise = 2
	// ScoreAggressive is the lower bound for high-confidence scanners/bruteforcers.
	ScoreAggressive = 3
	// ScoreUniversal is the lower bound for universally blacklisted infrastructure.
	ScoreUniversal = 6
)

var (
	ipsumMu    sync.RWMutex
	ipsumScore map[string]int // ip → consensus weight
	ipsumReady bool
)

// LoadIPSum fetches the IPSum list and loads it into memory.
// Safe to call concurrently; subsequent calls refresh the cache.
// Returns the number of entries loaded and any fetch/parse error.
func LoadIPSum() (int, error) {
	client := &http.Client{Timeout: IPSumTimeout}
	resp, err := client.Get(IPSumURL)
	if err != nil {
		return 0, fmt.Errorf("ipsum: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("ipsum: HTTP %d", resp.StatusCode)
	}

	newMap := make(map[string]int, 30000)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
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
		newMap[fields[0]] = score
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("ipsum: scan: %w", err)
	}

	ipsumMu.Lock()
	ipsumScore = newMap
	ipsumReady = true
	ipsumMu.Unlock()

	return len(newMap), nil
}

// LookupScore returns the IPSum consensus weight for ip.
// Returns 0 if the IP is not listed or the feed has not been loaded yet.
func LookupScore(ip string) int {
	ipsumMu.RLock()
	defer ipsumMu.RUnlock()
	if !ipsumReady {
		return 0
	}
	return ipsumScore[ip]
}

// ScoreBand returns a human-readable label for an IPSum score.
func ScoreBand(score int) string {
	switch {
	case score <= 0:
		return ""
	case score <= ScoreNoise:
		return "background noise"
	case score <= ScoreNoise+2: // 3-4
		return "aggressive scanner"
	case score < ScoreUniversal: // 5
		return "high-confidence threat"
	default: // 6+
		return "universally blacklisted"
	}
}
