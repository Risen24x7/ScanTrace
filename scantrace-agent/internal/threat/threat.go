// Package threat provides local threat-feed lookups for ScanTrace.
//
// It loads feed files on startup (refreshed nightly by cron):
//
//	/opt/scantrace/ipsum.txt          — stamparm/ipsum aggregated blocklist (scored)
//	/opt/scantrace/tor-exits.txt      — Tor Project bulk exit list
//	/opt/scantrace/benign-scanners.txt — known research scanner IPs/CIDRs (optional)
//
// Files are reloaded every 12 hours automatically. If a file is absent the
// lookup for that feed gracefully returns a zero score.
package threat

import (
	"bufio"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultIPSumPath          = "/opt/scantrace/ipsum.txt"
	DefaultTorExitPath        = "/opt/scantrace/tor-exits.txt"
	DefaultBenignScannersPath = "/opt/scantrace/benign-scanners.txt"

	// MaliciousThreshold is the minimum IPSum score to label a source IP as
	// confirmed malicious. IPSum scores reflect how many independent blocklists
	// flagged the IP (max ~30). Score >= 5 means at least 5 separate feeds agree.
	MaliciousThreshold = 5

	// BlacklistThreshold is the score above which an IP is considered
	// universally blacklisted across the majority of threat-feed sources.
	BlacklistThreshold = 6

	reloadInterval = 12 * time.Hour
)

// IPSum score tiers — maps feed consensus weight to operational priority.
const (
	TierClean       = 0 // not listed in any feed
	TierNoise       = 1 // score 1-2: internet background noise
	TierScanner     = 2 // score 3-5: confirmed aggressive scanner / brute-forcer
	TierBlacklisted = 3 // score 6+: universally blacklisted infrastructure
)

// Score holds the result of a threat-feed lookup for a single IP.
type Score struct {
	IPSumScore int  // 0 = not listed; >=MaliciousThreshold = confirmed malicious
	IsTorExit  bool // true if the IP is an active Tor exit node
}

// Tier returns the IPSum consensus tier for this score.
func (s Score) Tier() int {
	switch {
	case s.IPSumScore >= BlacklistThreshold:
		return TierBlacklisted
	case s.IPSumScore >= MaliciousThreshold:
		return TierScanner
	case s.IPSumScore >= 1:
		return TierNoise
	default:
		return TierClean
	}
}

// IsConfirmedMalicious returns true when the IPSum score meets the threshold.
func (s Score) IsConfirmedMalicious() bool {
	return s.IPSumScore >= MaliciousThreshold
}

// Tag returns a short human-readable label for use in triage context.
func (s Score) Tag() string {
	switch {
	case s.IPSumScore >= BlacklistThreshold && s.IsTorExit:
		return "☠️ UNIVERSALLY BLACKLISTED + TOR EXIT (IPSum score: " + itoa(s.IPSumScore) + "/30 feeds)"
	case s.IPSumScore >= BlacklistThreshold:
		return "☠️ UNIVERSALLY BLACKLISTED (IPSum score: " + itoa(s.IPSumScore) + "/30 feeds — automatic MALICIOUS verdict)"
	case s.IPSumScore >= MaliciousThreshold && s.IsTorExit:
		return "🔍 CONFIRMED SCANNER + TOR EXIT (IPSum score: " + itoa(s.IPSumScore) + "/30 feeds)"
	case s.IPSumScore >= MaliciousThreshold:
		return "🔍 CONFIRMED SCANNER / BRUTE-FORCER (IPSum score: " + itoa(s.IPSumScore) + "/30 feeds)"
	case s.IPSumScore >= 1 && s.IsTorExit:
		return "🌐 BACKGROUND NOISE + TOR EXIT (IPSum score: " + itoa(s.IPSumScore) + "/30 feeds)"
	case s.IPSumScore >= 1:
		return "🌐 BACKGROUND NOISE (IPSum score: " + itoa(s.IPSumScore) + "/30 feeds — low priority)"
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

// ── Benign Scanner Registry ───────────────────────────────────────────────────
//
// BenignScanners holds the IPs and CIDRs of well-known research scanners that
// should be auto-demoted to LOW priority regardless of event count.
// Sources: Shodan, Censys, Shadowserver, Binaryedge, GreyNoise, Google, Bing.

// defaultBenignIPs contains known static IPs for common research scanners.
// This list is a starting point — supplement with /opt/scantrace/benign-scanners.txt.
var defaultBenignIPs = []string{
	// Shodan
	"198.20.69.74", "198.20.69.75", "198.20.70.114", "198.20.70.115",
	"198.20.99.130", "198.20.99.131", "66.240.192.138", "66.240.236.119",
	"66.240.219.146", "71.6.135.131", "71.6.135.135", "71.6.165.200",
	"71.6.167.142", "82.221.105.6", "82.221.105.7", "85.25.43.94",
	"85.25.103.50", "93.120.27.62", "104.131.0.69", "104.236.198.48",
	// Censys
	"162.142.125.0", "167.248.133.0",
	// Shadowserver
	"184.105.139.66", "184.105.139.67", "184.105.139.68",
	"184.105.247.195", "184.105.247.196",
	// GreyNoise RIOT (benign)
	"45.83.66.65", "45.83.67.65",
	// Binaryedge
	"185.93.3.110",
	// Internet Archive / Wayback
	"208.70.31.0",
}

// defaultBenignCIDRs contains CIDR ranges for research scanner infrastructure.
var defaultBenignCIDRs = []string{
	// Censys ZMap scan ranges
	"162.142.125.0/24",
	"167.248.133.0/24",
	// Google crawl/scan infrastructure
	"66.249.64.0/19",
	// Bing crawl
	"40.77.167.0/24",
	// Shodan broader range
	"198.20.69.0/24",
	"198.20.70.0/24",
	"198.20.99.0/24",
}

// BenignScanners holds the compiled lookup structures for research scanner detection.
type BenignScanners struct {
	mu    sync.RWMutex
	ips   map[string]bool
	cidrs []*net.IPNet
	path  string
}

// NewBenignScanners creates a BenignScanners instance, loads the optional
// override file, and merges with the hardcoded defaults.
func NewBenignScanners(path string) *BenignScanners {
	if path == "" {
		path = DefaultBenignScannersPath
	}
	bs := &BenignScanners{
		ips:  make(map[string]bool),
		path: path,
	}
	bs.loadDefaults()
	bs.loadFile(path)
	go bs.reloadLoop()
	return bs
}

// IsBenignScanner returns true if the IP belongs to a known research scanner.
func (bs *BenignScanners) IsBenignScanner(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	if bs.ips[ipStr] {
		return true
	}
	for _, cidr := range bs.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (bs *BenignScanners) loadDefaults() {
	for _, ip := range defaultBenignIPs {
		bs.ips[ip] = true
	}
	for _, cidrStr := range defaultBenignCIDRs {
		_, block, err := net.ParseCIDR(cidrStr)
		if err == nil && block != nil {
			bs.cidrs = append(bs.cidrs, block)
		}
	}
}

func (bs *BenignScanners) loadFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[threat] benign-scanners open error: %v", err)
		}
		return
	}
	defer f.Close()

	bs.mu.Lock()
	defer bs.mu.Unlock()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			_, block, err := net.ParseCIDR(line)
			if err == nil && block != nil {
				bs.cidrs = append(bs.cidrs, block)
			}
		} else {
			bs.ips[line] = true
		}
	}
	log.Printf("[threat] benign-scanners loaded from %s", path)
}

func (bs *BenignScanners) reloadLoop() {
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	for range ticker.C {
		bs.loadFile(bs.path)
	}
}
