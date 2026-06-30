// Package threat provides local threat-feed lookups and live AbuseIPDB
// enrichment for ScanTrace.
//
// Local feeds loaded on startup (refreshed every 12h by background goroutine):
//
//	/opt/scantrace/ipsum.txt           — stamparm/ipsum aggregated blocklist
//	/opt/scantrace/tor-exits.txt       — Tor Project bulk exit list
//	/opt/scantrace/benign-scanners.txt — known research scanner IPs/CIDRs (optional)
//
// Live enrichment:
//
//	AbuseIPDB /api/v2/check — called per-IP at case-build time.
//	Requires ABUSEIPDB_API_KEY env var. Gracefully no-ops if unset.
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
	// confirmed malicious.
	MaliciousThreshold = 5

	// BlacklistThreshold is the score above which an IP is universally
	// blacklisted across the majority of threat-feed sources.
	BlacklistThreshold = 6

	reloadInterval = 12 * time.Hour
)

// IPSum score tiers.
const (
	TierClean       = 0
	TierNoise       = 1
	TierScanner     = 2
	TierBlacklisted = 3
)

// Score holds the combined result of all threat-feed lookups for a single IP.
type Score struct {
	IPSumScore      int
	IsTorExit       bool
	IsBenignScanner bool
	// AbuseIPDB live enrichment — zero if API key unset or lookup failed.
	Abuse AbuseResult
}

// Tier returns the IPSum consensus tier.
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

// IsConfirmedMalicious returns true when either IPSum or AbuseIPDB
// independently confirm this IP as malicious.
func (s Score) IsConfirmedMalicious() bool {
	return s.IPSumScore >= MaliciousThreshold || s.Abuse.IsConfirmedMaliciousAbuse()
}

// Tag returns the highest-priority human-readable label for this score.
// AbuseIPDB confirmed malicious overrides all IPSum tiers.
func (s Score) Tag() string {
	// Benign scanner always wins — demote regardless of other signals.
	if s.IsBenignScanner {
		if s.IPSumScore >= MaliciousThreshold {
			return "🔬 BENIGN SCANNER — known research scanner (IPSum score: " + itoa(s.IPSumScore) + "/30 — expected, demote to LOW)"
		}
		return "🔬 BENIGN SCANNER — known research scanner (Shodan / Censys / Shadowserver — demote to LOW)"
	}

	// AbuseIPDB confirmed malicious takes priority over IPSum tiers.
	if s.Abuse.IsConfirmedMaliciousAbuse() {
		base := "🚨 ABUSEIPDB CONFIRMED MALICIOUS (score: " + itoa(s.Abuse.AbuseScore) + "/100, " +
			itoa(s.Abuse.TotalReports) + " reports, last: " + s.Abuse.LastReportedAt + ")"
		if s.IsTorExit {
			base += " + TOR EXIT"
		}
		if s.IPSumScore >= MaliciousThreshold {
			base += " | IPSum: " + itoa(s.IPSumScore) + "/30"
		}
		return base
	}

	// AbuseIPDB suspicious (30-74) — surface alongside IPSum.
	if s.Abuse.AbuseScore >= 30 {
		base := "⚠️  ABUSEIPDB SUSPICIOUS (score: " + itoa(s.Abuse.AbuseScore) + "/100, " +
			itoa(s.Abuse.TotalReports) + " reports)"
		if s.IPSumScore >= MaliciousThreshold {
			base += " | IPSum: " + itoa(s.IPSumScore) + "/30 feeds"
		}
		if s.IsTorExit {
			base += " + TOR EXIT"
		}
		return base
	}

	// Fall back to IPSum tiers.
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
		if s.Abuse.AbuseScore > 0 {
			return s.Abuse.Tag()
		}
		return ""
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// Enricher holds in-memory copies of the threat feeds.
type Enricher struct {
	ipSumPath   string
	torExitPath string

	mu       sync.RWMutex
	ipsum    map[string]int
	torExits map[string]bool

	benign *BenignScanners
}

// New creates an Enricher, loads all feed files immediately, and starts the
// background reload ticker.
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
		benign:      NewBenignScanners(""),
	}
	e.reload()
	go e.reloadLoop()

	if os.Getenv("ABUSEIPDB_API_KEY") != "" {
		log.Printf("[threat] AbuseIPDB enrichment enabled")
	} else {
		log.Printf("[threat] AbuseIPDB enrichment disabled (ABUSEIPDB_API_KEY not set)")
	}

	return e
}

// Lookup returns the threat score for a given IP, including a live AbuseIPDB check.
func (e *Enricher) Lookup(ip string) Score {
	e.mu.RLock()
	s := Score{
		IPSumScore:      e.ipsum[ip],
		IsTorExit:       e.torExits[ip],
		IsBenignScanner: e.benign.IsBenignScanner(ip),
	}
	e.mu.RUnlock()
	s.Abuse = CheckAbuse(ip)
	return s
}

// LookupMany returns scores for a slice of IPs, including live AbuseIPDB checks.
// Only IPs with a non-zero score, positive flag, or abuse data are included.
func (e *Enricher) LookupMany(ips []string) map[string]Score {
	out := make(map[string]Score, len(ips))
	for _, ip := range ips {
		e.mu.RLock()
		isBenign := e.benign.IsBenignScanner(ip)
		s := Score{
			IPSumScore:      e.ipsum[ip],
			IsTorExit:       e.torExits[ip],
			IsBenignScanner: isBenign,
		}
		e.mu.RUnlock()
		s.Abuse = CheckAbuse(ip)
		if s.IPSumScore > 0 || s.IsTorExit || s.IsBenignScanner || s.Abuse.AbuseScore > 0 {
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
		fields := strings.Fields(line)
		out[fields[0]] = true
	}
	return out
}

// ── Benign Scanner Registry ───────────────────────────────────────────────────

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
	// GreyNoise RIOT
	"45.83.66.65", "45.83.67.65",
	// Binaryedge
	"185.93.3.110",
	// Internet Archive
	"208.70.31.0",
}

var defaultBenignCIDRs = []string{
	"162.142.125.0/24",
	"167.248.133.0/24",
	"66.249.64.0/19",
	"40.77.167.0/24",
	"198.20.69.0/24",
	"198.20.70.0/24",
	"198.20.99.0/24",
}

type BenignScanners struct {
	mu    sync.RWMutex
	ips   map[string]bool
	cidrs []*net.IPNet
	path  string
}

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
