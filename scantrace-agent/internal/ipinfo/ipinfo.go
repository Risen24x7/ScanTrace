// Package ipinfo provides IP enrichment via ip-api.com (free tier, no key
// required, max 45 req/min on the batch endpoint: up to 100 IPs per call).
package ipinfo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	batchURL = "http://ip-api.com/batch?fields=status,query,country,isp,org,as,proxy,hosting"
	timeout  = 10 * time.Second
)

// Info holds enrichment data for one IP.
type Info struct {
	IP      string
	Country string
	ISP     string
	Org     string
	AS      string
	Proxy   bool
	Hosting bool
	Err     error
}

// Classification is the high-level verdict for an IP based on org/ASN data.
type Classification int

const (
	ClassUnknown    Classification = iota
	ClassFeds                      // US government / military / federal agency
	ClassKnownGood                 // major CDN, cloud infra, well-known benign network (non-hosting)
	ClassKnownCloud                // major cloud/CDN provider flagged as hosting infra (Google, AWS, Azure, etc.)
	ClassKnownBad                  // anonymous proxy / bulletproof hosting DC
	ClassSuspicious                // proxy/VPN without DC hosting
)

// govOrgKeywords are substrings matched (case-insensitive) against Org or ISP
// to identify US federal / military networks.
var govOrgKeywords = []string{
	"department of defense",
	"dod network",
	"disa ",
	"disa,",
	"defense information systems",
	"us army",
	"u.s. army",
	"us navy",
	"u.s. navy",
	"us air force",
	"u.s. air force",
	"us marine",
	"u.s. marine",
	"pentagon",
	"national security agency",
	"nsa ",
	"central intelligence",
	"cia ",
	"federal bureau",
	"fbi ",
	"department of homeland",
	"dhs ",
	"nasa ",
	"national aeronautics",
	"us postal service",
	"usps ",
	"internal revenue service",
	"irs ",
	"veterans affairs",
	".mil",
	".gov",
	"us government",
	"united states government",
	"executive office",
	"white house",
	"senate.gov",
	"house.gov",
}

// govASNs are well-known US government / military AS numbers.
var govASNs = []string{
	"AS749",   // DoD Network Information Center
	"AS721",   // DoD NIC
	"AS8003",  // DISA
	"AS6325",  // DISA
	"AS12148", // US Treasury
	"AS2742",  // NASA
	"AS297",   // NASA
	"AS690",   // NSFNET / NSF
	"AS26008", // DHS
	"AS32934", // reserved DoD
	"AS27065", // DoJ
	"AS11557", // FBI
	"AS4323",  // CIA
}

// knownBulletproofASNs are ASNs explicitly identified as bulletproof or
// shady hosting operators based on active threat-feed telemetry. These are
// classified KnownBad regardless of what ip-api.com returns for the hosting
// or proxy boolean flags, which may lag for small/new ASNs.
var knownBulletproofASNs = []string{
	"AS209334", // Modat B.V. — NL-registered, OVH-colocated; active origin for Docker API scans,
	//             mass SSH brute-force, and RedTail miner botnet deployment per AbuseIPDB/ThreatFox/IPSum.
}

// knownBulletproofOrgKeywords are org/ISP substrings that reliably identify
// bulletproof or shady hosting operators even when the hosting flag is false.
var knownBulletproofOrgKeywords = []string{
	"modat b.v.",
	"modat bv",
}

// knownCloudKeywords identify major cloud/CDN providers that may be flagged as
// hosting infrastructure but are generally considered legitimate traffic sources.
// Checked BEFORE the generic hosting=true → KnownBad rule.
var knownCloudKeywords = []string{
	"google",
	"amazon",
	"microsoft",
	"cloudflare",
	"akamai",
	"fastly",
	"apple",
	"cdn77",
	"limelight",
	"edgecast",
	"stackpath",
	"oracle cloud",
	"digitalocean",
	"linode",
	"vultr",
}

// knownGoodKeywords identify well-known benign non-hosting networks (ISPs,
// carriers, major telecoms). These are checked after cloud keywords.
var knownGoodKeywords = []string{
	"level 3",
	"lumen",
	"comcast",
	"att ",
	"at&t",
	"verizon",
	"spectrum",
	"charter",
	"cox communications",
	"centurylink",
	"lumen technologies",
	"twc ",
	"time warner",
}

var client = &http.Client{Timeout: timeout}

// Classify returns the high-level verdict for this IP based on org/ASN data.
func (i *Info) Classify() Classification {
	if i.Err != nil {
		return ClassUnknown
	}
	orgLower := strings.ToLower(i.Org + " " + i.ISP)
	asUpper := ""
	if fields := strings.Fields(i.AS); len(fields) > 0 {
		asUpper = strings.ToUpper(fields[0]) // e.g. "AS749"
	}

	// 1. US Government / Military — takes precedence over everything.
	for _, kw := range govOrgKeywords {
		if strings.Contains(orgLower, kw) {
			return ClassFeds
		}
	}
	for _, asn := range govASNs {
		if asUpper == asn {
			return ClassFeds
		}
	}

	// 2. Explicitly known bulletproof ASNs — classified KnownBad regardless of
	//    ip-api.com hosting/proxy flags, which may not yet cover small/new ASNs.
	for _, asn := range knownBulletproofASNs {
		if asUpper == asn {
			return ClassKnownBad
		}
	}
	for _, kw := range knownBulletproofOrgKeywords {
		if strings.Contains(orgLower, kw) {
			return ClassKnownBad
		}
	}

	// 3. Hosting DC + Proxy together — bulletproof / C2 infra signal.
	//    Even major cloud providers get KnownBad if proxy is also flagged.
	if i.Hosting && i.Proxy {
		return ClassKnownBad
	}

	// 4. Proxy/VPN without hosting — anonymised source.
	if i.Proxy {
		return ClassSuspicious
	}

	// 5. Major cloud/CDN flagged as hosting — legitimate infra, not hostile DC.
	//    Must be checked BEFORE the generic hosting=true → KnownBad rule.
	if i.Hosting {
		for _, kw := range knownCloudKeywords {
			if strings.Contains(orgLower, kw) {
				return ClassKnownCloud
			}
		}
		// Generic hosting DC with no recognised cloud brand → KnownBad.
		return ClassKnownBad
	}

	// 6. Major CDN / carrier / big-tech (non-hosting) — benign.
	for _, kw := range knownCloudKeywords {
		if strings.Contains(orgLower, kw) {
			return ClassKnownGood
		}
	}
	for _, kw := range knownGoodKeywords {
		if strings.Contains(orgLower, kw) {
			return ClassKnownGood
		}
	}

	return ClassUnknown
}

// ClassBadge returns the Slack-formatted badge for the classification.
// Designed to be embedded inline in the IP intel section of a briefing.
func (i *Info) ClassBadge() string {
	switch i.Classify() {
	case ClassFeds:
		return "🇺🇸 *THE FEDS* — US Government / Federal Agency"
	case ClassKnownGood:
		return "✅ *KNOWN GOOD* — Major CDN / carrier infrastructure"
	case ClassKnownCloud:
		return "☁️ *KNOWN CLOUD* — Major cloud / CDN infrastructure"
	case ClassKnownBad:
		return "🚨 *KNOWN BAD* — Anonymous proxy / bulletproof hosting"
	case ClassSuspicious:
		return "⚠️ *SUSPICIOUS* — Proxy / VPN detected"
	default:
		return ""
	}
}

// Enrich fetches enrichment for up to 100 external IPs in a single batch call.
// Private/reserved IPs are skipped and returned with Org="internal".
func Enrich(ips []string) map[string]*Info {
	out := make(map[string]*Info, len(ips))
	var toQuery []string

	for _, ip := range ips {
		if isPrivate(ip) {
			out[ip] = &Info{IP: ip, Org: "internal (RFC1918)", Country: "local"}
			continue
		}
		toQuery = append(toQuery, ip)
	}

	if len(toQuery) == 0 {
		return out
	}

	// ip-api.com batch: max 100 per request
	for i := 0; i < len(toQuery); i += 100 {
		chunk := toQuery[i:min(i+100, len(toQuery))]
		results, err := batchQuery(chunk)
		if err != nil {
			for _, ip := range chunk {
				out[ip] = &Info{IP: ip, Err: err}
			}
			continue
		}
		for _, r := range results {
			out[r.IP] = r
		}
	}
	return out
}

func batchQuery(ips []string) ([]*Info, error) {
	type reqItem struct {
		Query string `json:"query"`
	}
	reqs := make([]reqItem, len(ips))
	for i, ip := range ips {
		reqs[i] = reqItem{Query: ip}
	}
	body, _ := json.Marshal(reqs)

	resp, err := client.Post(batchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ipinfo: request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipinfo: status %d", resp.StatusCode)
	}

	var items []struct {
		Status  string `json:"status"`
		Query   string `json:"query"`
		Country string `json:"country"`
		ISP     string `json:"isp"`
		Org     string `json:"org"`
		AS      string `json:"as"`
		Proxy   bool   `json:"proxy"`
		Hosting bool   `json:"hosting"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("ipinfo: decode: %w", err)
	}

	result := make([]*Info, 0, len(items))
	for _, item := range items {
		info := &Info{
			IP:      item.Query,
			Country: item.Country,
			ISP:     item.ISP,
			Org:     item.Org,
			AS:      item.AS,
			Proxy:   item.Proxy,
			Hosting: item.Hosting,
		}
		if item.Status != "success" {
			info.Err = fmt.Errorf("ipinfo: api status=%s for %s", item.Status, item.Query)
		}
		result = append(result, info)
	}
	return result, nil
}

// Summary returns a single-line human-readable description including
// the classification badge when one applies.
func (i *Info) Summary() string {
	if i.Err != nil {
		return "(lookup failed)"
	}

	badge := i.ClassBadge()

	var flags []string
	if i.Proxy {
		flags = append(flags, "proxy/VPN")
	}
	if i.Hosting {
		flags = append(flags, "hosting/DC")
	}
	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, ",") + "]"
	}

	base := fmt.Sprintf("%s | %s | %s%s", i.Country, i.Org, i.AS, flagStr)
	if badge != "" {
		return base + " — " + badge
	}
	return base
}

func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range private {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
