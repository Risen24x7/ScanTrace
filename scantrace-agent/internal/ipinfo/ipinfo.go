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

var client = &http.Client{Timeout: timeout}

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

// Summary returns a single-line human-readable description.
func (i *Info) Summary() string {
	if i.Err != nil {
		return "(lookup failed)"
	}
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
	return fmt.Sprintf("%s | %s | %s%s", i.Country, i.Org, i.AS, flagStr)
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
