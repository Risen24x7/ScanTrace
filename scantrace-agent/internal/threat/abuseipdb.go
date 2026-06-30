package threat

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	abuseIPDBEndpoint = "https://api.abuseipdb.com/api/v2/check"
	abuseScoreThreshold = 75 // confidence >= 75 = confirmed malicious
)

// AbuseResult holds the AbuseIPDB response for a single IP.
type AbuseResult struct {
	AbuseScore     int    // 0-100 confidence score
	TotalReports   int    // number of abuse reports
	LastReportedAt string // ISO8601 string, empty if never reported
	CountryCode    string
	Domain         string
	IsWhitelisted  bool
}

type abuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		Domain               string `json:"domain"`
		TotalReports         int    `json:"totalReports"`
		LastReportedAt       string `json:"lastReportedAt"`
		IsWhitelisted        bool   `json:"isWhitelisted"`
	} `json:"data"`
}

// abuseClient is a package-level HTTP client shared across calls.
var abuseClient = &http.Client{Timeout: 5 * time.Second}

// CheckAbuse queries AbuseIPDB for the given IP.
// Returns a zero AbuseResult if the API key is unset or the request fails.
func CheckAbuse(ip string) AbuseResult {
	key := os.Getenv("ABUSEIPDB_API_KEY")
	if key == "" {
		return AbuseResult{}
	}

	req, err := http.NewRequest(http.MethodGet, abuseIPDBEndpoint, nil)
	if err != nil {
		log.Printf("[threat/abuseipdb] request build error: %v", err)
		return AbuseResult{}
	}

	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	q.Set("verbose", "false")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")

	resp, err := abuseClient.Do(req)
	if err != nil {
		log.Printf("[threat/abuseipdb] request error for %s: %v", ip, err)
		return AbuseResult{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[threat/abuseipdb] non-200 for %s: %d — %s", ip, resp.StatusCode, string(body))
		return AbuseResult{}
	}

	var parsed abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		log.Printf("[threat/abuseipdb] decode error for %s: %v", ip, err)
		return AbuseResult{}
	}

	return AbuseResult{
		AbuseScore:     parsed.Data.AbuseConfidenceScore,
		TotalReports:   parsed.Data.TotalReports,
		LastReportedAt: parsed.Data.LastReportedAt,
		CountryCode:    parsed.Data.CountryCode,
		Domain:         parsed.Data.Domain,
		IsWhitelisted:  parsed.Data.IsWhitelisted,
	}
}

// IsConfirmedMaliciousAbuse returns true when AbuseIPDB confidence >= threshold.
func (a AbuseResult) IsConfirmedMaliciousAbuse() bool {
	return a.AbuseScore >= abuseScoreThreshold
}

// Tag returns a human-readable label for the AbuseIPDB result.
func (a AbuseResult) Tag() string {
	if a.AbuseScore == 0 && a.TotalReports == 0 {
		return ""
	}
	if a.IsWhitelisted {
		return fmt.Sprintf("✅ ABUSEIPDB WHITELISTED (score: %d)", a.AbuseScore)
	}
	if a.AbuseScore >= abuseScoreThreshold {
		return fmt.Sprintf("🚨 ABUSEIPDB CONFIRMED MALICIOUS (score: %d/100, %d reports, last: %s)",
			a.AbuseScore, a.TotalReports, a.LastReportedAt)
	}
	if a.AbuseScore >= 30 {
		return fmt.Sprintf("⚠️  ABUSEIPDB SUSPICIOUS (score: %d/100, %d reports)",
			a.AbuseScore, a.TotalReports)
	}
	return fmt.Sprintf("📋 ABUSEIPDB LOW CONFIDENCE (score: %d/100, %d reports)",
		a.AbuseScore, a.TotalReports)
}
