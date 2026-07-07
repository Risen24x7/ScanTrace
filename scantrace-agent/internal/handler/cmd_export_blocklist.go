package handler

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// exportBlocklistOpts holds the parsed flags for `/scantrace export-blocklist`.
type exportBlocklistOpts struct {
	limit       int
	since       time.Duration
	sinceRaw    string
	severities  map[string]bool // normalized to high/medium/low
	severityRaw string
	wanOnly     bool
	groupCIDR   bool
	format      string // txt | csv | ipset
}

const (
	exportDefaultLimit  = 32
	exportMaxLimit      = 256
	exportDefaultSince  = 7 * 24 * time.Hour
	cidrGroupThreshold  = 3
	blocklistPreviewCap = 20
)

// blocklistEntry is a single observed source IP with recency/context, the raw
// input to the (pure) blocklist builder.
type blocklistEntry struct {
	IP       string
	Time     time.Time
	Severity string
	CaseID   string
}

// blocklistLine is a rendered blocklist entry — either a single IP or an
// aggregated CIDR.
type blocklistLine struct {
	Value    string
	IsCIDR   bool
	Count    int
	LastSeen time.Time
}

// exportBlocklistUsage returns a usage string prefixed with the parse error.
func exportBlocklistUsage(err error) string {
	return fmt.Sprintf("⚠️ %v\n\nUsage: `/scantrace export-blocklist [--limit N] [--since 7d] "+
		"[--severity red,yellow] [--wan-only] [--group-cidr] [--format txt|csv|ipset]`", err)
}

// parseExportBlocklistFlags parses the export-blocklist flags with sensible
// defaults. Accepts both `--k=v` and `--k v` forms.
func parseExportBlocklistFlags(args []string) (exportBlocklistOpts, error) {
	o := exportBlocklistOpts{
		limit:       exportDefaultLimit,
		since:       exportDefaultSince,
		sinceRaw:    "7d",
		severities:  map[string]bool{"high": true, "medium": true},
		severityRaw: "red,yellow",
		wanOnly:     true,
		format:      "txt",
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			return o, fmt.Errorf("unexpected argument %q", a)
		}
		key := strings.TrimPrefix(a, "--")
		val := ""
		hasVal := false
		if idx := strings.Index(key, "="); idx >= 0 {
			val = key[idx+1:]
			key = key[:idx]
			hasVal = true
		}
		key = strings.ToLower(key)

		switch key {
		case "wan-only":
			o.wanOnly = !hasVal || parseBoolFlag(val)
			continue
		case "group-cidr":
			o.groupCIDR = !hasVal || parseBoolFlag(val)
			continue
		}

		if !hasVal {
			if i+1 >= len(args) {
				return o, fmt.Errorf("flag --%s requires a value", key)
			}
			i++
			val = args[i]
		}

		switch key {
		case "limit":
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil || n < 1 {
				return o, fmt.Errorf("invalid --limit %q (must be a positive integer)", val)
			}
			if n > exportMaxLimit {
				n = exportMaxLimit
			}
			o.limit = n
		case "since":
			d, err := parseFlexDuration(val)
			if err != nil || d <= 0 {
				return o, fmt.Errorf("invalid --since %q (use a duration like 24h, 7d)", val)
			}
			o.since = d
			o.sinceRaw = val
		case "severity":
			sevs, err := normalizeSeverities(val)
			if err != nil {
				return o, err
			}
			o.severities = sevs
			o.severityRaw = val
		case "format":
			f := strings.ToLower(strings.TrimSpace(val))
			switch f {
			case "txt", "csv", "ipset":
				o.format = f
			default:
				return o, fmt.Errorf("invalid --format %q (use txt, csv or ipset)", val)
			}
		default:
			return o, fmt.Errorf("unknown flag --%s", key)
		}
	}
	return o, nil
}

// cidrPrefix returns the aggregating CIDR prefix for an IP: /24 for IPv4 and
// /64 for IPv6.
func cidrPrefix(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		mask := net.CIDRMask(24, 32)
		return fmt.Sprintf("%s/24", v4.Mask(mask).String()), true
	}
	if v6 := ip.To16(); v6 != nil {
		mask := net.CIDRMask(64, 128)
		return fmt.Sprintf("%s/64", v6.Mask(mask).String()), true
	}
	return "", false
}

// buildBlocklistLines is the pure builder: it de-duplicates IPs (keeping the
// most recent occurrence), optionally aggregates IPv4/IPv6 by /24 and /64 when
// at least cidrGroupThreshold IPs share a prefix, orders results preferring
// larger and more recent groups, and enforces the limit.
func buildBlocklistLines(raw []blocklistEntry, groupCIDR bool, limit int) []blocklistLine {
	// Dedupe IPs, keeping the most recent occurrence and stable first-seen order.
	latest := make(map[string]blocklistEntry)
	var order []string
	for _, e := range raw {
		if e.IP == "" {
			continue
		}
		cur, ok := latest[e.IP]
		if !ok {
			order = append(order, e.IP)
			latest[e.IP] = e
			continue
		}
		if e.Time.After(cur.Time) {
			latest[e.IP] = e
		}
	}
	deduped := make([]blocklistEntry, 0, len(order))
	for _, ip := range order {
		deduped = append(deduped, latest[ip])
	}

	var lines []blocklistLine

	if groupCIDR {
		type grp struct {
			ips  []blocklistEntry
			last time.Time
		}
		groups := make(map[string]*grp)
		var groupOrder []string
		for _, e := range deduped {
			pfx, ok := cidrPrefix(e.IP)
			if !ok {
				continue
			}
			g := groups[pfx]
			if g == nil {
				g = &grp{}
				groups[pfx] = g
				groupOrder = append(groupOrder, pfx)
			}
			g.ips = append(g.ips, e)
			if e.Time.After(g.last) {
				g.last = e.Time
			}
		}
		used := make(map[string]bool)
		for _, pfx := range groupOrder {
			g := groups[pfx]
			if len(g.ips) >= cidrGroupThreshold {
				lines = append(lines, blocklistLine{
					Value:    pfx,
					IsCIDR:   true,
					Count:    len(g.ips),
					LastSeen: g.last,
				})
				for _, e := range g.ips {
					used[e.IP] = true
				}
			}
		}
		for _, e := range deduped {
			if used[e.IP] {
				continue
			}
			lines = append(lines, blocklistLine{Value: e.IP, Count: 1, LastSeen: e.Time})
		}
	} else {
		for _, e := range deduped {
			lines = append(lines, blocklistLine{Value: e.IP, Count: 1, LastSeen: e.Time})
		}
	}

	// Prefer larger (CIDR/higher-count) and more recent groups.
	sort.SliceStable(lines, func(i, j int) bool {
		li, lj := lines[i], lines[j]
		if li.IsCIDR != lj.IsCIDR {
			return li.IsCIDR
		}
		if li.Count != lj.Count {
			return li.Count > lj.Count
		}
		return li.LastSeen.After(lj.LastSeen)
	})

	if limit > 0 && len(lines) > limit {
		lines = lines[:limit]
	}
	return lines
}

// formatBlocklist renders the lines in the requested format.
func formatBlocklist(lines []blocklistLine, format string) string {
	var sb strings.Builder
	switch format {
	case "csv":
		sb.WriteString("ip_or_cidr,count,last_seen\n")
		for _, l := range lines {
			last := ""
			if !l.LastSeen.IsZero() {
				last = l.LastSeen.UTC().Format(time.RFC3339)
			}
			sb.WriteString(fmt.Sprintf("%s,%d,%s\n", l.Value, l.Count, last))
		}
	case "ipset":
		sb.WriteString("create scantrace-blocklist hash:net family inet -exist\n")
		for _, l := range lines {
			sb.WriteString(fmt.Sprintf("add scantrace-blocklist %s -exist\n", l.Value))
		}
	default: // txt
		for _, l := range lines {
			sb.WriteString(l.Value)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// writeBlocklistFile writes content to /opt/scantrace/exports, falling back to
// the current working directory when that path is not writable.
func writeBlocklistFile(content, format string, now time.Time) (string, error) {
	ext := "txt"
	if format == "csv" {
		ext = "csv"
	}
	name := fmt.Sprintf("blocklist-%s.%s", now.Format("20060102-1504"), ext)

	dir := "/opt/scantrace/exports"
	if err := os.MkdirAll(dir, 0o755); err == nil {
		full := filepath.Join(dir, name)
		if werr := os.WriteFile(full, []byte(content), 0o644); werr == nil {
			return full, nil
		}
	}
	// Fall back to the current working directory.
	full := filepath.Join(".", name)
	if werr := os.WriteFile(full, []byte(content), 0o644); werr != nil {
		return "", werr
	}
	return full, nil
}

// cmdExportBlocklist builds and writes a firewall blocklist from recent cases.
func (h *Handler) cmdExportBlocklist(channelID, userID string, args []string) {
	opts, err := parseExportBlocklistFlags(args)
	if err != nil {
		h.postEphemeral(channelID, userID, exportBlocklistUsage(err))
		return
	}

	cases, err := h.store.ListCases("", 200)
	if err != nil || len(cases) == 0 {
		h.postEphemeral(channelID, userID, "No cases available to export.")
		return
	}

	cutoff := time.Now().Add(-opts.since)
	var raw []blocklistEntry
	for _, c := range cases {
		if !opts.severities[strings.ToLower(c.Severity)] {
			continue
		}
		if opts.wanOnly && !h.caseIsWANOnly(c) {
			continue
		}
		t, ok := h.caseLatestEventTime(c)
		if opts.since > 0 && ok && t.Before(cutoff) {
			continue
		}
		recency := t
		if !ok {
			recency = h.caseRecency(c)
		}
		for _, ip := range h.caseSrcIPs(c) {
			raw = append(raw, blocklistEntry{
				IP:       ip,
				Time:     recency,
				Severity: c.Severity,
				CaseID:   c.CaseID,
			})
		}
	}

	lines := buildBlocklistLines(raw, opts.groupCIDR, opts.limit)
	if len(lines) == 0 {
		h.postEphemeral(channelID, userID, fmt.Sprintf(
			"No blocklist entries match severity=%s since=%s wan-only=%v.",
			opts.severityRaw, opts.sinceRaw, opts.wanOnly))
		return
	}

	content := formatBlocklist(lines, opts.format)
	path, werr := writeBlocklistFile(content, opts.format, time.Now())
	if werr != nil {
		log.Printf("[handler] export-blocklist write error: %v", werr)
		h.postEphemeral(channelID, userID, fmt.Sprintf("❌ Failed to write blocklist file: %v", werr))
		return
	}

	// Build the Slack preview: first ≤20 lines with a truncation notice.
	contentLines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	preview := contentLines
	truncated := false
	if len(preview) > blocklistPreviewCap {
		preview = preview[:blocklistPreviewCap]
		truncated = true
	}
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("✅ *Blocklist exported* — %d entr%s (format=%s)\n",
		len(lines), plural(len(lines), "y", "ies"), opts.format))
	msg.WriteString(fmt.Sprintf("• File: `%s`\n", path))
	msg.WriteString(fmt.Sprintf("• Filters: severity=%s since=%s wan-only=%v group-cidr=%v\n",
		opts.severityRaw, opts.sinceRaw, opts.wanOnly, opts.groupCIDR))
	msg.WriteString("```\n")
	msg.WriteString(strings.Join(preview, "\n"))
	msg.WriteString("\n```")
	if truncated {
		msg.WriteString(fmt.Sprintf("\n_…showing first %d of %d lines. See file for the full list._",
			blocklistPreviewCap, len(contentLines)))
	}
	h.postMessage(channelID, "", msg.String())
	log.Printf("[handler] export-blocklist wrote %d entries to %s by user=%s", len(lines), path, userID)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
