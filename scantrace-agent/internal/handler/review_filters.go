package handler

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
)

// reviewAllOpts holds the parsed flags for `/scantrace review-all`.
type reviewAllOpts struct {
	limit          int
	limitSet       bool
	since          time.Duration
	sinceSet       bool
	sinceRaw       string
	severities     map[string]bool // normalized to high/medium/low
	severitySet    bool
	severityRaw    string
	excludeWANOnly bool
	dedupe         bool
}

// filterSummary renders a short human-readable description of the active
// filters, used when zero cases remain after filtering.
func (o reviewAllOpts) filterSummary() string {
	var parts []string
	if o.severitySet {
		parts = append(parts, "severity="+o.severityRaw)
	}
	if o.sinceSet {
		parts = append(parts, "since="+o.sinceRaw)
	}
	if o.excludeWANOnly {
		parts = append(parts, "exclude-wan-only")
	}
	if o.dedupe {
		parts = append(parts, "dedupe")
	}
	if o.limitSet {
		parts = append(parts, fmt.Sprintf("limit=%d", o.limit))
	}
	if len(parts) == 0 {
		return "the supplied filters"
	}
	return strings.Join(parts, " ")
}

// reviewAllUsage returns a usage string prefixed with the parse error.
func reviewAllUsage(err error) string {
	return fmt.Sprintf("⚠️ %v\n\nUsage: `/scantrace review-all [--limit N] [--since 24h] "+
		"[--severity red,yellow,green] [--exclude-wan-only] [--dedupe]`", err)
}

// parseReviewAllFlags parses order-agnostic flags. It accepts both `--k=v` and
// `--k v` forms plus the boolean flags `--exclude-wan-only` and `--dedupe`.
func parseReviewAllFlags(args []string) (reviewAllOpts, error) {
	var o reviewAllOpts
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

		// Boolean flags (value is optional).
		switch key {
		case "exclude-wan-only":
			o.excludeWANOnly = !hasVal || parseBoolFlag(val)
			continue
		case "dedupe":
			o.dedupe = !hasVal || parseBoolFlag(val)
			continue
		}

		// Value flags: consume the next token when not given as --k=v.
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
			if err != nil || n < 1 || n > 200 {
				return o, fmt.Errorf("invalid --limit %q (must be an integer 1..200)", val)
			}
			o.limit = n
			o.limitSet = true
		case "since":
			d, err := parseFlexDuration(val)
			if err != nil || d <= 0 {
				return o, fmt.Errorf("invalid --since %q (use a duration like 24h, 48h, 7d)", val)
			}
			o.since = d
			o.sinceSet = true
			o.sinceRaw = val
		case "severity":
			sevs, err := normalizeSeverities(val)
			if err != nil {
				return o, err
			}
			o.severities = sevs
			o.severitySet = true
			o.severityRaw = val
		default:
			return o, fmt.Errorf("unknown flag --%s", key)
		}
	}
	return o, nil
}

// parseBoolFlag interprets common truthy/falsey tokens. Anything that is not an
// explicit falsey value is treated as true.
func parseBoolFlag(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "n", "off":
		return false
	default:
		return true
	}
}

// parseFlexDuration parses a Go duration, additionally supporting a trailing
// "d" (days) or "w" (weeks) suffix (e.g. 7d, 2w) which time.ParseDuration does
// not understand.
func parseFlexDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	unit := s[len(s)-1]
	switch unit {
	case 'd', 'D', 'w', 'W':
		numPart := strings.TrimSpace(s[:len(s)-1])
		n, err := strconv.ParseFloat(numPart, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		hours := 24.0
		if unit == 'w' || unit == 'W' {
			hours = 24.0 * 7.0
		}
		return time.Duration(n * hours * float64(time.Hour)), nil
	}
	return 0, fmt.Errorf("invalid duration %q", s)
}

// normalizeSeverities parses a comma/space separated list of severities. Color
// aliases red/yellow/green map to high/medium/low; the canonical names are also
// accepted. The result is keyed on the canonical high/medium/low values.
func normalizeSeverities(raw string) (map[string]bool, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(fields) == 0 {
		return nil, fmt.Errorf("invalid --severity %q (expected e.g. red,yellow,green)", raw)
	}
	out := make(map[string]bool)
	for _, f := range fields {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "red", "high":
			out["high"] = true
		case "yellow", "amber", "medium", "med":
			out["medium"] = true
		case "green", "low":
			out["low"] = true
		default:
			return nil, fmt.Errorf("invalid severity %q (use red/yellow/green or high/medium/low)", f)
		}
	}
	return out, nil
}

// caseLatestEventTime returns the most recent event timestamp for a case. The
// boolean is false when no event carries a usable timestamp.
func (h *Handler) caseLatestEventTime(c *db.Case) (time.Time, bool) {
	var latest time.Time
	found := false
	for _, id := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(id)
		if err != nil || evt == nil {
			continue
		}
		t := evt.Timestamp
		if t.IsZero() {
			t = evt.LastSeen
		}
		if t.IsZero() {
			continue
		}
		if !found || t.After(latest) {
			latest = t
			found = true
		}
	}
	return latest, found
}

// caseRecency returns a best-effort recency timestamp for ordering, falling
// back to the case update/create time when events lack timestamps.
func (h *Handler) caseRecency(c *db.Case) time.Time {
	if t, ok := h.caseLatestEventTime(c); ok {
		return t
	}
	if !c.UpdatedAt.IsZero() {
		return c.UpdatedAt
	}
	return c.CreatedAt
}

// caseIsWANOnly reports whether every event in the case only involves the WAN
// edge (reusing classifyDst). A case with no resolvable events is not WAN-only.
func (h *Handler) caseIsWANOnly(c *db.Case) bool {
	n := 0
	for _, id := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(id)
		if err != nil || evt == nil {
			continue
		}
		if _, isEdge := h.classifyDst(evt.DstIP, evt.EventType); !isEdge {
			return false
		}
		n++
	}
	return n > 0
}

// caseDedupeKey builds a de-duplication key from a case: src_ip, normalized
// destination (WAN_EDGE for WAN-only cases), dst_port, and protocol when
// available.
func (h *Handler) caseDedupeKey(c *db.Case) string {
	wanOnly := h.caseIsWANOnly(c)
	src := c.SrcIP
	var dst, proto string
	var port int
	for _, id := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(id)
		if err != nil || evt == nil {
			continue
		}
		if src == "" {
			src = evt.SrcIP
		}
		if dst == "" && evt.DstIP != "" {
			dst = evt.DstIP
		}
		if port == 0 && evt.DstPort > 0 {
			port = evt.DstPort
		}
		if proto == "" {
			proto = evt.Protocol
		}
	}
	normDst := dst
	if wanOnly {
		normDst = "WAN_EDGE"
	}
	return fmt.Sprintf("%s|%s|%d|%s",
		strings.ToLower(src), strings.ToLower(normDst), port, strings.ToLower(proto))
}

// filterReviewCases applies severity, since, exclude-wan-only and dedupe
// filters, then enforces the limit (defaulting to 50 when none was supplied).
func (h *Handler) filterReviewCases(cases []*db.Case, o reviewAllOpts) []*db.Case {
	out := cases

	if o.severitySet {
		var kept []*db.Case
		for _, c := range out {
			if o.severities[strings.ToLower(c.Severity)] {
				kept = append(kept, c)
			}
		}
		out = kept
	}

	if o.sinceSet {
		cutoff := time.Now().Add(-o.since)
		var kept []*db.Case
		for _, c := range out {
			t, ok := h.caseLatestEventTime(c)
			// Skip the time filter when timestamps are missing.
			if !ok || !t.Before(cutoff) {
				kept = append(kept, c)
			}
		}
		out = kept
	}

	if o.excludeWANOnly {
		var kept []*db.Case
		for _, c := range out {
			if !h.caseIsWANOnly(c) {
				kept = append(kept, c)
			}
		}
		out = kept
	}

	if o.dedupe {
		out = h.dedupeCases(out)
	}

	limit := 50
	if o.limitSet {
		limit = o.limit
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// dedupeCases collapses cases sharing a dedupe key, keeping the most recent one
// per key while preserving the original ordering of the surviving cases.
func (h *Handler) dedupeCases(cases []*db.Case) []*db.Case {
	type rec struct {
		idx int
		t   time.Time
	}
	best := make(map[string]rec)
	for i, c := range cases {
		k := h.caseDedupeKey(c)
		t := h.caseRecency(c)
		if b, ok := best[k]; !ok || t.After(b.t) {
			best[k] = rec{idx: i, t: t}
		}
	}
	winners := make(map[int]bool, len(best))
	for _, b := range best {
		winners[b.idx] = true
	}
	var out []*db.Case
	for i, c := range cases {
		if winners[i] {
			out = append(out, c)
		}
	}
	return out
}
