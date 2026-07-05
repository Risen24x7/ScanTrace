package handler

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
)

// reviewAllUsage is the short usage string appended to parse errors.
const reviewAllUsage = "Usage: `/scantrace review-all [--limit N] [--since 24h] [--severity red,yellow] [--exclude-wan-only] [--dedupe]`"

// severityColors lists the canonical severity colours in display order.
var severityColors = []string{"red", "yellow", "green"}

// reviewAllFlags captures the parsed flag state for /scantrace review-all.
// The *Set fields record whether the caller supplied the flag so that absent
// flags preserve the pre-existing default behaviour.
type reviewAllFlags struct {
	limit          int
	limitSet       bool
	since          time.Duration
	sinceRaw       string
	sinceSet       bool
	severities     map[string]bool
	severitySet    bool
	excludeWANOnly bool
	dedupe         bool
}

// colorForSeverity maps the stored severity label (high/medium/low) onto the
// red/yellow/green colour scheme used by the review filters. Values already in
// colour form are passed through unchanged.
func colorForSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "high", "red":
		return "red"
	case "medium", "yellow":
		return "yellow"
	case "low", "green":
		return "green"
	default:
		return ""
	}
}

// normalizeSeverities parses a comma/space tolerant severity list into a set of
// canonical colours. It accepts red/yellow/green and high/medium/low.
func normalizeSeverities(v string) (map[string]bool, error) {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make(map[string]bool)
	for _, f := range fields {
		c := colorForSeverity(f)
		if c == "" {
			return nil, fmt.Errorf("invalid severity %q (use red, yellow, green)", f)
		}
		out[c] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty severity list")
	}
	return out, nil
}

// parseFlexDuration parses a Go duration but additionally understands day (d)
// and week (w) suffixes, e.g. "7d" or "2w", which time.ParseDuration rejects.
func parseFlexDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	last := s[len(s)-1]
	if last == 'd' || last == 'D' || last == 'w' || last == 'W' {
		n, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return 0, err
		}
		unit := 24 * time.Hour
		if last == 'w' || last == 'W' {
			unit = 7 * 24 * time.Hour
		}
		return time.Duration(n * float64(unit)), nil
	}
	return time.ParseDuration(s)
}

// parseBoolValue interprets an optional boolean flag value. A bare flag (no
// value) is treated as true.
func parseBoolValue(hasVal bool, val string) (bool, error) {
	if !hasVal {
		return true, nil
	}
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1", "yes", "y", "on":
		return true, nil
	case "false", "0", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", val)
	}
}

// parseReviewAllFlags parses order-agnostic flags for /scantrace review-all.
// It supports both --k=v and --k v forms. On error it returns a short message
// that already includes the usage hint.
func parseReviewAllFlags(args []string) (reviewAllFlags, error) {
	f := reviewAllFlags{severities: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return f, fmt.Errorf("unexpected argument %q\n%s", arg, reviewAllUsage)
		}
		key := strings.TrimPrefix(arg, "--")
		val := ""
		hasVal := false
		if idx := strings.Index(key, "="); idx >= 0 {
			val = key[idx+1:]
			key = key[:idx]
			hasVal = true
		}
		takeVal := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
				return args[i], nil
			}
			return "", fmt.Errorf("flag --%s requires a value\n%s", key, reviewAllUsage)
		}
		switch key {
		case "limit":
			v, err := takeVal()
			if err != nil {
				return f, err
			}
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n <= 0 {
				return f, fmt.Errorf("invalid --limit %q (must be a positive integer)\n%s", v, reviewAllUsage)
			}
			if n > 200 {
				n = 200
			}
			f.limit, f.limitSet = n, true
		case "since":
			v, err := takeVal()
			if err != nil {
				return f, err
			}
			d, err := parseFlexDuration(v)
			if err != nil || d <= 0 {
				return f, fmt.Errorf("invalid --since %q (use e.g. 24h, 48h, 7d)\n%s", v, reviewAllUsage)
			}
			f.since, f.sinceRaw, f.sinceSet = d, strings.TrimSpace(v), true
		case "severity":
			v, err := takeVal()
			if err != nil {
				return f, err
			}
			sevs, err := normalizeSeverities(v)
			if err != nil {
				return f, fmt.Errorf("%v\n%s", err, reviewAllUsage)
			}
			f.severities, f.severitySet = sevs, true
		case "exclude-wan-only":
			b, err := parseBoolValue(hasVal, val)
			if err != nil {
				return f, fmt.Errorf("invalid --exclude-wan-only %q\n%s", val, reviewAllUsage)
			}
			f.excludeWANOnly = b
		case "dedupe":
			b, err := parseBoolValue(hasVal, val)
			if err != nil {
				return f, fmt.Errorf("invalid --dedupe %q\n%s", val, reviewAllUsage)
			}
			f.dedupe = b
		default:
			return f, fmt.Errorf("unknown flag --%s\n%s", key, reviewAllUsage)
		}
	}
	return f, nil
}

// caseFacts is the flattened, filter-ready view of a case derived from its
// events. Building it once keeps the filter helpers pure and testable.
type caseFacts struct {
	c        *db.Case
	srcIP    string
	dstNorm  string // "WAN_EDGE" when the case is WAN-only, else the internal dst IP
	dstPort  int
	protocol string
	label    string // signature/label (case title)
	lastSeen time.Time
	severity string // canonical colour
	wanOnly  bool
}

// caseEvents loads the events referenced by a case, skipping any that fail to
// load. Kept separate so the filter helpers can be exercised without a DB.
func (h *Handler) caseEvents(c *db.Case) []*db.Event {
	out := make([]*db.Event, 0, len(c.RelatedEventIDs))
	for _, id := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(id)
		if err != nil || evt == nil {
			continue
		}
		out = append(out, evt)
	}
	return out
}

// eventTime returns the most recent timestamp recorded on an event, preferring
// LastSeen and falling back to Timestamp.
func eventTime(e *db.Event) time.Time {
	t := e.LastSeen
	if e.Timestamp.After(t) {
		t = e.Timestamp
	}
	return t
}

// caseLastSeen returns the latest observed time across a case's events. It
// returns the zero time when no event carries a usable timestamp.
func caseLastSeen(events []*db.Event) time.Time {
	var latest time.Time
	for _, e := range events {
		if t := eventTime(e); t.After(latest) {
			latest = t
		}
	}
	return latest
}

// isWANOnlyEvents reports whether every event in a case targets the WAN edge
// (no internal target). It reuses the existing classifyDst logic.
func (h *Handler) isWANOnlyEvents(events []*db.Event) bool {
	if len(events) == 0 {
		return false
	}
	for _, e := range events {
		if _, edge := h.classifyDst(e.DstIP, e.EventType); !edge {
			return false
		}
	}
	return true
}

// isWANOnly reports whether a case only involves WAN-edge probes.
func (h *Handler) isWANOnly(c *db.Case) bool {
	return h.isWANOnlyEvents(h.caseEvents(c))
}

// caseFactsFromEvents flattens a case + its events into a caseFacts value.
func (h *Handler) caseFactsFromEvents(c *db.Case, events []*db.Event) caseFacts {
	f := caseFacts{
		c:        c,
		label:    c.Title,
		severity: colorForSeverity(c.Severity),
		lastSeen: caseLastSeen(events),
		wanOnly:  h.isWANOnlyEvents(events),
	}
	for _, e := range events {
		if f.srcIP == "" && e.SrcIP != "" {
			f.srcIP = e.SrcIP
		}
		if f.dstPort == 0 && e.DstPort > 0 {
			f.dstPort = e.DstPort
		}
		if f.protocol == "" && e.Protocol != "" {
			f.protocol = e.Protocol
		}
	}
	if f.srcIP == "" && c.SrcIP != "" {
		f.srcIP = c.SrcIP
	}
	if f.wanOnly {
		f.dstNorm = "WAN_EDGE"
	} else {
		for _, e := range events {
			if e.DstIP != "" && e.DstIP != h.wanIP {
				f.dstNorm = e.DstIP
				break
			}
		}
	}
	return f
}

// dedupeKey builds the de-duplication key from src_ip, normalized destination,
// dst_port, protocol, and signature/label.
func (f caseFacts) dedupeKey() string {
	return strings.Join([]string{
		f.srcIP,
		f.dstNorm,
		strconv.Itoa(f.dstPort),
		strings.ToLower(f.protocol),
		strings.ToLower(f.label),
	}, "|")
}

// filterBySeverity keeps only cases whose colour is in allowed. An empty set
// means "no filter".
func filterBySeverity(facts []caseFacts, allowed map[string]bool) []caseFacts {
	if len(allowed) == 0 {
		return facts
	}
	out := make([]caseFacts, 0, len(facts))
	for _, f := range facts {
		if allowed[f.severity] {
			out = append(out, f)
		}
	}
	return out
}

// filterBySince keeps cases whose last-seen time is at or after cutoff. Cases
// with no timestamp are retained (filter skipped).
func filterBySince(facts []caseFacts, cutoff time.Time) []caseFacts {
	out := make([]caseFacts, 0, len(facts))
	for _, f := range facts {
		if f.lastSeen.IsZero() || !f.lastSeen.Before(cutoff) {
			out = append(out, f)
		}
	}
	return out
}

// filterExcludeWANOnly drops cases that only involve WAN-edge probes.
func filterExcludeWANOnly(facts []caseFacts) []caseFacts {
	out := make([]caseFacts, 0, len(facts))
	for _, f := range facts {
		if !f.wanOnly {
			out = append(out, f)
		}
	}
	return out
}

// dedupeCases collapses similar cases by dedupeKey, keeping the most recent by
// last-seen timestamp. Original ordering of surviving entries is preserved.
func dedupeCases(facts []caseFacts) []caseFacts {
	seen := make(map[string]int)
	out := make([]caseFacts, 0, len(facts))
	for _, f := range facts {
		k := f.dedupeKey()
		if idx, ok := seen[k]; ok {
			if f.lastSeen.After(out[idx].lastSeen) {
				out[idx] = f
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	return out
}

// applyReviewFilters applies the configured filters in a deterministic order:
// severity, since, exclude-wan-only, dedupe, then the limit.
func applyReviewFilters(facts []caseFacts, f reviewAllFlags, now time.Time) []caseFacts {
	out := facts
	if f.severitySet {
		out = filterBySeverity(out, f.severities)
	}
	if f.sinceSet {
		out = filterBySince(out, now.Add(-f.since))
	}
	if f.excludeWANOnly {
		out = filterExcludeWANOnly(out)
	}
	if f.dedupe {
		out = dedupeCases(out)
	}
	limit := 50
	if f.limitSet {
		limit = f.limit
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// severityListForDisplay returns the selected colours in canonical order.
func severityListForDisplay(set map[string]bool) []string {
	var out []string
	for _, c := range severityColors {
		if set[c] {
			out = append(out, c)
		}
	}
	return out
}

// reviewFilterReason produces a concise description of the active filters for
// the "no cases match" reply.
func reviewFilterReason(f reviewAllFlags) string {
	var parts []string
	if f.severitySet {
		parts = append(parts, "severity="+strings.Join(severityListForDisplay(f.severities), ","))
	}
	if f.sinceSet {
		parts = append(parts, "since="+f.sinceRaw)
	}
	if f.excludeWANOnly {
		parts = append(parts, "exclude-wan-only")
	}
	if f.dedupe {
		parts = append(parts, "dedupe")
	}
	if f.limitSet {
		parts = append(parts, fmt.Sprintf("limit=%d", f.limit))
	}
	if len(parts) == 0 {
		return "No cases match the given filters."
	}
	return "No cases match " + strings.Join(parts, " ")
}
