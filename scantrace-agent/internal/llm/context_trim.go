package llm

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type TrimStats struct {
	Enabled    bool
	Budget     int
	Kept       int
	Compressed int
	Dropped    int
}

func maybeTrimContext(ctx string, isAsk bool) (string, TrimStats) {
	if ctx == "" {
		return ctx, TrimStats{Enabled: false}
	}

	enabled := envBoolDefault("LLM_CONTEXT_TRIM", false)
	if v, ok := os.LookupEnv(map[bool]string{true: "LLM_ASK_TRIM", false: "LLM_ASKCASE_TRIM"}[isAsk]); ok {
		enabled = parseBool(v)
	}
	if !enabled {
		return ctx, TrimStats{Enabled: false}
	}

	budget := envInt("LLM_CONTEXT_MAX_BYTES", 4000)
	dedup := envBoolDefault("LLM_TRIM_DEDUP", true)
	bySev := envBoolDefault("LLM_TRIM_BY_SEVERITY", true)

	lines := splitNonEmpty(ctx)
	if len(lines) == 0 {
		return ctx, TrimStats{Enabled: false}
	}

	type row struct {
		line     string
		sev      int
		sevLabel string
		subnet24 string
		idShort  string
		comp     string
	}
	rows := make([]row, 0, len(lines))
	reID := regexp.MustCompile(`\bcase id=([0-9a-fA-F]{8,})`)
	reSev := regexp.MustCompile(`\bsev=([a-zA-Z]+)`)
	rePrefix := regexp.MustCompile(`(\d+\.\d+\.\d+)\.\d+/\d+`)
	rePort := regexp.MustCompile(`port[ =](\d+)(?:/([A-Za-z]+))?`)
	for _, ln := range lines {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		id := find1(reID, ln)
		if len(id) > 8 {
			id = id[:8]
		}
		sevLabel := strings.ToLower(find1(reSev, ln))
		sev := map[string]int{"high": 3, "medium": 2, "med": 2, "low": 1, "info": 0}[sevLabel]
		if sevLabel == "" {
			sevLabel = "low"
			sev = 1
		}
		pfx := find1(rePrefix, ln)
		if pfx != "" {
			pfx = pfx + ".0/24"
		}
		port := find1(rePort, ln)
		comp := compactLine(id, sevLabel, pfx, port)
		rows = append(rows, row{line: ln, sev: sev, sevLabel: sevLabel, subnet24: pfx, idShort: id, comp: comp})
	}

	levels := []int{3, 2, 1, 0}
	if !bySev {
		levels = []int{3, 2, 1, 0}
	} // keep default order; selection keeps input order per level

	seen := map[string]bool{}
	out := make([]string, 0, len(rows))
	added := 0
	compressed, dropped := 0, 0
	size := 0
	for _, level := range levels {
		for i := range rows {
			r := rows[i]
			if r.sev != level {
				continue
			}
			if dedup && r.subnet24 != "" && seen[r.subnet24] {
				continue
			}
			full := r.line
			if fits(size, full, budget) {
				out, size, added = append(out, full), size+len(full)+1, added+1
				if dedup && r.subnet24 != "" {
					seen[r.subnet24] = true
				}
				continue
			}
			// try compressed
			if fits(size, r.comp, budget) {
				out, size, added, compressed = append(out, r.comp), size+len(r.comp)+1, added+1, compressed+1
				if dedup && r.subnet24 != "" {
					seen[r.subnet24] = true
				}
				continue
			}
			dropped++
		}
	}

	trimmed := strings.Join(out, "\n")
	if trimmed == ctx {
		return ctx, TrimStats{Enabled: false}
	}
	tag := fmt.Sprintf("...[context trimmed: kept=%d, compressed=%d, dropped=%d]", added, compressed, dropped)
	if !fits(len(trimmed), tag, budget) {
		// best effort: drop last line(s) to fit tag
		for len(out) > 0 && !fits(len(strings.Join(out, "\n")), tag, budget) {
			out = out[:len(out)-1]
		}
		trimmed = strings.Join(out, "\n")
	}
	if fits(len(trimmed), tag, budget) {
		trimmed += "\n" + tag
	}
	log.Printf("[llm-trim] enabled=%v budget=%dB kept=%d compressed=%d dropped=%d size=%dB", true, budget, added, compressed, dropped, len(trimmed))
	return trimmed, TrimStats{Enabled: true, Budget: budget, Kept: added, Compressed: compressed, Dropped: dropped}
}

func compactLine(id, sev, subnet24, port string) string {
	if id == "" {
		id = "-"
	}
	if sev == "" {
		sev = "-"
	}
	var sb strings.Builder
	sb.WriteString("case ")
	sb.WriteString("id=")
	sb.WriteString(id)
	sb.WriteString(" sev=")
	sb.WriteString(sev)
	if subnet24 != "" {
		sb.WriteString(" src=")
		sb.WriteString(subnet24)
	}
	if port != "" {
		sb.WriteString(" port=")
		sb.WriteString(port)
	}
	return sb.String()
}

func splitNonEmpty(s string) []string {
	parts := strings.Split(s, "\n")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fits(cur int, add string, budget int) bool { return cur+len(add)+1 <= budget }

func find1(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

func parseBool(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func envBoolDefault(k string, def bool) bool {
	if v, ok := os.LookupEnv(k); ok {
		return parseBool(v)
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
