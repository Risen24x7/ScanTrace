# Changelog

All notable changes to ScanTrace – Dead Reckoning Edition will be documented in this file.

---

## Unreleased

### Changes
- Default `LLM_BASE_URL` to `http://127.0.0.1:11434` (was a LAN IP)
- LLM client strips a trailing `/v1` from `LLM_BASE_URL` to avoid `/v1/v1/...` 404s
- `.env.example`, INSTALL, ARCHITECTURE, and TROUBLESHOOTING updated (note: do not include `/v1`)

---

## v0.5.0 — 2026-07-06

### Breaking
- Remove SCANTRACE_DB; use DB_PATH=/var/lib/scantrace/scantrace.db

### Features
- Slack review filters; blocklist export (txt/csv/ipset) with CIDR grouping

### Ops
- systemd unit, install scripts, CAP_NET_BIND_SERVICE

### Docs
- INSTALL and .env.example updated; status/queries guidance

### Fixes
- Syslog ingest robustness; WAN enrichment toggle polish

### Upgrade Notes
- Set DB_PATH in .env
- mkdir -p /var/lib/scantrace && mv existing DB if needed
- systemctl daemon-reload && systemctl restart scantrace-agent

---

## [2026-06-29] Port Intel + WAN-Edge Override

### New Features
- **Port Intelligence store** (`portintel/portintel.go`) — `HitRecord` struct + SQLite-backed `Store` tracks `(src_ip, dst_port, proto, count, first_seen, last_seen)` across cases; enables trend analysis across incidents.
- **`/scantrace port-trends`** slash command — queries the port intel store and surfaces the top repeatedly-hit ports across all cases, formatted as a Block Kit table in Slack.
- **Port intel advisory in LLM context** — `buildSingleCaseContext()` accumulates `HitRecord`s per event and injects a `[PORT INTEL ADVISORY]` block into the prompt when a port has been hit more than once across sessions, giving the model persistence-aware context without any DB writes in the LLM path.

### Bug Fixes
- **WAN-edge dst label override** (`fix/wan-edge-dst-override`, now merged) — `classifyDst()` now returns the authoritative WAN EDGE label for all three branches: `wan_new_connection`, `wan_forward` when `dst == wanIP`, and the default fallback when `dst == wanIP`. The LLM can no longer misread the operator's own WAN IP as a remote threat target.
- **WAN IP excluded from enrichment** — `buildSingleCaseContext()` skips adding `h.wanIP` to `ipSet`, so `ipinfo.Enrich()` never produces an ISP/org attribution line for the operator's own interface IP.
- **Event row format made explicit** — `sb.WriteString(fmt.Sprintf(...))` now always includes `dstLabel` in the event row sent to the LLM, so WAN EDGE hits are visibly annotated inline.

### Handler Internals
- `Handler` struct gains `portIntel *portintel.Store` field; `New()` calls `portintel.Open("")` and wires the store (nil-safe — logs a warning on DB open failure, port-trends degrades gracefully).
- `handleSlashCommand()` routes `port-trends` → `cmdPortTrends()`.
- `helpText()` lists `port-trends`.

---

## [2026-06-29] Deterministic Orchestration — Stable

### Architecture
- Moved all network topology classification and recommended-action logic fully into the Go layer.
- LLM (Qwen3-30B) is now a "dumb template filler" only: it synthesises the Assessment and Summary blocks, never the action list.
- `fmt.Sprintf` skeleton in the prompt pre-populates the Recommended Actions section before tokens are generated — the model cannot stray from the switch-case output.
- WAN IP misclassification fixed: `WAN_EDGE — gateway interface only` label correctly applied to all traffic arriving on the WAN interface IP, preventing false internal-device escalations.
- `EXTERNAL_THREAT_CHANNEL` env var separates LLM Q&A responses from raw alert noise in `#sec-alerts`.

### Bug Fixes
- Restored `envOrDefault("LLM_BASE_URL", "http://192.168.50.250:11434")` default that was dropped during a `main.go` refactor — agent no longer logs `LLM not configured` when `LLM_BASE_URL` is absent from `.env`.
- `export $(grep -v '^#' .env | xargs)` path corrected to run from `scantrace-agent/` directory.

### Agent Internals
- Handler gains `externalThreatChannel` field; `New()` takes it as 6th param.
- Correlator loop confirmed calling `PostCaseAlert` for every new case.
- PostCaseAlert thread reply condensed: one-liner format `[rule] Additional entry for Case ID: <id>  Port: <port>  Events: N`.
- Case IDs are plain text (not backtick code) for easy Slack copy.
- RTS `subscribe` error on startup is cosmetic (unknown_method on the Dilldozer sandbox); agent continues normally.

---

## [2026-06-28] Slack Agent Integration

- Added `scantrace-agent/` submodule: Slack Socket Mode bot with syslog listener, correlator, and MCP server.
- LLM client added for Qwen3-30B via `ik_llama.cpp` on desktop (`http://192.168.50.250:11434`).
- Alert channel defaulted to `C0BBP1EP68P`; external threat channel to `C0BCYSW3KNC`.
- Block Kit alert formatting with thread-based case updates.

---

## [2026-06-25] Dead Reckoning — Hackathon Baseline

- Locked the hackathon baseline around an end-to-end defensive scan intelligence pipeline.
- Added `Docs/HACKATHON_GOALS.md` describing the primary judging goal, stable baseline, stretch goals, and non-goals.
- Clarified that Suricata testdata and one live syslog-fed network source (ASUS router) must both flow into the common event schema and case reports.
- Confirmed SQLite as the MVP event/case store and CLI-first operation for demos.

---

## [2026-06-24] Initial MVP Flow

- Implemented the core pipeline components:
  - Collector: ingests raw events from supported sources.
  - Normalizer: maps source-specific records into a common event schema.
  - Enricher: attaches ASN and reverse-DNS metadata.
  - Correlator: groups repeated scan activity over time into cases.
  - Case builder: produces human-readable incident summaries and JSON exports.
- Wired Suricata EVE JSON testdata into the pipeline.
