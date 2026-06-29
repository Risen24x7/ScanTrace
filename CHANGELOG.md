# Changelog

All notable changes to ScanTrace – Dead Reckoning Edition will be documented in this file.

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
