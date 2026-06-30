# Stretch Goals – Dead Reckoning Edition

This document captures ScanTrace stretch goals beyond the hackathon baseline.
Items marked ✅ were completed during the hackathon build sprint.

---

## ✅ Shipped During Hackathon

### IPInfo enrichment (ASN, org, country)
- Source IPs enriched with ASN, org name, country, and classification badges (proxy/VPN, hosting/DC, residential) before LLM prompt is assembled.
- Badges appear on Block Kit alert cards in `#sec-alerts`.

### Slack `/scantrace` slash command suite
- `cases`, `report <id>`, `next`, `review-all`, `alert`, `devices`, `adddevice`, `removedevice`, `mcp` — all live.
- Quote-aware argument splitting so `label="Media Server"` works as a single token.

### `@ScanTrace case <id>` mention routing
- Deterministic fast path in `handleMention()` — no LLM involved in case selection or action plan.
- Supports `case <id>`, `report <id>`, `review case <id>`.
- Falls back to static `cmdReport()` if LLM is offline.

### MCP tool server
- `localhost:8765` exposes `list_cases`, `get_case`, `list_sensors`, `get_entity`, `list_known_devices`.
- Compatible with Claude Desktop, Cursor, and any MCP-capable host.

### Automated suppression for known-benign scanners
- `benign-scanners.txt` — Shodan, Censys, Shadowserver CIDRs.
- Cases from matched IPs receive Condition E verdict and no-block recommendation.

### Known device registry
- `/scantrace adddevice <ip> [label=...] [trust=...] [suppress=true]`
- Trust labels (`trusted` / `unknown` / `suspicious`) flow into triage context and LLM prompt.
- `suppress=true` silences low-severity cases for that host automatically.

---

## Open Stretch Goals

### 1. DHCP + MAC monitoring and unknown device detection
- Parse `dnsmasq-dhcp` logs to extract MAC, leased IP, hostname.
- Baseline known MACs per sensor; case on new or suspicious MACs.
- Correlate unknown-device cases with scan/exfil alerts.

### 2. Egress / data exfiltration detection
- Monitor outbound connections for unusual volume, new destinations, unexpected protocols.
- Raise cases like "Possible exfil from 10.0.0.X → IP:Y on port 443".
- Optional hooks for external scripts or router API calls to block/rate-limit.

### 3. Ingestion scalability and resilience
- Bounded queue + worker pool for parsing/normalisation/enrichment.
- Dedicated DB writer queue with batched inserts.
- Simple autoscaler based on queue depth.

### 4. Schema-first LLM helpers
- **UnknownFormatManager + LLMIntrospector** — detect high parse-failure sources, sample lines, query local LLM with strict JSON schema for format identification.
- **ModelRouter** — route tasks (log introspection, summarisation, DB audit) to appropriate local model by weight/capability.
- **Prompt-injection resistance** — sanitise log content before prompt injection, validate structured outputs, reject schema failures.

### 5. Database Auditor LLM
- Periodic read-only analysis of event/case store for coverage gaps, suspicious metadata, missing event types.
- Findings stored in a separate audit table; no direct mutations of raw data.

### 6. Database Investigator LLM with versioned patterns
- Surface higher-level patterns: repeated campaigns by ASN, devices oscillating between benign/suspicious, emerging exfil paths.
- Versioned pattern store with analyst promote/demote workflow.
- Accepted patterns feed new correlation rules.

### 7. Suricata EVE JSON ingestion
- Ingest Suricata `eve.json` alongside live router syslog.
- Map EVE alert fields to ScanTrace event schema.
- Correlate Suricata alerts with existing WAN cases.
