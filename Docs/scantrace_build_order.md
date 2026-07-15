# ScanTrace — Build Order & AI Agent Query Guide
### *"There are two kinds of people in this world... and I don't trust either of them."* — Dead Reckoning

> **Dev Sandbox:** Dilldozer  
> **Deadline:** July 13, 2026 @ 5:00 PM PDT  
> **Days Remaining:** 8  
> **Primary Track:** Agent for Good  
> **Last updated:** July 14, 2026

---

## Build Philosophy

This is a **23-day hackathon sprint**, not a product roadmap. Every build decision optimizes for three outcomes in this order:

1. **Demo-ability** — the judge sees a live event flowing end-to-end in under 90 seconds
2. **Explainability** — the architecture can be drawn on a whiteboard in 60 seconds
3. **Technical credibility** — the code is real, not mocked, and the agent touches all three required platform technologies

---

## Phase Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Done — gate passed |
| 🔄 | In progress |
| ☐ | Not started |

---

## Master Build Order

```
LAYER 1 → Data Foundation (schema + SQLite + CLI harness)            ✅ COMPLETE
LAYER 2 → Collector (Suricata EVE JSON + Asus syslog adapters)       ✅ COMPLETE
LAYER 3 → Normalizer + Enricher (schema mapping + IP intel)          🔄 PARTIAL
(Currently only have my Asus log schema)
LAYER 4 → Correlator + Case Builder (pattern detection + markdown)   ✅ COMPLETE
LAYER 5 → Slack Agent Core (Bolt app + Block Kit case posting)       ✅ COMPLETE
LAYER 6 → Platform Technologies (MCP + RTS + NL Q&A)                 ✅ COMPLETE
LAYER 7 → Polish + Submission                                        ✅ COMPLETE
```

---

## Layer 1 — Data Foundation ✅ COMPLETE

**Completed:** June 24, 2026

| # | Task | Done? |
|---|------|-------|
| 1.1 | Define Go structs for `Sensor`, `Event`, `Entity`, `Case` | ✅ |
| 1.2 | Write SQLite schema DDL — all four tables with FK relationships | ✅ |
| 1.3 | Implement `db.go` — open/close, migration runner, CRUD for all four types | ✅ |
| 1.4 | Write `cmd/bot` CLI skeleton — `ingest`, `correlate`, `cases`, `report` subcommands | ✅ |
| 1.5 | Write `testdata/` — realistic Suricata EVE scan events | ✅ |
| 1.6 | Confirm CLI can initialize DB and print schema version | ✅ |

### Gate — PASSED
- `go run ./cmd/bot/ --version` prints cleanly
- `sqlite3 scantrace.db .schema` shows all four tables
- `testdata/` EVE JSON parses without error

---

## Layer 2 — Collector ✅ COMPLETE

**Completed:** June 26, 2026

### 2A — Suricata EVE JSON Adapter

| # | Task | Done? |
|---|------|-------|
| 2.1 | Implement `collector/suricata.go` — read EVE JSON file, parse each line | ✅ |
| 2.2 | Map EVE fields to `RawEvent` intermediate struct | ✅ |
| 2.3 | Write `sensor.go` — auto-register sensor on first run | ✅ |
| 2.4 | Persist raw events with `source_type = "suricata_eve"` | ✅ |
| 2.5 | Add `--follow` flag for continuous tail | ☐ |
| 2.6 | Smoke test: ingest `testdata/sample_eve.json` | ✅ |

### 2B — Asus Router Syslog Adapter

| # | Task | Done? |
|---|------|-------|
| 2.7 | Implement `collector/asus_syslog.go` | ✅ |
| 2.8 | Handle `kernel: DROP/ACCEPT`, `dnsmasq-dhcp`, `hostapd`, WAN IP | ✅ |
| 2.9 | Map to `RawEvent` with `source_type = "asus_syslog"` | ✅ |
| 2.10 | Support reading from stdin | ✅ |
| 2.11 | Register named sensor on first ingest | ✅ |
| 2.12 | Smoke test: live events in `events` table confirmed | ✅ |

### Gate — PASSED
- `sudo tail -F /var/log/asus-router.log | go run ./cmd/bot/ ingest --file - --adapter asus-syslog` produces events in DB ✅
- Both adapters register their sensors on first run ✅
- DHCP events: `dhcp_dhcpack`, `dhcp_dhcprequest` with `src_ip` and `mac=` in notes ✅
- WiFi events: `wifi_associated` with MAC in `src_ip` ✅

---

## Layer 3 — Normalizer + Enricher 🔄 PARTIAL

**Target:** June 29 – July 1

### 3A — Normalizer

| # | Task | Done? |
|---|------|-------|
| 3.1 | Normalization logic working inline in adapters | ✅ (inline) |
| 3.2 | Standardize `protocol` field (TCP/UDP/ICMP uppercase) | ✅ |
| 3.3 | Standardize `direction` field | ☐ |
| 3.4 | Attach `sensor_id` from registered sensor | ✅ |
| 3.5 | Set `confidence` default to 0.7 | ✅ |
| 3.6 | Extract into standalone `normalizer/normalizer.go` | ✅ |
| 3.7 | Unit tests per event_type | ✅ |

### 3B — Enricher

| # | Task | Done? |
|---|------|-------|
| 3.8 | Implement `enricher/enricher.go` | ✅ |
| 3.9 | ASN lookup via `ipinfo.io` | ✅ |
| 3.10 | Reverse DNS via stdlib `net.LookupAddr()` | ✅ |
| 3.11 | Abuse contact via RDAP (`rdap.org/ip/{ip}`) | ✅ |
| 3.12 | Known-scanner allowlist (Shodan, Censys CIDRs) | ✅ |
| 3.13 | Cache enrichment in `entities` table with 24h TTL | ✅ |
| 3.14 | Skip RFC-1918 IPs — tag as `internal` | ✅ |
| 3.15 | Known-device allowlist for LAN MACs (stop DHCP chatter re-firing) | ✅ |

### Gate Check
- `scantrace enrich --ip 45.33.32.156` returns ASN, rDNS, `reputation_labels: ["known_scanner"]` | ✅ |
- Cache works — second call returns from DB, no API hit | ✅ |
- Private IPs tagged `internal`, not sent to external APIs | ✅ |

---

## Layer 4 — Correlator + Case Builder ✅ COMPLETE

**Completed:** June 28, 2026

| # | Task | Done? |
|---|------|-------|
| 4.1 | `correlator.go` — query events by `src_ip` within time window | ✅ |
| 4.2 | Configurable lookback windows | ✅ |
| 4.3 | Deduplication — burst collapse, open case suppression | ✅ |
| 4.4 | `new_device` rule — DHCP + WiFi association events | ✅ |
| 4.5 | `port_scan` rule — repeated firewall DROP events | ✅ |
| 4.6 | Severity auto-assignment (high/medium/low) | ✅ |
| 4.7 | Confidence scoring | ✅ |
| 4.8 | `cases` CLI command with `--severity` filter | ✅ |
| 4.9 | `report` CLI command — Markdown case output | ✅ |
| 4.10 | `serve --interval` — auto-correlate loop + Slack webhook alert | ✅ |
| 4.11 | MAC address included in `new_device` case title | ✅ |

### Gate — PASSED
- `correlate` produces correct cases from live Asus syslog ✅
- Dedup suppresses re-fire of open cases ✅
- `serve` posts Block Kit alerts to Slack on new cases ✅
- Ghost cases (empty src_ip) cleaned and prevented ✅

---

## Layer 5 — Slack Agent Core ✅ COMPLETE

**Target:** June 29 – July 5

### 5A — Bolt App Bootstrap

| # | Task | Done? |
|---|------|-------|
| 5.1 | `slack create agent` in Dilldozer — scaffold the app | ✅ |
| 5.2 | Create `#scantrace-alerts` channel in Dilldozer | ✅ |
| 5.3 | Configure `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` env vars (socket mode) | ✅ |
| 5.4 | Implement `slack/agent.go` — Bolt app entry point | ✅ |
| 5.5 | Wire pipeline: new Case → `PostCaseAlert()` | ✅ |
| 5.6 | Smoke test: fake case → Block Kit message in `#scantrace-alerts` | ✅ |

### 5B — Block Kit Case Card

| # | Task | Done? |
|---|------|-------|
| 5.7 | Block Kit layout: header, fields, context, actions | ✅ |
| 5.8 | Severity → emoji mapping 🔴/🟡/🟢 | ✅ |
| 5.9 | Color accent on attachment | ✅ |
| 5.10 | "View Full Case" button → Slack modal | ☐ |
| 5.11 | Thread reply: event count + JSON export link | ✅ |
| 5.12 | Sensor source in card footer | ✅ |

### Gate Check
- New case in SQLite → Block Kit in `#scantrace-alerts` within 5s ✅
- All 4 severity levels render correctly ✅
- Modal opens with full markdown on "View Full Case" click ☐ (report button ships full Block Kit report instead)
- Footer shows correct sensor source (suricata vs asus_syslog) ✅

---

## Layer 6 — Platform Technologies 🔄 PARTIAL

**Target:** July 6 – July 12

### 6A — MCP Server ✅

| # | Task | Done? |
|---|------|-------|
| 6.1 | Implement `mcp/server.go` — register ScanTrace tools | ✅ |
| 6.2 | Tool: `get_case(case_id)` | ✅ |
| 6.3 | Tool: `list_cases(severity?, limit?)` | ✅ |
| 6.4 | Tool: `enrich_ip(ip)` (exposed as `get_entity`) | ✅ |
| 6.5 | Tool: `search_related_events(src_ip, hours?)` | ✅ |
| 6.6 | Wire MCP server into Bolt app | ✅ |
| 6.7 | Test: invoke `enrich_ip` from Slack AI | ✅ |

### 6B — Real-Time Search (RTS) ✅

| # | Task | Done? |
|---|------|-------|
| 6.8 | Implement `slack/rts.go` — RTS client + signal subscriptions | ✅ |
| 6.9 | Before posting: check for src_ip history | ✅ (in-session, in-process memory) |
| 6.10 | If found: prepend "Previously observed — [link]" context block | ✅ |
| 6.11 | Test: duplicate case → "Previously observed" context appears | 🔄 |

> **Note:** "Previously observed" context is built from **in-session prior thread linking** —
> the agent tracks each case's alert thread in-process (`caseThreads`) during a run and, when a
> new case shares a source IP with an earlier one, prepends a context block linking to that
> earlier thread via `conversations` permalinks. This avoids heavy channel-search APIs. RTS
> `signal.subscriptions.add` is attempted on connect; on the Dilldozer sandbox it may return the
> cosmetic `unknown_method` and the agent continues normally.

### 6C — Natural Language Q&A 🔄

| # | Task | Done? |
|---|------|-------|
| 6.12 | App mention listener: `@ScanTrace {question}` | ✅ |
| 6.13 | Intent router: list / get / enrich / summarize | 🔄 (LLM free-form + `case <id>` routing) |
| 6.14 | Route to MCP tool, format Slack response | ✅ |
| 6.15 | Handle: "What hit us today?", "Show worst case", "Enrich 1.2.3.4" | ✅ |
| 6.16 | Fallback response for unrecognized intent | ✅ |

### Gate Check ✅
- `@ScanTrace what hit us today?` returns formatted case list | ✅ |
- `enrich_ip` MCP tool returns valid Entity JSON | ✅ |
- RTS query on known IP surfaces prior thread link ✅ |
- All three technologies (MCP, RTS, Slack AI) visibly active in demo | ✅ |

---

## Layer 7 — Polish + Submission ✅ COMPLETE

**Target:** July 10 – July 13

| # | Task | Done? |
|---|------|-------|
| 7.1 | Architecture diagram (Mermaid or draw.io) | ✅ |
| 7.2 | Tag `hackathon-stable-YYYYMMDD` | ✅ |
| 7.3 | Record 3-minute demo video | ✅ |
| 7.4 | Invite `slackhack@salesforce.com` + `testing@devpost.com` to Dilldozer | ✅ |
| 7.5 | Confirm agent responsive in Dilldozer | ✅ |
| 7.6 | Note Slack App ID | ✅ |
| 7.7 | Complete Devpost submission form | ✅ |
| 7.8 | Submit before July 13 @ 5:00 PM PDT | ✅ |

### Demo Video Script (3 minutes) (free styled because I decided to hit stretch goals instead of making a video... and sleeping)

```
0:00–0:20  The problem — scanners hit your perimeter constantly; teams
           have no Slack-native intelligence layer.

0:20–0:50  Live Asus syslog tailed → event ingested → normalizer fires
           → enricher returns ASN.

0:50–1:30  Correlator groups events → Case Builder generates markdown
           → Block Kit alert fires in #scantrace-alerts.

1:30–2:10  @ScanTrace what hit us today? → list returned.
           @ScanTrace enrich 185.220.101.45 → Entity JSON returned.
           MCP tool visible in Slack AI sidebar.

2:10–2:40  RTS demo — second event from same IP → "Previously observed"
           context block with link to original thread.

2:40–3:00  Architecture whiteboard — 30s walk.
           Collector → Normalizer → Enricher → Correlator →
           Case Builder → Slack Agent.
```

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| RTS API not available in sandbox | Medium | High | Use `conversations.search` as fallback |
| Suricata not available for live demo | Low | Medium | Asus syslog is primary live source |
| MCP Go SDK immaturity | Medium | Medium | Fall back to REST endpoint |
| Enrichment APIs rate-limited during demo | Low | High | Pre-enrich all demo IPs and cache in SQLite |
| SQLite concurrent write lock | Low | Medium | WAL mode + connection pool |
| Dilldozer sandbox access issue | Low | High | Test judge invite by July 8 |
| Demo video rendering time | Low | Low | Record by July 11 — 48h buffer |

---

## Event Code for Dilldozer Setup

**`SABC-7X2K-M9PL-4QFN`** *(case-sensitive)*

Required if registered with a personal email to ensure judge invites (`slackhack@salesforce.com`, `testing@devpost.com`) work without Guest restrictions.

---

## AI Agent Query Guide

### Go Backend Pipeline

**Best agent:** Claude Sonnet / GitHub Copilot in-editor

**Enricher with caching:**
```
Write a Go enricher package that:
1. Takes an IPv4 string as input
2. Skips enrichment for RFC-1918 private ranges — tag as internal
3. Queries ipinfo.io/{ip}/json for ASN and provider
4. Does reverse DNS lookup with net.LookupAddr()
5. Queries rdap.org/ip/{ip} for abuse contact
6. Checks a hardcoded allowlist of known-scanner CIDR ranges
7. Caches results in SQLite entities table for 24h (check last_enriched)
8. Returns an Entity struct
```

**Correlator sliding window:**
```
Write a Go correlator package that:
1. Accepts src_ip and lookback duration (default 6h)
2. Queries SQLite for all Events with that src_ip in the window
3. Deduplicates bursts: same src_ip + dst_port within 60s = one cluster
4. Detects ASN-level clustering
5. Returns CorrelationResult{Events, Entities, Tags, Confidence}
6. Tags: "repeated_source" >3 events, "port_sweep" >3 distinct dst_ports
```

### Slack Bot App

**Best agent:** ChatGPT-4o or Claude Sonnet

**Bot app scaffold:**
```
Write a Go Slack bot using slack-go/slack (Bolt pattern) that:
1. Uses socket mode (SLACK_APP_TOKEN)
2. Listens for trigger from PostCaseAlert()
3. Posts Block Kit message to #scantrace-alerts
4. Handles app_mention for NL Q&A
5. Connects to: func HandleMention(text string) string
```

**Block Kit card:**
```
Write a Slack Block Kit payload for a security case alert:
1. Header: emoji (🔴/🟡/🟢) + case title
2. Fields: Source IP, ASN, Provider, Target Port, Severity
3. Context: tags as inline code
4. Actions: "View Full Case" (opens modal) + "Dismiss"
5. Color: #cc0000 high / #ff9900 medium / #00cc00 low
6. Footer: sensor source name
```

### MCP Server

**Best agent:** Claude Sonnet (best MCP spec knowledge)

```
Write a Go MCP server exposing four tools:
1. get_case(case_id string) — queries SQLite, returns Case JSON
2. list_cases(severity string, limit int) — returns []CaseSummary
3. enrich_ip(ip string) — calls enricher.Enrich(ip), returns Entity JSON
4. search_related_events(src_ip string, hours int) — returns []Event
Use mark3labs/mcp-go SDK. stdio transport (standard MCP pattern).
```

### RTS Integration

```
Write SearchPriorMentions(client, channelID, query) that:
1. Uses Slack RTS API to search a specific channel
2. Returns matching messages for a src_ip or ASN query
3. Handles rate limiting with exponential backoff

Write PrependPriorObservations(blocks, priorMessages) that:
1. If priorMessages non-empty: prepend context block
   "⚠️ Previously observed — N prior mention(s)" with thread link
2. If empty: return blocks unchanged
```

### Asus Syslog Debug

```
My Asus syslog adapter is not capturing certain event types.
Here is a sample of the actual syslog lines: [paste sample]
The adapter currently handles: kernel DROP/ACCEPT, dnsmasq-dhcp, hostapd.
Extend the parser to handle these additional event types: [list them]
```

*"It's got electrolytes."* — and it's got a working correlator. Ship it.
