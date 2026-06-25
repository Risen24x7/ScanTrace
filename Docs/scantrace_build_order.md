# ScanTrace — Build Order & AI Agent Query Guide
### *"There are two kinds of people in this world... and I don't trust either of them."* — Dead Reckoning

> **Dev Sandbox:** Dilldozer  
> **Deadline:** July 13, 2026 @ 5:00 PM PDT  
> **Days Remaining at Writing:** 18  
> **Primary Track:** New Slack Agent  

---

## Build Philosophy

This is a **23-day hackathon sprint**, not a product roadmap. Every build decision optimizes for three outcomes in this order:

1. **Demo-ability** — the judge sees a live event flowing end-to-end in under 90 seconds  
2. **Explainability** — the architecture can be drawn on a whiteboard in 60 seconds  
3. **Technical credibility** — the code is real, not mocked, and the agent touches all three required platform technologies  

All other engineering virtue (test coverage, multi-tenancy, horizontal scale) is post-hackathon scope.

---

## Phase Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Done — gate passed |
| 🔄 | In progress |
| ☐ | Not started |

---

## Master Build Order

The pipeline has **6 sequential layers**. Each layer has a gate check — do not advance until the gate passes.

```
LAYER 1 → Data Foundation (schema + SQLite + CLI harness)            ✅ COMPLETE
LAYER 2 → Collector (Suricata EVE JSON + Asus syslog adapters)       🔄 IN PROGRESS
LAYER 3 → Normalizer + Enricher (schema mapping + IP intel)          ☐
LAYER 4 → Correlator + Case Builder (pattern detection + markdown)   ☐
LAYER 5 → Slack Agent Core (Bolt app + Block Kit case posting)        ☐
LAYER 6 → Platform Technologies (MCP + RTS + NL Q&A)                 ☐
```

---

## Layer 1 — Data Foundation ✅ COMPLETE

**Target Days:** 1–2 (June 19–20)  
**Completed:** June 24, 2026  
**Goal:** Schema locked, SQLite initialized, CLI wired, test event injectable  

### Tasks

| # | Task | Done? |
|---|------|-------|
| 1.1 | Define Go structs for `Sensor`, `Event`, `Entity`, `Case` | ✅ |
| 1.2 | Write SQLite schema DDL — create all four tables with FK relationships | ✅ |
| 1.3 | Implement `db.go` — open/close, migration runner, CRUD for all four types | ✅ |
| 1.4 | Write a `cmd/bot` CLI skeleton — `ingest`, `correlate`, `cases`, `report` subcommands | ✅ |
| 1.5 | Write a `testdata/` — realistic Suricata EVE scan events | ✅ |
| 1.6 | Confirm CLI can initialize DB and print schema version | ✅ |

### Gate Check — PASSED
- `go run ./cmd/bot/ --version` prints cleanly  
- `sqlite3 scantrace.db .schema` shows all four tables  
- `testdata/` EVE JSON parses without error  

### Key Design Decisions (locked)
- **Primary key:** UUID v4 (portable, no auto-increment collisions across sensors)  
- **Timestamps:** RFC3339 strings in SQLite (avoids timezone hell)  
- **Raw payload:** stored as JSON blob in `Event.raw_ref` column — never destructively normalized  
- **SQLite WAL mode ON** — concurrent reader + writer for CLI + agent layer  

---

## Layer 2 — Collector 🔄 IN PROGRESS

**Target Days:** 2–3 (June 20–21) — *running slightly behind; targeting June 26*  
**Goal:** Real Suricata EVE JSON file + live Asus router syslog → raw events persisted to SQLite  

> **Why two adapters now (not Layer 7)?**  
> The live Asus syslog is the primary real-network demo path for the hackathon judges. It must be solid before the Slack layer is built on top of it. Moving it from "Polish" (Layer 7) to here ensures the real-network path is tested and stable before Layer 5 Slack wiring begins.

### 2A — Suricata EVE JSON Adapter

| # | Task | Done? |
|---|------|-------|
| 2.1 | Implement `collector/suricata.go` — tail or read EVE JSON file, parse each line | ✅ |
| 2.2 | Map EVE fields to `RawEvent` intermediate struct (preserve original field names) | ✅ |
| 2.3 | Write `sensor.go` — auto-register sensor on first run, store sensor_id in config file | ✅ |
| 2.4 | Persist raw events to `Event` table with `source_type = "suricata_eve"` | ✅ |
| 2.5 | Add `--follow` flag to tail file continuously (like `tail -f`) | ☐ |
| 2.6 | Smoke test: ingest `testdata/sample_eve.json`, confirm rows in `events` table | ✅ |

### 2B — Asus Router Syslog Adapter (Live Home Network)

| # | Task | Done? |
|---|------|-------|
| 2.7 | Implement `collector/asus_syslog.go` — parse syslog lines from Asus (AsusWRT format) | ☐ |
| 2.8 | Handle key Asus syslog event types: `kernel: DROP`, `kernel: ACCEPT`, `dnsmasq-dhcp`, `hostapd`, `WAN IP`, `LAN to WAN` | ☐ |
| 2.9 | Map parsed Asus syslog fields to `RawEvent` struct with `source_type = "asus_syslog"` | ☐ |
| 2.10 | Support reading from stdin (for `tail -F /var/log/asus-router.log \| ingest --adapter asus-syslog`) | ☐ |
| 2.11 | Register a named sensor for the Asus source on first ingest | ☐ |
| 2.12 | Smoke test: tail live `/var/log/asus-router.log`, confirm Asus events appear in `events` table | ☐ |

### rsyslog setup (host-side)

This must be done on the ScanTrace host to receive router syslog *before* the adapter can be tested:

```bash
# 1. Enable UDP syslog in /etc/rsyslog.conf
# Uncomment or add:
#   $ModLoad imudp
#   $UDPServerRun 514

# 2. Create Asus-specific rule (replace IP with your router's LAN IP)
sudo sh -c 'cat > /etc/rsyslog.d/asus-router.conf <<EOF
if $fromhost-ip == "192.168.50.1" then /var/log/asus-router.log
& stop
EOF'

# 3. Restart rsyslog
sudo systemctl restart rsyslog

# 4. Verify logs arriving
sudo tail -n 20 /var/log/asus-router.log
```

See `Docs/GETTING_STARTED.md` and `Docs/TROUBLESHOOTING.md` for full detail.

### Suricata EVE Field Mapping Reference

| EVE Field | ScanTrace Event Field |
|-----------|----------------------|
| `timestamp` | `timestamp` |
| `src_ip` | `src_ip` |
| `src_port` | `src_port` |
| `dest_ip` | `dst_ip` |
| `dest_port` | `dst_port` |
| `proto` | `protocol` |
| `event_type` | `event_type` |
| `alert.signature` | `tags[]` (appended) |
| full line JSON | `raw_ref` |

### Asus Syslog Field Mapping Reference

| Syslog Pattern | ScanTrace Event Field | Notes |
|---|---|---|
| `kernel: DROP IN=... SRC=X DST=Y PROTO=Z DPT=N` | `src_ip`, `dst_ip`, `dst_port`, `protocol` | Firewall drop — primary scan signal |
| `kernel: ACCEPT IN=...` | same as above | Accepted connection |
| `dnsmasq-dhcp: DHCPACK ... MAC ... IP` | `src_ip` (leased IP), `tags["dhcp"]` | Device seen on LAN |
| `hostapd: STA ... associated` | `src_ip` (client), `tags["wifi"]` | Wireless association |
| Raw syslog line | `raw_ref` | Always preserve full line |

### Gate Check
- `CGO_ENABLED=1 go run ./cmd/bot/ ingest --file testdata/sample_eve.json --adapter suricata` exits 0, rows in `events` table  
- `sudo tail -F /var/log/asus-router.log | go run ./cmd/bot/ ingest --file - --adapter asus-syslog` produces events in DB  
- Both adapters register their respective sensors on first run  

---

## Layer 3 — Normalizer + Enricher

**Target Days:** 4–7 (June 22–25) — *adjust to June 26–30 given Layer 2 slip*  
**Goal:** Raw events → normalized schema + IP enrichment stored in `entities` table  

### 3A — Normalizer

| # | Task | Done? |
|---|------|-------|
| 3.1 | Implement `normalizer/normalizer.go` — reads raw events, maps to `Event` struct | ☐ |
| 3.2 | Standardize `protocol` field (TCP/UDP/ICMP uppercase) | ☐ |
| 3.3 | Standardize `direction` field (inbound/outbound/lateral from src/dst IP context) | ☐ |
| 3.4 | Attach `sensor_id` from registered sensor | ☐ |
| 3.5 | Set `confidence` default to 0.7 (known source, unverified behavior) | ☐ |
| 3.6 | Write normalizer unit tests for each event_type (suricata alert/flow/dns, asus DROP/ACCEPT/DHCP) | ☐ |

### 3B — Enricher

| # | Task | Done? |
|---|------|-------|
| 3.7 | Implement `enricher/enricher.go` — takes `src_ip`, returns populated `Entity` | ☐ |
| 3.8 | ASN lookup via `ipinfo.io/AS` or `bgpview.io` free API (no auth required for basic) | ☐ |
| 3.9 | Reverse DNS via stdlib `net.LookupAddr()` | ☐ |
| 3.10 | Abuse contact via RDAP (`https://rdap.org/ip/{ip}`) — parse `remarks` for abuse email | ☐ |
| 3.11 | Known-scanner allowlist: hardcode initial list (Shodan `66.240.0.0/15`, Censys `192.35.168.0/23`, etc.) as `reputation_labels: ["known_scanner"]` | ☐ |
| 3.12 | Cache enrichment results by IP in `entities` table with `last_enriched` TTL of 24h | ☐ |
| 3.13 | Smoke test: enrich 3 IPs, confirm `asn`, `rdns`, `abuse_contact` populated | ☐ |
| 3.14 | Skip enrichment for RFC-1918 private IPs (10.x, 192.168.x, 172.16–31.x) — tag as `internal` | ☐ |

### Gate Check
- `scantrace enrich --ip 45.33.32.156` (Shodan IP) returns ASN, rDNS, `reputation_labels: ["known_scanner"]`  
- Enrichment cache works — second call returns immediately from DB, no API hit  
- Private IPs tagged `internal`, not sent to external APIs  
- All test events (Suricata + Asus) have associated Entity records  

### Free Enrichment API Cheat Sheet

| Data | API | Auth | Rate Limit |
|------|-----|------|-----------|
| ASN + Provider | `https://ipinfo.io/{ip}/json` | None (50k/mo free) | 50k/month |
| Reverse DNS | Go stdlib `net.LookupAddr()` | None | DNS limits |
| RDAP / Abuse | `https://rdap.org/ip/{ip}` | None | Generous |
| Geo Country | included in ipinfo.io | None | Same token |
| BGP Route | `https://api.bgpview.io/ip/{ip}` | None | ~100/min |

---

## Layer 4 — Correlator + Case Builder

**Target Days:** 8–11 (June 26–29) — *adjust to July 1–5*  
**Goal:** Pattern detection → grouped cases → human-readable markdown output  

### 4A — Correlator

| # | Task | Done? |
|---|------|-------|
| 4.1 | Implement `correlator/correlator.go` — query events by `src_ip` within time window | ☐ |
| 4.2 | Configurable lookback windows: 1h, 6h, 24h (flag default: 6h) | ☐ |
| 4.3 | Deduplication: collapse burst events (same src_ip, same dst_port, <60s apart) into one cluster | ☐ |
| 4.4 | ASN-level correlation: group IPs sharing the same ASN that hit same dst_port in window | ☐ |
| 4.5 | Tag output: `["repeated_source"]`, `["asn_cluster"]`, `["port_sweep"]` based on pattern | ☐ |
| 4.6 | Return correlation result as `CorrelationResult{Events, Entities, Tags, Confidence}` | ☐ |
| 4.7 | DHCP/LAN correlation: flag `internal` IPs that also appear as scan sources (possible lateral movement) | ☐ |

### 4B — Case Builder

| # | Task | Done? |
|---|------|-------|
| 4.8 | Implement `casebuilder/builder.go` — takes `CorrelationResult`, writes `Case` to DB | ☐ |
| 4.9 | Generate markdown case summary using Go `text/template` | ☐ |
| 4.10 | Case template fields: title, severity, summary paragraph, IP list, ASN, timeline table, tags, abuse contact | ☐ |
| 4.11 | JSON export paired with markdown (`case_{id}.md` + `case_{id}.json`) | ☐ |
| 4.12 | Severity auto-assignment: `high` if repeated + no known-scanner tag; `low` if known-scanner; `medium` otherwise | ☐ |
| 4.13 | CLI: `go run ./cmd/bot/ cases` prints case ID, title, severity, created_at | ☐ |
| 4.14 | CLI: `go run ./cmd/bot/ report --case {id}` prints full markdown to stdout | ☐ |

### Gate Check
- Feed events from same source IP over 1h window  
- `cases` command shows 1 case (deduplicated)  
- `report --case {id}` prints complete markdown — title, ASN, timeline, tags  
- JSON export file is valid JSON  
- DHCP/Asus events produce `sensor_type: asus_syslog` cases where applicable  

### Markdown Case Template (Starter)

```
# Case: {{.Title}}
**ID:** {{.CaseID}}  **Severity:** {{.Severity}}  **Created:** {{.CreatedAt}}

## Summary
{{.Summary}}

## Source Infrastructure
| Field | Value |
|-------|-------|
| IP | {{.SrcIP}} |
| ASN | {{.ASN}} ({{.ASName}}) |
| Provider | {{.Provider}} |
| Reverse DNS | {{.RDNS}} |
| Abuse Contact | {{.AbuseContact}} |
| Geo | {{.GeoCountry}} |

## Timeline
| Timestamp | Dst Port | Protocol | Event Type |
|-----------|----------|----------|------------|
{{range .Events}}| {{.Timestamp}} | {{.DstPort}} | {{.Protocol}} | {{.EventType}} |
{{end}}

## Tags
{{range .Tags}}`{{.}}` {{end}}

## Raw Artifact References
{{range .RawRefs}}- {{.}}
{{end}}
```

---

## Layer 5 — Slack Agent Core

**Target Days:** 12–16 (June 30 – July 4) — *adjust to July 6–10*  
**Goal:** Bolt app running in Dilldozer, posting Block Kit case cards to channel on new case creation  

### 5A — Bolt App Bootstrap

| # | Task | Done? |
|---|------|-------|
| 5.1 | `slack create agent` in Dilldozer — scaffold the app | ☐ |
| 5.2 | Create `#scantrace-alerts` channel in Dilldozer | ☐ |
| 5.3 | Configure `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` env vars (socket mode for dev) | ☐ |
| 5.4 | Implement `slack/agent.go` — Bolt app entry point, listen for events | ☐ |
| 5.5 | Wire ScanTrace pipeline: on new Case created → trigger `PostCaseAlert()` | ☐ |
| 5.6 | Smoke test: trigger a fake case, confirm Block Kit message appears in `#scantrace-alerts` | ☐ |

### 5B — Block Kit Case Card

| # | Task | Done? |
|---|------|-------|
| 5.7 | Design Block Kit layout: header divider, case title section, fields (IP/ASN/Severity), context block (tags), actions (View Full Case button) | ☐ |
| 5.8 | Severity → emoji mapping: 🔴 high / 🟡 medium / 🟢 low / ⚪ known-scanner | ☐ |
| 5.9 | Color accent on attachment: `#cc0000` high, `#ff9900` medium, `#00cc00` low | ☐ |
| 5.10 | "View Full Case" button opens markdown in a Slack modal (plain_text_input display) | ☐ |
| 5.11 | Thread reply: attach raw event count + link to JSON export | ☐ |
| 5.12 | Include sensor source in card footer (e.g., `Source: asus_syslog @ scantrace-host`) | ☐ |

### Block Kit Card Wireframe

```
┌─────────────────────────────────────────────────────┐
│ 🔴  ScanTrace Alert — Repeated Port Scan Detected   │
│─────────────────────────────────────────────────────│
│ Source IP      │ 185.220.101.45                     │
│ ASN            │ AS4134 — CHINANET-BACKBONE          │
│ Provider       │ China Telecom                       │
│ Target Port    │ 22/TCP (repeated × 47)              │
│ Severity       │ HIGH                                │
│─────────────────────────────────────────────────────│
│ Tags: `repeated_source` `asn_cluster` `port_sweep`  │
│─────────────────────────────────────────────────────│
│ Sensor: asus_syslog @ scantrace-host                │
│─────────────────────────────────────────────────────│
│ [ View Full Case ]    [ Dismiss ]                   │
└─────────────────────────────────────────────────────┘
```

### Gate Check
- New case in SQLite → Block Kit message appears in `#scantrace-alerts` within 5 seconds  
- All 4 severity levels render correctly  
- Modal opens with full markdown case on "View Full Case" click  
- Card footer shows correct sensor source (suricata vs asus_syslog)  

---

## Layer 6 — Platform Technologies (MCP + RTS + NL Q&A)

**Target Days:** 17–21 (July 5–9) — *adjust to July 10–12*  
**Goal:** All three required technologies active and demo-able  

### 6A — MCP Server Integration

| # | Task | Done? |
|---|------|-------|
| 6.1 | Implement `mcp/server.go` — register ScanTrace MCP tools | ☐ |
| 6.2 | Tool: `get_case(case_id)` → returns Case JSON | ☐ |
| 6.3 | Tool: `list_cases(severity?, limit?)` → returns array of Case summaries | ☐ |
| 6.4 | Tool: `enrich_ip(ip)` → runs enricher pipeline, returns Entity JSON | ☐ |
| 6.5 | Tool: `search_related_events(src_ip, hours?)` → returns correlated events for an IP | ☐ |
| 6.6 | Wire MCP server into Bolt app — accessible from Slack AI / connected LLM | ☐ |
| 6.7 | Test: invoke `enrich_ip` tool from Slack AI assistant, confirm structured response | ☐ |

### MCP Tool Definitions

```json
{
  "tools": [
    {
      "name": "get_case",
      "description": "Retrieve a ScanTrace case by ID. Returns full case details including timeline, entities, and severity.",
      "parameters": {
        "case_id": { "type": "string", "description": "UUID of the case" }
      }
    },
    {
      "name": "list_cases",
      "description": "List recent ScanTrace cases, optionally filtered by severity.",
      "parameters": {
        "severity": { "type": "string", "enum": ["high", "medium", "low"], "required": false },
        "limit": { "type": "integer", "default": 10 }
      }
    },
    {
      "name": "enrich_ip",
      "description": "Run enrichment pipeline on an IP address. Returns ASN, provider, rDNS, abuse contact, and reputation labels.",
      "parameters": {
        "ip": { "type": "string", "description": "IPv4 address to enrich" }
      }
    },
    {
      "name": "search_related_events",
      "description": "Find all ScanTrace events associated with a source IP within a lookback window.",
      "parameters": {
        "src_ip": { "type": "string" },
        "hours": { "type": "integer", "default": 24 }
      }
    }
  ]
}
```

### 6B — Real-Time Search (RTS) API

| # | Task | Done? |
|---|------|-------|
| 6.8 | Implement `slack/rts.go` — query Slack RTS API for prior channel messages mentioning an IP or ASN | ☐ |
| 6.9 | Before posting a new case alert, query `#scantrace-alerts` for any prior messages containing `src_ip` | ☐ |
| 6.10 | If prior mentions found: prepend "Previously observed — [link to thread]" to the Block Kit card | ☐ |
| 6.11 | If no prior mentions: post fresh case card as normal | ☐ |
| 6.12 | Test: post a duplicate case, confirm "Previously observed" context appears | ☐ |

### 6C — Natural Language Q&A (Slack AI)

| # | Task | Done? |
|---|------|-------|
| 6.13 | Add app mention listener: `@ScanTrace {question}` | ☐ |
| 6.14 | Implement intent router: detect question type (list cases / get case / enrich IP / summarize) | ☐ |
| 6.15 | Route to appropriate MCP tool, format response as readable Slack message | ☐ |
| 6.16 | Handle: "What hit us today?", "Show me the worst case", "Enrich 1.2.3.4", "What is AS14061?" | ☐ |
| 6.17 | Fallback response for unrecognized intent | ☐ |

### Sample Q&A Interactions

```
User: @ScanTrace what hit us in the last 6 hours?
Bot:  3 cases in the last 6 hours:
      🔴 Repeated SSH scan — AS4134 (China Telecom) — 47 events
      🟡 Port sweep 80/443 — AS14061 (DigitalOcean) — 12 events
      🟢 Known scanner — AS32934 (Censys) — 8 events [allowlisted]

User: @ScanTrace enrich 185.220.101.45
Bot:  185.220.101.45
      ASN: AS4809 — China Telecom Next Generation Carrier Network
      rDNS: 45.101.220.185.broad.gz.gd.dynamic.163data.com.cn
      Abuse: abuse@chinatelecom.cn
      Tags: none (unknown)

User: @ScanTrace show worst case today
Bot:  [Block Kit card — same as automated alert format]
```

### Gate Check
- `@ScanTrace what hit us today?` returns formatted case list  
- `enrich_ip` MCP tool returns valid Entity JSON  
- RTS query on known IP surfaces prior message thread link  
- All three technologies (MCP, RTS, Slack AI) visibly active in demo scenario  

---

## Layer 7 — Polish + Submission (Final Sprint)

**Target Days:** 22–23 (July 10–13)  

| # | Task | Done? |
|---|------|-------|
| 7.1 | Create architecture diagram (Mermaid or draw.io) — collector → normalizer → enricher → correlator → case builder → Slack agent | ☐ |
| 7.2 | Cut and tag hackathon baseline branch: `hackathon-stable-YYYYMMDD` | ☐ |
| 7.3 | Record demo video: 3 minutes, start with the "why", show live event → case → Slack alert → Q&A | ☐ |
| 7.4 | Invite `slackhack@salesforce.com` and `testing@devpost.com` to Dilldozer as **Members** | ☐ |
| 7.5 | Confirm agent installed and responsive in Dilldozer | ☐ |
| 7.6 | Note Slack App ID from `api.slack.com/apps` → Basic Information | ☐ |
| 7.7 | Complete Devpost submission form — all fields, sandbox URL, App ID, track selection | ☐ |
| 7.8 | Submit before July 13 @ 5:00 PM PDT — no exceptions, no extensions | ☐ |

### Demo Video Script (3 minutes)

```
0:00–0:20  The problem — scanners hit your perimeter constantly; teams
           have no Slack-native intelligence layer. "You know what I call
           that? A waste of time." (cut to raw log dump)

0:20–0:50  Live event ingested — show Asus router syslog being tailed,
           event appears, normalizer fires, enricher returns ASN.

0:50–1:30  Correlator groups events from same ASN, Case Builder generates
           markdown. Block Kit alert fires in #scantrace-alerts with full
           severity, IP, ASN, port, tags, and sensor source.

1:30–2:10  Q&A demo — @ScanTrace what hit us today? List returned.
           @ScanTrace enrich 185.220.101.45 — Entity JSON returned.
           MCP tool visible in Slack AI sidebar.

2:10–2:40  RTS demo — second event from same IP triggers "Previously
           observed" context block with link to original thread.

2:40–3:00  Architecture — 30-second whiteboard walk. Collector →
           Normalizer → Enricher → Correlator → Case Builder → Slack.
           "That's it. Dead simple. Defensively correct."
```

---

## AI Agent Query Guide

These are the best agents for specific ScanTrace development tasks, with exact prompt patterns that produce correct, implementation-ready output.

---

### Go Backend Pipeline

**Best Agent:** Claude Sonnet (via Claude.ai or API) or GitHub Copilot (in-editor)  
**Why:** Best Go idiomatic output, strong struct/interface design, SQLite pattern knowledge  

#### Prompt Templates

**Schema + CRUD:**
```
I'm building a Go CLI tool called ScanTrace. Define Go structs for four
types: Sensor, Event, Entity, and Case. Use these field names exactly:
[paste data_model.md field list]

Then write:
1. SQLite DDL to create all four tables with correct FK relationships
2. A db.go package with Open(), Close(), and CRUD functions for each type
3. Use github.com/mattn/go-sqlite3 as the driver
4. Enable WAL mode on open
5. All timestamps as RFC3339 strings
```

**Suricata EVE Collector:**
```
Write a Go package called collector that:
1. Reads a Suricata EVE JSON log file line by line (and optionally tails it)
2. Maps each EVE JSON line to this RawEvent struct: [paste your struct]
3. Handles these EVE event_types: alert, flow, dns, http
4. Preserves the raw JSON line as a string in RawRef field
5. Returns a channel of RawEvent for the normalizer to consume
6. Use only stdlib — no external deps except go-sqlite3
```

**Asus Syslog Collector:**
```
Write a Go package called collector/asus_syslog that:
1. Reads syslog lines from stdin (or a file path) — one line per read
2. Parses Asus AsusWRT syslog format for these message types:
   - kernel: DROP IN=... SRC=... DST=... PROTO=... DPT=...
   - kernel: ACCEPT IN=...
   - dnsmasq-dhcp: DHCPACK / DHCPDISCOVER lines with MAC + IP
   - hostapd: STA <mac> associated/disassociated
3. Maps parsed fields to RawEvent struct with source_type = "asus_syslog"
4. Preserves the full raw line in RawRef
5. Returns a channel of RawEvent for the normalizer to consume
6. Handles malformed/unknown lines gracefully (log + skip, never crash)
```

**Enricher with caching:**
```
Write a Go enricher package that:
1. Takes an IPv4 string as input
2. Skips enrichment for RFC-1918 private ranges — tag as internal and return
3. Queries ipinfo.io/AS for ASN and provider (free tier, no auth)
4. Does reverse DNS lookup with net.LookupAddr()
5. Queries rdap.org/ip/{ip} for abuse contact
6. Checks a hardcoded allowlist of known-scanner CIDR ranges
7. Caches results in SQLite entities table for 24h (check last_enriched)
8. Returns an Entity struct [paste your Entity struct]
Include proper error handling — enrichment failures should not crash the pipeline.
```

**Correlator sliding window:**
```
Write a Go correlator package that:
1. Accepts a src_ip and a lookback duration (default 6h)
2. Queries SQLite for all Events with that src_ip in the window
3. Deduplicates bursts: same src_ip + dst_port within 60s = one cluster
4. Detects ASN-level clustering: multiple IPs from same ASN hitting same dst_port
5. Returns CorrelationResult{Events []Event, Entities []Entity, Tags []string, Confidence float64}
6. Tag logic: "repeated_source" if >3 events, "port_sweep" if >3 distinct dst_ports, "asn_cluster" if >1 IP from same ASN
```

---

### Slack Bolt App + Block Kit

**Best Agent:** ChatGPT-4o (excellent Slack API / Block Kit knowledge) or Claude Sonnet  
**Why:** Strong Block Kit JSON generation; ChatGPT has seen more Slack API examples  

#### Prompt Templates

**Bolt app scaffold:**
```
Write a Go Slack bot using the slack-go/slack library (Bolt pattern) that:
1. Uses socket mode (SLACK_APP_TOKEN env var)
2. Listens for a trigger from an internal function (PostCaseAlert)
3. Posts a Block Kit message to #scantrace-alerts channel
4. Handles app_mention events for natural language Q&A
5. Connects to a local function: func HandleMention(text string) string
Include all required imports and env var loading.
```

**Block Kit card JSON:**
```
Write a Slack Block Kit message payload for a security case alert with these sections:
1. Header: emoji based on severity (🔴/🟡/🟢) + case title
2. Section with fields: Source IP, ASN, Provider, Target Port, Severity
3. Context block: tags as inline code (backtick format)
4. Actions: "View Full Case" button (opens modal) and "Dismiss" button
5. Attachment color: #cc0000 for high, #ff9900 for medium, #00cc00 for low
6. Footer context block: sensor source name
Return valid JSON. I will use Go struct tags to marshal this.
```

**Modal with markdown case:**
```
Write a Slack views.open() call in Go (slack-go/slack) that:
1. Triggers on "View Full Case" button click (block_actions)
2. Opens a modal with title "Case Details"
3. Displays the case markdown content in a plain_text_input block (read-only)
4. Has a "Close" button only (no submit action needed)
```

---

### MCP Server Implementation

**Best Agent:** Claude Sonnet (best MCP pattern knowledge as of 2026)  
**Why:** Most up-to-date with Anthropic MCP spec; generates correct tool schema JSON  

#### Prompt Templates

**MCP server scaffold:**
```
Write a Go MCP server that exposes four tools for a security intelligence pipeline:
1. get_case(case_id string) — queries SQLite, returns Case JSON
2. list_cases(severity string, limit int) — returns []CaseSummary JSON
3. enrich_ip(ip string) — calls enricher.Enrich(ip), returns Entity JSON
4. search_related_events(src_ip string, hours int) — queries SQLite, returns []Event JSON

Use the MCP Go SDK (mark3labs/mcp-go or equivalent).
Each tool must have a JSON schema description matching the MCP tool definition format.
The server should run as a subprocess and communicate over stdio (standard MCP pattern).
```

---

### Real-Time Search (RTS) Integration

**Best Agent:** Claude Sonnet with Slack API docs pasted in context  
**Why:** RTS API is relatively new; paste the docs to guarantee accuracy  

#### Prompt Template

```
[Paste the Slack RTS API documentation here before this prompt]

Write a Go function called SearchPriorMentions(slackClient *slack.Client, channelID string, query string) ([]slack.Message, error) that:
1. Uses the Slack Real-Time Search API to search a specific channel
2. Takes a query string (usually a src_ip or ASN like "185.220.101.45" or "AS4134")
3. Returns matching messages from the channel
4. Handles rate limiting with exponential backoff
5. Returns empty slice (not error) if no results found

Then write a function PrependPriorObservations(blocks []slack.Block, priorMessages []slack.Message) []slack.Block that:
1. If priorMessages is non-empty, prepends a context block to the Block Kit payload
2. Context block text: "⚠️ Previously observed — N prior mention(s)" with link to first thread
3. If empty, returns blocks unchanged
```

---

### Case Markdown Template

**Best Agent:** Claude Sonnet (best Go `text/template` generation)  

```
Write a Go text/template for a security incident case report. The template
receives a Case struct with these fields: [paste your Case struct]
The output should be valid GitHub-Flavored Markdown with:
1. H1 title with case ID and severity badge
2. Summary paragraph
3. Source Infrastructure table (IP, ASN, Provider, rDNS, Abuse Contact, Geo)
4. Timeline table (sorted by timestamp ascending)
5. Pattern tags as inline code
6. Raw artifact reference list
7. Sensor source and adapter name
8. Footer: "Generated by ScanTrace | Case ID: {id} | {timestamp}"
```

---

### Debugging Patterns

**When the EVE collector misses events:**
```
My Go Suricata EVE JSON collector is dropping events. It reads the file
line by line but some EVE log lines span multiple JSON objects per line.
Here is a sample of the actual EVE output: [paste sample]
Fix the parser to handle this correctly.
```

**When the Asus syslog adapter misses event types:**
```
My Go Asus syslog collector is not capturing DHCP or hostapd events.
Here is a sample of the actual syslog lines it receives: [paste sample]
The adapter currently handles kernel: DROP and kernel: ACCEPT.
Extend the parser to handle these additional event types.
```

**When SQLite locks under concurrent access:**
```
My ScanTrace Go app has a SQLite write contention error when the Slack agent
and the pipeline collector both write simultaneously. I have WAL mode enabled.
Here is the error: [paste error]
Here is my db.go: [paste code]
Fix the connection pool configuration and transaction patterns.
```

**When Block Kit layout breaks:**
```
My Slack Block Kit message renders incorrectly — the fields section shows
as a single column instead of two columns. Here is my current payload:
[paste JSON]
The channel is #scantrace-alerts. Fix the block structure.
```

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| RTS API not available in sandbox | Medium | High | Use `conversations.search` as fallback; test in Dilldozer week 1 |
| Suricata not available for live demo | Low | Medium | Use Asus live syslog as primary live source; Suricata testdata as backup |
| MCP Go SDK immaturity | Medium | Medium | Fall back to REST endpoint served by ScanTrace; document as equivalent |
| Enrichment APIs rate-limited during demo | Low | High | Pre-enrich all demo IPs; cache in SQLite before demo recording |
| SQLite concurrent write lock | Low | Medium | WAL mode + connection pool; collector pauses enricher if locked |
| Asus syslog adapter misses event types | Low | Medium | Log unknown lines to a debug file; fix before demo; use testdata fallback |
| rsyslog UDP 514 blocked by host firewall | Low | High | Test and open port before demo day; document in TROUBLESHOOTING.md |
| Dilldozer sandbox access issue | Low | High | Test judge invite (slackhack@salesforce.com) by July 8 |
| Demo video rendering time | Low | Low | Record by July 11 — 48h buffer before deadline |

---

## Event Code for Dilldozer Setup

If registered with a personal email (non-work/school), use the official event code when provisioning:

**`SABC-7X2K-M9PL-4QFN`** *(case-sensitive)*

This ensures judge invites (`slackhack@salesforce.com`, `testing@devpost.com`) work without Guest restrictions.

---

*"It's got electrolytes."* — and it's got a working MCP server. Ship it.
