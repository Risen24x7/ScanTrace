# ScanTrace — Dead Reckoning Edition
## Hackathon Goals

> **Deadline:** July 13, 2026 @ 5:00 PM PDT  
> **Track:** New Slack Agent  
> **Days remaining:** 15

---

## Primary goal

Deliver a Slack-native, demo-ready defensive scan intelligence pipeline that:

- Ingests real events from at least two sources (Suricata EVE JSON + Asus router syslog)
- Normalizes events into a common internal schema
- Enriches source IPs with ASN, provider, rDNS, and abuse contact
- Correlates repeated activity to distinguish noise from recurring scan behavior
- Produces human-readable Slack Block Kit case cards and machine-readable JSON exports
- Exposes a Bolt app with MCP tools, Real-Time Search, and NL Q&A (`@ScanTrace what hit us today?`)

---

## Current pipeline status (as of June 28, 2026)

| Component | Status | Notes |
|---|---|---|
| Layer 1 — Data Foundation | ✅ Complete | Schema, SQLite, CLI, testdata all working |
| Layer 2 — Collector | ✅ Complete | Suricata + Asus syslog adapters live |
| Layer 3 — Normalizer | ✅ Functionally complete | MAC, event_type, confidence normalized; standalone normalizer.go not extracted yet |
| Layer 3 — Enricher | ☐ Not started | ipinfo.io + rDNS + RDAP needed |
| Layer 4 — Correlator | ✅ Complete | new_device, port_scan rules; dedup; severity; confidence working |
| Layer 4 — Case Builder | ✅ Complete | cases, report, serve commands working; Slack webhook alerts live |
| Layer 5 — Slack Bolt App | 🔄 Partial | Webhook alerting works; socket mode Bolt app + slash commands not built |
| Layer 6 — MCP Tools | ☐ Not started | get_case, list_cases, enrich_ip, search_related_events |
| Layer 6 — RTS Integration | ☐ Not started | Prior observation context block |
| Layer 6 — NL Q&A | ☐ Not started | @ScanTrace mention handler |
| Layer 7 — Polish/Submission | ☐ Not started | Architecture diagram, demo video, Devpost form |

---

## Stable baseline for judging (already working)

- Suricata EVE JSON testdata → ingest → correlate → cases → report ✅
- Live Asus syslog → ingest → correlate → cases ✅
- Slack webhook alert on new case ✅
- Dedup: open cases not re-fired ✅
- MAC address in `new_device` case titles ✅
- `serve --interval` auto-correlates on schedule ✅

---

## Remaining required for submission

All three Slack platform technologies must be visibly active for the agent track:

1. **Bolt app in Dilldozer** — socket mode, replaces webhook
2. **MCP server** — 4 tools: `get_case`, `list_cases`, `enrich_ip`, `search_related_events`
3. **Real-Time Search** — prior observation context block in case card
4. **NL Q&A** — `@ScanTrace {question}` mention handler

Supporting:
- IP enricher (feeds `enrich_ip` MCP tool)
- Known-device allowlist (prevent DHCP chatter from re-firing high-severity alerts)

---

## Stretch goals (nice-to-have, post-baseline)

- Suricata `--follow` flag (continuous tail of EVE file)
- DHCP/MAC baseline — flag stray MACs not previously seen
- Egress/exfil detection — unusual outbound volume per host
- Ingestion worker pool — bounded queues for high-volume ingest
- LLM-assisted unknown format classification (local model only, never blocks ingest loop)
- Web UI case viewer

---

## Explicit non-goals

- Multi-tenant auth or RBAC
- Offensive operations or automated countermeasures
- Deep ML/LLM-based threat actor attribution
- Full-featured dashboard beyond minimal case viewing

---

## Submission checklist

| # | Item | Done? |
|---|------|-------|
| 7.1 | Architecture diagram (Mermaid/draw.io) | ☐ |
| 7.2 | Tag `hackathon-stable-YYYYMMDD` branch | ☐ |
| 7.3 | 3-minute demo video recorded | ☐ |
| 7.4 | Invite `slackhack@salesforce.com` + `testing@devpost.com` to Dilldozer as Members | ☐ |
| 7.5 | Agent installed and responsive in Dilldozer | ☐ |
| 7.6 | Slack App ID noted from api.slack.com/apps | ☐ |
| 7.7 | Devpost form completed | ☐ |
| 7.8 | Submitted before July 13 @ 5:00 PM PDT | ☐ |
