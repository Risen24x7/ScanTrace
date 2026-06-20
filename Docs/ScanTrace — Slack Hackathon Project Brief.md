# ScanTrace — Slack Hackathon Project Brief
### *"The first step to fixing something is admitting it's broken."* — Idiocracy

> **Dev Sandbox:** Dilldozer  
> **Submission Deadline:** July 13, 2026 @ 5:00 PM PDT  
> **Winners Announced:** August 11, 2026  
> **Track:** New Slack Agent *(primary)* — eligible for Best Technological Implementation & Most Innovative Slack Agent achievement prizes  
> **Prize Pool:** $42,000 total; $8,000 first place per track + achievement prizes of $2,000 each

***

## Executive Summary

ScanTrace is a **defensive security telemetry and evidence pipeline delivered as a native Slack agent**. It ingests inbound scan events from firewalls, IDS engines, and honeypot sources; normalizes and enriches each event with infrastructure context (ASN, reverse DNS, abuse contact, geo); correlates repeated behavior over sliding time windows; and generates human-readable incident case summaries surfaced directly inside Slack channels — no external dashboard required.

The hackathon submission wires the ScanTrace backend pipeline into a Slack agent that listens for events, runs automated enrichment and correlation, posts structured case alerts to a designated security channel, and responds to analyst queries in real time using the Slack Real-Time Search (RTS) API and MCP server integration. Security operations teams get passive, evidence-quality scan intelligence without ever leaving Slack.

***

## Project Identity & Naming

### Working Name: ScanTrace

**ScanTrace** is clean, technically precise, and self-explanatory for judges spending 5–7 minutes per project. It communicates the core function — trace the scan — and avoids marketing noise.

### Obscure-Accurate Alternative Name Candidates

The following names are proposed for your love of the oblique reference:

| Name | Reference | Implied Message |
|------|-----------|-----------------|
| **Prodigy** | *Sneakers* (1992) — "We just need the codes, and then no more secrets" | Every scanner leaves a fingerprint; we collect them all |
| **SHODAN** | *System Shock* (1994) — the AI that sees everything on the network | We are the eye on your perimeter |
| **WINTERMUTE** | *Neuromancer* — the AI that wanted to become something greater | The pipeline that assembles intelligence from noise |
| **Choke Point** | Military/network ops vernacular — the one passage everything must cross | Every scan passes through our perimeter; we see it all |
| **Tap & Trace** | Legal wiretap term, *also* what you do to an attacker | We tap the scan, we trace the actor |
| **Dead Reckoning** | Navigation — knowing exactly where you are from where you've been | We reconstruct attacker infrastructure from event history alone |
| **The Long Count** | Mayan calendar — precise tracking over vast time with no gaps | Correlation engine that never forgets a source IP |

**Recommended working title for submission:** `ScanTrace` with subtitle `"Dead Reckoning for your perimeter"` — technically accurate, slightly haunting, explains itself to a judge in one read.

***

## Problem Statement

Every internet-connected infrastructure asset is continuously scanned by automated tooling — botnets, vulnerability scrapers, nation-state reconnaissance platforms, and gray-area research scanners like Shodan and Censys. Security teams have two bad options today:

1. **Ignore the noise** — miss real pre-attack reconnaissance
2. **Drown in raw logs** — export SIEM data, write detection rules, maintain dashboards in tools outside the natural work context

Neither produces evidence-quality case records that can be escalated, shared, or reported. And neither lives where the team already works: **Slack**.

ScanTrace solves the gap between raw scan telemetry and actionable intelligence by making the entire evidence pipeline a Slack-native workflow.

***

## Technology Stack & Hackathon Eligibility

The project must use **at least one** of: Slack AI capabilities, MCP server integration, or Real-Time Search API. ScanTrace uses **all three**, which maximizes the Technological Implementation judging score.

| Technology | ScanTrace Usage |
|------------|----------------|
| **Slack MCP Server** | Exposes ScanTrace case data and pipeline tools as structured MCP tool calls; allows LLMs (Claude, OpenAI) to query case history, run enrichment, and generate summaries natively |
| **Real-Time Search (RTS) API** | Searches prior Slack channel history for previous analyst discussions of the same source IP or ASN without exporting or storing message data externally — preserves compliance posture |
| **Slack AI / Bolt Framework** | Powers the Slack agent's natural language interface; analysts ask questions like *"what IPs hit us most from AS14061 this week?"* and get structured answers |
| **Bolt + `slack create agent` CLI** | Bootstraps the agent in the developer sandbox (Dilldozer); Bolt supports bring-your-own-LLM flexibility for the NLP layer |

**Language:** Go (backend pipeline — portability, static binaries, fast startup)  
**Storage:** SQLite for MVP; PostgreSQL upgrade path post-hackathon  
**Data Interchange:** JSON throughout  
**Deployment:** Container-friendly; single binary collectors; runs comfortably in Dilldozer sandbox

***

## Architecture

### High-Level Flow

```
[Event Source]
     │
     ▼
[Collector] ──────────────────────────── (Suricata EVE JSON / Syslog / Honeypot webhook)
     │
     ▼
[Normalizer] ─────────────────────────── (Maps to common event schema)
     │
     ▼
[Enricher] ───────────────────────────── (ASN · rDNS · Abuse contact · Geo · Reputation)
     │
     ▼
[Correlator] ─────────────────────────── (Sliding window · IP/ASN clustering · Pattern tags)
     │
     ▼
[Case Builder] ────────────────────────── (Markdown case + JSON export + artifact links)
     │
     ▼
[Slack Agent Layer]
  ├── Post case alert to #security-scans channel
  ├── MCP tool exposure (query cases, run enrichment on demand)
  ├── RTS API (search prior analyst channel history for related context)
  └── AI NL interface (analyst Q&A, case summary generation)
```

### Core Components

**Collector**
- Ingests raw data from Suricata EVE JSON, firewall syslog, optional honeypot webhook
- Timestamps and tags events at ingestion
- Preserves raw artifact reference for evidence integrity

**Normalizer**
- Maps all source formats to the ScanTrace common event schema
- Attaches sensor metadata and standardizes timestamps, ports, protocols, event types
- Adapter-per-source design keeps the schema stable as inputs change

**Enricher**
- Resolves ASN and provider name (BGP route origin)
- Queries reverse DNS
- Attaches abuse contact when available
- Optionally adds geo country and reputation labels (e.g., known scanner allowlist)

**Correlator**
- Deduplicates burst events from the same source within a short window
- Tracks recurring IPs and ASNs across sessions
- Groups scans by timing, target port, and infrastructure affiliation
- Tags known-benign scanners (Shodan, Censys, security research ranges) separately

**Case Builder**
- Produces a human-readable markdown incident summary
- Links raw event IDs, enrichment data, and timeline artifacts
- Exports paired markdown + JSON for portability

**Slack Agent Layer** *(hackathon-specific integration)*
- Bolt-based agent installed in the Dilldozer sandbox
- Posts structured case alerts with Block Kit formatting to a designated channel
- MCP server exposes: `get_case`, `list_cases`, `enrich_ip`, `search_related_events` as structured tools
- RTS API searches prior Slack channel history to surface past analyst notes on the same actor before posting a new case
- Natural language Q&A via Slack AI: analysts can ask freeform questions; the agent queries the case store and returns structured responses

***

## Data Model

### Primary Object Types

**Sensor** — source of observation
```
sensor_id · hostname · platform · role · public_ip
network_zone · location_tag · collector_type · version
```

**Event** — one normalized observation
```
event_id · timestamp · first_seen · last_seen · sensor_id
source_type · detector_type · event_type · src_ip · src_port
dst_ip · dst_port · protocol · transport · direction
raw_ref · pcap_ref · confidence · tags · notes
```

**Entity** — enriched infrastructure object
```
entity_id · entity_type · ip · asn · as_name · provider
rdns · abuse_contact · geo_country · reputation_labels · last_enriched
```

**Case** — grouped investigation record
```
case_id · title · summary · status · severity · confidence
created_at · updated_at · related_event_ids · related_entity_ids
timeline · artifacts · analyst_notes · report_exports
```

**Relationship rules:**
- One sensor → many events
- One entity → many events (same IP, different times)
- One case → many events and entities
- Correlation creates derived relationships on time window, ASN, or behavioral pattern

***

## MVP Scope

The MVP must demonstrate one complete, explainable path in real time during the demo.

### MVP Demo Path (5 steps)
1. A scan event arrives at the collector (Suricata EVE JSON or syslog)
2. The normalizer maps it to the common event schema
3. The enricher resolves ASN, rDNS, and abuse contact for the source IP
4. The correlator checks for prior observations of the same IP/ASN in the case store
5. The case builder generates a markdown incident summary
6. The **Slack agent posts the case to #security-scans** with Block Kit formatting
7. An analyst asks a natural language question; the agent responds using MCP + RTS

### In-Scope for MVP
- Suricata EVE JSON input adapter
- Syslog input adapter (firewall or appliance)
- IP enrichment via public BGP/WHOIS/rDNS APIs
- Sliding-window correlation (configurable lookback: 1h, 6h, 24h)
- Markdown case output with JSON export
- Slack agent: case posting, MCP tool exposure, RTS search, NL Q&A
- CLI mode for local testing and demo reliability

### Nice-to-Have (if time allows)
- Honeypot webhook listener as third input source
- Known-benign scanner allowlist handling
- Repeated-event clustering UI in Slack (thread-per-case)

### Explicitly Out of Scope for MVP
- Full web dashboard
- Multi-tenant deployment
- Offensive countermeasures or scan-back behavior *(non-goal by design — ScanTrace is defensive only)*
- Advanced ML-based attribution
- Full SIEM connector integrations
- Complex user management

***

## Judging Alignment

The four equally-weighted judging criteria are: Technological Implementation, Design, Potential Impact, and Quality of the Idea. ScanTrace addresses each directly.

| Criterion | ScanTrace Positioning |
|-----------|----------------------|
| **Technological Implementation** | Uses all three required technologies (MCP, RTS, Slack AI/Bolt); Go pipeline with clean adapter architecture; SQLite-backed case store; inspectable JSON at every stage |
| **Design** | Slack-native UX — no external dashboard; Block Kit formatted case cards; thread-per-case analyst workflow; CLI fallback for reliability |
| **Potential Impact** | Every security team on Slack can use this; addresses a universal problem (perimeter scan noise → actionable intelligence); post-hackathon path to Slack Marketplace |
| **Quality of the Idea** | No current Slack-native scan intelligence + case generation tool exists; solves the specific workflow problem of analyst context inside Slack rather than wrapping a generic chatbot |

**Achievement prize targeting:**
- **Best Technological Implementation** — all three platform technologies, clean modular pipeline, CLI-first reliability
- **Most Innovative Slack Agent** — scan telemetry → Slack case intelligence is a novel use of MCP + RTS in a defensive security context

***

## Track Recommendation

**Primary:** `New Slack Agent` — clean submission path, no Marketplace requirement, maximum creative latitude, $8,000 first prize.

**Secondary consideration:** `Slack Agent for Organizations` — if the agent is polished enough to submit to the Slack Marketplace before July 13 deadline, this track adds a 30-minute conversation with a Slack product executive and Stack Overflow podcast feature as prize extras for first place. The Marketplace submission adds submission overhead but the prize value is significant. Evaluate at week 3.

***

## Build Timeline (June 19 – July 13, 2026)

**~24 days remain.** Judges spend 5–7 minutes per project; a clean end-to-end demo matters more than breadth.

| Week | Focus | Deliverables |
|------|-------|-------------|
| **Week 1** (Jun 19–25) | Pipeline skeleton | Collector (Suricata EVE JSON), Normalizer, SQLite schema, CLI test harness |
| **Week 2** (Jun 26–Jul 2) | Enrichment + correlation | Enricher (ASN/rDNS), Correlator (24h sliding window), Case Builder (markdown output) |
| **Week 3** (Jul 3–9) | Slack agent integration | Bolt agent in Dilldozer, Block Kit case cards, MCP tool exposure, RTS search integration |
| **Week 4** (Jul 10–13) | Polish + submission | NL Q&A tuning, syslog adapter, demo video, architecture diagram, Devpost form |

**Demo success criteria (from MVP spec):**
- A real event flows through the full pipeline
- The case output is understandable in under one minute
- The architecture can be explained simply
- Scope feels credible for the hackathon timeline

***

## Sandbox Setup (Dilldozer)

The Slack developer sandbox — **Dilldozer** — is an Enterprise org environment that supports all Slack features safely without additional cost. It is provisioned through the Slack Developer Program and serves as the live test and judging environment.

**Pre-submission sandbox checklist:**
- [ ] Invite `slackhack@salesforce.com` and `testing@devpost.com` as **Members** (not guests)
- [ ] Confirm both accounts appear in the workspace member list
- [ ] Verify the ScanTrace agent is installed and authorized in Dilldozer
- [ ] Provide the workspace URL (`https://dilldozer.slack.com` or equivalent) in the Devpost submission form
- [ ] Confirm the agent is responsive to at least one test query before submitting
- [ ] Obtain and record the Slack App ID from Basic Information in the app settings

***

## Submission Checklist

All items required per official rules:

- [ ] **Track selected:** New Slack Agent
- [ ] **Text description:** Features, functionality, and architecture narrative (plain English)
- [ ] **Demo video:** Under 3 minutes, shows working agent end-to-end, uploaded to YouTube/Vimeo, public link
- [ ] **Architecture diagram:** Component flow from collector → Slack agent (export from draw.io, Mermaid, or equivalent)
- [ ] **Sandbox URL:** Dilldozer workspace URL with judge access confirmed
- [ ] **App ID:** From Slack app Basic Information page
- [ ] **Devpost form:** All fields complete; submitted before July 13 @ 5:00 PM PDT

***

## Non-Goals & Design Boundaries

These are explicit constraints, not gaps:

- **No offensive response behavior** — ScanTrace does not scan back, validate exploits, or take active countermeasures
- **No attribution beyond infrastructure** — the pipeline identifies ASN and provider, not individuals
- **No bulk data export** — RTS API is used to keep Slack conversation data in-platform; no external message storage
- **No real-time alerting fatigue** — correlation deduplicates bursts; a single case is created per correlated cluster, not one alert per raw event

***

## Post-Hackathon Expansion Path

| Feature | Effort | Value |
|---------|--------|-------|
| Web UI for case review | Medium | Broader audience outside Slack |
| Slack Marketplace publication | Medium | Distribution to enterprise customers |
| Additional input adapters (Zeek, Windows Event Log, cloud provider flow logs) | Low per adapter | Expands addressable environments |
| AI-generated incident summaries via Claude/OpenAI | Low | Faster analyst triage |
| Provider-specific abuse report automation | High | Closes the loop on reporting |
| Multi-tenant support | High | SaaS commercialization path |
| SIEM export connectors (Splunk, Elastic) | Medium | Enterprise integration |

***

## Key References

- Hackathon overview and prizes: [slackhack.devpost.com](https://slackhack.devpost.com)
- Official rules and judging: [slackhack.devpost.com/rules](https://slackhack.devpost.com/rules)
- FAQ and sandbox setup: [slackhack.devpost.com/details/faq-slackagent-builder](https://slackhack.devpost.com/details/faq-slackagent-builder)
- Slack developer sandbox docs: [docs.slack.dev/tools/developer-sandboxes](https://docs.slack.dev/tools/developer-sandboxes)
- Slack MCP Server + RTS API overview: [March 2026 platform newsletter](https://slack.dev/newsletter/platform-newsletter-march-2026/)
- Agent quickstart: [slack.dev](https://slack.dev)