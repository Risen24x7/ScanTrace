# ScanTrace – Dead Reckoning Edition

## Hackathon primary goal

Deliver a clear, demo-ready defensive scan intelligence pipeline that:

- Ingests real scan-related events from at least two sources (Suricata EVE JSON and a home router/firewall syslog feed).
- Normalizes those events into a common internal event schema.
- Enriches the source IP with basic infrastructure context (ASN, provider, reverse DNS, and abuse/geo hints where available).
- Correlates repeated activity over short time windows to distinguish one-off noise from recurring scan behavior.
- Produces human-readable case reports and machine-readable JSON exports summarizing scan campaigns.
- Exposes a simple CLI (and later MCP tools) to trigger, inspect, and export cases.

These capabilities must work **without any LLM dependency** for hackathon judging.

## Stable baseline for judging

The "Dead Reckoning" hackathon baseline is the minimum, stable feature set we commit to keep working end-to-end:

- **Inputs**
  - Suricata EVE JSON from `testdata/`.
  - Live syslog stream from at least one real network device (e.g., Asus router) forwarded via rsyslog.
- **Pipeline**
  - Collector ingests raw events and tags them with sensor metadata.
  - Normalizer maps source-specific fields into the common event schema.
  - Enricher attaches infrastructure context such as ASN, provider, and reverse DNS.
  - Correlator groups repeated activity over a demo-friendly time window.
  - Case builder generates incident-style case reports (Markdown + JSON).
- **Storage and tooling**
  - SQLite used as the embedded event + case store for MVP.
  - CLI commands:
    - `ingest` – read from file/stdin with a specified adapter.
    - `correlate` – build/refresh correlated views from raw events.
    - `cases` – list open/closed cases.
    - `report` – render a specific case in Markdown/JSON.

For the contest, we will cut and document a branch or tag (e.g., `hackathon-stable-2026-06-25`) that:

- Demonstrates Suricata testdata flowing end-to-end into a case report.
- Demonstrates live home-router syslog scan activity flowing into cases.
- Avoids schema-breaking changes to the SQLite layout.
- Runs entirely from the CLI with no external services required.

## Stretch goals (nice-to-have)

We will pursue these as time allows, but they are **not required** for the stable judging baseline:

### Detection + defense

- DHCP/MAC monitoring:
  - Parse DHCP logs to maintain a baseline of known MAC addresses per network.
  - Raise cases for "stray" or unknown MACs, especially if they participate in scans.
- Egress / exfil detection:
  - Detect unusual outbound volume per host or new destinations.
  - Optionally trigger user-configured actions (scripts, firewall hooks) to temporarily stall or block suspicious flows.

### Scalability + robustness

- Ingestion worker pool and autoscaler:
  - Bounded queues and worker pools for parsing and correlation.
  - Optional autoscaling of workers based on queue depth and latency.
- Dedicated DB writer queue:
  - Many producers, few writers to avoid SQLite lock contention.
  - Batched inserts for higher throughput.

### LLM-assisted, schema-first helpers

- UnknownFormatManager + LLMIntrospector:
  - When parse failures exceed a threshold for a source, sample a small set of lines.
  - Send them to a **local** LLM under a strict JSON schema to classify vendor/format and suggest an adapter.
  - Never block the main ingest loop; use bounded queues, timeouts, and circuit breakers.
- ModelRouter / LLM switcher:
  - Central abstraction that routes tasks (log introspection, case summarization, DB audit) to appropriate local models.
  - Enforces per-task token limits, timeouts, and rate limits.
- Database Auditor & Investigator LLMs (read-only):
  - Offline analysis of aggregated statistics and case history to suggest coverage gaps or interesting patterns.
  - All findings stored in separate, versioned tables to avoid mutating raw event data.

## Explicit non-goals for this hackathon

To keep the scope realistic, the following are explicitly **out of scope** for the hackathon timeframe:

- Full-featured web UI or dashboard beyond minimal case viewing.
- Offensive operations or automated active countermeasures beyond user-configured scripts.
- Multi-tenant auth, RBAC, or complex user management.
- Deep ML/LLM-based attribution of threat actors.

The emphasis for judging is a **reliable, explainable, CLI-first defensive pipeline** that turns noisy scans into actionable, evidence-oriented cases, with clearly documented stretch goals and a schema-first foundation for future LLM integration.
