# Stretch Goals – Dead Reckoning Edition

This document captures ScanTrace stretch goals that are **not required** for the hackathon baseline, but guide post-contest work and future LLM integration.

## 1. DHCP + MAC monitoring and unknown device detection

- Parse DHCP logs (e.g., `dnsmasq-dhcp` on Asus routers) to extract:
  - MAC address.
  - Leased IP.
  - Optional hostname/client identifier.
- Maintain a baseline of known MAC addresses per sensor/network.
- Create cases when:
  - A new, previously unseen MAC appears.
  - A guest/unknown MAC engages in scan-like behavior.
- Correlate unknown-device cases with scan and exfil alerts.

## 2. Egress / data exfiltration detection

- Monitor outbound connections for:
  - Unusual volume per host over a short window.
  - New destinations (IP, ASN, country) per host.
  - Unexpected protocols/ports for a given host profile.
- Raise cases like "Possible exfil from 10.0.0.X → IP:Y on port 443".
- Provide optional hooks for user-configured response actions:
  - Run external scripts.
  - Call firewall/router APIs to temporarily block or rate-limit flows.

## 3. Ingestion scalability and resilience

- Introduce explicit queues and worker pools:
  - Collector(s) feed a bounded queue of raw lines or normalized events.
  - Worker goroutines perform parsing, normalization, and enrichment.
- Add a dedicated DB writer queue:
  - Many producers, few writers.
  - Batched inserts to reduce lock contention and improve throughput.
- Implement a simple autoscaler:
  - Periodically check queue depth and worker utilization.
  - Scale worker counts up/down within configured bounds.

## 4. Schema-first LLM helpers

- **UnknownFormatManager + LLMIntrospector**
  - Detect sources with high parse failure rates.
  - Sample a small, deduplicated set of lines and send to a local LLM.
  - Use strict JSON schemas for responses (vendor, product, format family, field hints, confidence).
  - Update per-sensor adapter metadata only when confidence is high and/or after human approval.
  - Never inject raw log content as instructions; treat logs as untrusted text.

- **ModelRouter / LLM switcher**
  - Central component that routes tasks (log introspection, case summarization, DB audit) to:
    - Lightweight local models for structural tasks.
    - Heavier local/remote models for summarization or deep analysis.
  - Enforce per-task limits: max tokens, timeouts, rate limits.

- **Log safety and prompt-injection resistance**
  - Sanitize or escape obvious instruction markers in logs before they reach prompts.
  - Always wrap logs in prompts as untrusted input and require structured outputs.
  - Validate and reject LLM outputs that fail schema validation or exceed allowed keys.

## 5. Database Auditor LLM

- Periodic, read-only analysis of the event and case store to:
  - Identify coverage gaps (e.g., silent sensors, missing event types).
  - Spot inconsistent or suspicious metadata (e.g., timestamps in the future, impossible IPs).
  - Suggest additional sanity checks or rules.
- Store findings in a separate audit table with:
  - `id`, `created_at`, `scope`, `severity`, `description`, `status`.
- No direct mutations of raw event/case data; human or deterministic logic reviews findings.

## 6. Database Investigator LLM with versioned patterns

- Use aggregated statistics and sampled cases to surface potential higher-level patterns:
  - Repeated scan campaigns tied to certain ASNs or regions.
  - Devices that oscillate between benign and suspicious behavior.
  - Emerging exfil paths or lateral movement patterns.
- Store patterns in a dedicated, versioned pattern store:
  - `pattern_id`, `version`, `description`, `evidence_cases`, `confidence`, `status` (`proposed`, `accepted`, `rejected`).
- Allow analysts to promote or demote patterns without touching raw data.
- Over time, accepted patterns can inform new correlation rules or heuristics.

## 7. MCP-powered tools and assistants

- Expose ScanTrace capabilities via MCP tools so assistant-style agents can:
  - List sensors, events, and cases.
  - Drill into case details and evidence timelines.
  - Suggest additional enrichment or correlation steps.
- Layer specialized assistant personas on top of MCP:
  - "Database Auditor" focused on consistency and coverage.
  - "Investigator" focused on pattern recognition and evidence linking.

These stretch goals are intentionally modular. Each can be built on top of the stable, schema-first defensive pipeline defined in `Docs/HACKATHON_GOALS.md` and the core architecture overview.
