# Changelog

All notable changes to ScanTrace – Dead Reckoning Edition will be documented in this file.

## [Unreleased]

- Placeholder for post-hackathon changes.

## [2026-06-25] Dead Reckoning – Hackathon baseline

- Locked the hackathon baseline around an end-to-end defensive scan intelligence pipeline.
- Added `Docs/HACKATHON_GOALS.md` describing the primary judging goal, stable baseline, stretch goals, and non-goals.[cite:255]
- Clarified that Suricata testdata and one live syslog-fed network source (e.g., Asus router) must both flow into the common event schema and case reports.
- Confirmed SQLite as the MVP event/case store and CLI-first operation for demos.

## [2026-06-24] Initial MVP flow

- Implemented the core components outlined in the architecture overview:
  - Collector for ingesting raw events from supported sources.
  - Normalizer to map source-specific records into a common event schema.
  - Enricher to attach basic infrastructure metadata (e.g., ASN, reverse DNS).
  - Correlator to group repeated scan-related activity over time.
  - Case builder to produce human-readable incident summaries and JSON exports.[cite:196][cite:198]
- Wired the initial testdata path from Suricata EVE JSON into the pipeline.
