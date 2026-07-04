# Getting Started with ScanTrace — Dead Reckoning Edition

> Last updated: June 28, 2026

Addendum: Run-mode matrix and cross-links (hackathon scope)

Run-mode matrix
- Direct agent: listen UDP :5140 (env SCANTRACE_SYSLOG_PORT) — router forwards to 5140
- rsyslog relay: router -> rsyslog UDP :514, then forward/tail -> agent :5140

Cross-links
- INSTALL.md — .env copy, port defaults/override, setcap verification
- docs/router-logging-setup.md — firewall logging, port alignment, validation

For full demos, keep using the steps below.

## Prerequisites

- Go 1.21+ with CGO enabled (gcc required for go-sqlite3)
- Git
- SQLite3 CLI (optional, for direct DB inspection)
- For the live network demo:
  - Asus router (AsusWRT) with Remote Log Server enabled
  - Linux host running rsyslog to receive UDP 514

## 1. Clone the repository

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace
```

## 2. Testdata demo (Suricata EVE JSON)

```bash
CGO_ENABLED=1 go run ./cmd/bot/ ingest --file ./testdata/suricata-eve.json --adapter suricata
CGO_ENABLED=1 go run ./cmd/bot/ correlate
CGO_ENABLED=1 go run ./cmd/bot/ cases
CGO_ENABLED=1 go run ./cmd/bot/ report --case <CASE_ID>
```

## 3. Live home-router syslog demo (Asus)

... existing content unchanged ...
