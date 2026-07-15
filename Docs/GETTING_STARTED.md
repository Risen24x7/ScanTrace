# Getting Started with ScanTrace — Dead Reckoning Edition

> **Last updated:** June 28, 2026

This guide walks through the quickest way to run the demo paths for the hackathon baseline.

## Prerequisites

- Go 1.21+ with CGO enabled (`gcc` required for `go-sqlite3`)
- Git
- SQLite3 CLI (optional, for direct DB inspection)
- For the live network demo:
  - Asus router (AsusWRT) with **Remote Log Server** enabled
  - Linux host running `rsyslog` to receive UDP 514

## 1. Clone the repository

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace
```

## I'm sure there is supposed to be a step here for using make to build the agent, working on interactive installer, non-interactive installer, and probably a docker.

## 2. Testdata demo (Suricata EVE JSON)

```bash
# Ingest bundled EVE JSON testdata
CGO_ENABLED=1 go run ./cmd/bot/ ingest \
  --file ./testdata/suricata-eve.json \
  --adapter suricata

# Correlate into cases
CGO_ENABLED=1 go run ./cmd/bot/ correlate

# List cases
CGO_ENABLED=1 go run ./cmd/bot/ cases

# Render a case report
CGO_ENABLED=1 go run ./cmd/bot/ report --case <CASE_ID>
```

## 3. Live home-router syslog demo (Asus)

### 3.1 Configure the router

- Log into the Asus web GUI
- **Administration → System Log → General Log**
- Enable **Remote Log Server**
- Set the IP to your ScanTrace host's LAN IP
- Port: `5140` (UDP)
- Apply and save

### 3.2 Configure rsyslog on the ScanTrace host

```bash
# 1. Enable UDP syslog in /etc/rsyslog.conf — uncomment or add:
#   $ModLoad imudp
#   $UDPServerRun 514

# 2. Add an IP-scoped rule for the router (replace IP with your router's LAN IP)
sudo sh -c 'cat > /etc/rsyslog.d/asus-router.conf <<EOF
if $fromhost-ip == "192.168.50.1" then /var/log/asus-router.log
& stop
EOF'

# 3. Restart rsyslog
sudo systemctl restart rsyslog

# 4. Verify logs arriving
sudo tail -n 20 /var/log/asus-router.log
```

Expected output: lines containing `dnsmasq-dhcp`, `hostapd`, or `kernel` from the router.

### 3.3 One-shot ingest from existing log lines

```bash
sudo tail -n 50 /var/log/asus-router.log | \
CGO_ENABLED=1 go run ./cmd/bot/ ingest --adapter asus-syslog --file -
```

Verify rows were inserted:

```bash
sqlite3 scantrace.db "SELECT timestamp, event_type, src_ip, notes FROM events WHERE source_type='asus_syslog' ORDER BY timestamp DESC LIMIT 10;"
```

### 3.4 Live continuous ingest

```bash
# Terminal 1 — live tail + ingest
sudo tail -F /var/log/asus-router.log | \
CGO_ENABLED=1 go run ./cmd/bot/ ingest --adapter asus-syslog --file -

# Terminal 2 — correlate and alert
CGO_ENABLED=1 go run ./cmd/bot/ correlate
CGO_ENABLED=1 go run ./cmd/bot/ cases
```

### 3.5 Run with Slack alerts

```bash
SLACK_WEBHOOK_URL='<your-webhook>' CGO_ENABLED=1 go run ./cmd/bot/ serve --interval 2m
```

`serve` runs correlate on the given interval and posts new cases to Slack automatically.

### 3.6 Demo: live ingestion status in Slack (This would have been running if I wasn't a try hard and wanted to add more)

To let judges watch ingest flow, I ran the agent with periodic "Ingestion Status"
posts. These go to a hardcoded demo channel (`C0BHW7NSR7S`) and are independent
of case alerts / `ALERT_CHANNEL`.

```bash
SLACK_BOT_TOKEN=xoxb-... SLACK_APP_TOKEN=xapp-... ALERT_CHANNEL=C... \
  ./bin/scantrace-agent --ingest-metrics --ingest-metrics-interval=30s
```

- First status posts within ~5s of startup, then every interval (default `30s`).
- Each post shows totals and since-last deltas for LinesReceived / LinesParsed /
  LinesSkipped plus the skip rate (%).
- If `SLACK_BOT_TOKEN` or the channel is missing, the poster logs a warning and
  disables itself (no panic); the rest of the agent runs normally.

## 4. Database maintenance

```bash
# Close all open cases (demo reset)
sqlite3 scantrace.db "UPDATE cases SET status='closed' WHERE status='open';"

# Purge events with no src_ip (ghost records from before MAC fix)
sqlite3 scantrace.db "DELETE FROM events WHERE event_type LIKE 'wifi_%' AND src_ip='';"

# Check what's in the DB
sqlite3 scantrace.db "SELECT event_type, src_ip, dst_ip, dst_port FROM events WHERE source_type='asus_syslog' LIMIT 20;"
```

## 5. Project layout

```
cmd/bot/              CLI entrypoint — ingest, correlate, cases, report, serve
internal/collector/   Adapters: suricata, asus-syslog
internal/normalizer/  Field mapping → common Event schema
internal/enricher/    ASN, rDNS, RDAP enrichment (in progress)
internal/correlator/  Pattern detection → Case creation
Docs/                 Project brief, build order, goals, troubleshooting
testdata/             Sample Suricata EVE JSON
```

## 6. Next steps

- See `Docs/scantrace_build_order.md` for the full build roadmap and current layer status
- See `Docs/HACKATHON_GOALS.md` for judging baseline and stretch goals
- See `Docs/TROUBLESHOOTING.md` for common issues
