# ScanTrace — Installation & Run Guide

## Prerequisites

- Go 1.21+
- Linux host (tested on Ubuntu/Debian)
- ASUS router (BE96U or any ASUSWRT/Merlin firmware) with syslog forwarding enabled
- Slack workspace with a bot token (`SLACK_BOT_TOKEN`) and webhook URL (`SLACK_WEBHOOK_URL`)

---

## 1. Clone & Build

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace/scantrace-agent
go build -o scantrace ./cmd/bot/
```

The binary is `./scantrace`. All state files (`scantrace.db`, `.asus-sensor-id`) are written **next to the binary** automatically — you never need to `cd` to a specific directory to run it.

---

## 2. Environment Variables

Create a `.env` file in `ScanTrace/scantrace-agent/`:

```env
SLACK_BOT_TOKEN=xoxb-...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
IPINFO_TOKEN=optional_token
SCANTRACE_DB=/absolute/path/to/scantrace.db        # optional, defaults to <exe-dir>/scantrace.db
SCANTRACE_ASUS_STATE=/absolute/path/.asus-sensor-id # optional, defaults to <exe-dir>/.asus-sensor-id
SCANTRACE_SYSLOG_PORT=5140
```

Load and run:

```bash
export $(grep -v '^#' .env | xargs)
./scantrace
```

---

## 3. Port Binding (No sudo required)

The agent listens on UDP **:5140** by default. Grant the binary the capability to bind that port without root:

```bash
sudo setcap cap_net_bind_service=+ep ~/ScanTrace/scantrace-agent/scantrace
```

Run this once after every `go build`. Then run the binary as your normal user — **no sudo needed**.

> If you rebuild the binary, re-run `setcap` because the capability is attached to the file inode.

---

## 4. Router Syslog Configuration (ASUS BE96U)

1. Log in to router admin UI
2. Go to **Administration → System → Syslog**
3. Set:
   - **Enable:** Yes
   - **Server IP:** IP of your ScanTrace host (e.g. `192.168.50.x`)
   - **Port:** `5140`
4. Save & Apply

---

## 5. Running

```bash
cd ~/ScanTrace/scantrace-agent
export $(grep -v '^#' .env | xargs)
./scantrace
```

The agent will:
- Listen on UDP :5140 for router syslog
- Parse `WAN_NEW_ACCEPT` and `WAN_FWD` events
- Run the correlator every 5 minutes
- Post alerts to Slack for every new case (all severities)

---

## 6. After Every Rebuild

```bash
go build -o scantrace ./cmd/bot/
sudo setcap cap_net_bind_service=+ep ./scantrace
export $(grep -v '^#' .env | xargs) && ./scantrace
```

---

## 7. Verify Events Are Being Received

```bash
sqlite3 scantrace.db "SELECT event_type, src_ip, dst_port, timestamp FROM events ORDER BY timestamp DESC LIMIT 20;"
```
