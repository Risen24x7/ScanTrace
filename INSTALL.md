# ScanTrace — Installation & Run Guide

## Prerequisites

- Go 1.21+
- Linux host (tested on Ubuntu 22.04 / Debian 12)
- ASUS router (BE96U or any ASUSWRT/Merlin firmware) with syslog forwarding enabled
- Slack workspace with a bot token (`SLACK_BOT_TOKEN`) and an app-level Socket Mode token (`SLACK_APP_TOKEN`)
- (Optional) `ik_llama.cpp` running Qwen3-30B on a desktop reachable at `LLM_BASE_URL`

---

## 1. Clone & Build

Preferred (Makefile at repo root):

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace
make build
```

Binary is `./bin/scantrace`; SQLite DB (`scantrace.db`) is created next to it.

Alternative (agent-only):

```bash
cd ScanTrace/scantrace-agent
go build -o scantrace-agent ./cmd/bot/
```

---

## 2. Environment Variables (.env)

Create `.env` in `scantrace-agent/` from the example:

```bash
cp scantrace-agent/.env.example scantrace-agent/.env
```

Key variables (defaults shown where applicable):

```env
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
ALERT_CHANNEL=C0BBP1EP68P
EXTERNAL_THREAT_CHANNEL=C0BCYSW3KNC
LLM_BASE_URL=http://192.168.50.250:11434
LLM_MODEL=Qwen3-30B-A3B-UD-Q3_K_XL
DB_PATH=../scantrace.db
WAN_IP=
SCANTRACE_SYSLOG_PORT=5140
```

Load and run (agent-only path):

```bash
cd ~/ScanTrace/scantrace-agent
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

---

## 3. Syslog Port Defaults and Override

- Default agent UDP listen: SCANTRACE_SYSLOG_PORT=5140
- Override by setting SCANTRACE_SYSLOG_PORT in `.env`
- Router options:
  - Forward router syslog directly to 5140, or
  - Use rsyslog to receive on 514 and forward/tail to 5140

---

## 4. Capability Verification (binding <1024 or to keep consistent after rebuilds)

Grant capability to the built binary, and verify:

```bash
sudo setcap cap_net_bind_service=+ep ./bin/scantrace
getcap ./bin/scantrace
```

Expected: `./bin/scantrace = cap_net_bind_service+ep`

Re-run setcap after rebuilding.

---

## 5. Router Syslog Configuration (ASUS)

Administration → System → Syslog
- Enable: Yes
- Server IP: your ScanTrace host (e.g., 192.168.50.x)
- Port: 5140 (or 514 if relaying via rsyslog)

---

## 6. Running

```bash
./bin/scantrace
```

Startup should include:

```
[main] ScanTrace agent starting…
[handler] connecting to Slack...
```

---

## 7. Verify Events Are Being Received

```bash
sqlite3 scantrace.db "SELECT event_type, src_ip, dst_port, timestamp FROM events ORDER BY timestamp DESC LIMIT 20;"
```

---

## 8. Troubleshooting

See Docs/TROUBLESHOOTING.md for common issues.

Notes
- No Dockerfile in this repo; prefer local Go/Makefile path
- SQLite DB location can be adjusted via DB_PATH
- See docs/router-logging-setup.md for router configuration
