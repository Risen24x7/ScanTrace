# ScanTrace — Installation & Run Guide

## Prerequisites

- Go 1.21+
- Linux host (tested on Ubuntu 22.04 / Debian 12)
- ASUS router (BE96U or any ASUSWRT/Merlin firmware) with syslog forwarding enabled
- Slack workspace with a bot token (`SLACK_BOT_TOKEN`) and an app-level Socket Mode token (`SLACK_APP_TOKEN`)
- *(Optional)* `ik_llama.cpp` running Qwen3-30B on a desktop reachable at `LLM_BASE_URL`

---

## 1. Clone & Build

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace/scantrace-agent
go build -o scantrace-agent ./cmd/bot/
```

The binary is `./scantrace-agent`. The SQLite database (`scantrace.db`) is written next to the binary by default.

---

## 2. Environment Variables

Create `.env` in `ScanTrace/scantrace-agent/` (see `.env.example`):

```env
# Required
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
ALERT_CHANNEL=C0BBP1EP68P

# Optional — defaults shown
EXTERNAL_THREAT_CHANNEL=C0BCYSW3KNC   # channel for LLM Q&A replies (defaults to ALERT_CHANNEL)
LLM_BASE_URL=http://192.168.50.250:11434  # ik_llama.cpp endpoint; works without if omitted
LLM_MODEL=Qwen3-30B-A3B-UD-Q3_K_XL
DB_PATH=/opt/scantrace/scantrace.db      # RECOMMENDED: absolute path
WAN_IP=                                    # set explicitly (e.g., 24.20.77.75) or leave blank to auto-detect from syslog
SCANTRACE_SYSLOG_PORT=5140
```

Load and run:

```bash
cd ~/ScanTrace/scantrace-agent
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

> **Note:** Run `export $(...)` from inside `scantrace-agent/` so the path to `.env` is just `.env`.

---

## 3. Port Binding (No sudo required)

The agent listens on UDP **:5140** by default. Grant the capability once after each build:

```bash
sudo setcap cap_net_bind_service=+ep ~/ScanTrace/scantrace-agent/scantrace-agent
```

Re-run after every `go build` — the capability is attached to the file inode.

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
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

On startup you should see:

```
[main] ScanTrace agent starting…
[handler] connecting to Slack...
[handler] connected to Dilldozer ✓
[main] LLM endpoint: http://192.168.50.250:11434 (model="Qwen3-30B-A3B-UD-Q3_K_XL")
```

The `subscribe skipped: unknown_method` RTS line is cosmetic on the Dilldozer sandbox — the agent continues normally.

The agent will:
- Listen on UDP :5140 for router syslog
- Classify WAN edge traffic vs. internal traffic in Go (not the LLM)
- Run the correlator every 5 minutes
- Post Block Kit alerts to `#sec-alerts` for every new case
- Post LLM Q&A responses to `EXTERNAL_THREAT_CHANNEL`

---

## 6. After Every Rebuild

```bash
go build -o scantrace-agent ./cmd/bot/
sudo setcap cap_net_bind_service=+ep ./scantrace-agent
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

---

## 7. Verify Events Are Being Received

```bash
sqlite3 scantrace.db "SELECT event_type, src_ip, dst_port, timestamp FROM events ORDER BY timestamp DESC LIMIT 20;"
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `LLM not configured` in Slack | `LLM_BASE_URL` not exported | Add to `.env` or just restart — defaults to `http://192.168.50.250:11434` |
| `grep: scantrace-agent/.env: Not a directory` | Running `export $(...)` from parent dir | `cd scantrace-agent/` first |
| Agent exits immediately | Missing `SLACK_BOT_TOKEN` or `SLACK_APP_TOKEN` | Check `.env` has both |
| No alerts in Slack | Wrong `ALERT_CHANNEL` ID | Must be channel ID (`C0...`), not name |
| WAN traffic shows as internal threat | Old binary without WAN_IP pre-classification | Rebuild from current `main` |

---

## 9. Quick status

Run `/scantrace status` in Slack for liveness: DB OK, case counts, syslog port, WAN IP, LLM config, and alert channel.
