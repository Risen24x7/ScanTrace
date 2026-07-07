# ScanTrace — Installation & Run Guide

## Prerequisites

- Go 1.21+
- Linux host (tested on Ubuntu 22.04 / Debian 12)
- ASUS router (BE96U or any ASUSWRT/Merlin firmware) with syslog forwarding enabled
- Slack workspace with a bot token (`SLACK_BOT_TOKEN`) and an app-level Socket Mode token (`SLACK_APP_TOKEN`)
- (Optional) LLM endpoint reachable at `LLM_BASE_URL`

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
LLM_BASE_URL=http://192.168.50.250:11434
LLM_MODEL=Qwen3-30B-A3B-UD-Q3_K_XL
DB_PATH=../scantrace.db
WAN_IP=
SCANTRACE_SYSLOG_PORT=5140
```

Tips:
- Set `DB_PATH` to an absolute path (e.g. `/var/lib/scantrace/scantrace.db`). Otherwise it is resolved relative to the working directory.
- `WAN_IP` can be set explicitly to your gateway's public IP (auto-detected from syslog if omitted).
- Run `/scantrace status` in Slack for a liveness check.

Load and run manually:

```bash
cd ~/ScanTrace/scantrace-agent
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

---

## 3. Port Binding (no sudo at runtime)

The agent listens on UDP :5140 by default. Grant the capability after each build:

```bash
sudo setcap cap_net_bind_service=+ep ~/ScanTrace/scantrace-agent/scantrace-agent
```

---

## 4. Router Syslog Configuration (ASUS BE96U)

See `docs/router-logging-setup.md` for screenshots and steps.

---

## 5. Running (manual)

```bash
cd ~/ScanTrace/scantrace-agent
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

Expected startup log:

```
[main] ScanTrace agent starting…
[handler] connecting to Slack...
[handler] connected to Dilldozer ✓
```

---

## 6. After Every Rebuild (manual)

```bash
go build -o scantrace-agent ./cmd/bot/
sudo setcap cap_net_bind_service=+ep ./scantrace-agent
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

---

## 7. Run as a systemd service (recommended)

This example keeps configuration in the repo `.env` by default.

Create directories and install path:

```bash
sudo install -d -o "$USER" -g "$USER" /opt/scantrace/bin /opt/scantrace/exports /var/lib/scantrace
```

Build and install the binary out of the git tree:

```bash
cd ~/ScanTrace/scantrace-agent
GOFLAGS= go build -o /tmp/scantrace-agent ./cmd/bot/
sudo install -m0755 /tmp/scantrace-agent /opt/scantrace/bin/scantrace-agent
```

Write the unit file:

```bash
sudo tee /etc/systemd/system/scantrace-agent.service >/dev/null <<'EOF'
[Unit]
Description=ScanTrace Agent
After=network-online.target
Wants=network-online.target

[Service]
User=%i
WorkingDirectory=%h/ScanTrace/scantrace-agent
EnvironmentFile=%h/ScanTrace/scantrace-agent/.env
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStart=/opt/scantrace/bin/scantrace-agent
Restart=on-failure
RestartSec=3s

ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/lib/scantrace /opt/scantrace
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scantrace-agent@"$USER"
systemctl --no-pager status scantrace-agent@"$USER"
```

Daily update workflow:

```bash
cd "$HOME/ScanTrace" \
&& git fetch origin && git checkout main && git pull --ff-only \
&& cd scantrace-agent \
&& go build -o /tmp/scantrace-agent ./cmd/bot/ \
&& sudo install -m0755 /tmp/scantrace-agent /opt/scantrace/bin/scantrace-agent \
&& sudo systemctl restart scantrace-agent@"$USER"
```

Notes:
- `EnvironmentFile` points at the repo `.env`. Ensure lines are `KEY=VALUE` (no `export` prefix).
- Use an absolute `DB_PATH` (e.g., `/var/lib/scantrace/scantrace.db`) in `.env` to avoid "readonly database" with `ProtectHome=read-only`.
- Exports are written to `/opt/scantrace/exports` when writable; otherwise the current working directory.
- If you prefer a global `/etc/scantrace/scantrace.env`, point `EnvironmentFile` there instead.

Lint the unit (optional):

```bash
sudo systemd-analyze verify /etc/systemd/system/scantrace-agent.service
```

---

## 8. Slack commands

- `/scantrace status` — liveness (DB, case counts, syslog port, WAN IP, LLM, alerts channel)
- `/scantrace review-all [--limit N] [--since 7d|30d] [--severity red,yellow,green] [--exclude-wan-only] [--dedupe]`
- `/scantrace export-blocklist [--limit N] [--since 7d] [--severity …] [--wan-only] [--group-cidr] [--format txt|csv|ipset]`

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `db.Open: migrations: attempt to write a readonly database` | DB under `$HOME` while `ProtectHome` restricts access | Set `DB_PATH=/var/lib/scantrace/scantrace.db` |
| `Failed at step EXEC` | `ExecStart` points to a missing binary | Rebuild and install to `/opt/scantrace/bin/scantrace-agent` |
| `subscribe skipped: unknown_method` | Slack RTS in sandbox | Cosmetic, safe to ignore |
