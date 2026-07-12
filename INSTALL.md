# ScanTrace — Installation & Run Guide

## Prerequisites

- Go 1.21+
- Linux host (tested on Ubuntu 22.04 / Debian 12)
- ASUS router (BE96U or any ASUSWRT/Merlin firmware) with syslog forwarding enabled
- Slack workspace with a bot token (`SLACK_BOT_TOKEN`) and an app-level Socket Mode token (`SLACK_APP_TOKEN`)
- (Optional) LLM endpoint reachable at `LLM_BASE_URL`

---

## Quick install (recommended)

Installs a dedicated `scantrace` user, seeds env at `/etc/scantrace/scantrace.env`,
installs the binary to `/opt/scantrace/bin/`, and enables the service.

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace
./scripts/install-service.sh
sudoedit /etc/scantrace/scantrace.env   # fill tokens/channel IDs, verify DB_PATH
sudo systemctl restart scantrace-agent
```

Verify:
```bash
systemctl --no-pager status scantrace-agent
ps -o user,group,cmd -C scantrace-agent
```

---

## 1. Clone & Build (manual)

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace/scantrace-agent
go build -o scantrace-agent ./cmd/bot/
```

The binary is `./scantrace-agent`. By default (manual runs), the SQLite database resolves from `DB_PATH` relative to the working directory if not absolute. Service deployments SHOULD use an absolute DB path under `/var/lib/scantrace`.

---

## 2. Environment Variables (manual)

Create `.env` in `ScanTrace/scantrace-agent/` (see `.env.example`):

```env
# Required
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
ALERT_CHANNEL=C0BBP1EP68P

# Optional — defaults shown
EXTERNAL_THREAT_CHANNEL=C0BCYSW3KNC   # channel for LLM Q&A replies (defaults to ALERT_CHANNEL)
LLM_BASE_URL=http://127.0.0.1:11434    # do NOT include /v1; the agent adds it
LLM_MODEL=Qwen3-30B-A3B-UD-Q3_K_XL
DB_PATH=/var/lib/scantrace/scantrace.db
WAN_IP=
SCANTRACE_SYSLOG_PORT=5140
```

Tips:
- Always set `DB_PATH` to an absolute path (recommended: `/var/lib/scantrace/scantrace.db`).
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

## 7. Run as a systemd service (manual alternative)

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
User=scantrace
Group=scantrace
WorkingDirectory=/opt/scantrace
EnvironmentFile=/etc/scantrace/scantrace.env
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStart=/opt/scantrace/bin/scantrace-agent
Restart=on-failure
RestartSec=3s

ProtectSystem=full
ReadWritePaths=/var/lib/scantrace /opt/scantrace/exports
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scantrace-agent
systemctl --no-pager status scantrace-agent
```

Daily update workflow:

```bash
cd "$HOME/ScanTrace" \
&& git fetch origin && git checkout main && git pull --ff-only \
&& cd scantrace-agent \
&& go build -o /tmp/scantrace-agent ./cmd/bot/ \
&& sudo install -m0755 /tmp/scantrace-agent /opt/scantrace/bin/scantrace-agent \
&& sudo systemctl restart scantrace-agent
```

Notes:
- Environment lives at `/etc/scantrace/scantrace.env`. Lines must be `KEY=VALUE` (no `export`).
- Use an absolute `DB_PATH` under `/var/lib/scantrace` to avoid permission issues.
- Exports are written to `/opt/scantrace/exports` when writable; otherwise the current working directory.
