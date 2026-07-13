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
bash ./scripts/install-service.sh
sudoedit /etc/scantrace/scantrace.env   # fill tokens/channel IDs, verify DB_PATH
sudo systemctl restart scantrace-agent
```

Optional: set up local LLM (llama.cpp + TinyLlama):
```bash
bash ./scripts/setup-llama.sh
sudo sed -i 's|^LLM_BASE_URL=.*|LLM_BASE_URL=http://127.0.0.1:11434|' /etc/scantrace/scantrace.env
sudo sed -i 's|^#\?LLM_MODEL=.*|LLM_MODEL=tinyllama.gguf|' /etc/scantrace/scantrace.env
sudo systemctl restart scantrace-agent
```

Verify:
```bash
systemctl --no-pager status scantrace-agent
journalctl -u scantrace-agent -n 50 --no-pager
curl -sS http://127.0.0.1:11434/v1/models | head -c 200 || true
```

---

## Install latest tag (non-interactive)

```bash
git clone https://github.com/Risen24x7/ScanTrace.git && cd ScanTrace
git fetch --tags --quiet
LATEST_TAG=$(git tag --sort=-creatordate | head -n1)
echo "Using tag: $LATEST_TAG"
git checkout --quiet "$LATEST_TAG"
make install-service-noninteractive LLM_BASE_URL=http://127.0.0.1:11434 LLM_MODEL=
# Then configure tokens and start
sudoedit /etc/scantrace/scantrace.env
sudo systemctl enable --now scantrace-agent
```

---

## Manual build/run

```bash
git clone https://github.com/Risen24x7/ScanTrace.git
cd ScanTrace/scantrace-agent
go build -o scantrace-agent ./cmd/bot/
```

Create `.env` in `ScanTrace/scantrace-agent/` (see `.env.example`). Then:
```bash
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

Notes:
- Use an absolute `DB_PATH` under `/var/lib/scantrace`.
- LLM_BASE_URL defaults to `http://127.0.0.1:11434`. Leave `LLM_MODEL` blank to disable LLM.

### Demo flags

- `--ingest-metrics` — post periodic "Ingestion Status" summaries to Slack (demo only; hardcoded channel `C0BHW7NSR7S`, ignores `ALERT_CHANNEL`).
- `--ingest-metrics-interval=<duration>` — posting interval (Go duration, default `30s`). Example:

```bash
SLACK_BOT_TOKEN=... SLACK_APP_TOKEN=... ./bin/scantrace-agent \
  --ingest-metrics --ingest-metrics-interval=30s
```
