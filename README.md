# ScanTrace

Threat detection from home router syslog with LLM enrichment and Slack workflows.

- Install and manual run guide: see INSTALL.md
- Router logging setup: see docs/router-logging-setup.md

## Operations quickstart

Daily update and restart (service):

```bash
cd "$HOME/ScanTrace" \
&& git fetch origin && git checkout main && git pull --ff-only \
&& cd scantrace-agent \
&& go build -o /tmp/scantrace-agent ./cmd/bot/ \
&& sudo install -m0755 /tmp/scantrace-agent /opt/scantrace/bin/scantrace-agent \
&& sudo systemctl restart scantrace-agent
```

Slack commands:

- `/scantrace status` — liveness (DB, case counts, syslog port, WAN IP, LLM, alerts channel)
- `/scantrace review-all [--limit N] [--since 7d|30d] [--severity red,yellow,green] [--exclude-wan-only] [--dedupe]`
- `/scantrace export-blocklist [--limit N] [--since 7d] [--severity …] [--wan-only] [--group-cidr] [--format txt|csv|ipset]`

Notes:
- Blocklist exports are written to `/opt/scantrace/exports` when writable; otherwise the agent’s current working directory. The Slack message previews up to the first 20 lines.
- Build the binary outside tracked paths (e.g., `/opt/scantrace/bin` or `~/ScanTrace/bin`) to avoid dirtying the git worktree.
