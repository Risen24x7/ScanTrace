# ScanTrace — Troubleshooting

## Agent Won't Start

### `LLM not configured`

**Cause:** `LLM_BASE_URL` not in environment.  
**Fix:** The agent now defaults to `http://127.0.0.1:11434` — just restart and it will connect. If your `ik_llama.cpp` is on a different host, add `LLM_BASE_URL=http://<host>:11434` to `.env`.

### `grep: scantrace-agent/.env: Not a directory`

**Cause:** Running the `export $(grep ...)` command from the parent `ScanTrace/` directory.  
**Fix:**
```bash
cd ~/ScanTrace/scantrace-agent
export $(grep -v '^#' .env | xargs) && ./scantrace-agent
```

### `required env var "SLACK_BOT_TOKEN" is not set`

**Cause:** `.env` file missing or not loaded.  
**Fix:** Create `.env` from `.env.example` and `export` it before running.

---

## No Alerts Appearing in Slack

### Wrong channel ID

`ALERT_CHANNEL` must be the channel **ID** (format `C0XXXXXXXXX`), not the channel name.  
Get it from Slack: right-click the channel → **Copy link** → the ID is the last path component.

### Events not reaching the agent

Verify UDP packets are arriving:
```bash
sudo tcpdump -i any -n udp port 5140
```

Verify events are stored:
```bash
sqlite3 scantrace.db "SELECT count(*) FROM events;"
```

---

## WAN Traffic Shows as Internal Threat

**Cause:** Running an older binary that lacked Go-layer WAN IP pre-classification.  
**Fix:** Rebuild from current `main`:
```bash
cd ~/ScanTrace/scantrace-agent
go build -o scantrace-agent ./cmd/bot/
sudo setcap cap_net_bind_service=+ep ./scantrace-agent
```

After the fix, triage output will read:
```
Dst host in registry? [WAN EDGE — gateway interface only]
```
And the Assessment block will correctly state no internal devices are at risk.

---

## LLM Responses

### Assessment or Summary blocks are missing

**Cause:** `ik_llama.cpp` not running or unreachable.  
**Fix:** Start the model server on localhost and confirm:
```bash
curl http://127.0.0.1:11434/v1/models
```

### `llm: status 404: {"error":{"message":"File Not Found"...}}`

**Cause:** `LLM_BASE_URL` includes a trailing `/v1` (leading to `/v1/v1/...`) or points at a non-OpenAI route.  
**Fix:** Set `LLM_BASE_URL` to `http://127.0.0.1:11434` (no `/v1`). The client automatically calls `/v1/chat/completions` and tolerates an accidental `/v1` suffix.

### LLM generates wrong action list

This should no longer happen. The Recommended Actions section is now a `fmt.Sprintf` skeleton populated entirely in Go — the LLM only fills the Assessment and Summary blocks. If you see hallucinated actions, you are running an old binary.

---

## RTS Subscription Error on Startup

```
[rts] subscribe skipped: [rts] signal.subscriptions.add error: unknown_method
```

This is **cosmetic**. The Dilldozer Slack sandbox does not support the RTS subscription method. The agent continues normally — all Socket Mode events are still received and processed.

---

## Capability Lost After Rebuild

`setcap` is attached to the file inode. Every `go build` produces a new inode.  
Always re-run after rebuilding:
```bash
sudo setcap cap_net_bind_service=+ep ./scantrace-agent
```
