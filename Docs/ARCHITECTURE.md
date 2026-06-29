# ScanTrace — Architecture

## Design Philosophy

ScanTrace uses **deterministic orchestration**: all logic that can be computed in code is computed in Go. The LLM is used exclusively for natural-language synthesis of the Assessment and Summary blocks — it never decides what actions to take or how to classify traffic.

> *Compute deterministically in code wherever possible; use the LLM only for semantic synthesis.*

This eliminates prompt-grammar arguments with open-weight local models and produces consistent, structured output regardless of model temperature or sampling variation.

---

## Pipeline

```
ASUS Router (UDP :5140)
        │
        ▼
  Syslog Listener
  (internal/collector)
        │  raw log line
        ▼
  Normalizer
  (internal/normalizer)
        │  common Event{}
        ▼
  Enricher
  (internal/enricher)           ← ASN, reverse DNS, WAN_IP pre-classification
        │  enriched Event{}
        ▼
  Correlator
  (internal/correlator)         ← groups events into Cases every 5 min
        │  Case{}
        ▼
  Handler (scantrace-agent)
  ├─ Go triage layer             ← switch-case topology mapping
  │   ├─ WAN EDGE detection      ← src == WAN IP → gateway-only label
  │   ├─ registry lookup         ← known device hostnames
  │   └─ Recommended Actions     ← fmt.Sprintf skeleton, deterministic
  │
  ├─ LLM client (llm.New)
  │   └─ fills Assessment + Summary blocks only
  │
  └─ Slack
      ├─ #sec-alerts             ← Block Kit case alerts + thread updates
      └─ EXTERNAL_THREAT_CHANNEL ← LLM Q&A responses (@mention)
```

---

## Key Design Decisions

### 1. Go-Layer Topology Classification

Before the prompt is built, the handler resolves:
- **WAN edge traffic**: if `dst_ip == WAN_IP`, the destination is labelled `WAN EDGE — gateway interface only`. No internal device is at risk. The Assessment block reflects this correctly without being told.
- **Registry lookup**: known internal IPs/hostnames are resolved to friendly names from a local registry.
- **Event type switch**: `wan_new_connection`, `wan_fwd`, `drop`, and `accept` each get a deterministic action list.

### 2. Fill-in-the-Blank Prompt Skeleton

The Recommended Actions section is pre-populated via `fmt.Sprintf` before the prompt reaches the model:

```go
actions := buildActions(eventType, proto, dstPort) // pure Go switch-case
prompt := fmt.Sprintf(templateWithActions, ..., actions, ...)
```

The LLM receives a prompt where that section is already written. It cannot replace, reorder, or hallucinate alternative steps.

### 3. Dual Slack Channels

- `ALERT_CHANNEL` (`#sec-alerts`): raw case alerts, thread replies for repeated hits.
- `EXTERNAL_THREAT_CHANNEL` (`#sec-intel-external`): LLM responses to @mention queries. Keeps signal/noise ratio high in `#sec-alerts`.

---

## Component Map

| Package | Path | Responsibility |
|---|---|---|
| `collector` | `internal/collector` | UDP syslog listener |
| `normalizer` | `internal/normalizer` | Raw log → `Event{}` |
| `enricher` | `internal/enricher` | ASN, rDNS, WAN IP label |
| `correlator` | `internal/correlator` | Event grouping → `Case{}` |
| `db` | `internal/db` | SQLite read/write |
| `handler` | `scantrace-agent/internal/handler` | Slack dispatch, triage, prompt building |
| `llm` | `scantrace-agent/internal/llm` | HTTP client for `ik_llama.cpp` |
| `rts` | `scantrace-agent/internal/rts` | Slack RTS subscription (cosmetic on sandbox) |
| `mcp` | `scantrace-agent/internal/mcp` | MCP HTTP server for tool integrations |
| `bot/main.go` | `scantrace-agent/cmd/bot/main.go` | Entry point, env wiring |

---

## LLM Configuration

The agent defaults to `http://192.168.50.250:11434` (desktop `ik_llama.cpp`) when `LLM_BASE_URL` is not set. Model is selected by `LLM_MODEL` env var.

The LLM is only called for:
1. `@mention` Q&A queries from users in Slack
2. The Assessment and Summary blocks of a case alert (2–4 sentences each)

It is **never** called to decide actions, classify IPs, or route events.
