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
  │   ├─ classifyDst()           ← WAN EDGE override (all 3 branches enforced)
  │   │   ├─ wan_new_connection  → always WAN EDGE label
  │   │   ├─ wan_forward         → WAN EDGE if dst == wanIP
  │   │   └─ default             → WAN EDGE if dst == wanIP
  │   ├─ ipSet exclusion         ← wanIP never enriched by ipinfo
  │   ├─ registry lookup         ← known device hostnames
  │   ├─ port intel accumulation ← HitRecord written per event; advisory injected into prompt
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
- **WAN edge traffic**: `classifyDst()` returns `WAN EDGE — gateway interface only` for all three branches where the destination is the operator's WAN IP. The WAN IP is also excluded from `ipSet` so `ipinfo.Enrich()` never produces an ISP/org attribution line for it.
- **Registry lookup**: known internal IPs/hostnames are resolved to friendly names from a local registry.
- **Event type switch**: `wan_new_connection`, `wan_fwd`, `drop`, and `accept` each get a deterministic action list.

### 2. Fill-in-the-Blank Prompt Skeleton

The Recommended Actions section is pre-populated via `fmt.Sprintf` before the prompt reaches the model:

```go
actions := selectActionPlan(triageState) // pure Go switch-case (A–F conditions)
prompt := fmt.Sprintf(templateWithActions, ..., actions, ...)
```

The LLM receives a prompt where that section is already written. It cannot replace, reorder, or hallucinate alternative steps.

### 3. Port Intelligence Store

The `portintel` package maintains a SQLite-backed `Store` that records `HitRecord{SrcIP, DstPort, Proto, Count, FirstSeen, LastSeen}` for every event processed. This enables:
- **`/scantrace port-trends`**: queries the store and returns a ranked Block Kit table of the most repeatedly hit ports across all cases.
- **LLM advisory context**: when a port has been hit more than once historically, a `[PORT INTEL ADVISORY]` block is injected into the prompt so the model can reason about persistence and repeat targeting without needing DB access itself.

### 4. Dual Slack Channels

- `ALERT_CHANNEL` (`#sec-alerts`): raw case alerts, thread replies for repeated hits.
- `EXTERNAL_THREAT_CHANNEL` (`#sec-intel-external`): LLM responses to @mention queries. Keeps signal/noise ratio high in `#sec-alerts`.

### 5. @Mention Case Routing (Deterministic Fast Path)

`handleMention` strips the `<@BOTID>` token and checks for case-specific commands **before** any LLM call:

```
@ScanTrace case <id>         → full LLM briefing for that case
@ScanTrace report <id>       → same as above
@ScanTrace review case <id>  → same as above
@ScanTrace cases             → Block Kit case list (no LLM)
@ScanTrace help              → ephemeral help text (no LLM)
<anything else>              → generic LLM Q&A via llm.Ask()
```

Case ID matching is prefix-based and case-insensitive — `abc123` matches `abc12345-…`. If no match is found, the bot replies with `Case 'abc123' not found. Try /scantrace cases.` No LLM is called for the not-found path.

---

## Component Map

| Package | Path | Responsibility |
|---|---|---|
| `collector` | `internal/collector` | UDP syslog listener |
| `normalizer` | `internal/normalizer` | Raw log → `Event{}` |
| `enricher` | `internal/enricher` | ASN, rDNS, WAN IP label |
| `correlator` | `internal/correlator` | Event grouping → `Case{}` |
| `db` | `internal/db` | SQLite read/write |
| `portintel` | `scantrace-agent/internal/portintel` | Port hit tracking, `HitRecord` store, trend queries |
| `handler` | `scantrace-agent/internal/handler` | Slack dispatch, triage, prompt building, port intel wiring |
| `llm` | `scantrace-agent/internal/llm` | HTTP client for `ik_llama.cpp` |
| `rts` | `scantrace-agent/internal/rts` | Slack RTS subscription (cosmetic on sandbox) |
| `mcp` | `scantrace-agent/internal/mcp` | MCP HTTP server for tool integrations |
| `bot/main.go` | `scantrace-agent/cmd/bot/main.go` | Entry point, env wiring |

---

## LLM Configuration

The agent defaults to `http://192.168.50.250:11434` (desktop `ik_llama.cpp`) when `LLM_BASE_URL` is not set. Model is selected by `LLM_MODEL` env var.

The LLM is only called for:
1. `@mention` Q&A queries (generic chat path — fallthrough after fast-path checks)
2. `@ScanTrace case <id>` / `review-all` / `next` — single-case or batch briefings
3. The Assessment and Summary blocks of a case alert (2–4 sentences each)

It is **never** called to decide actions, classify IPs, route events, or handle `cases` / `help` / `not-found` replies. It also cannot see raw ISP/org attribution for the operator's WAN IP — that data is excluded from `ipSet` before enrichment runs.
