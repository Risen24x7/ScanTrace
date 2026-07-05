# ScanTrace — Build Order & AI Agent Query Guide
### *"There are two kinds of people in this world... and I don't trust either of them."* — Dead Reckoning

> **Dev Sandbox:** Dilldozer  
> **Deadline:** July 13, 2026 @ 5:00 PM PDT  
> **Days Remaining:** 8  
> **Primary Track:** New Slack Agent  
> **Last updated:** July 5, 2026

---

## Build Philosophy

This is a **23-day hackathon sprint**, not a product roadmap. Every build decision optimizes for three outcomes in this order:

1. **Demo-ability** — the judge sees a live event flowing end-to-end in under 90 seconds
2. **Explainability** — the architecture can be drawn on a whiteboard in 60 seconds
3. **Technical credibility** — the code is real, not mocked, and the agent touches all three required platform technologies

---

## Phase Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Done — gate passed |
| 🔄 | In progress |
| ☐ | Not started |

---

## Master Build Order

```
LAYER 1 → Data Foundation (schema + SQLite + CLI harness)            ✅ COMPLETE
LAYER 2 → Collector (Suricata EVE JSON + Asus syslog adapters)       ✅ COMPLETE
LAYER 3 → Normalizer + Enricher (schema mapping + IP intel)          🔄 PARTIAL
LAYER 4 → Correlator + Case Builder (pattern detection + markdown)   ✅ COMPLETE
LAYER 5 → Slack Agent Core (Bolt app + Block Kit case posting)       ✅ COMPLETE
LAYER 6 → Platform Technologies (MCP + RTS + NL Q&A)                🔄 PARTIAL
LAYER 7 → Polish + Submission                                        🔄 IN PROGRESS
```

---

## Notes

- "Previously observed" context is implemented via in-session prior-thread linking (no heavy search). If a new case shares a src_ip with a prior case seen during the current run, the alert prepends a context block with a permalink to the earlier thread.
- MCP server and NL Q&A are wired for demo: deterministic action planning remains in Go; LLM provides prose only.
