# ScanTrace Test Data

Sample log files for local development and demo runs.

## Files

| File | Adapter | Contents |
|------|---------|----------|
| `sample_suricata.json` | `suricata` | 10 Suricata EVE JSON alerts — port scan from 198.51.100.10, SSH brute force from 203.0.113.55, SQLi attempt from 192.0.2.77 |
| `sample_syslog.log` | `syslog` | 7 UFW BLOCK syslog lines — same IPs, exercises the syslog adapter |

## Usage

```bash
# From repo root — ingest suricata sample
CGO_ENABLED=1 go run ./cmd/bot/ ingest --file testdata/sample_suricata.json --adapter suricata

# Ingest syslog sample
CGO_ENABLED=1 go run ./cmd/bot/ ingest --file testdata/sample_syslog.log --adapter syslog

# Run correlator to generate cases
CGO_ENABLED=1 go run ./cmd/bot/ correlate

# List generated cases
CGO_ENABLED=1 go run ./cmd/bot/ cases
```

## Expected Output After Ingest + Correlate

At least 2 cases should be generated:
- **High severity** — SSH brute force cluster from 203.0.113.55 (3+ events, same dest port)
- **Medium severity** — Horizontal port scan from 198.51.100.10 (6 events, multiple dest ports)
