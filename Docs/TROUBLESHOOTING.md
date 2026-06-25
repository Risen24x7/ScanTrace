# Troubleshooting

Common issues and quick checks for ScanTrace – Dead Reckoning Edition.

## No logs appearing in `/var/log/asus-router.log`

- Confirm the router is configured to send syslog to the **correct IP and port (514)**.
- On the ScanTrace host:
  - Ensure rsyslog is listening on UDP 514:
    - Check `/etc/rsyslog.conf` for:
      - `$ModLoad imudp`
      - `$UDPServerRun 514`[web:190]
    - Restart rsyslog:
      - `sudo systemctl restart rsyslog`
  - Verify the Asus-specific rule exists (example IP `192.168.50.1`):
    - `/etc/rsyslog.d/asus-router.conf` should contain something like:
      ```conf
      if $fromhost-ip == "192.168.50.1" then /var/log/asus-router.log
      & stop
      ```
  - Check for general Asus messages in the main syslog:
    - `sudo grep -i "asus" /var/log/syslog | tail -n 20`

If messages show up in `/var/log/syslog` but not in `/var/log/asus-router.log`, the filter condition in `asus-router.conf` likely needs adjustment.

## `ingest` runs but no cases are created

- Verify you are using the correct adapter:
  - Suricata testdata: `--adapter suricata`.
  - Asus router syslog: `--adapter asus-syslog` (or the current documented name in `Docs/scantrace_build_order.md`).[cite:254]
- After ingesting events, ensure you run:
  - `go run ./cmd/bot/ correlate`
  - `go run ./cmd/bot/ cases`
- If cases are still empty:
  - Inspect the events table directly with `sqlite3` on the database file (e.g., `scantrace.db`) to confirm events are being stored.

## LLM features not working or unavailable

LLM-based helpers (unknown format classification, DB audit, etc.) are **optional** and may be disabled for the hackathon baseline.

- Check documentation:
  - `Docs/HACKATHON_GOALS.md` for which LLM features are in-scope vs stretch goals.[cite:255]
  - `CHANGELOG.md` for any notes on LLM integration state.[cite:256]
- Ensure any required environment variables or config files (for local LLM endpoints) are set if you enable these features.

## CLI command not found or failing

- Make sure you are running commands from the repository root and using the correct path:
  - `go run ./cmd/bot/ ...`
- Ensure Go is installed and on your `PATH`.
- For CGO-enabled builds (e.g., to support SQLite features), set `CGO_ENABLED=1` as shown in `Docs/GETTING_STARTED.md`.[cite:257]

## Still stuck?

- Review `Docs/GETTING_STARTED.md` to double-check the demo steps.[cite:257]
- Check `Docs/scantrace_build_order.md` for details on the current build order and implementation phases.[cite:254]
- File an issue on GitHub with:
  - Your OS and Go version.
  - Exact commands run.
  - Relevant log output or error messages.
