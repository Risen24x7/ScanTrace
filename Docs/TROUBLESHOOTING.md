# ScanTrace — Troubleshooting

> **Last updated:** June 28, 2026

---

## `systemctl restart` — "Too few arguments"

You forgot the unit name. Always specify the service:

```bash
sudo systemctl restart rsyslog
```

---

## `tail -F` pipe appears to hang with no output

This is expected. `tail -F` waits for **new lines to be appended** to the file. The pipeline will sit idle until the router sends a new syslog message.

**Immediate test — ingest existing lines:**
```bash
sudo tail -n 50 /var/log/asus-router.log | \
CGO_ENABLED=1 go run ./cmd/bot/ ingest --adapter asus-syslog --file -
```

**Trigger a live event on the router side** (not the ScanTrace host):
- Disconnect and reconnect a Wi-Fi device
- Let any DHCP lease renew

**Note:** `logger` on the ScanTrace host writes to the local syslog, NOT to `/var/log/asus-router.log`. Only messages forwarded from the router land there.

---

## No events in DB after ingest

The Asus adapter only parses these line types:
- `kernel: DROP` / `kernel: ACCEPT` — firewall events
- `dnsmasq-dhcp: DHCPACK` / `DHCPREQUEST` / `DHCPDISCOVER` — DHCP events
- `hostapd: STA ... associated/disassociated` — Wi-Fi association events
- WAN IP change lines

Unknown line types are silently skipped. Check:

```bash
sudo tail -n 20 /var/log/asus-router.log
```

If you only see lines from daemons other than the above, those will not produce events.

**Isolation test — pipe a known-good line directly:**
```bash
printf '2026-06-25T21:39:30+00:00 Rzn-BE96U dnsmasq-dhcp[8492]: DHCPACK(br0) 192.168.50.238 70:f0:88:2d:db:1e\n' | \
CGO_ENABLED=1 go run ./cmd/bot/ ingest --adapter asus-syslog --file -

sqlite3 scantrace.db "SELECT * FROM events WHERE source_type='asus_syslog' ORDER BY timestamp DESC LIMIT 5;"
```

---

## Ghost cases with blank `src_ip` or title `[new_device]`

These come from `wifi_associated` events ingested before the MAC-fix was deployed. The adapter was not populating `src_ip` for hostapd lines.

**Clean them up:**
```bash
# Find the ghost case ID
sqlite3 scantrace.db "SELECT case_id FROM cases WHERE title='[new_device]' AND status='open';"

# Delete it
sqlite3 scantrace.db "DELETE FROM cases WHERE case_id='<full-uuid>';"

# Purge the underlying events with no src_ip
sqlite3 scantrace.db "DELETE FROM events WHERE event_type LIKE 'wifi_%' AND src_ip='';"
```

---

## Correlator keeps re-opening the same case

This means the case was closed (or deleted) but the underlying events remain. Dedup only skips re-firing if an **open** case already exists for that `srcIP + ruleType`.

To reset cleanly for a demo:
```bash
# Close all open cases
sqlite3 scantrace.db "UPDATE cases SET status='closed' WHERE status='open';"

# Then run correlate — should produce zero new cases if all events are already covered
CGO_ENABLED=1 go run ./cmd/bot/ correlate
```

---

## rsyslog not writing to `/var/log/asus-router.log`

1. Confirm UDP 514 is open on the host firewall:
   ```bash
   sudo ufw status
   sudo ufw allow 514/udp
   ```

2. Confirm rsyslog is listening:
   ```bash
   sudo ss -ulnp | grep 514
   ```

3. Confirm the rule file syntax is correct (IP-scoped, not wildcard):
   ```bash
   cat /etc/rsyslog.d/asus-router.conf
   # Should contain:
   # if $fromhost-ip == "192.168.50.1" then /var/log/asus-router.log
   # & stop
   ```

4. Restart rsyslog after any config change:
   ```bash
   sudo systemctl restart rsyslog
   ```

5. Check rsyslog errors:
   ```bash
   sudo journalctl -u rsyslog -n 30
   ```

---

## Slack alerts not posting

- Confirm `SLACK_WEBHOOK_URL` is set and not expired
- Rotate the webhook in Slack if it was accidentally exposed: **Apps → Incoming Webhooks → Regenerate**
- For socket mode (Bolt app), confirm both `SLACK_BOT_TOKEN` and `SLACK_APP_TOKEN` are set
- Check the serve output for `[alerts] posted case` vs. any HTTP error lines
