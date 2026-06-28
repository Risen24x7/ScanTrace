# ScanTrace — AsusWRT iptables Logging Rules

## Status: APPLIED 2026-06-28

Rules have been applied and verified on `Rzn-BE96U`. Persistence confirmed via
`ubi:jffs2` partition at `/jffs` (not tmpfs). Script survives reboots.

---

## Why We Log Accepted Connections Too

Dropped traffic means the firewall worked. **Accepted traffic on open ports is the real threat surface** — any service
listening on an open port may have unpatched CVEs regardless of what that service is. ScanTrace needs both:

- `WAN_NEW_ACCEPT` → actual connections reaching open services (higher severity — something answered)
- `WAN_FWD` → connections forwarded to internal hosts via port-forward rules

---

## What Was Changed

### Removed
- **Original line 1 of INPUT:** `LOG all -- * * 0.0.0.0/0 0.0.0.0/0 LOG flags 2 level 4 prefix "DROP "`
  - This was logging ALL traffic on ALL interfaces including br0, lo, and every ACK of every
    established session (24M bytes of noise). This was the cause of router UI slowness.

### Added
- **INPUT line 4:** `LOG all -- eth0 * state NEW prefix "WAN_NEW_ACCEPT "` — scoped to WAN only
- **FORWARD line 1:** `LOG all -- eth0 * state NEW prefix "WAN_FWD "` — port-forward visibility

---

## Verified Final INPUT Chain (top 6 rules)

```
num   pkts  target      prot  in     out    source       destination
1           URLFI       udp   *      *      0.0.0.0/0    0.0.0.0/0    udp dpt:53
2           INPUT_PING  icmp  *      *      0.0.0.0/0    0.0.0.0/0    icmptype 8
3           ACCEPT      all   *      *      0.0.0.0/0    0.0.0.0/0    state RELATED,ESTABLISHED
4           LOG         all   eth0   *      0.0.0.0/0    0.0.0.0/0    state NEW prefix "WAN_NEW_ACCEPT "
5           DROP        all   *      *      0.0.0.0/0    0.0.0.0/0    state INVALID
6           PTCSRVWAN   all   !br0   *      0.0.0.0/0    0.0.0.0/0
```

## Verified Final FORWARD Chain (top 2 rules)

```
num   pkts  target  prot  in     out   source      destination
1           LOG     all   eth0   *     0.0.0.0/0   0.0.0.0/0   state NEW prefix "WAN_FWD "
2           NWFF    all   *      *     0.0.0.0/0   0.0.0.0/0
```

---

## Persistence — /jffs/scripts/firewall-start

### AsusWRT JFFS2 Notes for this device
- `jffs2_enable=1` — confirmed
- `jffs2_on=1` — confirmed
- `log_path=/jffs` — confirmed
- `jffs2_scripts` key does **not exist** on this firmware — not needed, `jffs2_on=1` is sufficient
- Partition: `ubi:jffs2` mounted at `/jffs` (persistent, not tmpfs), 37MB free

### /jffs/scripts/firewall-start contents

```sh
#!/bin/sh

# ScanTrace WAN logging rules — added 2026-06-28
# Removes broad catch-all LOG, scopes to eth0 NEW only
# See Docs/IPTABLES_LOGGING.md in ScanTrace repo
iptables -D INPUT 1 2>/dev/null || true
iptables -I INPUT 4 -i eth0 -m state --state NEW -j LOG --log-prefix "WAN_NEW_ACCEPT " --log-level 4
iptables -I FORWARD 1 -i eth0 -m state --state NEW -j LOG --log-prefix "WAN_FWD " --log-level 4
```

> **Note on `iptables -D INPUT 1`:** On this firmware, the broad catch-all LOG rule
> is re-inserted at position 1 on every reboot by AsusWRT. This line removes it before
> our scoped rules are applied. The `2>/dev/null || true` prevents errors if it's
> already been removed.

---

## Open Issues

### FUPNP chain is unreferenced
The `FUPNP` chain contains Sunshine/Moonlight streaming port forwards to `192.168.50.202`
but has 0 references — nothing calls it. These port forwards are currently inactive from WAN.
Needs investigation: either wire it in with `iptables -I INPUT -j FUPNP` or confirm
UPnP handles this dynamically at runtime.

### SECURITY chain is unreferenced
The `SECURITY` chain (SYN/RST flood rate limiting) also has 0 references. It is defined
but never called. Should be wired into INPUT for WAN protection.

---

## ScanTrace Event Type Mapping

| Log Prefix | Parser `event_type` | Default Severity |
|---|---|---|
| `WAN_NEW_ACCEPT` | `wan_new_connection` | HIGH — service was reached |
| `WAN_FWD` | `wan_forward` | HIGH — internal host exposed |

The asus_syslog parser (`internal/ingest/asus_syslog.go`) must be updated to match these
prefixes in addition to existing DHCP/WiFi event parsing.

---

## Infrastructure Note

Router syslog target is the **VM** (`192.168.50.x`), not the desktop. This was configured
prior to this document and must not be changed. The VM runs the ScanTrace ingest daemon
which receives log lines via UDP syslog.
