# ScanTrace — AsusWRT iptables Logging Rules

## Why We Log Accepted Connections Too

Dropped traffic means the firewall worked. **Accepted traffic on open ports is the real threat surface** — any service
listening on an open port may have unpatched CVEs regardless of what that service is. ScanTrace needs both:

- `WAN_NEW_DROP` → external scanner/probe events
- `WAN_NEW_ACCEPT` → actual connections reaching open services (higher severity)
- `WAN_FWD` → connections forwarded to internal hosts via port-forward rules

---

## Rule Application Order

iptables evaluates rules **top-to-bottom and stops at the first match**. The order below is the exact order
you must insert rules. All inserts use `-I` (insert at top of chain) so run them **bottom-to-top** — the last
command run ends up at position 1.

### Run these commands in this exact sequence (top to bottom):

```bash
# ── STEP 1: SKIP noise — must be inserted last so they sit at the TOP of INPUT ──

# 1a. Skip loopback entirely
iptables -I INPUT -i lo -j RETURN

# 1b. Skip internal LAN bridge (ScanTrace already reads this via syslog)
iptables -I INPUT -i br0 -j RETURN

# 1c. Skip already-established/related sessions — we logged the SYN, no need to log every ACK
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j RETURN


# ── STEP 2: LOG inbound WAN new connections that will be ACCEPTED ──
# Insert BEFORE your ACCEPT rules so it fires on the way through
# Captures traffic hitting any open port (SSH, HTTPS, game servers, etc.)
iptables -I INPUT -i eth0 -m state --state NEW -j LOG \
  --log-prefix "WAN_NEW_ACCEPT " --log-level 4


# ── STEP 3: LOG inbound WAN new connections that will be DROPPED ──
# Insert BEFORE your DROP rules so it fires before the packet is silently discarded
iptables -I INPUT -i eth0 -m state --state NEW -j LOG \
  --log-prefix "WAN_NEW_DROP " --log-level 4


# ── STEP 4: LOG forwarded connections (port-forward rules hitting internal hosts) ──
iptables -I FORWARD -i eth0 -m state --state NEW -j LOG \
  --log-prefix "WAN_FWD " --log-level 4
```

> **Note:** `-I` inserts at position 1 (top). Because we run them top-to-bottom, each new insert pushes the
> previous ones down. Final chain order from top will be:
> 1. RETURN lo
> 2. RETURN br0
> 3. RETURN ESTABLISHED,RELATED
> 4. LOG WAN_NEW_ACCEPT (eth0, NEW)
> 5. LOG WAN_NEW_DROP (eth0, NEW)
> 6. (existing ACCEPT / DROP rules continue below)

---

## Verify the Order

```bash
iptables -L INPUT -n --line-numbers
iptables -L FORWARD -n --line-numbers
```

Expected top of INPUT:
```
1  RETURN  --  lo
2  RETURN  --  br0
3  RETURN  --  state ESTABLISHED,RELATED
4  LOG     --  eth0  state NEW  /* WAN_NEW_ACCEPT */
5  LOG     --  eth0  state NEW  /* WAN_NEW_DROP */
```

---

## Make Rules Persistent on AsusWRT

AsusWRT resets iptables on reboot. Use the custom script hook:

```bash
# On the router via SSH:
cat >> /jffs/scripts/firewall-start << 'EOF'

# ScanTrace logging rules — see Docs/IPTABLES_LOGGING.md
iptables -I INPUT -i lo -j RETURN
iptables -I INPUT -i br0 -j RETURN
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j RETURN
iptables -I INPUT -i eth0 -m state --state NEW -j LOG --log-prefix "WAN_NEW_ACCEPT " --log-level 4
iptables -I INPUT -i eth0 -m state --state NEW -j LOG --log-prefix "WAN_NEW_DROP " --log-level 4
iptables -I FORWARD -i eth0 -m state --state NEW -j LOG --log-prefix "WAN_FWD " --log-level 4
EOF

chmod +x /jffs/scripts/firewall-start
```

---

## ScanTrace Event Type Mapping

| Log Prefix | Parser `event_type` | Default Severity |
|---|---|---|
| `WAN_NEW_ACCEPT` | `wan_new_connection` | HIGH — service was reached |
| `WAN_NEW_DROP` | `wan_new_drop` | MEDIUM — probe blocked |
| `WAN_FWD` | `wan_forward` | HIGH — internal host exposed |

The asus_syslog parser (`internal/ingest/asus_syslog.go`) must be updated to match these prefixes
in addition to existing DHCP/WiFi event parsing.

---

## Infrastructure Note

Router syslog target is the **VM** (`192.168.50.x`), not the desktop. This was configured prior to
this document and should not be changed. The VM runs the ScanTrace ingest daemon which receives
these log lines via UDP syslog.
