# Router Logging Setup for External Scan Detection

ScanTrace detects external port scans by parsing **iptables LOG target** entries
from your router's syslog. Without this, only DHCP and Wi-Fi events are visible
and external scans will go undetected.

## Asus Router (ASUSWRT / Merlin) — Enable Firewall Logging

### Step 1: Enable syslog forwarding

In the router admin panel: **Administration → System → Syslog**
- Enable: `Yes`
- Syslog server IP: `<IP of your ScanTrace host>`
- Port: `514` (UDP)

### Step 2: Enable iptables DROP logging

SSH into the router and add persistent logging rules via a post-firewall script.

Create `/jffs/scripts/firewall-start` (Merlin only):
```bash
#!/bin/sh
# Log all inbound DROP packets — feeds ScanTrace external scan detection
iptables -I INPUT -j LOG --log-prefix "DROP " --log-level 4 --log-tcp-options
iptables -I FORWARD -i eth0 -j LOG --log-prefix "DROP " --log-level 4
```

Make it executable:
```bash
chmod +x /jffs/scripts/firewall-start
```

Restart the firewall:
```bash
service restart_firewall
```

### Step 3: Verify log output

From the ScanTrace host:
```bash
tcpdump -i any udp port 514 -A | grep DROP
```

You should see lines like:
```
Jun 28 15:01:22 kernel: DROP IN=eth0 OUT= SRC=24.20.77.75 DST=192.168.50.1 LEN=44 TTL=50 PROTO=TCP SPT=54321 DPT=22 SYN
```

If you see these, ScanTrace will ingest them as `netfilter_drop` events and the
correlator's `ExternalScanRule` will fire when 3+ distinct ports are probed
from the same external IP.

## What ScanTrace does with these events

| Syslog line | Event type | Correlator rule |
|---|---|---|
| `DROP IN=eth0 SRC=<external>` | `netfilter_drop` | `inbound_scan` |
| `REJECT IN=eth0 SRC=<external>` | `netfilter_reject` | `inbound_scan` |
| `[CONN] NEW SRC=<external>` | `conn_attempt` | `inbound_scan` |
| `DHCPACK 192.168.x.x` | `dhcp_dhcpack` | `new_device` |
| `wlceventd: fe:... Associated` | `wifi_associated` | `new_device` |

Once iptables logging is enabled and ScanTrace receives the drops, the Slack
bot will answer questions like *"what IPs have been scanning my network?"*
with real external scan data.

## Threshold defaults

- `ExternalScanRule.MinPorts = 3` — fires after 3 distinct ports probed from same external IP
- `RepeatedDropRule.MinDrops = 3` — fires after 3 drop events from same IP (even single-port)
- Both can be tuned in `correlator.DefaultRules()`
