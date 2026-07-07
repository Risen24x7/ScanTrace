# Enforcement Options: Home and Enterprise

ScanTrace detects; your firewall enforces. Two tracks:

- Pull/Import (no forced firewall): Firewalls pull an exported list
- Inline: A Linux bridge enforces with nftables

## Pull / Import

### pfSense / OPNsense (URL Table alias)

1. Serve exports over HTTP from the ScanTrace host:
   ```bash
   sudo python3 -m http.server 8080 --directory /opt/scantrace/exports
   # or nginx/Apache pointing to /opt/scantrace/exports
   ```
2. In pfSense/OPNsense, create an Alias (URL Table) pointing to e.g.:
   `http://scantrace-host:8080/blocklist-latest.txt`
3. Create a rule using the alias (block on WAN or appropriate interface).

### Linux gateway (nftables)

One-time:
```bash
sudo nft add table inet scantrace
sudo nft add set inet scantrace blocklist_v4 { type ipv4_addr; flags interval; }
sudo nft add set inet scantrace blocklist_v6 { type ipv6_addr; flags interval; }
# Hook chain (gateway/bridge)
sudo nft add chain inet scantrace filter { type filter hook forward priority 0; }
sudo nft add rule inet scantrace filter ip daddr @blocklist_v4 drop
sudo nft add rule inet scantrace filter ip6 daddr @blocklist_v6 drop
```

Apply exports atomically:
```bash
./scripts/apply-nft.sh /opt/scantrace/exports/blocklist.txt
```

### Linux gateway (ipset + iptables)

One-time:
```bash
sudo ipset create scantrace_blocklist hash:net family inet -exist
sudo iptables -I FORWARD -m set --match-set scantrace_blocklist dst -j DROP
```

Apply exports atomically:
```bash
./scripts/apply-ipset.sh /opt/scantrace/exports/blocklist.txt
```

## Inline (transparent bridge)

Place a Linux box between modem↔firewall (or firewall↔LAN):

```bash
# Example: enp1s0 (WAN side), enp2s0 (firewall side)
sudo ip link add name br0 type bridge
sudo ip link set enp1s0 master br0
sudo ip link set enp2s0 master br0
sudo ip link set br0 up
# Optional: assign mgmt IP on br0: sudo ip addr add 192.168.50.10/24 dev br0
```

Then use the nftables rules above on the bridge host.

## Export tips

- Home: keep it small and summarized:
  ```
  /scantrace export-blocklist --since 7d --severity red,yellow --wan-only --group-cidr --format txt --limit 64
  ```
- Enterprise: larger sets or full list; consider hourly rotation. Serve via HTTP to firewalls.
- Exports default to `/opt/scantrace/exports` when writable; otherwise the agent’s working directory.
