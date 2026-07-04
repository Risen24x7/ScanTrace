# Router Logging Setup for External Scan Detection

ScanTrace detects external port scans by parsing iptables LOG target entries from your router's syslog.

Port alignment note
- Router typically forwards syslog to UDP 514
- ScanTrace agent default listens on UDP 5140 (env: SCANTRACE_SYSLOG_PORT)
- Align one side: either forward router to 5140, or run rsyslog on 514 and forward to agent 5140

Asus Router (ASUSWRT / Merlin)
1) Enable syslog forwarding (Administration → System → Syslog)
   - Enable: Yes
   - Server IP: <ScanTrace host>
   - Port: 514 or 5140 (see note above)
   - See INSTALL.md for port/env details
2) Enable iptables DROP logging
   - Create /jffs/scripts/firewall-start (Merlin only):
     #!/bin/sh
     iptables -I INPUT -j LOG --log-prefix "DROP " --log-level 4 --log-tcp-options
     iptables -I FORWARD -i eth0 -j LOG --log-prefix "DROP " --log-level 4
   - chmod +x /jffs/scripts/firewall-start
   - service restart_firewall
3) Verify log output
   - tcpdump -i any udp port 514 or 5140 -A | grep DROP
   - You should see lines with DROP ... DPT=<port>

End-to-end validation
1) Generate a couple of external connection attempts to your WAN IP (e.g., nmap from LTE)
2) Confirm ScanTrace stored netfilter_drop events:
   sqlite3 scantrace.db "SELECT event_type, src_ip, dst_port, timestamp FROM events WHERE event_type='netfilter_drop' ORDER BY timestamp DESC LIMIT 10;"
3) If empty, re-check port alignment and that firewall logging is enabled

More
- See INSTALL.md for env and capability steps
- See Docs/TROUBLESHOOTING.md for router/port-mode tips
