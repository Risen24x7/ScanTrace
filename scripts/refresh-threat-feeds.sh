#!/usr/bin/env bash
# ScanTrace — nightly threat feed refresh
# Install: sudo cp scripts/refresh-threat-feeds.sh /etc/cron.daily/scantrace-feeds
#          sudo chmod +x /etc/cron.daily/scantrace-feeds

set -euo pipefail

DIR=/opt/scantrace
mkdir -p "$DIR"

echo "[$(date -u +%FT%TZ)] Refreshing ScanTrace threat feeds..."

# IPSum — stamparm/ipsum aggregated blocklist (scored, one IP+score per line)
# Score = number of independent blocklists that flagged the IP (max ~30).
# ScanTrace treats score >= 5 as confirmed malicious.
curl -sf --max-time 60 \
  https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt \
  > "$DIR/ipsum.txt.tmp" && mv "$DIR/ipsum.txt.tmp" "$DIR/ipsum.txt"
echo "  ipsum.txt: $(grep -c '^[0-9]' "$DIR/ipsum.txt" || true) IPs"

# Tor Project bulk exit list — active exit nodes right now
curl -sf --max-time 60 \
  https://check.torproject.org/torbulkexitlist \
  > "$DIR/tor-exits.txt.tmp" && mv "$DIR/tor-exits.txt.tmp" "$DIR/tor-exits.txt"
echo "  tor-exits.txt: $(wc -l < "$DIR/tor-exits.txt") IPs"

echo "[$(date -u +%FT%TZ)] Threat feed refresh complete."
