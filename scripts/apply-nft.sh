#!/usr/bin/env bash
# Atomic nftables set update from a blocklist file containing IPv4/IPv6 (IPs or CIDRs)
set -euo pipefail

LIST_FILE=${1:-}
SET_V4="inet scantrace blocklist_v4"
SET_V6="inet scantrace blocklist_v6"

if [[ -z "$LIST_FILE" || ! -f "$LIST_FILE" ]]; then
  echo "Usage: $0 /path/to/blocklist.txt" >&2; exit 1
fi

TMP4=$(mktemp)
TMP6=$(mktemp)
trap 'rm -f "$TMP4" "$TMP6"' EXIT

# Split v4/v6; ignore comments/blank
awk 'NF && $1 !~ /^#/ {print}' "$LIST_FILE" | while read -r net; do
  if [[ "$net" == *:* ]]; then echo "$net" >> "$TMP6"; else echo "$net" >> "$TMP4"; fi
done

if [[ -s "$TMP4" ]]; then
  {
    echo "flush set $SET_V4"
    printf 'add element %s { ' "$SET_V4"
    paste -sd, "$TMP4" | sed 's/$/ }/'
  } | sudo nft -f -
fi

if [[ -s "$TMP6" ]]; then
  {
    echo "flush set $SET_V6"
    printf 'add element %s { ' "$SET_V6"
    paste -sd, "$TMP6" | sed 's/$/ }/'
  } | sudo nft -f -
fi

echo "Applied nftables blocklists from $LIST_FILE"