#!/usr/bin/env bash
# Atomic ipset update from a blocklist file containing IPv4/IPv6 (IPs or CIDRs)
set -euo pipefail

LIST_FILE=${1:-}
SET_NAME="scantrace_blocklist"

if [[ -z "$LIST_FILE" || ! -f "$LIST_FILE" ]]; then
  echo "Usage: $0 /path/to/blocklist.txt" >&2; exit 1
fi

# Build a restore script for IPv4 (extend as needed for IPv6)
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

{
  echo "create ${SET_NAME}_new hash:net family inet -exist"
  awk 'NF && $1 !~ /^#/ && $1 !~ /:/ {print "add ${SET_NAME}_new "$1}' "$LIST_FILE"
  echo "swap ${SET_NAME}_new ${SET_NAME}"
  echo "destroy ${SET_NAME}_new"
} > "$TMP"

sudo ipset restore -! < "$TMP"
echo "Applied ipset from $LIST_FILE"