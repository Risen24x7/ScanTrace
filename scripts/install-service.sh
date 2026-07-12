#!/usr/bin/env bash
set -euo pipefail

# Resolve repo root (this script lives in repo/scripts/)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_ROOT}/scantrace-agent"

BIN_INSTALL="/opt/scantrace/bin/scantrace-agent"
ENV_DIR="/etc/scantrace"
ENV_FILE="${ENV_DIR}/scantrace.env"
UNIT_FILE="/etc/systemd/system/scantrace-agent.service"
RUN_USER="scantrace"
RUN_GROUP="scantrace"
STATE_DIR="/var/lib/scantrace"
EXPORTS_DIR="/opt/scantrace/exports"
WORK_DIR="/opt/scantrace"

# Build out of tree
BUILD_BIN="/tmp/scantrace-agent.$$"
GOFLAGS= CGO_ENABLED=1 go build -o "${BUILD_BIN}" "${SRC_DIR}/cmd/bot/"

# Create dedicated system user/group if missing
if ! id -u "${RUN_USER}" >/dev/null 2>&1; then
  sudo useradd \
    --system \
    --home-dir "${STATE_DIR}" \
    --create-home \
    --shell /usr/sbin/nologin \
    --comment "ScanTrace Service" \
    "${RUN_USER}"
fi

# Create directories with correct ownership
sudo install -d -m0755 -o "${RUN_USER}" -g "${RUN_GROUP}" \
  "${STATE_DIR}" "${EXPORTS_DIR}" /opt/scantrace/bin

# Install binary
sudo install -m0755 "${BUILD_BIN}" "${BIN_INSTALL}"
rm -f "${BUILD_BIN}"

# Environment file (create if absent)
sudo install -d -m0755 "${ENV_DIR}"
if [[ ! -f "${ENV_FILE}" ]]; then
  sudo cp "${SRC_DIR}/.env.example" "${ENV_FILE}"
  sudo chown root:root "${ENV_FILE}"
  sudo chmod 600 "${ENV_FILE}"
  echo "Created ${ENV_FILE}. Edit tokens/channel IDs before starting." >&2
fi

# Write systemd unit
sudo tee "${UNIT_FILE}" >/dev/null <<EOF
[Unit]
Description=ScanTrace Agent
After=network-online.target
Wants=network-online.target

[Service]
User=${RUN_USER}
Group=${RUN_GROUP}
WorkingDirectory=${WORK_DIR}
EnvironmentFile=${ENV_FILE}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStart=${BIN_INSTALL}
Restart=on-failure
RestartSec=3s

ProtectSystem=full
ReadWritePaths=${STATE_DIR} ${EXPORTS_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now scantrace-agent
systemctl --no-pager status scantrace-agent || true
