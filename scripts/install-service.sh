#!/usr/bin/env bash
set -euo pipefail

ROOT="${HOME}/ScanTrace"
SRC_DIR="${ROOT}/scantrace-agent"
BUILD_BIN="${ROOT}/bin/scantrace-agent"
INSTALL_BIN="/opt/scantrace/bin/scantrace-agent"
UNIT_FILE="/etc/systemd/system/scantrace-agent.service"

# Pick env file: prefer ROOT/.env, fallback to SRC_DIR/.env
ENV_FILE=""
if [[ -f "${ROOT}/.env" ]]; then
  ENV_FILE="${ROOT}/.env"
elif [[ -f "${SRC_DIR}/.env" ]]; then
  ENV_FILE="${SRC_DIR}/.env"
else
  echo "ERROR: No .env found at ${ROOT}/.env or ${SRC_DIR}/.env" >&2
  exit 1
fi

mkdir -p "${ROOT}/bin"
cd "${SRC_DIR}"
GOFLAGS= CGO_ENABLED=1 go build -o "${BUILD_BIN}" ./cmd/bot/

sudo install -d -o "${USER}" -g "${USER}" /opt/scantrace/bin /opt/scantrace/exports /var/lib/scantrace
sudo install -m0755 "${BUILD_BIN}" "${INSTALL_BIN}"

# Write unit
sudo tee "${UNIT_FILE}" >/dev/null <<EOF
[Unit]
Description=ScanTrace Agent
After=network-online.target
Wants=network-online.target

[Service]
User=${USER}
WorkingDirectory=${ROOT}/scantrace-agent
EnvironmentFile=${ENV_FILE}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStart=${INSTALL_BIN}
Restart=on-failure
RestartSec=3s

ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/lib/scantrace /opt/scantrace
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now scantrace-agent
systemctl --no-pager status scantrace-agent
