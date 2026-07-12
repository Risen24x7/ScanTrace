#!/usr/bin/env bash
set -euo pipefail

# Non-interactive overrides
NONINT=${SCANTRACE_NONINTERACTIVE:-0}
OVERRIDE_LLM_BASE=${LLM_BASE_URL:-}
OVERRIDE_LLM_MODEL=${LLM_MODEL:-}

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

# Build out of tree from module dir (avoids module path issues)
BUILD_BIN="/tmp/scantrace-agent.$$"
pushd "${SRC_DIR}" >/dev/null
GOFLAGS= CGO_ENABLED=1 go build -o "${BUILD_BIN}" ./cmd/bot/
popd >/dev/null

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
sudo install -d -m0755 -o "${RUN_USER}" -g "${RUN_GROUP}" "${WORK_DIR}"

# Install binary
sudo install -m0755 "${BUILD_BIN}" "${BIN_INSTALL}"
rm -f "${BUILD_BIN}"

# Environment file (create if absent)
sudo install -d -m0755 "${ENV_DIR}"
if [[ ! -f "${ENV_FILE}" ]]; then
  sudo cp "${SRC_DIR}/.env.example" "${ENV_FILE}"
  sudo chown root:root "${ENV_FILE}"
  sudo chmod 600 "${ENV_FILE}"
  echo "Created ${ENV_FILE}." >&2
fi

apply_env() {
  local key="$1"; shift
  local val="$1"; shift || true
  if grep -q "^${key}=" "${ENV_FILE}"; then
    sudo sed -i "s|^${key}=.*|${key}=${val}|" "${ENV_FILE}"
  elif grep -q "^#\s*${key}=" "${ENV_FILE}"; then
    sudo sed -i "s|^#\s*${key}=.*|${key}=${val}|" "${ENV_FILE}"
  else
    echo "${key}=${val}" | sudo tee -a "${ENV_FILE}" >/dev/null
  fi
}

comment_env() {
  local key="$1"
  if grep -q "^${key}=" "${ENV_FILE}"; then
    sudo sed -i "s|^${key}=.*|# ${key}=|" "${ENV_FILE}"
  elif ! grep -q "^#\s*${key}=" "${ENV_FILE}"; then
    echo "# ${key}=" | sudo tee -a "${ENV_FILE}" >/dev/null
  fi
}

if [[ "${NONINT}" == "1" ]]; then
  # Non-interactive: honor overrides, otherwise defaults
  apply_env LLM_BASE_URL "${OVERRIDE_LLM_BASE:-http://127.0.0.1:11434}"
  if [[ -n "${OVERRIDE_LLM_MODEL:-}" ]]; then
    apply_env LLM_MODEL "${OVERRIDE_LLM_MODEL}"
  else
    comment_env LLM_MODEL
  fi
else
  # Interactive setup (optional, non-blocking)
  echo
  echo "=== ScanTrace setup ==="
  echo "Choose mode:"
  echo "  1) LLM (local endpoint, default)"
  echo "  2) MCP-only (skip LLM for now)"
  read -r -p "Selection [1/2, default 1]: " _mode || true
  _mode=${_mode:-1}
  if [[ "${_mode}" == "1" || -z "${_mode}" ]]; then
    read -r -p "LLM base URL [http://127.0.0.1:11434]: " _llm_base || true
    _llm_base=${_llm_base:-http://127.0.0.1:11434}
    read -r -p "LLM model (e.g., tinyllama.gguf) [leave blank to set later]: " _llm_model || true
    apply_env LLM_BASE_URL "${_llm_base}"
    if [[ -n "${_llm_model:-}" ]]; then
      apply_env LLM_MODEL "${_llm_model}"
    else
      comment_env LLM_MODEL
    fi
  else
    comment_env LLM_MODEL
  fi
fi

echo
echo "Environment saved to ${ENV_FILE}."

# Write systemd unit (hardened)
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
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${STATE_DIR} ${EXPORTS_DIR}
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
SystemCallFilter=@system-service
UMask=027

ExecStart=${BIN_INSTALL}
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

# Start only if Slack tokens/channel look configured (avoid hard fail on placeholders)
if grep -q '^SLACK_BOT_TOKEN=xoxb-' "${ENV_FILE}" || \
   grep -q '^SLACK_APP_TOKEN=xapp-' "${ENV_FILE}" || \
   grep -q '^ALERT_CHANNEL=C0BBP1EP68P' "${ENV_FILE}"; then
  echo "Service installed but not started. Next steps:"
  echo "  1) sudoedit ${ENV_FILE}  # set SLACK_BOT_TOKEN, SLACK_APP_TOKEN, ALERT_CHANNEL"
  echo "  2) sudo systemctl enable --now scantrace-agent"
  echo "  3) journalctl -u scantrace-agent -n 80 --no-pager"
else
  sudo systemctl enable --now scantrace-agent || true
  systemctl --no-pager status scantrace-agent || true
fi
