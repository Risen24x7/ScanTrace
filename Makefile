BINARY    := scantrace-agent
SRC_DIR   := ./scantrace-agent
BUILD_DIR := ./bin
INSTALL_BIN := /opt/scantrace/bin/scantrace-agent
UNIT_FILE := /etc/systemd/system/scantrace-agent.service
ENV_PRIMARY := $(HOME)/ScanTrace/.env
ENV_FALLBACK := $(HOME)/ScanTrace/scantrace-agent/.env

.PHONY: build test clean install-service update-service

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY) $(SRC_DIR)/cmd/bot/
	@echo "Binary: $(BUILD_DIR)/$(BINARY)"

install-service: build
	@echo "Selecting env file..."
	@if [ -f "$(ENV_PRIMARY)" ]; then ENV_FILE="$(ENV_PRIMARY)"; \
	elif [ -f "$(ENV_FALLBACK)" ]; then ENV_FILE="$(ENV_FALLBACK)"; \
	else echo "ERROR: No .env found at $(ENV_PRIMARY) or $(ENV_FALLBACK)" >&2; exit 1; fi; \
	echo "Using $$ENV_FILE"; \
	sudo install -d -o "$(USER)" -g "$(USER)" /opt/scantrace/bin /opt/scantrace/exports /var/lib/scantrace; \
	sudo install -m0755 $(BUILD_DIR)/$(BINARY) $(INSTALL_BIN); \
	sudo tee $(UNIT_FILE) >/dev/null <<EOF; \
[Unit]
Description=ScanTrace Agent
After=network-online.target
Wants=network-online.target

[Service]
User=$(USER)
WorkingDirectory=$(HOME)/ScanTrace/scantrace-agent
EnvironmentFile=$$ENV_FILE
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

ExecStart=$(INSTALL_BIN)
Restart=on-failure
RestartSec=3s

ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/lib/scantrace /opt/scantrace
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
	sudo systemctl daemon-reload; \
	sudo systemctl enable --now scantrace-agent; \
	systemctl --no-pager status scantrace-agent

update-service: build
	sudo install -m0755 $(BUILD_DIR)/$(BINARY) $(INSTALL_BIN)
	sudo systemctl restart scantrace-agent
	@echo "Updated and restarted scantrace-agent"
