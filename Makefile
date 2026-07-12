BINARY    := scantrace-agent
SRC_DIR   := ./scantrace-agent
BUILD_DIR := ./bin
INSTALL_BIN := /opt/scantrace/bin/scantrace-agent

.PHONY: build install-service install-service-noninteractive update-service

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY) $(SRC_DIR)/cmd/bot/
	@echo "Binary: $(BUILD_DIR)/$(BINARY)"

# Delegate service install to the hardened installer script (creates scantrace user, env, unit)
install-service:
	bash ./scripts/install-service.sh

# Non-interactive install with optional overrides:
#   make install-service-noninteractive LLM_BASE_URL=http://127.0.0.1:11434 LLM_MODEL=tinyllama.gguf
install-service-noninteractive:
	SCANTRACE_NONINTERACTIVE=1 LLM_BASE_URL="$(LLM_BASE_URL)" LLM_MODEL="$(LLM_MODEL)" bash ./scripts/install-service.sh

# Fast binary update for development; assumes service already installed by the script
update-service: build
	sudo install -m0755 $(BUILD_DIR)/$(BINARY) $(INSTALL_BIN)
	sudo systemctl restart scantrace-agent
	@echo "Updated and restarted scantrace-agent"