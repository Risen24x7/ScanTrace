.PHONY: run run-local build tidy check mcp-test rts-test

# Primary: load .env then run the bot + MCP server
run:
	@test -f .env || (echo "ERROR: .env not found. Run: cp .env.example .env  then fill in tokens."; exit 1)
	env $$(grep -v '^#' .env | grep -v '^$$' | xargs) go run ./cmd/bot/

# Alternative if the env loader gives you trouble
run-local:
	go run ./cmd/bot/

# Build a binary instead of running from source
build:
	@mkdir -p bin
	go build -o ./bin/scantrace-agent ./cmd/bot/

# Run the compiled binary (after make build)
bin/scantrace-agent: build
	./bin/scantrace-agent

# Download dependencies
tidy:
	go mod tidy

check:
	go vet ./...

# Test MCP tools endpoint (requires bot to be running)
mcp-test:
	@echo "--- MCP tools list ---"
	curl -s http://localhost:8765/mcp/tools/list | python3 -m json.tool
	@echo "--- MCP list_cases ---"
	curl -s -X POST http://localhost:8765/mcp/tools/call \
	  -H 'Content-Type: application/json' \
	  -d '{"name":"list_cases","input":{"severity":"high","limit":5}}' | python3 -m json.tool

# Test RTS subscriptions (requires SLACK_BOT_TOKEN in env)
rts-test:
	@test -f .env || (echo "ERROR: .env not found"; exit 1)
	env $$(grep -v '^#' .env | grep -v '^$$' | xargs) \
	  curl -s -X POST https://slack.com/api/signal.subscriptions.list \
	  -H "Authorization: Bearer $$SLACK_BOT_TOKEN" \
	  -H 'Content-Type: application/json' \
	  -d '{}' | python3 -m json.tool
