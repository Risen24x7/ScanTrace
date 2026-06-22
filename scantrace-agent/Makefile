.PHONY: run run-local build tidy check

# Primary: load .env then run the bot
run:
	@test -f .env || (echo "ERROR: .env not found. Run: cp .env.example .env  then fill in tokens."; exit 1)
	env $$(grep -v '^#' .env | grep -v '^$$' | xargs) go run ./cmd/bot/

# Alternative if the env loader gives you trouble — set vars manually then call this
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
