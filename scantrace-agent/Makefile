.PHONY: run build tidy

run:
	@if [ ! -f .env ]; then echo "ERROR: .env not found. Copy .env.example to .env and fill in tokens."; exit 1; fi
	@export $$(cat .env | grep -v '^#' | xargs) && go run ./cmd/bot/

build:
	go build -o ./bin/scantrace-agent ./cmd/bot/

tidy:
	go mod tidy
