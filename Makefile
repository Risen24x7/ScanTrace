BINARY    := scantrace
BUILD_DIR := ./bin

.PHONY: build test clean run-demo

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY) ./cmd/bot/
	@echo "Binary: $(BUILD_DIR)/$(BINARY)"

test:
	CGO_ENABLED=1 go test ./... -v

clean:
	rm -rf $(BUILD_DIR) scantrace.db

run-demo: build
	$(BUILD_DIR)/$(BINARY) ingest --file testdata/sample_eve.json --adapter suricata
	$(BUILD_DIR)/$(BINARY) correlate
	$(BUILD_DIR)/$(BINARY) cases

run: build
	$(BUILD_DIR)/$(BINARY)