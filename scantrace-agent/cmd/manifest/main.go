// Prints hooks for the Slack CLI get-hooks call.
package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	hooks := map[string]interface{}{
		"hooks": map[string]string{
			"build":        "go build -o ./bin/scantrace-agent ./cmd/bot/",
			"start":        "SLACK_BOT_TOKEN=$SLACK_BOT_TOKEN SLACK_APP_TOKEN=$SLACK_APP_TOKEN ./bin/scantrace-agent",
			"get-hooks":    "go run ./cmd/manifest/main.go",
			"get-manifest": "go run ./cmd/getmanifest/main.go",
		},
	}
	b, _ := json.MarshalIndent(hooks, "", "  ")
	fmt.Println(string(b))
}
