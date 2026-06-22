// Prints hooks for the Slack CLI get-hooks call.
package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	hooks := map[string]interface{}{
		"hooks": map[string]string{
			"build":     "go build ./cmd/bot/",
			"start":     "go run ./cmd/bot/",
			"get-hooks": "go run ./cmd/manifest/main.go",
		},
	}
	b, _ := json.MarshalIndent(hooks, "", "  ")
	fmt.Println(string(b))
}
