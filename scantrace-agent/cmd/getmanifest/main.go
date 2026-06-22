// Prints the app manifest JSON for the Slack CLI get-manifest hook.
// Ignores all flags (including --source) passed by the CLI.
package main

import (
	"fmt"
	"os"
)

func main() {
	data, err := os.ReadFile("manifest.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading manifest.json: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(data))
}
