// ScanTrace Slack Bot — Dead Reckoning Edition
// Connects to Dilldozer sandbox via Socket Mode.
// Runs the MCP server on a separate goroutine.
//
// Required env vars:
//   SLACK_BOT_TOKEN   xoxb-...  (Bot token from OAuth)
//   SLACK_APP_TOKEN   xapp-...  (App-level token for Socket Mode)
//   SCANTRACE_DB      path to scantrace.db (default: ../ScanTrace/scantrace.db)
//   ALERT_CHANNEL     channel ID to post case alerts
//   MCP_ADDR          address for MCP HTTP server (default: :8765)
package main

import (
	"log"
	"os"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/handler"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/mcp"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

func main() {
	botToken := mustEnv("SLACK_BOT_TOKEN")
	appToken := mustEnv("SLACK_APP_TOKEN")
	dbPath := envOrDefault("SCANTRACE_DB", "../ScanTrace/scantrace.db")
	alertChannel := envOrDefault("ALERT_CHANNEL", "#sec-alerts")
	mcpAddr := envOrDefault("MCP_ADDR", ":8765")

	store, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("[bot] failed to open db: %v", err)
	}
	defer store.Close()

	// Start MCP server in background
	mcpServer := mcp.New(store)
	go func() {
		if err := mcpServer.ListenAndServe(mcpAddr); err != nil {
			log.Fatalf("[mcp] server error: %v", err)
		}
	}()

	// Initialize RTS client
	rtsClient := rts.New(botToken)

	api := slack.New(
		botToken,
		slack.OptionAppLevelToken(appToken),
		slack.OptionDebug(false),
		slack.OptionLog(log.New(os.Stdout, "[slack] ", log.LstdFlags|log.Lshortfile)),
	)

	client := socketmode.New(
		api,
		socketmode.OptionDebug(false),
		socketmode.OptionLog(log.New(os.Stdout, "[socketmode] ", log.LstdFlags|log.Lshortfile)),
	)

	h := handler.New(api, store, alertChannel, rtsClient)

	go func() {
		for evt := range client.Events {
			h.Dispatch(client, evt)
		}
	}()

	log.Printf("[bot] ScanTrace connecting to Dilldozer sandbox (MCP on %s)...", mcpAddr)
	if err := client.Run(); err != nil {
		log.Fatalf("[bot] socket mode error: %v", err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("[bot] required env var %s is not set", key)
	}
	return v
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
