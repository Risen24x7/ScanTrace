package main

import (
	"log"
	"os"
	"strings"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/handler"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/llm"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/syslog"
	"github.com/joho/godotenv"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

func main() {
	// Load .env silently only if present (avoid noisy service logs)
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			log.Printf("[main] WARNING: failed to load .env: %v", err)
		}
	}

	botToken := mustEnv("SLACK_BOT_TOKEN")
	appToken := mustEnv("SLACK_APP_TOKEN")
	alertChannel := mustEnv("ALERT_CHANNEL")

	externalThreatChannel := os.Getenv("EXTERNAL_THREAT_CHANNEL")
	if externalThreatChannel == "" {
		externalThreatChannel = alertChannel
	}

	wanIP := strings.TrimSpace(os.Getenv("WAN_IP"))

	// Use DB_PATH. Absolute path strongly recommended.
	storeConn := os.Getenv("DB_PATH")
	if storeConn == "" {
		storeConn = "../scantrace.db"
		log.Printf("[main] WARNING: DB_PATH not set — using relative path %q (may open wrong file depending on cwd)", storeConn)
	}
	log.Printf("[main] database: %s", storeConn)

	store, err := db.Open(storeConn)
	if err != nil {
		log.Fatalf("[main] db.Open: %v", err)
	}
	defer store.Close()

	// RTS client uses the bot token for Authorization: Bearer <token>
	rtsClient := rts.New(botToken)

	// LLM configuration: expects an Ollama-compatible endpoint.
	// For local development, defaults to localhost:11434.
	// For production or remote LLM services, set LLM_BASE_URL explicitly.
	llmBase := envOrDefault("LLM_BASE_URL", "http://127.0.0.1:11434")
	llmModel := os.Getenv("LLM_MODEL")
	llmClient := llm.New(llmBase, llmModel)
	log.Printf("[main] LLM endpoint: %s (model=%q)", llmBase, llmModel)

	api := slack.New(
		botToken,
		slack.OptionAppLevelToken(appToken),
	)
	client := socketmode.New(api)

	h := handler.New(api, store, alertChannel, externalThreatChannel, wanIP, rtsClient, llmClient)

	// ── Syslog UDP ingest ──────────────────────────────────────────────────
	// Binds to SCANTRACE_SYSLOG_PORT (default 5140) and parses iptables DROP
	// lines forwarded from the gateway router into ScanTrace events + cases.
	syslogPort := envOrDefault("SCANTRACE_SYSLOG_PORT", "5140")
	go func() {
		if err := syslog.Listen(":"+syslogPort, store, h); err != nil {
			log.Fatalf("[main] syslog listener: %v", err)
		}
	}()
	log.Printf("[main] syslog ingest started on UDP :%s", syslogPort)

	// ── Slack Socket Mode ──────────────────────────────────────────────────
	go func() {
		for evt := range client.Events {
			h.Dispatch(client, evt)
		}
	}()

	log.Println("[main] ScanTrace agent starting…")
	if err := client.Run(); err != nil {
		log.Fatalf("[main] socketmode: %v", err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("[main] required env var %q is not set", key)
	}
	return v
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
