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
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

func main() {
	botToken := mustEnv("SLACK_BOT_TOKEN")
	appToken := mustEnv("SLACK_APP_TOKEN")
	alertChannel := mustEnv("ALERT_CHANNEL")

	externalThreatChannel := os.Getenv("EXTERNAL_THREAT_CHANNEL")
	if externalThreatChannel == "" {
		externalThreatChannel = alertChannel
	}

	wanIP := strings.TrimSpace(os.Getenv("WAN_IP"))

	// Accept SCANTRACE_DB (legacy) or DB_PATH. Absolute path strongly recommended.
	storeConn := os.Getenv("DB_PATH")
	if storeConn == "" {
		storeConn = os.Getenv("SCANTRACE_DB")
	}
	if storeConn == "" {
		storeConn = "../scantrace.db"
		log.Printf("[main] WARNING: neither DB_PATH nor SCANTRACE_DB set — using relative path %q (may open wrong file depending on cwd)", storeConn)
	}
	log.Printf("[main] database: %s", storeConn)

	store, err := db.Open(storeConn)
	if err != nil {
		log.Fatalf("[main] db.Open: %v", err)
	}

	rtsURL := os.Getenv("RTS_BASE_URL")
	rtsClient := rts.New(rtsURL)

	// Default to the desktop inference endpoint so the agent works without
	// explicitly setting LLM_BASE_URL in the environment.
	llmBase := envOrDefault("LLM_BASE_URL", "http://192.168.50.250:11434")
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
