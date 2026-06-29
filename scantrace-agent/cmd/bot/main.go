package main

import (
	"log"
	"os"
	"strings"

	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/handler"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/llm"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
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

	storeConn := os.Getenv("DB_PATH")
	if storeConn == "" {
		storeConn = "../scantrace.db"
	}

	store, err := db.Open(storeConn)
	if err != nil {
		log.Fatalf("[main] db.Open: %v", err)
	}

	rtsURL := os.Getenv("RTS_BASE_URL")
	rtsClient := rts.New(rtsURL)

	var llmClient *llm.Client
	if llmURL := os.Getenv("LLM_BASE_URL"); llmURL != "" {
		llmClient = llm.New(llmURL, os.Getenv("LLM_MODEL"))
	}

	api := slack.New(
		botToken,
		slack.OptionAppLevelToken(appToken),
	)
	client := socketmode.New(api)

	h := handler.New(api, store, alertChannel, externalThreatChannel, wanIP, rtsClient, llmClient)

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
