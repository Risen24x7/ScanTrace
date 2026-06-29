// ScanTrace Slack Bot — Dead Reckoning Edition
//
// Required env vars:
//   SLACK_BOT_TOKEN      xoxb-...  (Bot token from OAuth)
//   SLACK_APP_TOKEN      xapp-...  (App-level token for Socket Mode)
//
// Optional env vars:
//   SCANTRACE_DB              path to scantrace.db   (default: ../ScanTrace/scantrace.db)
//   SCANTRACE_ASUS_STATE      Asus sensor-id file    (default: .asus-sensor-id)
//   SCANTRACE_SYSLOG_PORT     UDP syslog port        (default: 5140)
//   CORRELATE_INTERVAL        correlator run interval (default: 5m)
//   ALERT_CHANNEL             Slack channel ID for incoming case alerts (default: C0BBP1EP68P)
//   EXTERNAL_THREAT_CHANNEL   Slack channel ID where external threat work is done;
//                             @mention LLM responses are posted here (default: ALERT_CHANNEL)
//   MCP_ADDR                  MCP HTTP listen addr   (default: :8765)
//   LLM_BASE_URL              llama.cpp endpoint    (default: http://192.168.50.250:11434)
//   LLM_MODEL                 model name
package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/Risen24x7/scantrace/internal/collector"
	"github.com/Risen24x7/scantrace/internal/correlator"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/handler"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/llm"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/mcp"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

func main() {
	botToken := mustEnv("SLACK_BOT_TOKEN")
	appToken := mustEnv("SLACK_APP_TOKEN")

	dbPath := envOrDefault("SCANTRACE_DB", "../ScanTrace/scantrace.db")
	alertChannel := envOrDefault("ALERT_CHANNEL", "C0BBP1EP68P")
	// EXTERNAL_THREAT_CHANNEL: where @mention LLM responses are posted (sec-intel-external).
	// Falls back to alertChannel so single-channel setups keep working.
	externalThreatChannel := envOrDefault("EXTERNAL_THREAT_CHANNEL", alertChannel)
	mcpAddr := envOrDefault("MCP_ADDR", ":8765")
	llmBase := envOrDefault("LLM_BASE_URL", "http://192.168.50.250:11434")
	llmModel := envOrDefault("LLM_MODEL", "")

	store, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("[bot] failed to open db: %v", err)
	}
	defer store.Close()

	api := slack.New(
		botToken,
		slack.OptionAppLevelToken(appToken),
		slack.OptionDebug(false),
		slack.OptionLog(log.New(os.Stdout, "[slack] ", log.LstdFlags|log.Lshortfile)),
	)

	llmClient := llm.New(llmBase, llmModel)
	log.Printf("[bot] LLM endpoint: %s (model=%q)", llmBase, llmModel)

	rtsClient := rts.New(botToken)
	h := handler.New(api, store, alertChannel, externalThreatChannel, rtsClient, llmClient)
	log.Printf("[bot] alert channel: %s | external threat channel: %s", alertChannel, externalThreatChannel)

	// UDP syslog listener
	statePath := envOrDefault("SCANTRACE_ASUS_STATE", ".asus-sensor-id")
	asusSensorID, err := collector.RegisterAsusSensor(store, statePath)
	if err != nil {
		log.Printf("[bot] asus sensor registration failed: %v — syslog listener disabled", err)
	} else {
		port := syslogPortFromEnv()
		adapter := collector.NewAsusAdapter(asusSensorID)
		syslogSrv := collector.NewSyslogServer(port, store, adapter)
		go func() {
			if err := syslogSrv.Listen(); err != nil {
				log.Printf("[syslog] fatal: %v", err)
			}
		}()
		log.Printf("[bot] syslog listener on UDP :%d (sensor=%s)", port, asusSensorID[:8])
	}

	// Correlator loop
	correlateInterval := correlateIntervalFromEnv()
	go func() {
		runCorrelate(store, h)
		ticker := time.NewTicker(correlateInterval)
		defer ticker.Stop()
		for range ticker.C {
			runCorrelate(store, h)
		}
	}()
	log.Printf("[bot] correlator running every %s", correlateInterval)

	// MCP server
	mcpServer := mcp.New(store)
	go func() {
		if err := mcpServer.ListenAndServe(mcpAddr); err != nil {
			log.Fatalf("[mcp] server error: %v", err)
		}
	}()

	// Slack socket-mode bot
	client := socketmode.New(
		api,
		socketmode.OptionDebug(false),
		socketmode.OptionLog(log.New(os.Stdout, "[socketmode] ", log.LstdFlags|log.Lshortfile)),
	)
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

func runCorrelate(store *db.DB, h *handler.Handler) {
	cfg := correlator.DefaultConfig()
	corr := correlator.New(store, cfg)
	cases, err := corr.Run()
	if err != nil {
		log.Printf("[correlator] error: %v", err)
		return
	}
	if len(cases) == 0 {
		log.Printf("[correlator] cycle complete — no new cases")
		return
	}
	log.Printf("[correlator] %d new case(s)", len(cases))
	for _, c := range cases {
		log.Printf("[correlator]   • [%s] %s severity=%s confidence=%.0f%%",
			c.CaseID[:8], c.Title, c.Severity, c.Confidence*100)
		h.PostCaseAlert(c)
	}
}

func syslogPortFromEnv() int {
	if v := os.Getenv("SCANTRACE_SYSLOG_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			return p
		}
	}
	return 5140
}

func correlateIntervalFromEnv() time.Duration {
	if v := os.Getenv("CORRELATE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 10*time.Second {
			return d
		}
	}
	return 5 * time.Minute
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
