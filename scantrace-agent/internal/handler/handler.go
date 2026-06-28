// Package handler dispatches Slack Socket Mode events to the appropriate handler.
package handler

import (
	"fmt"
	"log"
	"strings"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/llm"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"
)

type Handler struct {
	api          *slack.Client
	store        *db.DB
	alertChannel string
	rts          *rts.Client
	llm          *llm.Client
}

func New(api *slack.Client, store *db.DB, alertChannel string, rtsClient *rts.Client, llmClient *llm.Client) *Handler {
	return &Handler{api: api, store: store, alertChannel: alertChannel, rts: rtsClient, llm: llmClient}
}

// Dispatch routes incoming Socket Mode events.
func (h *Handler) Dispatch(client *socketmode.Client, evt socketmode.Event) {
	switch evt.Type {
	case socketmode.EventTypeConnecting:
		log.Println("[handler] connecting to Slack...")
	case socketmode.EventTypeConnected:
		log.Println("[handler] connected to Dilldozer ✓")
		go h.subscribeRTS()

	case socketmode.EventTypeSlashCommand:
		cmd, ok := evt.Data.(slack.SlashCommand)
		if !ok {
			client.Ack(*evt.Request)
			return
		}
		client.Ack(*evt.Request)
		h.handleSlashCommand(cmd)

	case socketmode.EventTypeEventsAPI:
		eventsAPI, ok := evt.Data.(slackevents.EventsAPIEvent)
		if !ok {
			client.Ack(*evt.Request)
			return
		}
		client.Ack(*evt.Request)
		h.handleEvent(eventsAPI)

	default:
		// ignore heartbeats and unknown types
	}
}

func (h *Handler) subscribeRTS() {
	_, err := h.rts.Subscribe(rts.SignalAppMention, "scantrace-mention")
	if err != nil {
		log.Printf("[rts] subscribe skipped: %v", err)
		return
	}
	log.Printf("[rts] signal subscriptions active")
}

func (h *Handler) handleSlashCommand(cmd slack.SlashCommand) {
	parts := strings.Fields(strings.TrimSpace(cmd.Text))
	sub := "help"
	if len(parts) > 0 {
		sub = strings.ToLower(parts[0])
	}
	switch sub {
	case "cases":
		h.cmdCases(cmd.ChannelID, cmd.UserID)
	case "report":
		if len(parts) < 2 {
			h.postEphemeral(cmd.ChannelID, cmd.UserID, "Usage: `/scantrace report <case-id>`")
			return
		}
		h.cmdReport(cmd.ChannelID, cmd.UserID, parts[1])
	case "alert":
		h.cmdPostLatestAlert(cmd.ChannelID)
	case "devices":
		h.cmdDevices(cmd.ChannelID, cmd.UserID)
	case "mcp":
		h.postEphemeral(cmd.ChannelID, cmd.UserID,
			"*MCP Server* is running on `localhost:8765`\n"+
				"Tools: `list_cases`, `get_case`, `list_sensors`, `get_entity`, `list_known_devices`\n"+
				"Connect any MCP host (Claude Desktop, Cursor) to `http://localhost:8765`")
	default:
		h.postEphemeral(cmd.ChannelID, cmd.UserID, helpText())
	}
}

func (h *Handler) cmdCases(channelID, userID string) {
	cases, err := h.store.ListCases("", 10)
	if err != nil || len(cases) == 0 {
		h.postEphemeral(channelID, userID, "No cases found.")
		return
	}
	var lines []string
	for _, c := range cases {
		emoji := severityEmoji(c.Severity)
		lines = append(lines, fmt.Sprintf("%s `%s` *%s* — %s (%.0f%%)",
			emoji, c.CaseID[:8], strings.ToUpper(c.Severity), c.Title, c.Confidence*100))
	}
	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject("plain_text", "🔍 ScanTrace Cases", false, false)),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", strings.Join(lines, "\n"), false, false),
			nil, nil,
		),
	}
	h.postBlocks(channelID, blocks)
}

func (h *Handler) cmdDevices(channelID, userID string) {
	devices, err := h.store.ListKnownDevices("", 20)
	if err != nil || len(devices) == 0 {
		h.postEphemeral(channelID, userID, "No devices in registry. Use the API or MCP tool to register devices.")
		return
	}
	var lines []string
	for _, d := range devices {
		emoji := trustEmoji(d.TrustLabel)
		identifier := d.IP
		if identifier == "" {
			identifier = d.MAC
		}
		label := d.Label
		if label == "" {
			label = "(unlabeled)"
		}
		suppress := ""
		if d.AutoSuppress {
			suppress = " — _suppressed_"
		}
		lines = append(lines, fmt.Sprintf("%s `%s` *%s* [%s]%s",
			emoji, identifier, label, d.TrustLabel, suppress))
	}
	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject("plain_text", "🖥️ Known Device Registry", false, false)),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", strings.Join(lines, "\n"), false, false),
			nil, nil,
		),
	}
	h.postBlocks(channelID, blocks)
}

func (h *Handler) cmdReport(channelID, userID, caseIDPrefix string) {
	cases, _ := h.store.ListCases("", 50)
	var fullID string
	for _, c := range cases {
		if strings.HasPrefix(c.CaseID, caseIDPrefix) {
			fullID = c.CaseID
			break
		}
	}
	if fullID == "" {
		h.postEphemeral(channelID, userID, fmt.Sprintf("Case `%s` not found.", caseIDPrefix))
		return
	}
	builder := casebuilder.New(h.store)
	report, err := builder.BuildReport(fullID)
	if err != nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf("Error building report: %v", err))
		return
	}
	raw := report.SlackBlock()
	blocks, err := blocksFromRaw(raw)
	if err != nil {
		h.postMessage(channelID, report.Markdown)
		return
	}
	h.postBlocks(channelID, blocks)
}

func (h *Handler) cmdPostLatestAlert(cmdChannelID string) {
	cases, err := h.store.ListCases("high", 1)
	if err != nil || len(cases) == 0 {
		cases, err = h.store.ListCases("", 1)
		if err != nil || len(cases) == 0 {
			h.postMessage(cmdChannelID, "No cases available to alert.")
			return
		}
	}
	h.PostCaseAlert(cases[0])
}

func (h *Handler) PostCaseAlert(c *db.Case) {
	builder := casebuilder.New(h.store)
	report, err := builder.BuildReport(c.CaseID)
	if err != nil {
		report = casebuilder.BuildReportFromCase(c, nil, nil)
	}
	raw := report.SlackBlock()
	blocks, err := blocksFromRaw(raw)
	if err != nil {
		h.postMessage(h.alertChannel, report.Markdown)
		return
	}
	h.postBlocks(h.alertChannel, blocks)

	go func() {
		err := h.rts.PublishSignal(h.alertChannel, "scantrace.case.alert", map[string]interface{}{
			"case_id":  c.CaseID,
			"severity": c.Severity,
			"title":    c.Title,
		})
		if err != nil {
			log.Printf("[rts] publish signal failed (non-fatal): %v", err)
		}
	}()

	log.Printf("[handler] posted alert for case %s to %s", c.CaseID[:8], h.alertChannel)
}

func (h *Handler) handleEvent(event slackevents.EventsAPIEvent) {
	switch event.InnerEvent.Type {
	case "app_mention":
		ev, ok := event.InnerEvent.Data.(*slackevents.AppMentionEvent)
		if !ok {
			return
		}
		h.handleMention(ev.Channel, ev.User, ev.Text)
	case "message":
		ev, ok := event.InnerEvent.Data.(*slackevents.MessageEvent)
		if !ok || ev.BotID != "" {
			return
		}
		h.handleMention(ev.Channel, ev.User, ev.Text)
	}
}

func (h *Handler) handleMention(channelID, userID, text string) {
	clean := strings.TrimSpace(mentionRE(text))
	lower := strings.ToLower(clean)

	switch {
	case strings.Contains(lower, "cases") || strings.Contains(lower, "list"):
		h.cmdCases(channelID, userID)
		return
	case strings.Contains(lower, "high") || strings.Contains(lower, "critical"):
		h.cmdHighSeverity(channelID, userID)
		return
	case strings.Contains(lower, "device") && strings.Contains(lower, "registry"):
		h.cmdDevices(channelID, userID)
		return
	case strings.Contains(lower, "mcp"):
		h.postEphemeral(channelID, userID,
			"*MCP Server* is live on `localhost:8765` — tools: `list_cases`, `get_case`, `list_sensors`, `get_entity`, `list_known_devices`")
		return
	case lower == "help" || lower == "" || strings.Contains(lower, "help"):
		h.postEphemeral(channelID, userID, helpText())
		return
	}

	if h.llm == nil {
		h.postEphemeral(channelID, userID, "LLM not configured. Use `/scantrace help` for available commands.")
		return
	}

	h.postMessage(channelID, "_Thinking…_")

	ctx := h.buildLLMContext()
	answer, err := h.llm.Ask(clean, ctx)
	if err != nil {
		log.Printf("[handler] llm error: %v", err)
		h.postMessage(channelID,
			"⚠️ Could not reach the inference worker. Is the desktop running?\n"+
				"Use `/scantrace cases` or `/scantrace report <id>` in the meantime.")
		return
	}
	h.postMessage(channelID, answer)
}

// buildLLMContext assembles a rich text summary of recent DB state.
// Hydrates linked events (IPs, MACs, event types) and cross-references
// the known_devices registry so the model knows device trust status.
func (h *Handler) buildLLMContext() string {
	var sb strings.Builder

	// --- known device registry snapshot (top 50) ---
	devices, _ := h.store.ListKnownDevices("", 50)
	if len(devices) > 0 {
		sb.WriteString(fmt.Sprintf("Known device registry (%d entries):\n", len(devices)))
		for _, d := range devices {
			identifier := d.IP
			if identifier == "" {
				identifier = d.MAC
			}
			sb.WriteString(fmt.Sprintf(
				"  %s trust=%s label=%q zone=%s suppress=%v last_seen=%s\n",
				identifier, d.TrustLabel, d.Label, d.NetworkZone,
				d.AutoSuppress, d.LastSeen.Format("2006-01-02 15:04"),
			))
		}
		sb.WriteString("\n")
	}

	// --- cases with hydrated events ---
	cases, err := h.store.ListCases("", 20)
	if err != nil || len(cases) == 0 {
		sb.WriteString("No cases in database.\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("Total cases: %d\n\nRecent cases (newest first):\n", len(cases)))

	for _, c := range cases {
		sb.WriteString(fmt.Sprintf(
			"\nCase id=%s severity=%s confidence=%.0f%% status=%s title=%q\n",
			c.CaseID[:8], c.Severity, c.Confidence*100, c.Status, c.Title,
		))
		if c.Summary != "" {
			sb.WriteString(fmt.Sprintf("  summary: %s\n", c.Summary))
		}

		// Hydrate linked events (cap at 10 per case).
		const maxEvents = 10
		if len(c.RelatedEventIDs) > 0 {
			sb.WriteString("  events:\n")
			for i, evtID := range c.RelatedEventIDs {
				if i >= maxEvents {
					sb.WriteString(fmt.Sprintf("    … and %d more\n", len(c.RelatedEventIDs)-maxEvents))
					break
				}
				evt, err := h.store.GetEvent(evtID)
				if err != nil || evt == nil {
					continue
				}
				var parts []string
				parts = append(parts, fmt.Sprintf("type=%s", evt.EventType))
				parts = append(parts, fmt.Sprintf("source=%s", evt.SourceType))
				if evt.SrcIP != "" {
					parts = append(parts, fmt.Sprintf("src=%s", evt.SrcIP))
					// Cross-reference device registry.
					if dev, _ := h.store.GetKnownDeviceByIP(evt.SrcIP); dev != nil {
						parts = append(parts, fmt.Sprintf("[trust=%s label=%q]", dev.TrustLabel, dev.Label))
					}
				}
				if evt.DstIP != "" {
					parts = append(parts, fmt.Sprintf("dst=%s", evt.DstIP))
				}
				if evt.SrcPort > 0 {
					parts = append(parts, fmt.Sprintf("sport=%d", evt.SrcPort))
				}
				if evt.DstPort > 0 {
					parts = append(parts, fmt.Sprintf("dport=%d", evt.DstPort))
				}
				if evt.Protocol != "" {
					parts = append(parts, fmt.Sprintf("proto=%s", evt.Protocol))
				}
				if len(evt.Tags) > 0 {
					parts = append(parts, fmt.Sprintf("tags=%s", strings.Join(evt.Tags, ",")))
				}
				parts = append(parts, fmt.Sprintf("ts=%s", evt.Timestamp.Format("2006-01-02 15:04")))
				sb.WriteString(fmt.Sprintf("    - %s\n", strings.Join(parts, " ")))
			}
		}

		// Linked entity enrichment (external IPs, ASN, reputation).
		if len(c.RelatedEntityIDs) > 0 {
			entities, err := h.store.GetEntitiesForCase(c.CaseID)
			if err == nil && len(entities) > 0 {
				sb.WriteString("  entities:\n")
				for _, en := range entities {
					sb.WriteString(fmt.Sprintf(
						"    - ip=%s type=%s asn=%s provider=%s country=%s rdns=%s\n",
						en.IP, en.EntityType, en.ASN, en.Provider, en.GeoCountry, en.RDNS,
					))
				}
			}
		}
	}

	return sb.String()
}

func mentionRE(text string) string {
	if len(text) > 0 && text[0] == '<' {
		if idx := strings.Index(text, ">"); idx != -1 {
			return strings.TrimSpace(text[idx+1:])
		}
	}
	return text
}

func (h *Handler) cmdHighSeverity(channelID, userID string) {
	cases, err := h.store.ListCases("high", 5)
	if err != nil || len(cases) == 0 {
		h.postEphemeral(channelID, userID, "No high severity cases found.")
		return
	}
	var lines []string
	for _, c := range cases {
		lines = append(lines, fmt.Sprintf("🔴 `%s` *%s* (%.0f%% confidence)",
			c.CaseID[:8], c.Title, c.Confidence*100))
	}
	h.postBlocks(channelID, []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject("plain_text", "🔴 High Severity Cases", false, false)),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", strings.Join(lines, "\n"), false, false),
			nil, nil,
		),
	})
}

func (h *Handler) postMessage(channelID, text string) {
	_, _, err := h.api.PostMessage(channelID,
		slack.MsgOptionText(text, false),
		slack.MsgOptionAsUser(false),
	)
	if err != nil {
		log.Printf("[handler] postMessage error: %v", err)
	}
}

func (h *Handler) postEphemeral(channelID, userID, text string) {
	_, err := h.api.PostEphemeral(channelID, userID,
		slack.MsgOptionText(text, false),
	)
	if err != nil {
		log.Printf("[handler] postEphemeral error: %v", err)
	}
}

func (h *Handler) postBlocks(channelID string, blocks []slack.Block) {
	_, _, err := h.api.PostMessage(channelID,
		slack.MsgOptionBlocks(blocks...),
	)
	if err != nil {
		log.Printf("[handler] postBlocks error: %v", err)
	}
}

func blocksFromRaw(raw map[string]interface{}) ([]slack.Block, error) {
	rawBlocks, ok := raw["blocks"].([]map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid blocks structure")
	}
	var blocks []slack.Block
	for _, rb := range rawBlocks {
		switch rb["type"] {
		case "divider":
			blocks = append(blocks, slack.NewDividerBlock())
		case "section":
			if text, ok := rb["text"].(map[string]string); ok {
				blocks = append(blocks, slack.NewSectionBlock(
					slack.NewTextBlockObject(text["type"], text["text"], false, false),
					nil, nil,
				))
			}
		case "context":
			if elems, ok := rb["elements"].([]map[string]string); ok {
				var textObjs []slack.MixedElement
				for _, e := range elems {
					textObjs = append(textObjs, slack.NewTextBlockObject(e["type"], e["text"], false, false))
				}
				blocks = append(blocks, slack.NewContextBlock("", textObjs...))
			}
		}
	}
	return blocks, nil
}

func severityEmoji(s string) string {
	switch strings.ToLower(s) {
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func trustEmoji(t string) string {
	switch strings.ToLower(t) {
	case "trusted":
		return "✅"
	case "suspicious":
		return "🚨"
	default:
		return "❔"
	}
}

func helpText() string {
	return `*ScanTrace — Network Security Intelligence*

Available commands:
• ` + "`/scantrace cases`" + ` — list recent cases
• ` + "`/scantrace report <case-id>`" + ` — full case report
• ` + "`/scantrace alert`" + ` — post latest high-severity case to #sec-alerts
• ` + "`/scantrace devices`" + ` — show known device registry
• ` + "`/scantrace mcp`" + ` — MCP server status
• ` + "`/scantrace help`" + ` — this message

You can also @mention ScanTrace or DM it with any security question.
Example: _@ScanTrace are there any unclassified devices on the network?_`
}
