// Package handler dispatches Slack Socket Mode events to the appropriate handler.
package handler

import (
	"fmt"
	"log"
	"strings"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"
)

type Handler struct {
	api          *slack.Client
	store        *db.DB
	alertChannel string
}

func New(api *slack.Client, store *db.DB, alertChannel string) *Handler {
	return &Handler{api: api, store: store, alertChannel: alertChannel}
}

// Dispatch routes incoming Socket Mode events.
func (h *Handler) Dispatch(client *socketmode.Client, evt socketmode.Event) {
	switch evt.Type {
	case socketmode.EventTypeConnecting:
		log.Println("[handler] connecting to Slack...")
	case socketmode.EventTypeConnected:
		log.Println("[handler] connected to Dilldozer ✓")

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

func (h *Handler) cmdPostLatestAlert(channelID string) {
	cases, err := h.store.ListCases("high", 1)
	if err != nil || len(cases) == 0 {
		cases, err = h.store.ListCases("", 1)
		if err != nil || len(cases) == 0 {
			h.postMessage(channelID, "No cases available to alert.")
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
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "cases") || strings.Contains(lower, "list"):
		h.cmdCases(channelID, userID)
	case strings.Contains(lower, "report") || strings.Contains(lower, "detail"):
		h.postEphemeral(channelID, userID, "Use `/scantrace report <case-id>` to get a full report.")
	case strings.Contains(lower, "high") || strings.Contains(lower, "critical"):
		h.cmdHighSeverity(channelID, userID)
	default:
		h.postEphemeral(channelID, userID, helpText())
	}
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
	h.postMessage(channelID, "*High severity cases:*\n"+strings.Join(lines, "\n"))
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

func helpText() string {
	return `*ScanTrace — Dead Reckoning Edition*

Available commands:
• ` + "`/scantrace cases`" + ` — list recent cases
• ` + "`/scantrace report <case-id>`" + ` — full case report
• ` + "`/scantrace alert`" + ` — post latest high-severity case
• ` + "`/scantrace help`" + ` — this message

You can also @mention ScanTrace or DM it.`
}
