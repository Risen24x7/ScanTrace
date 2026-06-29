// Package handler dispatches Slack Socket Mode events to the appropriate handler.
package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/ipinfo"
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

	mu          sync.Mutex
	caseThreads map[string]string
}

func New(api *slack.Client, store *db.DB, alertChannel string, rtsClient *rts.Client, llmClient *llm.Client) *Handler {
	return &Handler{
		api:          api,
		store:        store,
		alertChannel: alertChannel,
		rts:          rtsClient,
		llm:          llmClient,
		caseThreads:  make(map[string]string),
	}
}

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
	h.postBlocks(channelID, "", blocks)
}

func (h *Handler) cmdDevices(channelID, userID string) {
	devices, err := h.store.ListKnownDevices("", 20)
	if err != nil || len(devices) == 0 {
		h.postEphemeral(channelID, userID, "No devices in registry.")
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
	h.postBlocks(channelID, "", blocks)
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
	blocks, err := blocksFromRaw(report.SlackBlock())
	if err != nil {
		h.postMessage(channelID, "", report.Markdown)
		return
	}
	h.postBlocks(channelID, "", blocks)
}

func (h *Handler) cmdPostLatestAlert(cmdChannelID string) {
	cases, err := h.store.ListCases("high", 1)
	if err != nil || len(cases) == 0 {
		cases, err = h.store.ListCases("", 1)
		if err != nil || len(cases) == 0 {
			h.postMessage(cmdChannelID, "", "No cases available to alert.")
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

	h.mu.Lock()
	existingThread := h.caseThreads[c.CaseID]
	h.mu.Unlock()

	if existingThread != "" {
		update := fmt.Sprintf("🔄 *Case `%s` updated* — %s (%.0f%% confidence)",
			c.CaseID[:8], c.Title, c.Confidence*100)
		h.postMessage(h.alertChannel, existingThread, update)
		log.Printf("[handler] thread reply for case %s to %s", c.CaseID[:8], h.alertChannel)
		return
	}

	blocks, err := blocksFromRaw(report.SlackBlock())
	var ts string
	if err != nil {
		text := fmt.Sprintf("%s *[%s] Case `%s`* — %s\nseverity=%s confidence=%.0f%%",
			severityEmoji(c.Severity), strings.ToUpper(c.Severity),
			c.CaseID[:8], c.Title, c.Severity, c.Confidence*100)
		_, ts, err = h.api.PostMessage(h.alertChannel,
			slack.MsgOptionText(text, false),
			slack.MsgOptionAsUser(false),
		)
	} else {
		_, ts, err = h.api.PostMessage(h.alertChannel,
			slack.MsgOptionBlocks(blocks...),
		)
	}
	if err != nil {
		log.Printf("[handler] PostMessage error for case %s: %v", c.CaseID[:8], err)
		return
	}

	h.mu.Lock()
	h.caseThreads[c.CaseID] = ts
	h.mu.Unlock()

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

	log.Printf("[handler] posted alert for case %s to %s (ts=%s)", c.CaseID[:8], h.alertChannel, ts)
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

	if lower == "" || lower == "help" {
		h.postEphemeral(channelID, userID, helpText())
		return
	}
	if h.llm == nil {
		h.postEphemeral(channelID, userID, "LLM not configured. Use `/scantrace help` for available commands.")
		return
	}

	h.postMessage(channelID, "", "_Thinking…_")

	ctx := h.buildLLMContext()
	answer, err := h.llm.Ask(clean, ctx)
	if err != nil {
		log.Printf("[handler] llm error: %v", err)
		h.postMessage(channelID, "",
			"⚠️ Could not reach the inference worker. Is the desktop running?\n"+
				"Use `/scantrace cases` or `/scantrace report <id>` in the meantime.")
		return
	}
	h.postMessage(channelID, "", answer)
}

// buildLLMContext assembles a compact snapshot for the LLM.
// Limits: 10 cases, 5 events/case, 20 IPs for enrichment.
func (h *Handler) buildLLMContext() string {
	var sb strings.Builder

	devices, _ := h.store.ListKnownDevices("", 30)
	if len(devices) > 0 {
		sb.WriteString(fmt.Sprintf("Known devices (%d):\n", len(devices)))
		for _, d := range devices {
			identifier := d.IP
			if identifier == "" {
				identifier = d.MAC
			}
			sb.WriteString(fmt.Sprintf("  %s trust=%s label=%q suppress=%v\n",
				identifier, d.TrustLabel, d.Label, d.AutoSuppress))
		}
		sb.WriteString("\n")
	}

	cases, err := h.store.ListCases("", 10)
	if err != nil || len(cases) == 0 {
		sb.WriteString("No cases.\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("Cases (%d):\n", len(cases)))

	ipSet := make(map[string]struct{})

	for _, c := range cases {
		sb.WriteString(fmt.Sprintf("%s id=%s sev=%s conf=%.0f%% status=%s\n",
			c.Title, c.CaseID[:8], c.Severity, c.Confidence*100, c.Status))

		const maxEvents = 5
		for i, evtID := range c.RelatedEventIDs {
			if i >= maxEvents {
				sb.WriteString(fmt.Sprintf("  +%d more events\n", len(c.RelatedEventIDs)-maxEvents))
				break
			}
			evt, err := h.store.GetEvent(evtID)
			if err != nil || evt == nil {
				continue
			}
			line := fmt.Sprintf("  evt type=%s src=%s dst=%s dport=%d proto=%s",
				evt.EventType, evt.SrcIP, evt.DstIP, evt.DstPort, evt.Protocol)
			if evt.SrcIP != "" {
				ipSet[evt.SrcIP] = struct{}{}
			}
			sb.WriteString(line + "\n")
		}
	}

	// Enrich up to 20 unique external IPs.
	if len(ipSet) > 0 {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			if len(ips) >= 20 {
				break
			}
			ips = append(ips, ip)
		}
		enriched := ipinfo.Enrich(ips)
		sb.WriteString("\nIP intel:\n")
		for ip, info := range enriched {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", ip, info.Summary()))
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
	h.postBlocks(channelID, "", []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject("plain_text", "🔴 High Severity Cases", false, false)),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", strings.Join(lines, "\n"), false, false),
			nil, nil,
		),
	})
}

func (h *Handler) postMessage(channelID, threadTS, text string) {
	opts := []slack.MsgOption{
		slack.MsgOptionText(text, false),
		slack.MsgOptionAsUser(false),
	}
	if threadTS != "" {
		opts = append(opts, slack.MsgOptionTS(threadTS))
	}
	_, _, err := h.api.PostMessage(channelID, opts...)
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

func (h *Handler) postBlocks(channelID, threadTS string, blocks []slack.Block) {
	opts := []slack.MsgOption{slack.MsgOptionBlocks(blocks...)}
	if threadTS != "" {
		opts = append(opts, slack.MsgOptionTS(threadTS))
	}
	_, _, err := h.api.PostMessage(channelID, opts...)
	if err != nil {
		log.Printf("[handler] postBlocks error: %v", err)
	}
}

func blocksFromRaw(raw map[string]interface{}) ([]slack.Block, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("blocksFromRaw marshal: %w", err)
	}
	var msg slack.Msg
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("blocksFromRaw unmarshal: %w", err)
	}
	if len(msg.Blocks.BlockSet) == 0 {
		return nil, fmt.Errorf("blocksFromRaw: no blocks in payload")
	}
	return msg.Blocks.BlockSet, nil
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
• ` + "`/scantrace alert`" + ` — post latest high-severity case to alerts channel
• ` + "`/scantrace devices`" + ` — show known device registry
• ` + "`/scantrace mcp`" + ` — MCP server status
• ` + "`/scantrace help`" + ` — this message

You can also @mention ScanTrace with any natural language security question.
Example: _@ScanTrace review all open cases and advise on course of action_`
}
