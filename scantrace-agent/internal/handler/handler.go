// Package handler dispatches Slack Socket Mode events to the appropriate handler.
package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/ipinfo"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/llm"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/threat"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"
)

type Handler struct {
	api                   *slack.Client
	store                 *db.DB
	alertChannel          string // sec-alerts — raw case alerts
	externalThreatChannel string // sec-intel-external — LLM mention responses
	wanIP                 string // public WAN IP of the gateway
	rts                   *rts.Client
	llm                   *llm.Client
	threat                *threat.Enricher

	mu          sync.Mutex
	caseThreads map[string]string
}

func New(api *slack.Client, store *db.DB, alertChannel, externalThreatChannel, wanIP string, rtsClient *rts.Client, llmClient *llm.Client) *Handler {
	return &Handler{
		api:                   api,
		store:                 store,
		alertChannel:          alertChannel,
		externalThreatChannel: externalThreatChannel,
		wanIP:                 wanIP,
		rts:                   rtsClient,
		llm:                   llmClient,
		threat:                threat.New("", ""), // uses default /opt/scantrace paths
		caseThreads:           make(map[string]string),
	}
}

// triageState captures the facts Go already knows so we can pre-select the
// correct action plan before the LLM prompt is assembled.
type triageState struct {
	isWANEdgeOnly        bool // all events are wan_new_connection
	dstInRegistry        bool // at least one dst IP found in device registry
	logsConfirmMalicious bool // set by threat-feed lookup (IPSum or Tor exit)
}

// selectActionPlan converts the pre-evaluated triage state into a single
// ready-to-inject action block. The model receives only this block — no
// alternative conditions to collapse into a checklist.
func selectActionPlan(ts triageState) string {
	switch {
	case ts.logsConfirmMalicious:
		return "*Recommended Actions*\nCondition Matched: D — host verified, logs confirm malicious activity\n" +
			"- Block the source IP or subnet at the gateway firewall.\n" +
			"- Close or restrict the targeted port if no external access is required.\n" +
			"- Escalate to a human analyst if the internal host shows signs of compromise."

	case ts.isWANEdgeOnly:
		return "*Recommended Actions*\nCondition Matched: A — wan_new_connection (WAN edge only, never reached LAN)\n" +
			"- Traffic hit the WAN interface only and was not forwarded. No internal host is at risk.\n" +
			"- If the port is not intentionally exposed, consider closing it at the gateway to reduce noise.\n" +
			"- No urgent action required unless volume is significant or ports are highly sensitive (22, 3389)."

	case !ts.dstInRegistry:
		return "*Recommended Actions*\nCondition Matched: B — unknown internal host, wan_forward traffic landed\n" +
			"- Identify the device at the destination IP — run arp-scan or check DHCP leases before any other step.\n" +
			"- Once identified, check its app/proxy logs for requests matching these event timestamps.\n" +
			"- If no legitimate service found, remove or restrict the port-forwarding rule at the gateway."

	default:
		return "*Recommended Actions*\nCondition Matched: C — registered host, wan_forward traffic landed\n" +
			"- Check app/proxy logs on the destination host for requests matching these timestamps.\n" +
			"- If no matching legitimate requests, restrict or remove the port-forwarding rule.\n" +
			"- If logs confirm malicious intent, block the source IP at the gateway."
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
	case "review-all":
		h.cmdReviewAll(cmd.ChannelID, cmd.UserID)
	case "next":
		h.cmdNext(cmd.ChannelID, cmd.UserID)
	case "mcp":
		h.postEphemeral(cmd.ChannelID, cmd.UserID,
			"*MCP Server* is running on `localhost:8765`\n"+
				"Tools: `list_cases`, `get_case`, `list_sensors`, `get_entity`, `list_known_devices`\n"+
				"Connect any MCP host (Claude Desktop, Cursor) to `http://localhost:8765`")
	default:
		h.postEphemeral(cmd.ChannelID, cmd.UserID, helpText())
	}
}

// cmdReviewAll queues every open case and posts one LLM briefing per case to
// sec-intel-external, with a 3-second gap between each post.
func (h *Handler) cmdReviewAll(channelID, userID string) {
	if h.llm == nil {
		h.postEphemeral(channelID, userID, "LLM not configured.")
		return
	}
	cases, err := h.store.ListCases("", 50)
	if err != nil || len(cases) == 0 {
		h.postEphemeral(channelID, userID, "No open cases found.")
		return
	}

	dest := h.externalThreatChannel
	h.postMessage(dest, "", fmt.Sprintf(
		"_Queuing %d cases for review — posting one at a time…_", len(cases),
	))

	go func() {
		for i, c := range cases {
			ctx, triage := h.buildSingleCaseContext(c)
			actionPlan := selectActionPlan(triage)
			prompt := fmt.Sprintf(
				"Analyse this single case and provide a full briefing.\n\nCase ID: %s",
				c.CaseID[:8],
			)
			answer, err := h.llm.AskCase(prompt, ctx, actionPlan)
			if err != nil {
				log.Printf("[handler] review-all llm error case %s: %v", c.CaseID[:8], err)
				h.postMessage(dest, "", fmt.Sprintf(
					"⚠️ Case %s — inference error: %v", c.CaseID[:8], err,
				))
			} else {
				h.postMessage(dest, "", fmt.Sprintf(
					"*Case %d/%d — %s*\n%s", i+1, len(cases), c.CaseID[:8], answer,
				))
			}
			if i < len(cases)-1 {
				time.Sleep(3 * time.Second)
			}
		}
		h.postMessage(dest, "", fmt.Sprintf("_Review complete — %d cases processed._", len(cases)))
	}()
}

// cmdNext pops the highest-priority open case and posts a single full briefing.
func (h *Handler) cmdNext(channelID, userID string) {
	if h.llm == nil {
		h.postEphemeral(channelID, userID, "LLM not configured.")
		return
	}

	var target *db.Case
	for _, sev := range []string{"high", "medium", "low"} {
		cases, err := h.store.ListCases(sev, 1)
		if err == nil && len(cases) > 0 {
			target = cases[0]
			break
		}
	}
	if target == nil {
		h.postEphemeral(channelID, userID, "No open cases found.")
		return
	}

	dest := h.externalThreatChannel
	h.postMessage(dest, "", fmt.Sprintf("_Briefing next case: %s %s…_",
		severityEmoji(target.Severity), target.CaseID[:8]))

	go func() {
		ctx, triage := h.buildSingleCaseContext(target)
		actionPlan := selectActionPlan(triage)
		prompt := fmt.Sprintf(
			"Analyse this case and provide a full briefing.\n\nCase ID: %s",
			target.CaseID[:8],
		)
		answer, err := h.llm.AskCase(prompt, ctx, actionPlan)
		if err != nil {
			log.Printf("[handler] next llm error case %s: %v", target.CaseID[:8], err)
			h.postMessage(dest, "", fmt.Sprintf(
				"⚠️ Case %s — inference error: %v", target.CaseID[:8], err,
			))
			return
		}
		h.postMessage(dest, "", fmt.Sprintf("*Case %s — Full Briefing*\n%s", target.CaseID[:8], answer))
	}()
}

// classifyDst determines the triage label for a destination IP.
func (h *Handler) classifyDst(dstIP, eventType string) string {
	if h.wanIP != "" && dstIP == h.wanIP {
		return "WAN edge interface (gateway external IP — not an internal host)"
	}
	if strings.EqualFold(eventType, "wan_new_connection") {
		return "WAN edge interface (connection hit gateway only — no port-forward rule matched)"
	}
	return ""
}

// buildSingleCaseContext builds the LLM context string and simultaneously
// evaluates the triageState so the caller can pre-select the action plan
// without asking the model to perform conditional logic.
func (h *Handler) buildSingleCaseContext(c *db.Case) (string, triageState) {
	var sb strings.Builder
	var ts triageState

	evtTypesSeen := make(map[string]int)

	devices, _ := h.store.ListKnownDevices("", 30)
	deviceMap := make(map[string]*db.KnownDevice)
	if len(devices) > 0 {
		sb.WriteString("Known devices:\n")
		for i, d := range devices {
			identifier := d.IP
			if identifier == "" {
				identifier = d.MAC
			}
			if d.IP != "" {
				deviceMap[d.IP] = devices[i]
			}
			sb.WriteString(fmt.Sprintf("  %s trust=%s label=%q suppress=%v\n",
				identifier, d.TrustLabel, d.Label, d.AutoSuppress))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Case: id=%s title=%q sev=%s conf=%.0f%% status=%s events=%d\n",
		c.CaseID[:8], c.Title, c.Severity, c.Confidence*100, c.Status, len(c.RelatedEventIDs)))

	ipSet := make(map[string]struct{})
	for _, evtID := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(evtID)
		if err != nil || evt == nil {
			continue
		}

		evtTypesSeen[strings.ToLower(evt.EventType)]++

		dstLabel := h.classifyDst(evt.DstIP, evt.EventType)
		if dstLabel == "" {
			if dev, ok := deviceMap[evt.DstIP]; ok {
				dstLabel = fmt.Sprintf("registry: label=%q trust=%s", dev.Label, dev.TrustLabel)
				ts.dstInRegistry = true
			} else {
				dstLabel = "unknown internal host"
			}
		}

		sb.WriteString(fmt.Sprintf("  evt type=%s src=%s dst=%s [%s] dport=%d proto=%s\n",
			evt.EventType, evt.SrcIP, evt.DstIP, dstLabel, evt.DstPort, evt.Protocol))
		if evt.SrcIP != "" {
			ipSet[evt.SrcIP] = struct{}{}
		}
	}

	// Determine dominant event type.
	total := 0
	for _, n := range evtTypesSeen {
		total += n
	}
	if total > 0 && evtTypesSeen["wan_new_connection"] == total {
		ts.isWANEdgeOnly = true
	}

	// ── Threat-feed enrichment ───────────────────────────────────────────────
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	if h.threat != nil && len(ips) > 0 {
		scores := h.threat.LookupMany(ips)
		if len(scores) > 0 {
			sb.WriteString("\nThreat feed verdicts:\n")
			for ip, s := range scores {
				tag := s.Tag()
				if tag != "" {
					sb.WriteString(fmt.Sprintf("  %s → %s\n", ip, tag))
				}
				if s.IsConfirmedMalicious() || s.IsTorExit {
					ts.logsConfirmMalicious = true
				}
			}
		}
	}

	// ── IPInfo geo/ASN enrichment ────────────────────────────────────────────
	if len(ips) > 0 {
		enriched := ipinfo.Enrich(ips)
		sb.WriteString("\nIP intel:\n")
		for ip, info := range enriched {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", ip, info.Summary()))
		}
	}

	return sb.String(), ts
}

// cmdCases posts a rich Block Kit card per case — severity colour, ID, title,
// confidence pill, event count, and a Report button. Fully deterministic.
func (h *Handler) cmdCases(channelID, userID string) {
	cases, err := h.store.ListCases("", 10)
	if err != nil || len(cases) == 0 {
		h.postEphemeral(channelID, userID, "No cases found.")
		return
	}

	// Count by severity for the header summary line.
	counts := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, c := range cases {
		counts[strings.ToLower(c.Severity)]++
	}

	headerText := fmt.Sprintf(
		"🔍  *ScanTrace — Active Cases*   %s %d HIGH  %s %d MED  %s %d LOW",
		"🔴", counts["high"], "🟡", counts["medium"], "🟢", counts["low"],
	)

	blocks := []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", "ScanTrace — Active Cases", false, false),
		),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", headerText, false, false),
			nil, nil,
		),
		slack.NewDividerBlock(),
	}

	for _, c := range cases {
		sev := strings.ToUpper(c.Severity)
		emoji := severityEmoji(c.Severity)
		shortID := c.CaseID[:8]
		conf := int(c.Confidence * 100)
		evtCount := len(c.RelatedEventIDs)

		// Confidence pill: filled squares as a visual bar (max 5 squares).
		filled := conf / 20
		if filled > 5 {
			filled = 5
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", 5-filled)
		confPill := fmt.Sprintf("`%s` %d%%", bar, conf)

		caseText := fmt.Sprintf(
			"%s  *[%s]* `%s`\n>%s\n>Confidence: %s   Events: *%d*",
			emoji, sev, shortID, c.Title, confPill, evtCount,
		)

		reportBtn := slack.NewButtonBlockElement(
			"scantrace_report_"+shortID,
			shortID,
			slack.NewTextBlockObject("plain_text", "📋 Report", false, false),
		)

		blocks = append(blocks,
			slack.NewSectionBlock(
				slack.NewTextBlockObject("mrkdwn", caseText, false, false),
				nil,
				slack.NewAccessory(reportBtn),
			),
			slack.NewDividerBlock(),
		)
	}

	// Footer hint.
	blocks = append(blocks,
		slack.NewContextBlock("",
			slack.NewTextBlockObject("mrkdwn",
				"Use `/scantrace report <id>` or `@ScanTrace case <id>` for a full briefing",
				false, false),
		),
	)

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
		port := extractFirstPort(report)
		eventCount := len(c.RelatedEventIDs)
		var update string
		if port != "" {
			update = fmt.Sprintf("%s [%s] Additional entry for Case ID: %s  Port: %s  Events: %d",
				severityEmoji(c.Severity), c.Title, c.CaseID[:8], port, eventCount)
		} else {
			update = fmt.Sprintf("%s [%s] Additional entry for Case ID: %s  Events: %d",
				severityEmoji(c.Severity), c.Title, c.CaseID[:8], eventCount)
		}
		h.postMessage(h.alertChannel, existingThread, update)
		log.Printf("[handler] thread reply for case %s to %s", c.CaseID[:8], h.alertChannel)
		return
	}

	blocks, err := blocksFromRaw(report.SlackBlock())
	var ts string
	if err != nil {
		text := fmt.Sprintf("%s *[%s] Case %s* — %s\nseverity=%s confidence=%.0f%%",
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

func extractFirstPort(report *casebuilder.CaseReport) string {
	if report == nil {
		return ""
	}
	for _, line := range strings.Split(report.Markdown, "\n") {
		if strings.Contains(line, "dport=") {
			for _, field := range strings.Fields(line) {
				if strings.HasPrefix(field, "dport=") {
					return strings.TrimPrefix(field, "dport=")
				}
			}
		}
	}
	return ""
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

	// Fast path: deterministic case-specific commands — no LLM involved.
	if h.handleMentionCaseCommand(channelID, userID, clean) {
		return
	}

	// Fast path: @ScanTrace cases — same rich card as /scantrace cases.
	if lower == "cases" {
		h.cmdCases(channelID, userID)
		return
	}

	if h.llm == nil {
		h.postEphemeral(channelID, userID, "LLM not configured. Use `/scantrace help` for available commands.")
		return
	}

	destChannel := h.externalThreatChannel
	h.postMessage(destChannel, "", "_Thinking…_")

	ctx := h.buildLLMContext()
	answer, err := h.llm.Ask(clean, ctx)
	if err != nil {
		log.Printf("[handler] llm error: %v", err)
		h.postMessage(destChannel, "",
			"⚠️ Could not reach the inference worker. Is the desktop running?\n"+
				"Use `/scantrace cases` or `/scantrace report <id>` in the meantime.")
		return
	}
	h.postMessage(destChannel, "", answer)
}

// handleMentionCaseCommand handles mention patterns that target a specific case:
//
//	@ScanTrace case <id>
//	@ScanTrace report <id>
//	@ScanTrace review case <id>
//
// Returns true if the command was recognised and handled (caller should return).
func (h *Handler) handleMentionCaseCommand(channelID, userID, clean string) bool {
	parts := strings.Fields(strings.ToLower(clean))
	if len(parts) < 2 {
		return false
	}

	rawParts := strings.Fields(clean)

	var caseIDPrefix string
	switch parts[0] {
	case "case", "report":
		caseIDPrefix = rawParts[1]
	case "review":
		if len(parts) >= 3 && parts[1] == "case" {
			caseIDPrefix = rawParts[2]
		} else {
			return false
		}
	default:
		return false
	}

	cases, _ := h.store.ListCases("", 50)
	var target *db.Case
	for _, c := range cases {
		if strings.HasPrefix(strings.ToLower(c.CaseID), strings.ToLower(caseIDPrefix)) {
			target = c
			break
		}
	}
	if target == nil {
		h.postMessage(channelID, "", fmt.Sprintf(
			"Case `%s` not found. Try `/scantrace cases` to list active cases.", caseIDPrefix,
		))
		return true
	}

	if h.llm == nil {
		h.postMessage(channelID, "", "LLM not configured.")
		return true
	}

	h.postMessage(channelID, "", fmt.Sprintf("_Briefing case: %s %s…_",
		severityEmoji(target.Severity), target.CaseID[:8]))

	go func() {
		ctx, triage := h.buildSingleCaseContext(target)
		actionPlan := selectActionPlan(triage)
		prompt := fmt.Sprintf(
			"Analyse this case and provide a full briefing.\n\nCase ID: %s",
			target.CaseID[:8],
		)
		answer, err := h.llm.AskCase(prompt, ctx, actionPlan)
		if err != nil {
			log.Printf("[handler] mention case llm error %s: %v", target.CaseID[:8], err)
			h.postMessage(channelID, "", fmt.Sprintf(
				"⚠️ Case %s — inference error: %v", target.CaseID[:8], err,
			))
			return
		}
		h.postMessage(channelID, "", fmt.Sprintf("*Case %s — Full Briefing*\n%s", target.CaseID[:8], answer))
	}()

	return true
}

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

	if len(ipSet) > 0 {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			if len(ips) >= 20 {
				break
			}
			ips = append(ips, ip)
		}
		if h.threat != nil {
			scores := h.threat.LookupMany(ips)
			if len(scores) > 0 {
				sb.WriteString("\nThreat feed verdicts:\n")
				for ip, s := range scores {
					if tag := s.Tag(); tag != "" {
						sb.WriteString(fmt.Sprintf("  %s → %s\n", ip, tag))
					}
				}
			}
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
• ` + "`/scantrace review-all`" + ` — queue all open cases for individual LLM briefings (posted to sec-intel-external)
• ` + "`/scantrace next`" + ` — briefing for the single highest-priority open case
• ` + "`/scantrace mcp`" + ` — MCP server status
• ` + "`/scantrace help`" + ` — this message

You can also @mention ScanTrace with a specific case or any natural language question:
• ` + "`@ScanTrace cases`" + ` — same rich case list
• ` + "`@ScanTrace case <id>`" + ` — full briefing for a specific case
• ` + "`@ScanTrace report <id>`" + ` — alias for case briefing
• ` + "`@ScanTrace review case <id>`" + ` — alias for case briefing
• ` + "`@ScanTrace <any question>`" + ` — natural language security analysis

Example: _@ScanTrace case 7f3a21c9_`
}
