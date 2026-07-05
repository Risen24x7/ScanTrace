// Package handler dispatches Slack Socket Mode events to the appropriate handler.
package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/ipinfo"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/llm"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/portintel"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/threat"
	"github.com/google/uuid"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"
)

// mentionRE strips all <@UXXXXXXXX> mention tokens from a Slack message.
var mentionPattern = regexp.MustCompile(`<@[A-Z0-9]+>`)

func mentionRE(text string) string {
	return mentionPattern.ReplaceAllString(text, "")
}

type Handler struct {
	api                   *slack.Client
	store                 *db.DB
	alertChannel          string
	externalThreatChannel string
	wanIP                 string
	rts                   *rts.Client
	llm                   *llm.Client
	threat                *threat.Enricher
	benignScanners        *threat.BenignScanners
	portIntel             *portintel.Store

	mu          sync.Mutex
	caseThreads map[string]string
}

func New(api *slack.Client, store *db.DB, alertChannel, externalThreatChannel, wanIP string, rtsClient *rts.Client, llmClient *llm.Client) *Handler {
	h := &Handler{
		api:                   api,
		store:                 store,
		alertChannel:          alertChannel,
		externalThreatChannel: externalThreatChannel,
		wanIP:                 wanIP,
		rts:                   rtsClient,
		llm:                   llmClient,
		threat:                threat.New("", ""),
		benignScanners:        threat.NewBenignScanners(""),
		caseThreads:           make(map[string]string),
	}
	pi, err := portintel.Open("")
	if err != nil {
		log.Printf("[handler] portintel store unavailable (port-trends disabled): %v", err)
	} else {
		h.portIntel = pi
	}
	return h
}

// triageState captures pre-evaluated facts injected into the LLM prompt.
type triageState struct {
	isWANEdgeOnly        bool
	hasWANForward        bool
	dstInRegistry        bool
	logsConfirmMalicious bool
	isBenignScanner      bool
	ipsumTier            int
	dstLabel             string
	evtSummary           string
}

func selectActionPlan(ts triageState) string {
	switch {
	case ts.ipsumTier >= threat.TierBlacklisted:
		return "*Recommended Actions*\nCondition Matched: F — source universally blacklisted (IPSum score ≥6, majority of feeds agree)\n" +
			"- [VERDICT: LIKELY MALICIOUS] Source is blacklisted across the majority of independent threat-feed sources.\n" +
			"- Block the source IP or subnet at the gateway firewall immediately.\n" +
			"- Close or restrict the targeted port if no external access is required.\n" +
			"- Escalate to a human analyst if the internal host shows any signs of compromise."
	case ts.isBenignScanner:
		return "*Recommended Actions*\nCondition Matched: E — source is a known benign research scanner (Shodan / Censys / Shadowserver / similar)\n" +
			"- [VERDICT: LIKELY BENIGN] This traffic originates from a well-known, opt-outable internet scanning service.\n" +
			"- No blocking required. These scanners perform routine internet-wide surveys.\n" +
			"- If you wish to suppress future alerts from this source, add the IP/CIDR to /opt/scantrace/benign-scanners.txt.\n" +
			"- Review only if the scan volume is unusually high (>50 events/hour from the same IP)."
	case ts.logsConfirmMalicious:
		return "*Recommended Actions*\nCondition Matched: D — host verified, logs confirm malicious activity\n" +
			"- Block the source IP or subnet at the gateway firewall.\n" +
			"- Close or restrict the targeted port if no external access is required.\n" +
			"- Escalate to a human analyst if the internal host shows any signs of compromise."
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

func buildTriageBlock(ts triageState, portsSeen []string) string {
	blacklistNote := ""
	switch {
	case ts.ipsumTier >= threat.TierBlacklisted:
		blacklistNote = "\n- Source threat tier? [UNIVERSALLY BLACKLISTED — IPSum score ≥6, majority of independent feeds agree]"
	case ts.isBenignScanner:
		blacklistNote = "\n- Source threat tier? [BENIGN SCANNER — known research scanner, opt-outable]"
	case ts.logsConfirmMalicious:
		blacklistNote = "\n- Source threat tier? [CONFIRMED MALICIOUS — threat feed verified]"
	}
	return fmt.Sprintf(
		"- Dst host in registry? [%s]\n- Event type(s)? [%s]\n- Ports targeted? [%s]%s",
		ts.dstLabel, ts.evtSummary, strings.Join(portsSeen, ", "), blacklistNote,
	)
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
	case socketmode.EventTypeInteractive:
		interaction, ok := evt.Data.(slack.InteractionCallback)
		if !ok {
			client.Ack(*evt.Request)
			return
		}
		client.Ack(*evt.Request)
		h.handleBlockAction(interaction)
	}
}

// handleEvent routes Slack EventsAPI events.
func (h *Handler) handleEvent(event slackevents.EventsAPIEvent) {
	switch event.Type {
	case slackevents.CallbackEvent:
		inner := event.InnerEvent
		switch ev := inner.Data.(type) {
		case *slackevents.AppMentionEvent:
			go h.handleMention(ev.Channel, ev.TimeStamp, ev.ThreadTimeStamp, mentionRE(ev.Text))
		}
	}
}

// handleMention processes @ScanTrace mentions.
//
// Routing rules:
//   - "case <id>"  → full Block Kit report, posted top-level in the alert channel
//   - general Q&A → LLM answer posted as a reply in the existing case thread if
//     the mention itself arrived inside a case thread; otherwise top-level reply
//     in the channel where the mention was received.
func (h *Handler) handleMention(channel, ts, threadTS, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		h.postMessage(channel, ts, "Hi! Ask me about a case: `@ScanTrace case <id>` or just ask a question.")
		return
	}

	lower := strings.ToLower(text)

	// Explicit "case <id>" — post a full report top-level.
	if strings.HasPrefix(lower, "case ") {
		parts := strings.Fields(text)
		if len(parts) >= 2 {
			h.cmdReport(channel, "", parts[1])
			return
		}
	}

	if h.llm == nil {
		h.postMessage(channel, ts, "LLM not configured — I can't answer questions right now.")
		return
	}

	// Determine the reply thread.
	// If the mention arrived inside an existing thread, reply there.
	// Otherwise reply in-thread under the mention message itself.
	replyThread := threadTS
	if replyThread == "" {
		replyThread = ts
	}

	// Try to resolve case context from the thread we're in.
	var caseCtx string
	h.mu.Lock()
	for caseID, caseTS := range h.caseThreads {
		if caseTS == replyThread {
			// We're inside this case's thread — load its context.
			cases, _ := h.store.ListCases("", 50)
			for _, c := range cases {
				if strings.HasPrefix(c.CaseID, caseID) {
					ctx, _, _ := h.buildSingleCaseContext(c)
					caseCtx = ctx
					break
				}
			}
			break
		}
	}
	h.mu.Unlock()

	// Fall back to a summary of recent cases if no specific case thread matched.
	if caseCtx == "" {
		cases, _ := h.store.ListCases("", 5)
		var ctxLines []string
		for _, c := range cases {
			ctxLines = append(ctxLines, fmt.Sprintf("case id=%s title=%q sev=%s status=%s",
				c.CaseID[:8], c.Title, c.Severity, c.Status))
		}
		caseCtx = strings.Join(ctxLines, "\n")
	}

	answer, err := h.llm.AskCase(text, caseCtx, "", "")
	if err != nil {
		log.Printf("[handler] mention llm error: %v", err)
		h.postMessage(channel, replyThread, fmt.Sprintf("⚠️ Inference error: %v", err))
		return
	}
	h.postMessage(channel, replyThread, answer)
}

func (h *Handler) subscribeRTS() {
	_, err := h.rts.Subscribe(rts.SignalAppMention, "scantrace-mention")
	if err != nil {
		log.Printf("[rts] subscribe skipped: %v", err)
		return
	}
	log.Printf("[rts] signal subscriptions active")
}

// splitArgs splits command text into tokens, respecting double-quoted strings.
func splitArgs(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func (h *Handler) handleSlashCommand(cmd slack.SlashCommand) {
	parts := splitArgs(strings.TrimSpace(cmd.Text))
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
	case "close":
		if len(parts) < 2 {
			h.postEphemeral(cmd.ChannelID, cmd.UserID, "Usage: `/scantrace close <case-id>`")
			return
		}
		h.cmdCloseCase(cmd.ChannelID, cmd.UserID, parts[1])
	case "reopen":
		if len(parts) < 2 {
			h.postEphemeral(cmd.ChannelID, cmd.UserID, "Usage: `/scantrace reopen <case-id>`")
			return
		}
		h.cmdReopenCase(cmd.ChannelID, cmd.UserID, parts[1])
	case "alert":
		h.cmdPostLatestAlert(cmd.ChannelID)
	case "devices":
		h.cmdDevices(cmd.ChannelID, cmd.UserID)
	case "adddevice":
		h.cmdAddDevice(cmd.ChannelID, cmd.UserID, parts[1:])
	case "removedevice":
		if len(parts) < 2 {
			h.postEphemeral(cmd.ChannelID, cmd.UserID, "Usage: `/scantrace removedevice <ip>`")
			return
		}
		h.cmdRemoveDevice(cmd.ChannelID, cmd.UserID, parts[1])
	case "review-all":
		h.cmdReviewAll(cmd.ChannelID, cmd.UserID, parts[1:])
	case "export-blocklist":
		h.cmdExportBlocklist(cmd.ChannelID, cmd.UserID, parts[1:])
	case "next":
		h.cmdNext(cmd.ChannelID, cmd.UserID)
	case "port-trends":
		h.cmdPortTrends(cmd.ChannelID, cmd.UserID, parts[1:])
	case "mcp":
		h.postEphemeral(cmd.ChannelID, cmd.UserID,
			"*MCP Server* is running on `localhost:8765`\n"+
				"Tools: `list_cases`, `get_case`, `list_sensors`, `get_entity`, `list_known_devices`\n"+
				"Connect any MCP host (Claude Desktop, Cursor) to `http://localhost:8765`")
	case "status":
		h.cmdStatus(cmd.ChannelID, cmd.UserID)
	default:
		h.postEphemeral(cmd.ChannelID, cmd.UserID, helpText())
	}
}

func (h *Handler) handleBlockAction(cb slack.InteractionCallback) {
	for _, action := range cb.ActionCallback.BlockActions {
		actionID := action.ActionID
		channelID := cb.Channel.ID
		userID := cb.User.ID
		switch {
		case strings.HasPrefix(actionID, "scantrace_close_"):
			h.cmdCloseCase(channelID, userID, strings.TrimPrefix(actionID, "scantrace_close_"))
		case strings.HasPrefix(actionID, "scantrace_reopen_"):
			h.cmdReopenCase(channelID, userID, strings.TrimPrefix(actionID, "scantrace_reopen_"))
		case strings.HasPrefix(actionID, "scantrace_report_"):
			h.cmdReport(channelID, userID, strings.TrimPrefix(actionID, "scantrace_report_"))
		}
	}
}

func (h *Handler) cmdStatus(channelID, userID string) {
	// Basic counts
	cases, _ := h.store.ListCases("", 50)
	counts := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, c := range cases {
		counts[strings.ToLower(c.Severity)]++
	}
	port := os.Getenv("SCANTRACE_SYSLOG_PORT")
	if port == "" {
		port = "5140"
	}
	llmBase := os.Getenv("LLM_BASE_URL")
	llmModel := os.Getenv("LLM_MODEL")
	llmLine := "LLM: not configured"
	if llmBase != "" || llmModel != "" {
		if llmModel != "" {
			llmLine = fmt.Sprintf("LLM: %s (model=%s)", llmBase, llmModel)
		} else {
			llmLine = fmt.Sprintf("LLM: %s", llmBase)
		}
	}
	text := fmt.Sprintf("*ScanTrace Status*\n• DB: OK\n• Cases — 🔴 %d  🟡 %d  🟢 %d\n• Syslog: UDP :%s\n• WAN IP: %s (enrichment suppressed)\n• %s\n• Alerts channel: %s",
		counts["high"], counts["medium"], counts["low"], port, h.wanIP, llmLine, h.alertChannel)
	blocks := []slack.Block{
		slack.NewSectionBlock(slack.NewTextBlockObject("mrkdwn", text, false, false), nil, nil),
	}
	h.postBlocks(channelID, "", blocks)
}

// classifyDst determines whether the destination is the WAN edge interface.
// When it is, the label explicitly notes that provider/org attribution for the
// destination IP should be ignored — it belongs to the operator's own perimeter.
func (h *Handler) classifyDst(dstIP, eventType string) (label string, isWANEdge bool) {
	switch strings.ToLower(eventType) {
	case "wan_new_connection":
		return "WAN EDGE — gateway interface only (destination is your perimeter, ignore ISP/org attribution)", true
	case "wan_forward":
		if h.wanIP != "" && dstIP == h.wanIP {
			return "WAN EDGE — gateway interface only (destination is your perimeter, ignore ISP/org attribution)", true
		}
		return "", false
	default:
		if h.wanIP != "" && dstIP == h.wanIP {
			return "WAN EDGE — gateway interface only (destination is your perimeter, ignore ISP/org attribution)", true
		}
		return "", false
	}
}

func (h *Handler) buildSingleCaseContext(c *db.Case) (string, triageState, []string) {
	var sb strings.Builder
	var ts triageState

	evtTypeCount := make(map[string]int)
	var portsSeen []string
	portSet := make(map[int]struct{})

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
	type evtRow struct {
		evtType  string
		srcIP    string
		dstIP    string
		dstPort  int
		proto    string
		dstLabel string
	}
	var rows []evtRow
	var hitRecords []portintel.HitRecord

	for _, evtID := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(evtID)
		if err != nil || evt == nil {
			continue
		}
		key := strings.ToLower(evt.EventType)
		evtTypeCount[key]++
		dstLabel, isEdge := h.classifyDst(evt.DstIP, evt.EventType)
		if !isEdge {
			if dev, ok := deviceMap[evt.DstIP]; ok {
				dstLabel = fmt.Sprintf("registry: label=%q trust=%s", dev.Label, dev.TrustLabel)
				ts.dstInRegistry = true
			} else if dstLabel == "" {
				dstLabel = "unknown internal host"
			}
			ts.hasWANForward = true
		}
		if evt.DstPort > 0 {
			if _, seen := portSet[evt.DstPort]; !seen {
				portSet[evt.DstPort] = struct{}{}
				portsSeen = append(portsSeen, fmt.Sprintf("%d", evt.DstPort))
			}
			if evt.SrcIP != "" {
				hitRecords = append(hitRecords, portintel.HitRecord{
					Port:      evt.DstPort,
					SrcIP:     evt.SrcIP,
					EventType: evt.EventType,
				})
			}
		}
		rows = append(rows, evtRow{
			evtType:  evt.EventType,
			srcIP:    evt.SrcIP,
			dstIP:    evt.DstIP,
			dstPort:  evt.DstPort,
			proto:    evt.Protocol,
			dstLabel: dstLabel,
		})
		// Always collect the source IP for enrichment.
		// Only collect the destination IP for enrichment when it is NOT the WAN
		// edge interface — the WAN IP belongs to the operator and would produce
		// misleading ISP/org attribution in the LLM context.
		if evt.SrcIP != "" {
			ipSet[evt.SrcIP] = struct{}{}
		}
		if evt.DstIP != "" && evt.DstIP != h.wanIP {
			ipSet[evt.DstIP] = struct{}{}
		}
	}

	if len(hitRecords) > 0 {
		go h.recordPortHits(hitRecords)
	}

	total := 0
	for _, n := range evtTypeCount {
		total += n
	}
	if total > 0 && evtTypeCount["wan_new_connection"] == total {
		ts.isWANEdgeOnly = true
	}

	var evtParts []string
	for typ, n := range evtTypeCount {
		evtParts = append(evtParts, fmt.Sprintf("%s (%d)", typ, n))
	}
	ts.evtSummary = strings.Join(evtParts, ", ")

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	var threatLines []string
	if h.benignScanners != nil {
		for _, ip := range ips {
			if h.benignScanners.IsBenignScanner(ip) {
				ts.isBenignScanner = true
				threatLines = append(threatLines, fmt.Sprintf(
					"Benign scanner detected: %s → known research scanner (Shodan/Censys/Shadowserver/similar)", ip,
				))
				break
			}
		}
	}

	var threatFeedLines []string
	if h.threat != nil && len(ips) > 0 {
		scores := h.threat.LookupMany(ips)
		for ip, s := range scores {
			if tag := s.Tag(); tag != "" {
				threatFeedLines = append(threatFeedLines, fmt.Sprintf("  %s → %s", ip, tag))
			}
			if s.IsConfirmedMalicious() || s.IsTorExit {
				ts.logsConfirmMalicious = true
			}
			if tier := s.Tier(); tier > ts.ipsumTier {
				ts.ipsumTier = tier
			}
		}
	}

	if ts.isWANEdgeOnly {
		ts.dstLabel = fmt.Sprintf("%s [WAN EDGE — gateway interface only]", h.wanIP)
	} else if ts.hasWANForward && ts.dstInRegistry {
		ts.dstLabel = "YES — registered internal device"
	} else if ts.hasWANForward {
		ts.dstLabel = "NO — unknown internal host"
	} else {
		ts.dstLabel = "MIXED — see event list below"
	}

	blacklistNote := ""
	switch {
	case ts.ipsumTier >= threat.TierBlacklisted:
		blacklistNote = "\n- Source threat tier? [UNIVERSALLY BLACKLISTED — IPSum score ≥6, majority of independent feeds agree]"
	case ts.isBenignScanner:
		blacklistNote = "\n- Source threat tier? [BENIGN SCANNER — known research scanner, opt-outable]"
	case ts.logsConfirmMalicious:
		blacklistNote = "\n- Source threat tier? [CONFIRMED MALICIOUS — threat feed verified]"
	}

	sb.WriteString(fmt.Sprintf(
		"\nTriage:\n"+
			"- Dst host in registry? [%s]\n"+
			"- Event type(s)? [%s]\n"+
			"- Ports targeted? [%s]%s\n",
		ts.dstLabel, ts.evtSummary, strings.Join(portsSeen, ", "), blacklistNote,
	))

	for _, r := range rows {
		// dstLabel is authoritative: for WAN-edge events it always reads
		// "WAN EDGE — gateway interface only (destination is your perimeter,
		// ignore ISP/org attribution)" which prevents the LLM from treating
		// the operator's own WAN IP as a remote target.
		sb.WriteString(fmt.Sprintf("  evt type=%s src=%s dst=%s [%s] dport=%d proto=%s\n",
			r.evtType, r.srcIP, r.dstIP, r.dstLabel, r.dstPort, r.proto))
	}
	for _, line := range threatLines {
		sb.WriteString("\n" + line + "\n")
	}
	if len(threatFeedLines) > 0 {
		sb.WriteString("\nThreat feed verdicts:\n")
		for _, line := range threatFeedLines {
			sb.WriteString(line + "\n")
		}
	}
	if advisory := h.portIntelAdvisory(portsSeenInts(portSet)); advisory != "" {
		sb.WriteString("\n" + advisory + "\n")
	}
	if len(ips) > 0 {
		enriched := ipinfo.Enrich(ips)
		sb.WriteString("\nIP intel:\n")
		for ip, info := range enriched {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", ip, info.Summary()))
		}
	}

	return sb.String(), ts, portsSeen
}

func portsSeenInts(portSet map[int]struct{}) []int {
	out := make([]int, 0, len(portSet))
	for p := range portSet {
		out = append(out, p)
	}
	return out
}

func (h *Handler) caseSrcIPs(c *db.Case) []string {
	seen := make(map[string]struct{})
	for _, evtID := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(evtID)
		if err != nil || evt == nil || evt.SrcIP == "" {
			continue
		}
		seen[evt.SrcIP] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	return out
}

func ipClassificationBadges(ips []string) []string {
	if len(ips) == 0 {
		return nil
	}
	enriched := ipinfo.Enrich(ips)
	seen := make(map[string]struct{})
	var badges []string
	for _, info := range enriched {
		b := info.ClassBadge()
		if b == "" {
			continue
		}
		if _, ok := seen[b]; ok {
			continue
		}
		seen[b] = struct{}{}
		badges = append(badges, b)
	}
	return badges
}

func (h *Handler) cmdCases(channelID, userID string) {
	cases, err := h.store.ListCases("", 10)
	if err != nil || len(cases) == 0 {
		h.postEphemeral(channelID, userID, "No cases found.")
		return
	}
	counts := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, c := range cases {
		counts[strings.ToLower(c.Severity)]++
	}
	headerText := fmt.Sprintf(
		"🔍  *ScanTrace — Active Cases*   🔴 %d HIGH  🟡 %d MED  🟢 %d LOW",
		counts["high"], counts["medium"], counts["low"],
	)
	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject("plain_text", "ScanTrace — Active Cases", false, false)),
		slack.NewSectionBlock(slack.NewTextBlockObject("mrkdwn", headerText, false, false), nil, nil),
		slack.NewDividerBlock(),
	}
	for _, c := range cases {
		sev := strings.ToUpper(c.Severity)
		emoji := severityEmoji(c.Severity)
		shortID := c.CaseID[:8]
		conf := int(c.Confidence * 100)
		evtCount := len(c.RelatedEventIDs)
		filled := conf / 20
		if filled > 5 {
			filled = 5
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", 5-filled)
		confPill := fmt.Sprintf("`%s` %d%%", bar, conf)
		srcIPs := h.caseSrcIPs(c)
		badges := ipClassificationBadges(srcIPs)
		badgeLine := ""
		if len(badges) > 0 {
			badgeLine = "\n>" + strings.Join(badges, "  ·  ")
		}
		statusTag := ""
		if !strings.EqualFold(c.Status, "open") {
			statusTag = fmt.Sprintf(" `%s`", strings.ToUpper(c.Status))
		}
		caseText := fmt.Sprintf(
			"%s  *[%s]* `%s`%s\n>%s\n>Confidence: %s   Events: *%d*%s",
			emoji, sev, shortID, statusTag, c.Title, confPill, evtCount, badgeLine,
		)
		reportBtn := slack.NewButtonBlockElement(
			"scantrace_report_"+shortID, shortID,
			slack.NewTextBlockObject("plain_text", "📋 Report", false, false),
		)
		blocks = append(blocks,
			slack.NewSectionBlock(
				slack.NewTextBlockObject("mrkdwn", caseText, false, false),
				nil, slack.NewAccessory(reportBtn),
			),
			slack.NewDividerBlock(),
		)
	}
	blocks = append(blocks,
		slack.NewContextBlock("",
			slack.NewTextBlockObject("mrkdwn",
				"Use `/scantrace report <id>` · `/scantrace close <id>` · `/scantrace reopen <id>` · `@ScanTrace case <id>`",
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
		slack.NewSectionBlock(slack.NewTextBlockObject("mrkdwn", strings.Join(lines, "\n"), false, false), nil, nil),
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
	blocks, err := blocksFromMap(report.SlackBlock())
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

// findPriorObservation returns a permalink to a prior case thread with overlapping src_ip.
func (h *Handler) findPriorObservation(c *db.Case) (link, shortID string, count int) {
	cur := make(map[string]struct{})
	for _, ip := range h.caseSrcIPs(c) {
		cur[ip] = struct{}{}
	}
	if len(cur) == 0 {
		return "", "", 0
	}
	cases, _ := h.store.ListCases("", 50)
	for _, pc := range cases {
		if pc.CaseID == c.CaseID {
			continue
		}
		priorIPs := h.caseSrcIPs(pc)
		matched := false
		for _, ip := range priorIPs {
			if _, ok := cur[ip]; ok {
				matched = true
				break
			}
		}
		if matched {
			count++
			// Read the thread timestamp under the mutex to avoid a data race
			// with concurrent PostCaseAlert writers touching h.caseThreads.
			h.mu.Lock()
			threadTS := h.caseThreads[pc.CaseID]
			h.mu.Unlock()
			if threadTS != "" && link == "" {
				if pl, err := h.api.GetPermalink(&slack.PermalinkParameters{Channel: h.alertChannel, Ts: threadTS}); err == nil {
					link = pl
					shortID = pc.CaseID[:8]
				}
			}
		}
	}
	return
}

func prependPriorObservation(blocks []slack.Block, link, shortID string, count int) []slack.Block {
	if link == "" || count == 0 {
		return blocks
	}
	note := fmt.Sprintf("⚠️ Previously observed — %d prior mention(s). See <%s|Case %s>", count, link, shortID)
	ctx := slack.NewContextBlock("", slack.NewTextBlockObject("mrkdwn", note, false, false))
	return append([]slack.Block{ctx, slack.NewDividerBlock()}, blocks...)
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

	blocks, bErr := blocksFromMap(report.SlackBlock())
	// Prepend prior-observed context if available
	if link, sid, cnt := h.findPriorObservation(c); link != "" {
		blocks = prependPriorObservation(blocks, link, sid, cnt)
	}

	var ts string
	var errPost error
	if bErr != nil || len(blocks) == 0 {
		text := fmt.Sprintf("%s *[%s] Case %s* — %s\nseverity=%s confidence=%.0f%%",
			severityEmoji(c.Severity), strings.ToUpper(c.Severity),
			c.CaseID[:8], c.Title, c.Severity, c.Confidence*100)
		if link, sid, cnt := h.findPriorObservation(c); link != "" {
			text = fmt.Sprintf("⚠️ Previously observed — %d prior mention(s). See Case %s: %s\n%s", cnt, sid, link, text)
		}
		_, ts, errPost = h.api.PostMessage(h.alertChannel,
			slack.MsgOptionText(text, false),
			slack.MsgOptionDisableLinkUnfurl(),
		)
	} else {
		_, ts, errPost = h.api.PostMessage(h.alertChannel,
			slack.MsgOptionBlocks(blocks...),
			slack.MsgOptionDisableLinkUnfurl(),
		)
	}
	if errPost != nil {
		log.Printf("[handler] PostCaseAlert error: %v", errPost)
		return
	}
	h.mu.Lock()
	h.caseThreads[c.CaseID] = ts
	h.mu.Unlock()
	log.Printf("[handler] case alert posted case=%s ts=%s", c.CaseID[:8], ts)
}

func helpText() string {
	return `*ScanTrace — Slash Commands*
` + "```" + `
/scantrace cases              — List the latest open cases
/scantrace report <id>        — Full Block Kit report for a case
/scantrace close <id>         — Mark a case closed
/scantrace reopen <id>        — Reopen a closed case
/scantrace alert              — Re-post the latest high/open case alert
/scantrace next               — LLM briefing for the next highest-priority case
/scantrace review-all [--limit N] [--since 24h] [--severity red,yellow] [--exclude-wan-only] [--dedupe]
                              — Queue open cases for LLM review (filters optional)
/scantrace export-blocklist [--limit N] [--since 7d] [--severity red,yellow] [--wan-only] [--group-cidr] [--format txt|csv|ipset]
                              — Export a firewall blocklist from recent cases
/scantrace devices            — List the known device registry
/scantrace adddevice <ip> [label="..."] [trust=trusted|unknown|suspicious] [suppress=true]
/scantrace removedevice <ip>  — Remove a device from the registry
/scantrace port-trends [days] — Perimeter port intelligence report (default: 7 days)
/scantrace mcp                — Show MCP server info
/scantrace status             — Show agent liveness and configuration summary
` + "```" + `
You can also @mention ScanTrace in any channel to ask questions about cases.`
}

func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
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

func trustEmoji(trust string) string {
	switch strings.ToLower(trust) {
	case "trusted":
		return "✅"
	case "suspicious":
		return "⚠️"
	default:
		return "❓"
	}
}

// extractFirstPort scans the report Markdown for a "Port:" line.
func extractFirstPort(report *casebuilder.CaseReport) string {
	if report == nil {
		return ""
	}
	for _, line := range strings.Split(report.Markdown, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Port:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func blocksFromMap(m map[string]interface{}) ([]slack.Block, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Blocks []json.RawMessage `json:"blocks"`
	}
	if err := json.Unmarshal(b, &wrapper); err != nil {
		return nil, err
	}
	blocks := make([]slack.Block, 0, len(wrapper.Blocks))
	for _, raw := range wrapper.Blocks {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &typed); err != nil {
			continue
		}
		switch typed.Type {
		case "header":
			var blk slack.HeaderBlock
			if json.Unmarshal(raw, &blk) == nil {
				blocks = append(blocks, &blk)
			}
		case "section":
			var blk slack.SectionBlock
			if json.Unmarshal(raw, &blk) == nil {
				blocks = append(blocks, &blk)
			}
		case "divider":
			blocks = append(blocks, slack.NewDividerBlock())
		case "context":
			var blk slack.ContextBlock
			if json.Unmarshal(raw, &blk) == nil {
				blocks = append(blocks, &blk)
			}
		case "actions":
			var blk slack.ActionBlock
			if json.Unmarshal(raw, &blk) == nil {
				blocks = append(blocks, &blk)
			}
		}
	}
	return blocks, nil
}

func (h *Handler) postMessage(channel, thread, text string) {
	opts := []slack.MsgOption{
		slack.MsgOptionText(text, false),
		slack.MsgOptionDisableLinkUnfurl(),
	}
	if thread != "" {
		opts = append(opts, slack.MsgOptionTS(thread))
	}
	if _, _, err := h.api.PostMessage(channel, opts...); err != nil {
		log.Printf("[handler] postMessage error channel=%s: %v", channel, err)
	}
}

func (h *Handler) postBlocks(channel, thread string, blocks []slack.Block) {
	opts := []slack.MsgOption{
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionDisableLinkUnfurl(),
	}
	if thread != "" {
		opts = append(opts, slack.MsgOptionTS(thread))
	}
	if _, _, err := h.api.PostMessage(channel, opts...); err != nil {
		log.Printf("[handler] postBlocks error channel=%s: %v", channel, err)
	}
}

func (h *Handler) postEphemeral(channel, userID, text string) {
	if _, err := h.api.PostEphemeral(channel, userID, slack.MsgOptionText(text, false)); err != nil {
		log.Printf("[handler] postEphemeral error: %v", err)
	}
}

func (h *Handler) postCaseBriefingWithActions(channel, shortID, text string) {
	closeBtn := slack.NewButtonBlockElement(
		"scantrace_close_"+shortID, shortID,
		slack.NewTextBlockObject("plain_text", "✅ Close", false, false),
	)
	reportBtn := slack.NewButtonBlockElement(
		"scantrace_report_"+shortID, shortID,
		slack.NewTextBlockObject("plain_text", "📋 Report", false, false),
	)
	blocks := []slack.Block{
		slack.NewSectionBlock(slack.NewTextBlockObject("mrkdwn", text, false, false), nil, nil),
		slack.NewActionBlock("", closeBtn, reportBtn),
	}
	h.postBlocks(channel, "", blocks)
}

// ── Device & review commands (restored from main) ──────────────────────────
func (h *Handler) cmdAddDevice(channelID, userID string, args []string) {
	if len(args) == 0 {
		h.postEphemeral(channelID, userID,
			"Usage: `/scantrace adddevice <ip> [label=\"My Device\"] [trust=trusted|unknown|suspicious] [suppress=true]`\n"+
				"Examples:\n"+
				"• `/scantrace adddevice 192.168.50.4 label=\"Plex Server\" trust=trusted`\n"+
				"• `/scantrace adddevice 192.168.50.4 trust=suspicious`")
		return
	}
	ipArg := args[0]
	if net.ParseIP(ipArg) == nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf("`%s` is not a valid IP address.", ipArg))
		return
	}
	label := ipArg
	trustLabel := "unknown"
	autoSuppress := false
	for _, arg := range args[1:] {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "label":
			label = val
		case "trust":
			switch strings.ToLower(val) {
			case "trusted", "unknown", "suspicious":
				trustLabel = strings.ToLower(val)
			default:
				h.postEphemeral(channelID, userID,
					fmt.Sprintf("Invalid trust value `%s`. Use: `trusted`, `unknown`, or `suspicious`.", val))
				return
			}
		case "suppress":
			autoSuppress = strings.ToLower(val) == "true"
		}
	}
	existing, _ := h.store.GetKnownDeviceByIP(ipArg)
	now := time.Now().UTC()
	deviceID := uuid.NewString()
	if existing != nil {
		deviceID = existing.DeviceID
	}
	d := &db.KnownDevice{
		DeviceID:     deviceID,
		IP:           ipArg,
		Label:        label,
		TrustLabel:   trustLabel,
		AutoSuppress: autoSuppress,
		FirstSeen:    now,
		LastSeen:     now,
	}
	if existing != nil && !existing.FirstSeen.IsZero() {
		d.FirstSeen = existing.FirstSeen
	}
	if err := h.store.UpsertKnownDevice(d); err != nil {
		log.Printf("[handler] adddevice upsert error ip=%s label=%q: %v", ipArg, label, err)
		h.postEphemeral(channelID, userID, fmt.Sprintf("❌ Failed to save device `%s`: %v", ipArg, err))
		return
	}
	action := "✅ Device *added* to registry"
	if existing != nil {
		action = "✏️ Device *updated* in registry"
	}
	suppressLine := ""
	if autoSuppress {
		suppressLine = "\n• Auto-suppress: *on* (low-severity cases for this host will be silenced)"
	}
	h.postMessage(channelID, "", fmt.Sprintf(
		"%s\n• IP: `%s`\n• Label: *%s*\n• Trust: `%s`%s\n\nRe-run `/scantrace report <case-id>` or `@ScanTrace case <id>` to see the updated classification.",
		action, ipArg, label, trustLabel, suppressLine,
	))
	log.Printf("[handler] adddevice ip=%s label=%q trust=%s suppress=%v by user=%s",
		ipArg, label, trustLabel, autoSuppress, userID)
}

func (h *Handler) cmdRemoveDevice(channelID, userID, ipArg string) {
	existing, _ := h.store.GetKnownDeviceByIP(ipArg)
	if existing == nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf("Device `%s` not found in registry.", ipArg))
		return
	}
	if err := h.store.DeleteKnownDevice(existing.DeviceID); err != nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf("Failed to remove device: %v", err))
		return
	}
	h.postMessage(channelID, "", fmt.Sprintf(
		"🗑️ Device `%s` (*%s*) removed from registry.", ipArg, existing.Label,
	))
	log.Printf("[handler] removedevice ip=%s label=%q by user=%s", ipArg, existing.Label, userID)
}

func (h *Handler) cmdReviewAll(channelID, userID string, args []string) {
	if h.llm == nil {
		h.postEphemeral(channelID, userID, "LLM not configured.")
		return
	}

	opts, err := parseReviewAllFlags(args)
	if err != nil {
		h.postEphemeral(channelID, userID, reviewAllUsage(err))
		return
	}
	hasFlags := len(args) > 0

	// Preserve the original behaviour when no flags are supplied: pull the most
	// recent 50 cases and queue them all. With flags, pull a larger pool so the
	// filters have enough cases to work over.
	poolLimit := 50
	if hasFlags {
		poolLimit = 200
	}
	cases, err := h.store.ListCases("", poolLimit)
	if err != nil || len(cases) == 0 {
		h.postEphemeral(channelID, userID, "No open cases found.")
		return
	}

	if hasFlags {
		cases = h.filterReviewCases(cases, opts)
		if len(cases) == 0 {
			h.postEphemeral(channelID, userID,
				fmt.Sprintf("No cases match %s", opts.filterSummary()))
			return
		}
	}

	dest := h.externalThreatChannel
	h.postMessage(dest, "", fmt.Sprintf("_Queuing %d cases for review — posting one at a time…_", len(cases)))
	go func() {
		for i, c := range cases {
			ctx, triage, portsSeen := h.buildSingleCaseContext(c)
			triageBlock := buildTriageBlock(triage, portsSeen)
			actionPlan := selectActionPlan(triage)
			prompt := fmt.Sprintf("Analyse this single case and provide a full briefing.\n\nCase ID: %s", c.CaseID[:8])
			answer, err := h.llm.AskCase(prompt, ctx, triageBlock, actionPlan)
			if err != nil {
				log.Printf("[handler] review-all llm error case %s: %v", c.CaseID[:8], err)
				h.postMessage(dest, "", fmt.Sprintf("⚠️ Case %s — inference error: %v", c.CaseID[:8], err))
			} else {
				h.postCaseBriefingWithActions(dest, c.CaseID[:8], fmt.Sprintf("*Case %d/%d — %s*\n%s", i+1, len(cases), c.CaseID[:8], answer))
			}
			if i < len(cases)-1 {
				time.Sleep(3 * time.Second)
			}
		}
		h.postMessage(dest, "", fmt.Sprintf("_Review complete — %d cases processed._", len(cases)))
	}()
}

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
	h.postMessage(dest, "", fmt.Sprintf("_Briefing next case: %s %s…_", severityEmoji(target.Severity), target.CaseID[:8]))
	go func() {
		ctx, triage, portsSeen := h.buildSingleCaseContext(target)
		triageBlock := buildTriageBlock(triage, portsSeen)
		actionPlan := selectActionPlan(triage)
		prompt := fmt.Sprintf("Analyse this case and provide a full briefing.\n\nCase ID: %s", target.CaseID[:8])
		answer, err := h.llm.AskCase(prompt, ctx, triageBlock, actionPlan)
		if err != nil {
			log.Printf("[handler] next llm error case %s: %v", target.CaseID[:8], err)
			h.postMessage(dest, "", fmt.Sprintf("⚠️ Case %s — inference error: %v", target.CaseID[:8], err))
			return
		}
		h.postCaseBriefingWithActions(dest, target.CaseID[:8],
			fmt.Sprintf("*Case %s — Full Briefing*\n%s", target.CaseID[:8], answer))
	}()
}
