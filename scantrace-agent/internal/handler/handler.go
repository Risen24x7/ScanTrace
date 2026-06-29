// Package handler dispatches Slack Socket Mode events to the appropriate handler.
package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Risen24x7/scantrace/internal/casebuilder"
	"github.com/Risen24x7/scantrace/internal/db"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/ipinfo"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/llm"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/rts"
	"github.com/Risen24x7/scantrace/scantrace-agent/internal/threat"
	"github.com/google/uuid"
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
	benignScanners        *threat.BenignScanners

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
		threat:                threat.New("", ""),
		benignScanners:        threat.NewBenignScanners(""),
		caseThreads:           make(map[string]string),
	}
}

// triageState captures the facts Go already knows so we can pre-select the
// correct action plan before the LLM prompt is assembled.
type triageState struct {
	isWANEdgeOnly        bool // ALL events are wan_new_connection (no wan_forward present)
	hasWANForward        bool // at least one wan_forward event exists
	dstInRegistry        bool // at least one wan_forward dst IP found in device registry
	logsConfirmMalicious bool // set by threat-feed lookup (IPSum >= threshold or Tor exit)
	isBenignScanner      bool // source matched known research scanner list
	ipsumTier            int  // highest IPSum tier across all case IPs
	// Triage summary strings — injected directly into LLM context.
	dstLabel   string // e.g. "WAN EDGE — gateway interface only" or "unknown internal host" or "registry: label=..."
	evtSummary string // e.g. "wan_forward (2), wan_new_connection (2)"
}

// selectActionPlan converts the pre-evaluated triage state into a single
// ready-to-inject action block.
func selectActionPlan(ts triageState) string {
	switch {
	// F — universally blacklisted.
	case ts.ipsumTier >= threat.TierBlacklisted:
		return "*Recommended Actions*\nCondition Matched: F — source universally blacklisted (IPSum score ≥6, majority of feeds agree)\n" +
			"- [VERDICT: LIKELY MALICIOUS] Source is blacklisted across the majority of independent threat-feed sources.\n" +
			"- Block the source IP or subnet at the gateway firewall immediately.\n" +
			"- Close or restrict the targeted port if no external access is required.\n" +
			"- Escalate to a human analyst if the internal host shows any signs of compromise."

	// E — benign research scanner.
	case ts.isBenignScanner:
		return "*Recommended Actions*\nCondition Matched: E — source is a known benign research scanner (Shodan / Censys / Shadowserver / similar)\n" +
			"- [VERDICT: LIKELY BENIGN] This traffic originates from a well-known, opt-outable internet scanning service.\n" +
			"- No blocking required. These scanners perform routine internet-wide surveys.\n" +
			"- If you wish to suppress future alerts from this source, add the IP/CIDR to /opt/scantrace/benign-scanners.txt.\n" +
			"- Review only if the scan volume is unusually high (>50 events/hour from the same IP)."

	// D — threat feed confirms malicious.
	case ts.logsConfirmMalicious:
		return "*Recommended Actions*\nCondition Matched: D — host verified, logs confirm malicious activity\n" +
			"- Block the source IP or subnet at the gateway firewall.\n" +
			"- Close or restrict the targeted port if no external access is required.\n" +
			"- Escalate to a human analyst if the internal host shows signs of compromise."

	// A — WAN edge only, never reached LAN.
	case ts.isWANEdgeOnly:
		return "*Recommended Actions*\nCondition Matched: A — wan_new_connection (WAN edge only, never reached LAN)\n" +
			"- Traffic hit the WAN interface only and was not forwarded. No internal host is at risk.\n" +
			"- If the port is not intentionally exposed, consider closing it at the gateway to reduce noise.\n" +
			"- No urgent action required unless volume is significant or ports are highly sensitive (22, 3389)."

	// B — unknown internal host, wan_forward landed.
	case !ts.dstInRegistry:
		return "*Recommended Actions*\nCondition Matched: B — unknown internal host, wan_forward traffic landed\n" +
			"- Identify the device at the destination IP — run arp-scan or check DHCP leases before any other step.\n" +
			"- Once identified, check its app/proxy logs for requests matching these event timestamps.\n" +
			"- If no legitimate service found, remove or restrict the port-forwarding rule at the gateway."

	// C — registered host, wan_forward landed.
	default:
		return "*Recommended Actions*\nCondition Matched: C — registered host, wan_forward traffic landed\n" +
			"- Check app/proxy logs on the destination host for requests matching these timestamps.\n" +
			"- If no matching legitimate requests, restrict or remove the port-forwarding rule.\n" +
			"- If logs confirm malicious intent, block the source IP at the gateway."
	}
}

// buildTriageBlock returns the plain-text triage block that is injected
// verbatim into the singleCasePromptTemplate %s[0] placeholder.
// It must match what buildSingleCaseContext writes into the context string
// so the LLM sees consistent data in both places.
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
		ts.dstLabel,
		ts.evtSummary,
		strings.Join(portsSeen, ", "),
		blacklistNote,
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

// splitArgs splits a raw Slack command text string into tokens, respecting
// double-quoted strings. For example:
//
//	adddevice 192.168.50.4 label="Media Server" trust=trusted
//
// becomes ["adddevice", "192.168.50.4", `label=Media Server`, "trust=trusted"].
// Quotes are stripped from the result values so downstream key=value parsing
// works correctly regardless of whether the user quotes their label or not.
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
	// Use quote-aware splitting so label="Media Server" is one token.
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

// cmdAddDevice handles:
//
//	/scantrace adddevice <ip> [label="My Device"] [trust=trusted|unknown|suspicious] [suppress=true]
//
// All fields except <ip> are optional and default to label="<ip>", trust=unknown, suppress=false.
// The upsert is keyed on IP — running the command again updates an existing entry.
// Args are pre-split by splitArgs so quoted labels arrive as single tokens.
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

	// Defaults.
	label := ipArg
	trustLabel := "unknown"
	autoSuppress := false

	// Parse key=value pairs from remaining args.
	// splitArgs already stripped surrounding quotes, so val is clean.
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

	// Check if this IP already exists so we can report add vs update.
	existing, _ := h.store.GetKnownDeviceByIP(ipArg)

	now := time.Now().UTC()
	deviceID := uuid.NewString()
	if existing != nil {
		deviceID = existing.DeviceID // keep stable ID on update
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

// cmdRemoveDevice handles: /scantrace removedevice <ip>
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
			ctx, triage, portsSeen := h.buildSingleCaseContext(c)
			triageBlock := buildTriageBlock(triage, portsSeen)
			actionPlan := selectActionPlan(triage)
			prompt := fmt.Sprintf(
				"Analyse this single case and provide a full briefing.\n\nCase ID: %s",
				c.CaseID[:8],
			)
			answer, err := h.llm.AskCase(prompt, ctx, triageBlock, actionPlan)
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
		ctx, triage, portsSeen := h.buildSingleCaseContext(target)
		triageBlock := buildTriageBlock(triage, portsSeen)
		actionPlan := selectActionPlan(triage)
		prompt := fmt.Sprintf(
			"Analyse this case and provide a full briefing.\n\nCase ID: %s",
			target.CaseID[:8],
		)
		answer, err := h.llm.AskCase(prompt, ctx, triageBlock, actionPlan)
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

// classifyDst resolves the destination label for a single event.
//
// Rules (in priority order):
//  1. wan_new_connection → traffic never left the WAN interface, so the
//     "destination" is always the gateway itself regardless of the dst IP field.
//  2. wan_forward + dst == wanIP → same gateway IP but traffic was forwarded;
//     label it as gateway-forwarded rather than a plain WAN-edge hit.
//  3. wan_forward → look up dst in device registry; fall through to
//     "unknown internal host" if not found.
func (h *Handler) classifyDst(dstIP, eventType string) (label string, isWANEdge bool) {
	switch strings.ToLower(eventType) {
	case "wan_new_connection":
		// Packet was dropped at the WAN interface — never reached LAN.
		return "WAN EDGE — gateway interface only", true
	case "wan_forward":
		if h.wanIP != "" && dstIP == h.wanIP {
			// Forwarded but dst happens to be the gateway's own IP (hairpin/NAT).
			return "WAN gateway IP (forwarded — check NAT rules)", false
		}
		// Fall through: registry and unknown-host logic handled in caller.
		return "", false
	default:
		if h.wanIP != "" && dstIP == h.wanIP {
			return "WAN EDGE — gateway interface only", true
		}
		return "", false
	}
}

// buildSingleCaseContext builds the LLM context string and simultaneously
// evaluates the triageState so the caller can pre-select the action plan.
// It now also returns portsSeen so callers can pass it to buildTriageBlock.
//
// Key ordering guarantee: threat-feed and benign-scanner checks run during
// Pass 1 (alongside event classification) so ts.ipsumTier,
// ts.logsConfirmMalicious, and ts.isBenignScanner are all resolved before
// the Triage block is written. This ensures the LLM sees the blacklist
// verdict inline in Triage rather than only discovering it later.
func (h *Handler) buildSingleCaseContext(c *db.Case) (string, triageState, []string) {
	var sb strings.Builder
	var ts triageState

	evtTypeCount := make(map[string]int) // "wan_new_connection" → n, "wan_forward" → n
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

	// ── Pass 1: collect per-event data ───────────────────────────────────────
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

	for _, evtID := range c.RelatedEventIDs {
		evt, err := h.store.GetEvent(evtID)
		if err != nil || evt == nil {
			continue
		}

		key := strings.ToLower(evt.EventType)
		evtTypeCount[key]++

		// Classify destination.
		dstLabel, isEdge := h.classifyDst(evt.DstIP, evt.EventType)
		if !isEdge {
			// wan_forward: check registry.
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
		}

		rows = append(rows, evtRow{
			evtType:  evt.EventType,
			srcIP:    evt.SrcIP,
			dstIP:    evt.DstIP,
			dstPort:  evt.DstPort,
			proto:    evt.Protocol,
			dstLabel: dstLabel,
		})
		if evt.SrcIP != "" {
			ipSet[evt.SrcIP] = struct{}{}
		}
	}

	// ── Compute triage flags ─────────────────────────────────────────────────
	total := 0
	for _, n := range evtTypeCount {
		total += n
	}
	// isWANEdgeOnly only if every single event was wan_new_connection.
	if total > 0 && evtTypeCount["wan_new_connection"] == total {
		ts.isWANEdgeOnly = true
	}

	// Build human-readable event-type summary string.
	var evtParts []string
	for typ, n := range evtTypeCount {
		evtParts = append(evtParts, fmt.Sprintf("%s (%d)", typ, n))
	}
	ts.evtSummary = strings.Join(evtParts, ", ")

	// ── Resolve threat-feed + benign-scanner flags BEFORE writing Triage ─────
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
		if len(scores) > 0 {
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
	}

	// ── Build dst label for Triage ────────────────────────────────────────────
	if ts.isWANEdgeOnly {
		ts.dstLabel = "WAN EDGE — gateway interface only"
	} else if ts.hasWANForward && ts.dstInRegistry {
		ts.dstLabel = "YES — registered internal device"
	} else if ts.hasWANForward {
		ts.dstLabel = "NO — unknown internal host"
	} else {
		ts.dstLabel = "MIXED — see event list below"
	}

	// ── Triage block written into context string ──────────────────────────────
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
		ts.dstLabel,
		ts.evtSummary,
		strings.Join(portsSeen, ", "),
		blacklistNote,
	))

	// ── Pass 2: write per-event lines ────────────────────────────────────────
	for _, r := range rows {
		sb.WriteString(fmt.Sprintf("  evt type=%s src=%s dst=%s [%s] dport=%d proto=%s\n",
			r.evtType, r.srcIP, r.dstIP, r.dstLabel, r.dstPort, r.proto))
	}

	// ── Write pre-resolved threat-feed lines ─────────────────────────────────
	for _, line := range threatLines {
		sb.WriteString("\n" + line + "\n")
	}
	if len(threatFeedLines) > 0 {
		sb.WriteString("\nThreat feed verdicts:\n")
		for _, line := range threatFeedLines {
			sb.WriteString(line + "\n")
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

	return sb.String(), ts, portsSeen
}

// caseSrcIPs collects unique source IPs for a case (fast, no LLM).
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

		caseText := fmt.Sprintf(
			"%s  *[%s]* `%s`\n>%s\n>Confidence: %s   Events: *%d*%s",
			emoji, sev, shortID, c.Title, confPill, evtCount, badgeLine,
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

	// Fast path: deterministic case-specific commands.
	if h.handleMentionCaseCommand(channelID, userID, clean) {
		return
	}

	// Fast path: @ScanTrace cases.
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

// handleMentionCaseCommand handles:
//
//	@ScanTrace case <id>
//	@ScanTrace report <id>
//	@ScanTrace review case <id>
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
		// No LLM — fall back to static report.
		h.cmdReport(channelID, userID, caseIDPrefix)
		return true
	}

	dest := h.externalThreatChannel
	h.postMessage(dest, "", fmt.Sprintf("_Briefing case %s…_", target.CaseID[:8]))

	go func() {
		ctx, triage, portsSeen := h.buildSingleCaseContext(target)
		triageBlock := buildTriageBlock(triage, portsSeen)
		actionPlan := selectActionPlan(triage)
		prompt := fmt.Sprintf(
			"Analyse this case and provide a full briefing.\n\nCase ID: %s",
			target.CaseID[:8],
		)
		answer, err := h.llm.AskCase(prompt, ctx, triageBlock, actionPlan)
		if err != nil {
			log.Printf("[handler] mention case llm error %s: %v", target.CaseID[:8], err)
			h.postMessage(dest, "", fmt.Sprintf("⚠️ Case %s — inference error: %v", target.CaseID[:8], err))
			return
		}
		h.postMessage(dest, "", fmt.Sprintf("*Case %s — Full Briefing*\n%s", target.CaseID[:8], answer))
	}()

	return true
}

func (h *Handler) buildLLMContext() string {
	var sb strings.Builder
	cases, _ := h.store.ListCases("", 10)
	if len(cases) > 0 {
		sb.WriteString("Recent cases:\n")
		for _, c := range cases {
			sb.WriteString(fmt.Sprintf("  id=%s title=%q sev=%s conf=%.0f%%\n",
				c.CaseID[:8], c.Title, c.Severity, c.Confidence*100))
		}
	}
	devices, _ := h.store.ListKnownDevices("", 20)
	if len(devices) > 0 {
		sb.WriteString("Known devices:\n")
		for _, d := range devices {
			sb.WriteString(fmt.Sprintf("  %s trust=%s label=%q\n", d.IP, d.TrustLabel, d.Label))
		}
	}
	return sb.String()
}

func blocksFromRaw(raw string) ([]slack.Block, error) {
	var payload struct {
		Blocks []json.RawMessage `json:"blocks"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	blocks := make([]slack.Block, 0, len(payload.Blocks))
	for _, b := range payload.Blocks {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(b, &typed); err != nil {
			continue
		}
		switch typed.Type {
		case "header":
			var v slack.HeaderBlock
			if err := json.Unmarshal(b, &v); err == nil {
				blocks = append(blocks, &v)
			}
		case "section":
			var v slack.SectionBlock
			if err := json.Unmarshal(b, &v); err == nil {
				blocks = append(blocks, &v)
			}
		case "divider":
			blocks = append(blocks, slack.NewDividerBlock())
		case "context":
			var v slack.ContextBlock
			if err := json.Unmarshal(b, &v); err == nil {
				blocks = append(blocks, &v)
			}
		}
	}
	return blocks, nil
}

func (h *Handler) postMessage(channelID, threadTS, text string) {
	opts := []slack.MsgOption{slack.MsgOptionText(text, false)}
	if threadTS != "" {
		opts = append(opts, slack.MsgOptionTS(threadTS))
	}
	_, _, err := h.api.PostMessage(channelID, opts...)
	if err != nil {
		log.Printf("[handler] postMessage error channel=%s: %v", channelID, err)
	}
}

func (h *Handler) postEphemeral(channelID, userID, text string) {
	_, err := h.api.PostEphemeralMessage(channelID, userID, slack.MsgOptionText(text, false))
	if err != nil {
		log.Printf("[handler] postEphemeral error channel=%s user=%s: %v", channelID, userID, err)
	}
}

func (h *Handler) postBlocks(channelID, threadTS string, blocks []slack.Block) {
	opts := []slack.MsgOption{slack.MsgOptionBlocks(blocks...)}
	if threadTS != "" {
		opts = append(opts, slack.MsgOptionTS(threadTS))
	}
	_, _, err := h.api.PostMessage(channelID, opts...)
	if err != nil {
		log.Printf("[handler] postBlocks error channel=%s: %v", channelID, err)
	}
}

func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	default:
		return "🟢"
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

func helpText() string {
	return "*ScanTrace Commands*\n\n" +
		"*Cases*\n" +
		"• `/scantrace cases` — list active cases\n" +
		"• `/scantrace report <id>` — static report for a case\n" +
		"• `/scantrace next` — AI briefing of highest-priority case\n" +
		"• `/scantrace review-all` — AI briefing of all open cases\n" +
		"• `/scantrace alert` — repost latest case alert\n\n" +
		"*Devices*\n" +
		"• `/scantrace devices` — list known device registry\n" +
		"• `/scantrace adddevice <ip> [label=\"Name\"] [trust=trusted|unknown|suspicious] [suppress=true]`\n" +
		"• `/scantrace removedevice <ip>` — remove device from registry\n\n" +
		"*Mentions*\n" +
		"• `@ScanTrace case <id>` — AI briefing for a specific case\n" +
		"• `@ScanTrace report <id>` — same as above\n" +
		"• `@ScanTrace cases` — list active cases\n\n" +
		"*Other*\n" +
		"• `/scantrace mcp` — MCP server info"
}
