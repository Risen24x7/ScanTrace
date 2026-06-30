package handler

import (
	"fmt"
	"strings"

	"github.com/Risen24x7/scantrace/scantrace-agent/internal/portintel"
	"github.com/slack-go/slack"
)

// cmdPortTrends handles: /scantrace port-trends [days]
// Posts a Block Kit port-trends intelligence report to the channel.
func (h *Handler) cmdPortTrends(channelID, userID string, args []string) {
	if h.portIntel == nil {
		h.postEphemeral(channelID, userID, "Port intel store not initialised. Restart the agent.")
		return
	}

	days := 7
	if len(args) > 0 {
		fmt.Sscanf(args[0], "%d", &days)
		if days < 1 || days > 365 {
			days = 7
		}
	}

	tops, err := h.portIntel.TopPorts(days, 15)
	if err != nil || len(tops) == 0 {
		h.postEphemeral(channelID, userID, fmt.Sprintf(
			"No port hit data for the last %d days. Data accumulates as cases are processed.", days,
		))
		return
	}

	behavior := h.portIntel.GlobalBehavior(days)

	headerText := fmt.Sprintf(
		"📊 *ScanTrace — Global Perimeter Intelligence* (Last %d Days)", days,
	)

	// TOP TARGETED PORTS section.
	var portLines []string
	for i, ps := range tops {
		if i >= 10 {
			break
		}
		orgNote := ""
		if len(ps.TopOrgs) > 0 {
			orgNote = " — " + strings.Join(ps.TopOrgs, ", ")
		}
		portLines = append(portLines, fmt.Sprintf(
			"• Port *%d*: %d hits · %d unique IPs · %d ASNs  [%s]%s",
			ps.Port, ps.HitCount, ps.UniqueIPs, ps.UniqueASNs, ps.TrendArrow(), orgNote,
		))
	}

	// BEHAVIOR section.
	behaviorText := fmt.Sprintf(
		"🎯 *Behavior Detection*\n"+
			"• %d Horizontal Campaigns (5+ unique IPs → same port, coordinated botnet sweep)\n"+
			"• %d Vertical Recon Probes (single IP → 3+ ports, active scanner)\n"+
			"• %d New Ports (never seen before this window)",
		behavior.HorizontalCampaigns,
		behavior.VerticalProbes,
		behavior.NewPorts,
	)

	// HIGH-RISK callout: ports with 10+ unique IPs.
	var highRiskLines []string
	for _, ps := range tops {
		if ps.UniqueIPs >= 10 {
			highRiskLines = append(highRiskLines, fmt.Sprintf(
				"🚨 Port *%d* — %d unique sources · possible CVE campaign or credential-stuffing sweep",
				ps.Port, ps.UniqueIPs,
			))
		}
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", "ScanTrace — Global Perimeter Intelligence", false, false),
		),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", headerText, false, false),
			nil, nil,
		),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn",
				"🔥 *Top Targeted Ports*\n"+strings.Join(portLines, "\n"),
				false, false),
			nil, nil,
		),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", behaviorText, false, false),
			nil, nil,
		),
	}

	if len(highRiskLines) > 0 {
		blocks = append(blocks,
			slack.NewDividerBlock(),
			slack.NewSectionBlock(
				slack.NewTextBlockObject("mrkdwn",
					"⚠️ *High-Risk Ports — Immediate Review*\n"+strings.Join(highRiskLines, "\n"),
					false, false),
				nil, nil,
			),
		)
	}

	blocks = append(blocks,
		slack.NewContextBlock("",
			slack.NewTextBlockObject("mrkdwn",
				fmt.Sprintf("Use `/scantrace port-trends <days>` to change the window · showing top %d ports", len(tops)),
				false, false),
		),
	)

	h.postBlocks(channelID, "", blocks)
}

// portIntelAdvisory builds the [PORT INTEL ADVISORY] block for a list of ports.
// Returns empty string if nothing significant.
func (h *Handler) portIntelAdvisory(ports []int) string {
	if h.portIntel == nil || len(ports) == 0 {
		return ""
	}
	return h.portIntel.PortAdvisory(ports, 7)
}

// recordPortHits persists (port, srcIP, srcASN, srcOrg, srcCountry) tuples for
// all ports seen in a case. Called from buildSingleCaseContext.
func (h *Handler) recordPortHits(ports []portintel.HitRecord) {
	if h.portIntel == nil {
		return
	}
	for _, r := range ports {
		h.portIntel.RecordHit(r.Port, r.SrcIP, r.SrcASN, r.SrcOrg, r.SrcCountry, r.EventType)
	}
}
