package handler

import (
	"fmt"
	"strings"

	"github.com/Risen24x7/scantrace/internal/db"
)

// cmdCloseCase handles: /scantrace close <id>
func (h *Handler) cmdCloseCase(channelID, userID, caseIDPrefix string) {
	target := h.resolveCaseByPrefix(caseIDPrefix)
	if target == nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf(
			"Case `%s` not found. Try `/scantrace cases` to list active cases.", caseIDPrefix,
		))
		return
	}

	if strings.EqualFold(target.Status, "closed") {
		h.postEphemeral(channelID, userID, fmt.Sprintf(
			"Case `%s` is already closed.", target.CaseID[:8],
		))
		return
	}

	if err := h.store.SetCaseStatus(target.CaseID, "closed"); err != nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf("Failed to close case: %v", err))
		return
	}

	h.postMessage(channelID, "", fmt.Sprintf(
		"✅ Case `%s` — *%s* marked as *closed*.",
		target.CaseID[:8], target.Title,
	))
}

// cmdReopenCase handles: /scantrace reopen <id>
func (h *Handler) cmdReopenCase(channelID, userID, caseIDPrefix string) {
	target := h.resolveCaseByPrefix(caseIDPrefix)
	if target == nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf(
			"Case `%s` not found. Use `/scantrace cases` to list cases.", caseIDPrefix,
		))
		return
	}

	if err := h.store.SetCaseStatus(target.CaseID, "open"); err != nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf("Failed to reopen case: %v", err))
		return
	}

	h.postMessage(channelID, "", fmt.Sprintf(
		"🔓 Case `%s` — *%s* reopened.",
		target.CaseID[:8], target.Title,
	))
}

// resolveCaseByPrefix finds the first case whose CaseID starts with prefix
// (case-insensitive). Searches all cases regardless of status.
func (h *Handler) resolveCaseByPrefix(prefix string) *db.Case {
	cases, err := h.store.ListCases("", 100)
	if err != nil {
		return nil
	}
	lower := strings.ToLower(prefix)
	for _, c := range cases {
		if strings.HasPrefix(strings.ToLower(c.CaseID), lower) {
			return c
		}
	}
	return nil
}
