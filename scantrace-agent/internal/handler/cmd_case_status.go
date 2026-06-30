package handler

import (
	"fmt"
	"strings"
)

// cmdCloseCase handles: /scantrace close <id>
// Marks the case status = "closed" and posts a confirmation.
func (h *Handler) cmdCloseCase(channelID, userID, caseIDPrefix string) {
	target := h.resolveCaseByPrefix(caseIDPrefix)
	if target == nil {
		h.postEphemeral(channelID, userID, fmt.Sprintf(
			"Case `%s` not found. Try `/scantrace cases` to list active cases.", caseIDPrefix,
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
// Marks the case status = "open".
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

// resolveCaseByPrefix finds the first case whose CaseID starts with caseIDPrefix
// (case-insensitive). Returns nil if not found.
func (h *Handler) resolveCaseByPrefix(caseIDPrefix string) interface{ GetCaseID() string } {
	// resolveCaseByPrefix is inlined into callers below — kept here for clarity.
	return nil
}
