package casebuilder

import (
	"strings"
	"testing"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
)

func TestRenderMarkdown(t *testing.T) {
	cas := &db.Case{
		CaseID: "case-test-001", Title: "Scan from 1.2.3.4",
		Summary: "5 events over 10 minutes", Status: "open",
		Severity: "high", Confidence: 0.82,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	r := BuildReportFromCase(cas, nil, nil)
	if r.Markdown == "" {
		t.Fatal("markdown should not be empty")
	}
	if !strings.Contains(r.Markdown, "ScanTrace Case Report") {
		t.Error("markdown missing title")
	}
}

func TestSlackBlock(t *testing.T) {
	cas := &db.Case{
		CaseID: "case-test-002", Title: "Scan from 5.5.5.5",
		Summary: "Port sweep detected", Status: "open",
		Severity: "medium", Confidence: 0.60,
	}
	r := BuildReportFromCase(cas, nil, nil)
	block := r.SlackBlock()
	if _, ok := block["blocks"]; !ok {
		t.Fatal("SlackBlock missing blocks key")
	}
}
