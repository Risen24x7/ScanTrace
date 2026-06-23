// Package mcp implements the Model Context Protocol server for ScanTrace.
// It exposes ScanTrace case data as MCP tools that any MCP-compatible
// AI host (Claude, Cursor, etc.) can call.
package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Risen24x7/scantrace/internal/db"
)

// ToolSchema describes a single MCP tool.
type ToolSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Server is the MCP HTTP server.
type Server struct {
	store *db.DB
	mux   *http.ServeMux
}

// New creates a new MCP server backed by the given store.
func New(store *db.DB) *Server {
	s := &Server{store: store, mux: http.NewServeMux()}
	s.mux.HandleFunc("/mcp/tools/list", s.handleToolsList)
	s.mux.HandleFunc("/mcp/tools/call", s.handleToolCall)
	return s
}

// ListenAndServe starts the MCP HTTP server on addr (e.g. ":8765").
func (s *Server) ListenAndServe(addr string) error {
	log.Printf("[mcp] server listening on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

// tools returns the full tool registry.
func tools() []ToolSchema {
	return []ToolSchema{
		{
			Name:        "list_cases",
			Description: "List recent ScanTrace investigation cases. Optionally filter by severity.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "severity": {
      "type": "string",
      "enum": ["high", "medium", "low", ""],
      "description": "Filter by severity. Leave empty for all."
    },
    "limit": {
      "type": "integer",
      "description": "Max number of cases to return (default 10, max 50)."
    }
  }
}`),
		},
		{
			Name:        "get_case",
			Description: "Get full details for a specific ScanTrace case by ID prefix.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "required": ["case_id"],
  "properties": {
    "case_id": {
      "type": "string",
      "description": "Case ID or 8-character prefix."
    }
  }
}`),
		},
		{
			Name:        "list_sensors",
			Description: "List registered ScanTrace sensors (firewalls, IDS nodes).",
			InputSchema: json.RawMessage(`{"type": "object", "properties": {}}`),
		},
		{
			Name:        "get_entity",
			Description: "Get enriched entity (IP or hostname) details from the ScanTrace DB.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "required": ["value"],
  "properties": {
    "value": {
      "type": "string",
      "description": "IP address or hostname to look up."
    }
  }
}`),
		},
	}
}

func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"tools": tools()})
}

func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body")
		return
	}
	switch req.Name {
	case "list_cases":
		s.toolListCases(w, req.Input)
	case "get_case":
		s.toolGetCase(w, req.Input)
	case "list_sensors":
		s.toolListSensors(w)
	case "get_entity":
		s.toolGetEntity(w, req.Input)
	default:
		writeError(w, fmt.Sprintf("unknown tool: %s", req.Name))
	}
}

func (s *Server) toolListCases(w http.ResponseWriter, input json.RawMessage) {
	var params struct {
		Severity string `json:"severity"`
		Limit    int    `json:"limit"`
	}
	json.Unmarshal(input, &params)
	if params.Limit <= 0 || params.Limit > 50 {
		params.Limit = 10
	}
	cases, err := s.store.ListCases(params.Severity, params.Limit)
	if err != nil {
		writeError(w, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"cases": cases})
}

func (s *Server) toolGetCase(w http.ResponseWriter, input json.RawMessage) {
	var params struct {
		CaseID string `json:"case_id"`
	}
	if err := json.Unmarshal(input, &params); err != nil || params.CaseID == "" {
		writeError(w, "case_id is required")
		return
	}
	cases, err := s.store.ListCases("", 100)
	if err != nil {
		writeError(w, err.Error())
		return
	}
	for _, c := range cases {
		if strings.HasPrefix(c.CaseID, params.CaseID) {
			json.NewEncoder(w).Encode(map[string]interface{}{"case": c})
			return
		}
	}
	writeError(w, fmt.Sprintf("case %s not found", params.CaseID))
}

func (s *Server) toolListSensors(w http.ResponseWriter) {
	sensors, err := s.store.ListSensors()
	if err != nil {
		writeError(w, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"sensors": sensors})
}

func (s *Server) toolGetEntity(w http.ResponseWriter, input json.RawMessage) {
	var params struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(input, &params); err != nil || params.Value == "" {
		writeError(w, "value is required")
		return
	}
	entity, err := s.store.GetEntityByValue(params.Value)
	if err != nil {
		writeError(w, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"entity": entity})
}

func writeError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
