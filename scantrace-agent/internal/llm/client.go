// Package llm provides a thin client for the ik_llama.cpp OpenAI-compatible
// endpoint. Called directly from the Slack bot — not via MCP route_inference.
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	// systemPrompt is injected as the first message on every request.
	// /no_think disables Qwen3 chain-of-thought — Ollama may ignore this;
	// partial or full think blocks are stripped client-side by thinkRE/partialThinkRE.
	systemPrompt = `/no_think
You are ScanTrace, an AI-powered network security analyst.
You help security teams triage alerts, investigate incidents, and understand
network activity across enterprise and SMB environments.

You have access to real-time data from a network security monitoring pipeline
that ingests and correlates events from IDS sensors (Suricata), firewall and
router syslogs, DHCP logs, and other network telemetry sources.

Network classification rules:
- RFC1918 private address spaces are INTERNAL: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- Any address outside RFC1918 is an EXTERNAL/PUBLIC IP
- Clearly distinguish internal devices from external actors in every response
- Do not treat internal IPs as threat actors unless there is lateral movement or policy violation evidence

Device trust context:
- Devices marked trust_label=trusted are known-good assets registered by an analyst
- Devices marked trust_label=unknown have been seen on the network but not yet classified
- Devices marked trust_label=suspicious are flagged for elevated scrutiny
- When a device is trusted and auto_suppress=true, low-severity noise cases can be disregarded

Your responsibilities:
- Triage alerts and explain what they mean in plain language
- Identify patterns: repeated IPs, port scans, unusual protocols, lateral movement
- Correlate events across cases to surface campaign-level activity
- Recommend concrete next steps: block IP, investigate device, escalate case, update device registry
- Be concise — responses appear in Slack, keep under 300 words
- Format key values (IPs, case IDs, ports, MACs) in backticks
- Never fabricate case IDs, IPs, or data not present in the provided context
- Do NOT use markdown headers (###) — use bold (*text*) and bullet points only

When context is provided, prioritise it over general knowledge.
When no relevant context is available, say so honestly.`

	defaultTimeout = 120 * time.Second
)

// thinkRE strips complete Qwen3 <think>...</think> reasoning blocks.
var thinkRE = regexp.MustCompile(`(?s)<think>.*?</think>`)

// partialThinkRE strips an opening <think> tag with no matching </think>
// (i.e. the model started reasoning but the block was never closed — everything
// after the tag is reasoning, so we drop it all).
var partialThinkRE = regexp.MustCompile(`(?s)<think>.*$`)

// Message is an OpenAI-style chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Client calls the ik_llama.cpp /v1/chat/completions endpoint.
type Client struct {
	baseURL    string
	model      string
	httpClient *http.Client
}

// New creates a Client.
// baseURL example: "http://192.168.50.250:11434"
// model example:   "Qwen3-30B-A3B-UD-Q3_K_XL" (pass "" to use server default)
func New(baseURL, model string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      model,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

// Ask sends a question with optional DB context to the LLM and returns
// the assistant reply. context is injected as a system message before
// the user question so the model can reference live data.
func (c *Client) Ask(question, context string) (string, error) {
	messages := []Message{
		{Role: "system", Content: systemPrompt},
	}
	if context != "" {
		messages = append(messages, Message{
			Role:    "system",
			Content: "Current ScanTrace data:\n" + context,
		})
	}
	messages = append(messages, Message{Role: "user", Content: question})

	body := map[string]interface{}{
		"messages":   messages,
		"stream":     false,
		"max_tokens": 800,
		// Ollama-specific: disable thinking mode
		"think": false,
	}
	if c.model != "" {
		body["model"] = c.model
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("llm: marshal: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/v1/chat/completions",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return "", fmt.Errorf("llm: request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("llm: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm: status %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("llm: decode: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("llm: api error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("llm: empty choices")
	}

	text := result.Choices[0].Message.Content

	// 1. Strip complete <think>...</think> blocks.
	text = thinkRE.ReplaceAllString(text, "")

	// 2. Strip any remaining partial <think> block (open tag, no close).
	text = partialThinkRE.ReplaceAllString(text, "")

	return strings.TrimSpace(text), nil
}
