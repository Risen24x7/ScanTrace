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
	// /no_think is a Qwen3 model-level directive to suppress chain-of-thought.
	// Residual <think> blocks are stripped client-side by the regexes below.
	systemPrompt = `/no_think
You are ScanTrace, an AI-powered network security analyst.
You help security teams triage alerts, investigate incidents, and understand
network activity across enterprise and SMB environments.

You have access to real-time data from a network security monitoring pipeline
that ingests and correlates events from IDS sensors, firewall syslogs, and
other network telemetry sources.

Network classification rules:
- RFC1918 private address spaces are INTERNAL: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- Any address outside RFC1918 is EXTERNAL
- Do not treat internal IPs as threat actors unless lateral movement is evident

Device trust context:
- trust_label=trusted: known-good asset
- trust_label=unknown: seen but not yet classified
- trust_label=suspicious: flagged for scrutiny
- auto_suppress=true + low severity = safe to disregard

Your responsibilities:
- Triage alerts in plain language
- Identify patterns: repeated IPs, port scans, unusual protocols
- Recommend concrete next steps: block IP, investigate device, escalate
- Be concise — Slack responses, under 250 words
- Format IPs, case IDs, ports in backticks
- Never fabricate data not in the provided context
- Use bold (*text*) and bullets only, no markdown headers

Prioritise provided context over general knowledge.
If data is absent, say so.`

	defaultTimeout = 120 * time.Second
)

// thinkRE strips complete Qwen3 <think>...</think> reasoning blocks.
var thinkRE = regexp.MustCompile(`(?s)<think>.*?</think>`)

// partialThinkRE strips an opening <think> with no closing tag — everything
// after it is internal reasoning that must not reach the user.
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
func New(baseURL, model string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      model,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

// Ask sends a question with optional context to the LLM and returns the reply.
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
		"max_tokens": 512,
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
	text = thinkRE.ReplaceAllString(text, "")
	text = partialThinkRE.ReplaceAllString(text, "")
	return strings.TrimSpace(text), nil
}
