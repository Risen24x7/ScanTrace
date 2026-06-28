// Package llm provides a thin client for the ik_llama.cpp OpenAI-compatible
// endpoint running on the desktop (Worker A). It is called directly — not via
// the MCP route_inference — so the agent does not depend on VM 106 being up.
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
	// /no_think is a Qwen3 soft-prompt token that disables chain-of-thought
	// reasoning, cutting GPU load and latency significantly.
	systemPrompt = `/no_think
You are ScanTrace, a network security analyst assistant.
You have access to real-time data from a home network intrusion-detection system
that ingests Suricata IDS alerts and Asus router syslog events.

Network context:
- Home LAN subnet: 192.168.50.0/24 (all 192.168.50.x addresses are INTERNAL devices)
- Any 192.168.x.x, 10.x.x.x, or 172.16-31.x.x address is a private/internal IP
- External/public IPs are anything outside those ranges
- The router itself is typically 192.168.50.1

Your job:
- Triage alerts and explain what they mean in plain language
- Clearly distinguish between INTERNAL devices and EXTERNAL threat actors
- Identify patterns across cases (repeated IPs, MAC addresses, port scans)
- Recommend concrete next steps (block IP, investigate device, watch port)
- Be concise — your answers appear in Slack, keep responses under 300 words
- Format important values (IPs, case IDs, ports) in backticks
- Never fabricate case IDs or IP addresses; only reference data provided in context
- Do NOT use markdown headers (###) — use bold (*text*) and bullet points only

When context is provided, prioritise it over general knowledge.
When no relevant context is available, say so honestly.`

	defaultTimeout = 120 * time.Second
)

// thinkRE strips Qwen3 <think>...</think> reasoning blocks from output.
var thinkRE = regexp.MustCompile(`(?s)<think>.*?</think>`)

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

// Ask sends a freeform question with optional context to the LLM and returns
// the assistant reply text. context is injected as a system-level note before
// the user question so the model can reference live DB data.
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

	// Strip any residual <think>...</think> reasoning blocks.
	text := thinkRE.ReplaceAllString(result.Choices[0].Message.Content, "")
	return strings.TrimSpace(text), nil
}
