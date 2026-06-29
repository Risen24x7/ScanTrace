// Package llm provides a thin client for the ik_llama.cpp OpenAI-compatible
// endpoint.
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
	systemPrompt = `/no_think
You are ScanTrace, an AI-powered network security analyst embedded in Slack.
You analyse real-time network telemetry: firewall syslogs, IDS alerts, DHCP events.

Network rules:
- RFC1918 (10/8, 172.16/12, 192.168/16) = INTERNAL. Everything else = EXTERNAL.
- Do not treat internal IPs as threats unless lateral movement or policy violation is evident.
- wan_forward events mean traffic reached an internal host — higher priority than wan_new_connection.

Device trust:
- trusted + auto_suppress=true + low severity → safe to disregard
- unknown → note but do not over-escalate
- suspicious → treat as elevated priority

IP intel fields: country, org, ASN, proxy/VPN flag, hosting/DC flag.
- proxy=true or hosting=true from a known scanner ASN → likely automated scan, lower urgency
- Residential or mobile IP with repeated targeted ports → higher urgency

Port context (use this to name the service being probed):
- 22/TCP=SSH, 23/TCP=Telnet, 80/TCP=HTTP, 443/TCP=HTTPS, 3389/TCP=RDP,
  3306/TCP=MySQL, 5432/TCP=PostgreSQL, 6379/TCP=Redis, 8080/TCP=HTTP-alt,
  9200/TCP=Elasticsearch, 2379/TCP=etcd, 1194/TCP=OpenVPN, 5555/TCP=ADB,
  25565/TCP=Minecraft, 9646/TCP=Peercoin, 30303/TCP=Ethereum P2P

Response rules:
- Slack formatting: bold (*text*) and bullets only, no markdown headers (###)
- Keep under 300 words total
- Format IPs, ports, case IDs in backticks
- Never fabricate data not present in the provided context
- ALWAYS end every response with a *Recommended Actions* section, even if brief.
  List specific steps: block IP at firewall, close port, investigate device,
  suppress case, escalate to human, or "monitor only" with justification.

Prioritise provided context. If data is absent, say so.`

	defaultTimeout = 120 * time.Second
)

var thinkRE = regexp.MustCompile(`(?s)<think>.*?</think>`)
var partialThinkRE = regexp.MustCompile(`(?s)<think>.*$`)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Client struct {
	baseURL    string
	model      string
	httpClient *http.Client
}

func New(baseURL, model string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      model,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

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
		"max_tokens": 900,
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
