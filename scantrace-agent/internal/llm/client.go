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
- wan_forward events mean traffic reached an internal host via an active port-forwarding rule.
  Before recommending a block, determine whether that forwarding rule is intentional.

Device trust:
- trusted + auto_suppress=true + low severity → safe to disregard
- unknown → note but do not over-escalate
- suspicious → treat as elevated priority

IP intel fields: country, org, ASN, proxy/VPN flag, hosting/DC flag.
- proxy=true or hosting=true from a known scanner ASN → likely automated scan, lower urgency
- Residential or mobile IP with repeated targeted ports → higher urgency

█ IP ACCURACY — CRITICAL
NEVER construct, guess, or derive IP addresses. Only use the exact src/dst IP
values present in the provided context data. Mixing octets between cases is a
critical error. If you are not 100%% certain of an IP from the context, omit it
or write "(see case data)" instead of guessing.

Subnet grouping:
When multiple cases share the same /24 (e.g. 85.217.149.x from one org), treat
them as a single coordinated scan campaign. Consolidate into one action item:
block or monitor the /24 subnet — do not list each IP as a separate incident.

Major cloud provider IPs (Google 216.239.x, 142.251.x, 34.x; Cloudflare 104.x;
AWS 3.x, 18.x, 52.x; Azure 20.x, 40.x): blanket IP blocks may break legitimate
services. Prefer closing the exposed port over blocking the source IP.

Port context:
- 22/TCP=SSH, 23/TCP=Telnet, 80/TCP=HTTP, 443/TCP=HTTPS, 3389/TCP=RDP,
  3306/TCP=MySQL, 5432/TCP=PostgreSQL, 6379/TCP=Redis, 8080/TCP=HTTP-alt,
  9200/TCP=Elasticsearch, 2379/TCP=etcd, 1194/TCP=OpenVPN, 5555=ADB,
  25565=Minecraft, 30303=Ethereum P2P

Response rules:
- Slack formatting: bold (*text*) and bullets only, no markdown headers (###)
- Keep under 300 words total
- Never fabricate data not present in the provided context
- ALWAYS end with a *Recommended Actions* section with specific steps.

Prioritise provided context. If data is absent, say so.`

	// singleCasePromptTemplate is rendered by AskCase.
	//
	// %s [0] — pre-resolved Triage block (built by Go handler, verbatim)
	// %s [1] — pre-selected Recommended Actions block (built by selectActionPlan)
	//
	// The LLM authors: Summary verdict sentence, Details, and Assessment.
	// It must NOT rewrite or re-derive anything in the Triage or Recommended Actions.
	singleCasePromptTemplate = `/no_think
You are ScanTrace, a network security analyst. Analyse the case below and write a Slack-formatted briefing.

CRITICAL RULES:
- wan_new_connection = connection hit ONLY the WAN edge. It was NOT forwarded to any internal host.
  The dst IP is the router's own external interface. Do NOT call it an unknown internal host.
- wan_forward = traffic was ACTIVELY forwarded to an internal host via a port-forwarding rule. It LANDED.
- "WAN EDGE — gateway interface only" means the destination is the gateway itself, not an internal device.
- Major cloud IPs (Google 34.x/216.239.x/142.251.x, AWS 3.x/18.x/52.x, Cloudflare 104.x, Azure 20.x/40.x):
  prefer closing the exposed port over blocking the source IP.
- Only use IP addresses that appear verbatim in the context data. Never guess or construct an IP.

Port context: 22=SSH, 80=HTTP, 443=HTTPS, 3389=RDP, 3306=MySQL, 5432=PostgreSQL,
6379=Redis, 8080=HTTP-alt, 9200=Elasticsearch, 2379=etcd, 1194=OpenVPN,
5555=ADB, 25565=Minecraft, 30303=Ethereum P2P

PRE-FILLED TRIAGE (do not rewrite this section, copy it exactly as-is):

*Triage*
%s

Now write the following three sections in order. Use Slack mrkdwn formatting (*bold*, bullets). No markdown headers (###). Total under 250 words.

*Summary*
Begin with exactly one of these verdict tokens: [VERDICT: LIKELY BENIGN] or [VERDICT: NEEDS INVESTIGATION] or [VERDICT: LIKELY MALICIOUS]
Then write one sentence explaining the verdict based on the triage facts.

*Details*
Bullet list:
- Source: IP address, organisation, country, ASN, and any hosting/proxy/threat-feed flags from context
- Destination: IP address, classification from Triage, port number, service name
- Events: event count, event type(s), port(s) targeted

*Assessment*
Two to four sentences of engineering analysis tied directly to the triage facts. If the event type is wan_new_connection, state clearly that the traffic never reached the LAN. Do not repeat the triage block.

PRE-FILLED RECOMMENDED ACTIONS (copy this block exactly as-is, do not rewrite or add bullets):

%s`

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
	b := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(b, "/v1") {
		b = strings.TrimSuffix(b, "/v1")
	}
	return &Client{
		baseURL:    b,
		model:      model,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

func (c *Client) Ask(question, context string) (string, error) {
	return c.ask(systemPrompt, question, context)
}

// AskCase renders the single-case prompt with the pre-resolved triage block
// and pre-selected actionPlan both injected by the Go handler layer.
func (c *Client) AskCase(question, context, triageBlock, actionPlan string) (string, error) {
	prompt := fmt.Sprintf(singleCasePromptTemplate, triageBlock, actionPlan)
	return c.ask(prompt, question, context)
}

func (c *Client) ask(prompt, question, context string) (string, error) {
	messages := []Message{
		{Role: "system", Content: prompt},
	}
	if context != "" {
		messages = append(messages, Message{
			Role:    "system",
			Content: "Current ScanTrace data:\n" + context,
		})
	}
	messages = append(messages, Message{Role: "user", Content: question})

	body := map[string]interface{}{
		"messages": messages,
		"stream":   false,
	}
	if prompt == systemPrompt {
		body["max_tokens"] = 900
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
