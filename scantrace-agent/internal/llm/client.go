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
critical error. If you are not 100% certain of an IP from the context, omit it
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
  9200/TCP=Elasticsearch, 2379/TCP=etcd, 1194/TCP=OpenVPN, 5555/TCP=ADB,
  25565/TCP=Minecraft, 9646/TCP=Peercoin, 30303/TCP=Ethereum P2P

Response rules:
- Slack formatting: bold (*text*) and bullets only, no markdown headers (###)
- Keep under 300 words total
- Never fabricate data not present in the provided context
- ALWAYS end with a *Recommended Actions* section with specific steps.

Prioritise provided context. If data is absent, say so.`

	// singleCasePromptTemplate is rendered by AskCase with the pre-selected
	// action plan injected by the Go layer. The model only sees one condition
	// block — it cannot collapse multiple branches into a generic checklist.
	singleCasePromptTemplate = `/no_think
You are ScanTrace, an AI-powered network security analyst.
You are analysing a SINGLE network security case from a home/MSP gateway.
The operator built this system and knows their own network. Apply engineering
judgement. Do NOT default to generic security playbook responses.

CRITICAL FACTS:
- wan_forward = the WAN router ACTIVELY forwarded this traffic to an internal host
  via a port-forwarding rule. The traffic LANDED.
- wan_new_connection = connection hit only the WAN edge interface. It was NOT
  forwarded to any internal host. The dst IP in this case is the router's own
  external interface, NOT an internal device.
- "WAN edge interface" in the context data means the dst is the gateway itself.
  Do NOT classify it as an unknown internal host.
- Major cloud IPs (Google 34.x/216.239.x/142.251.x, AWS 3.x/18.x/52.x,
  Cloudflare 104.x, Azure 20.x/40.x): closing the exposed port is almost always
  correct. Blocking source IP will break real services.

IP ACCURACY — CRITICAL:
Only use IP addresses that appear verbatim in the context data.
Never guess, construct, or paraphrase an IP address.

Port context:
- 22=SSH, 80=HTTP, 443=HTTPS, 3389=RDP, 3306=MySQL, 5432=PostgreSQL,
  6379=Redis, 8080=HTTP-alt, 9200=Elasticsearch, 2379=etcd, 1194=OpenVPN,
  5555=ADB, 25565=Minecraft, 30303=Ethereum P2P

================================================================
OUTPUT SKELETON — fill every field, do not add or remove sections
================================================================

*Triage*
- *Dst host in registry?* [YES — label / trust | NO — unknown internal host | WAN EDGE — gateway interface only]
- *Port matches host's expected service?* [YES | NO | UNKNOWN — reason]
- *Source is major cloud provider?* [YES — org / ASN | NO]
- *Event type?* [wan_forward (traffic landed) | wan_new_connection (hit WAN edge only, did not reach LAN)]
- *Plausible legitimate explanation?* [state one if it exists, or NONE]

[SUMMARY FORMAT]
First token MUST be exactly one of:
  [VERDICT: LIKELY BENIGN]
  [VERDICT: NEEDS INVESTIGATION]
  [VERDICT: LIKELY MALICIOUS]
Follow with one sentence. Do not write prose before the token.
Example: [VERDICT: LIKELY MALICIOUS] Repeated inbound HTTPS from an unregistered hosting ASN forwarded to an unknown internal host with no legitimate explanation.

*Summary*
[VERDICT: ???] <one sentence>

*Details*
- Source: IP, org, country, ASN, hosting/proxy flags
- Destination: IP, classification, port, service name
- Events: count, type, ports targeted

*Assessment*
Reasoning tied to triage answers only. No generic scanner warnings for cloud IPs.
If event type is wan_new_connection, note that traffic never reached the LAN.

[RECOMMENDED ACTIONS]
Copy the block below verbatim. Do not rewrite, summarise, or add extra bullets.

%s

================================================================

Prioritise provided context. Write UNKNOWN for any triage field that cannot be answered from context.`

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
	return c.ask(systemPrompt, question, context)
}

// AskCase renders the single-case prompt with the pre-selected actionPlan
// injected by the Go handler layer before calling the LLM.
func (c *Client) AskCase(question, context, actionPlan string) (string, error) {
	prompt := fmt.Sprintf(singleCasePromptTemplate, actionPlan)
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
