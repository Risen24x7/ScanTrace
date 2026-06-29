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
	// systemPrompt is used for general @mention queries (multi-case context).
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
- Format IPs, ports, case IDs in backticks
- Never fabricate data not present in the provided context
- ALWAYS end with a *Recommended Actions* section with specific steps.

Prioritise provided context. If data is absent, say so.`

	// singleCasePrompt forces the model to emit a structured triage block
	// BEFORE drawing any conclusions. The triage fields are mandatory output —
	// the model cannot skip them because the response template requires them.
	singleCasePrompt = `/no_think
You are ScanTrace, an AI-powered network security analyst.
You are analysing a SINGLE network security case from a home/MSP gateway.
The operator built this system and knows their own network. Apply engineering
judgement. Do NOT default to generic security playbook responses.

CRITICAL FACTS:
- wan_forward = the WAN router ACTIVELY forwarded this traffic to an internal host
  via a port-forwarding rule. The traffic LANDED. This is not a scan that was blocked.
  Public CDNs and cloud services do NOT spontaneously initiate inbound connections to
  RFC1918 addresses — wan_forward only occurs when the operator has an explicit rule.
- wan_new_connection = a connection attempt hit the WAN interface. It may or may not
  have been forwarded. Lower urgency than wan_forward unless repeated on sensitive ports.
- Major cloud IPs (Google 34.x/216.239.x/142.251.x, AWS 3.x/18.x/52.x,
  Cloudflare 104.x, Azure 20.x/40.x): blocking these ranges will break real services.
  Closing the exposed port is almost always the correct action.

IP ACCURACY — CRITICAL:
Only use IP addresses that appear verbatim in the context data.
Never guess, construct, or paraphrase an IP address.

Port context:
- 22=SSH, 80=HTTP, 443=HTTPS, 3389=RDP, 3306=MySQL, 5432=PostgreSQL,
  6379=Redis, 8080=HTTP-alt, 9200=Elasticsearch, 2379=etcd, 1194=OpenVPN,
  5555=ADB, 25565=Minecraft, 30303=Ethereum P2P

You MUST produce output in EXACTLY this structure. Do not skip any section.
Fill every TRIAGE field with a concrete answer from the context data.

---
*Triage*
- *Dst host in registry?* [YES — label / trust | NO — unknown internal host]
- *Port matches host's expected service?* [YES | NO | UNKNOWN — reason]
- *Source is major cloud provider?* [YES — org / ASN | NO]
- *Event type?* [wan_forward (traffic landed) | wan_new_connection (hit WAN only)]
- *Plausible legitimate explanation?* [state one if it exists, or NONE]

*Summary*
One sentence verdict: what is happening and whether it is LIKELY BENIGN, NEEDS INVESTIGATION, or LIKELY MALICIOUS. Base this on the triage answers above.

*Details*
- Source: IP, org, country, ASN, hosting/proxy flags
- Destination: IP, registry label, port, service name
- Events: count, type, ports targeted

*Assessment*
Reasoning tied directly to the triage answers. If Plausible legitimate explanation is not NONE, explain why you still consider it a threat (or don't). Do not repeat generic scanner warnings for cloud provider IPs.

*Recommended Actions*
Priority rules — apply the FIRST matching rule, then continue with the rest:
1. If "Dst host in registry" is NO: the absolute first action is "Identify the
   device at [dst IP] — run arp-scan or check DHCP leases to determine what
   machine this is before any other step."
2. If "Dst host in registry" is YES and event type is wan_forward: the first
   action is "Check app/proxy logs on [dst IP] for requests matching these
   timestamps."
3. Only recommend firewall changes after the above identification/log steps,
   and only if findings confirm malicious intent.
---

Prioritise provided context. If a triage field cannot be answered from context, write UNKNOWN.`

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

// Ask is used for general @mention queries — multi-case context, 300-word cap.
func (c *Client) Ask(question, context string) (string, error) {
	return c.ask(systemPrompt, question, context)
}

// AskCase is used by review-all and next — single-case context, no word cap.
func (c *Client) AskCase(question, context string) (string, error) {
	return c.ask(singleCasePrompt, question, context)
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
