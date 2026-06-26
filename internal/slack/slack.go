// Package slack posts ScanTrace case alerts to a Slack channel via Incoming Webhooks.
// No bot token is required — just set SLACK_WEBHOOK_URL.
package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client sends alerts to a single Slack Incoming Webhook URL.
type Client struct {
	webhookURL string
	httpClient *http.Client
}

// New creates a Slack client for the given Incoming Webhook URL.
func New(webhookURL string) *Client {
	return &Client{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// PostBlock sends a pre-built Block Kit payload to the webhook.
func (c *Client) PostBlock(payload map[string]interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshal payload: %w", err)
	}
	resp, err := c.httpClient.Post(c.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: webhook returned %d", resp.StatusCode)
	}
	return nil
}

// PostText sends a plain-text message.
func (c *Client) PostText(text string) error {
	return c.PostBlock(map[string]interface{}{"text": text})
}

// Enabled returns true if a webhook URL is configured.
func (c *Client) Enabled() bool {
	return c.webhookURL != ""
}
