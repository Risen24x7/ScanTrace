// Package rts implements the Slack Real-Time Signals (RTS) API client.
// RTS lets the agent subscribe to workspace signals (new messages, reactions,
// channel joins) and react to them in near real-time beyond normal event subs.
//
// Slack RTS API reference:
// https://api.slack.com/methods#realtime_signals
package rts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const rtsBaseURL = "https://slack.com/api"

// Signal types ScanTrace subscribes to.
const (
	SignalMessageChannel = "message.channels"
	SignalAppMention     = "app_mention"
	SignalReactionAdded  = "reaction_added"
)

// Client is the RTS API client.
type Client struct {
	token      string
	httpClient *http.Client
	handlers   map[string][]SignalHandler
}

// SignalHandler is a callback for a received signal.
type SignalHandler func(payload map[string]interface{})

// SignalSubscription represents a registered signal subscription.
type SignalSubscription struct {
	SignalType string `json:"signal_type"`
	CallbackID string `json:"callback_id"`
}

// New creates an RTS client with the given bot token.
func New(token string) *Client {
	return &Client{
		token:      token,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		handlers:   make(map[string][]SignalHandler),
	}
}

// On registers a handler for a signal type.
func (c *Client) On(signalType string, handler SignalHandler) {
	c.handlers[signalType] = append(c.handlers[signalType], handler)
}

// Dispatch routes an incoming signal payload to registered handlers.
// Call this from your Socket Mode event loop when you receive RTS events.
func (c *Client) Dispatch(signalType string, payload map[string]interface{}) {
	handlers, ok := c.handlers[signalType]
	if !ok {
		return
	}
	for _, h := range handlers {
		h(payload)
	}
}

// Subscribe registers a signal subscription with the Slack API.
// Returns the subscription ID or an error.
func (c *Client) Subscribe(signalType, callbackID string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"signal_type": signalType,
		"callback_id": callbackID,
	})
	resp, err := c.post("signal.subscriptions.add", body)
	if err != nil {
		return "", err
	}
	subID, _ := resp["subscription_id"].(string)
	log.Printf("[rts] subscribed to %s (id: %s)", signalType, subID)
	return subID, nil
}

// Unsubscribe removes a signal subscription.
func (c *Client) Unsubscribe(subscriptionID string) error {
	body, _ := json.Marshal(map[string]string{
		"subscription_id": subscriptionID,
	})
	_, err := c.post("signal.subscriptions.remove", body)
	return err
}

// ListSubscriptions returns all active signal subscriptions for this app.
func (c *Client) ListSubscriptions() ([]SignalSubscription, error) {
	resp, err := c.post("signal.subscriptions.list", []byte(`{}`))
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(resp["subscriptions"])
	var subs []SignalSubscription
	json.Unmarshal(raw, &subs)
	return subs, nil
}

// PublishSignal sends a custom signal to a channel.
// Use this to broadcast ScanTrace alerts as workspace signals.
func (c *Client) PublishSignal(channelID, signalType string, payload map[string]interface{}) error {
	body, _ := json.Marshal(map[string]interface{}{
		"channel":     channelID,
		"signal_type": signalType,
		"payload":     payload,
	})
	_, err := c.post("signal.publish", body)
	return err
}

func (c *Client) post(method string, body []byte) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/%s", rtsBaseURL, method)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[rts] %s request failed: %w", method, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("[rts] %s bad response: %w", method, err)
	}
	if ok, _ := result["ok"].(bool); !ok {
		errMsg, _ := result["error"].(string)
		return nil, fmt.Errorf("[rts] %s error: %s", method, errMsg)
	}
	return result, nil
}
