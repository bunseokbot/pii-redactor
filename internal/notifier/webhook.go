package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookNotifier sends alerts to a generic HTTP webhook
type WebhookNotifier struct {
	url        string
	method     string
	headers    map[string]string
	httpClient *http.Client
}

// WebhookConfig holds configuration for WebhookNotifier
type WebhookConfig struct {
	URL     string
	Method  string // POST or PUT
	Headers map[string]string
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(config WebhookConfig) *WebhookNotifier {
	if config.Method == "" {
		config.Method = http.MethodPost
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	return &WebhookNotifier{
		url:     config.URL,
		method:  config.Method,
		headers: config.Headers,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Type returns the notifier type
func (w *WebhookNotifier) Type() string {
	return "webhook"
}

// Validate checks if the configuration is valid
func (w *WebhookNotifier) Validate() error {
	if w.url == "" {
		return fmt.Errorf("webhook URL is required")
	}
	if w.method != http.MethodPost && w.method != http.MethodPut {
		return fmt.Errorf("webhook method must be POST or PUT")
	}
	return nil
}

// Send sends an alert to the webhook
func (w *WebhookNotifier) Send(ctx context.Context, alert *Alert) error {
	payload := w.buildPayload(alert)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PII-Redactor/1.0")

	for key, value := range w.headers {
		req.Header.Set(key, value)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

// webhookPayload represents the JSON payload sent to webhooks
type webhookPayload struct {
	Event     string                 `json:"event"`
	Timestamp string                 `json:"timestamp"`
	Alert     webhookAlert           `json:"alert"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// webhookAlert represents the alert data in the webhook payload
type webhookAlert struct {
	ID                 string            `json:"id"`
	Severity           string            `json:"severity"`
	PatternName        string            `json:"patternName"`
	PatternDisplayName string            `json:"patternDisplayName,omitempty"`
	Namespace          string            `json:"namespace"`
	Pod                string            `json:"pod,omitempty"`
	Container          string            `json:"container,omitempty"`
	Message            string            `json:"message"`
	MatchCount         int               `json:"matchCount"`
	PolicyName         string            `json:"policyName,omitempty"`
	Source             string            `json:"source,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
}

// buildPayload builds a webhook payload from an alert
func (w *WebhookNotifier) buildPayload(alert *Alert) webhookPayload {
	return webhookPayload{
		Event:     "pii.detected",
		Timestamp: alert.Timestamp.Format(time.RFC3339),
		Alert: webhookAlert{
			ID:                 alert.ID,
			Severity:           alert.Severity,
			PatternName:        alert.PatternName,
			PatternDisplayName: alert.PatternDisplayName,
			Namespace:          alert.Namespace,
			Pod:                alert.Pod,
			Container:          alert.Container,
			Message:            alert.Message,
			MatchCount:         alert.MatchCount,
			PolicyName:         alert.PolicyName,
			Source:             alert.Source,
			Labels:             alert.Labels,
		},
		Metadata: map[string]interface{}{
			"version": "1.0",
			"source":  "pii-redactor",
		},
	}
}

// SetHTTPClient sets a custom HTTP client (useful for testing)
func (w *WebhookNotifier) SetHTTPClient(client *http.Client) {
	w.httpClient = client
}

// AddHeader adds or updates a header
func (w *WebhookNotifier) AddHeader(key, value string) {
	w.headers[key] = value
}
