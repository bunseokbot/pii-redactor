package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const pagerDutyEventsAPIURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyNotifier sends alerts to PagerDuty
type PagerDutyNotifier struct {
	routingKey string
	severity   string
	apiURL     string
	httpClient *http.Client
}

// PagerDutyConfig holds configuration for PagerDutyNotifier
type PagerDutyConfig struct {
	RoutingKey string // Integration/routing key
	Severity   string // critical, error, warning, info
}

// NewPagerDutyNotifier creates a new PagerDuty notifier
func NewPagerDutyNotifier(config PagerDutyConfig) *PagerDutyNotifier {
	if config.Severity == "" {
		config.Severity = "critical"
	}

	return &PagerDutyNotifier{
		routingKey: config.RoutingKey,
		severity:   config.Severity,
		apiURL:     pagerDutyEventsAPIURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Type returns the notifier type
func (p *PagerDutyNotifier) Type() string {
	return "pagerduty"
}

// Validate checks if the configuration is valid
func (p *PagerDutyNotifier) Validate() error {
	if p.routingKey == "" {
		return fmt.Errorf("pagerduty routing key is required")
	}
	return nil
}

// Send sends an alert to PagerDuty
func (p *PagerDutyNotifier) Send(ctx context.Context, alert *Alert) error {
	event := p.buildEvent(alert)

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal pagerduty event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send pagerduty event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pagerduty returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

// pagerDutyEvent represents a PagerDuty Events API v2 event
type pagerDutyEvent struct {
	RoutingKey  string             `json:"routing_key"`
	EventAction string             `json:"event_action"`
	DedupKey    string             `json:"dedup_key,omitempty"`
	Payload     pagerDutyPayload   `json:"payload"`
	Links       []pagerDutyLink    `json:"links,omitempty"`
	Images      []pagerDutyImage   `json:"images,omitempty"`
}

// pagerDutyPayload represents the payload section of a PagerDuty event
type pagerDutyPayload struct {
	Summary       string                 `json:"summary"`
	Source        string                 `json:"source"`
	Severity      string                 `json:"severity"`
	Timestamp     string                 `json:"timestamp,omitempty"`
	Component     string                 `json:"component,omitempty"`
	Group         string                 `json:"group,omitempty"`
	Class         string                 `json:"class,omitempty"`
	CustomDetails map[string]interface{} `json:"custom_details,omitempty"`
}

// pagerDutyLink represents a link in a PagerDuty event
type pagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text,omitempty"`
}

// pagerDutyImage represents an image in a PagerDuty event
type pagerDutyImage struct {
	Src  string `json:"src"`
	Href string `json:"href,omitempty"`
	Alt  string `json:"alt,omitempty"`
}

// buildEvent builds a PagerDuty event from an alert
func (p *PagerDutyNotifier) buildEvent(alert *Alert) pagerDutyEvent {
	summary := fmt.Sprintf("PII Detected: %s in %s", alert.PatternName, alert.Namespace)
	if alert.PatternDisplayName != "" {
		summary = fmt.Sprintf("PII Detected: %s in %s", alert.PatternDisplayName, alert.Namespace)
	}

	source := "pii-redactor"
	if alert.Namespace != "" {
		source = fmt.Sprintf("pii-redactor/%s", alert.Namespace)
	}

	customDetails := map[string]interface{}{
		"pattern_name": alert.PatternName,
		"namespace":    alert.Namespace,
		"severity":     alert.Severity,
		"match_count":  alert.MatchCount,
	}

	if alert.Pod != "" {
		customDetails["pod"] = alert.Pod
	}
	if alert.Container != "" {
		customDetails["container"] = alert.Container
	}
	if alert.PolicyName != "" {
		customDetails["policy"] = alert.PolicyName
	}
	if alert.Source != "" {
		customDetails["source"] = alert.Source
	}
	if alert.Message != "" {
		customDetails["message"] = alert.Message
	}

	// Map our severity to PagerDuty severity
	pdSeverity := p.mapSeverity(alert.Severity)

	return pagerDutyEvent{
		RoutingKey:  p.routingKey,
		EventAction: "trigger",
		DedupKey:    fmt.Sprintf("pii-%s-%s-%s", alert.Namespace, alert.PatternName, alert.ID),
		Payload: pagerDutyPayload{
			Summary:       summary,
			Source:        source,
			Severity:      pdSeverity,
			Timestamp:     alert.Timestamp.Format(time.RFC3339),
			Component:     "pii-redactor",
			Group:         alert.Namespace,
			Class:         "pii-detection",
			CustomDetails: customDetails,
		},
	}
}

// mapSeverity maps our severity levels to PagerDuty severity levels
func (p *PagerDutyNotifier) mapSeverity(severity string) string {
	switch severity {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "info"
	default:
		return p.severity
	}
}

// SetHTTPClient sets a custom HTTP client (useful for testing)
func (p *PagerDutyNotifier) SetHTTPClient(client *http.Client) {
	p.httpClient = client
}
