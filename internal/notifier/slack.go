package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SlackNotifier sends alerts to Slack via webhook
type SlackNotifier struct {
	webhookURL string
	channel    string
	username   string
	iconEmoji  string
	httpClient *http.Client
}

// SlackConfig holds configuration for SlackNotifier
type SlackConfig struct {
	WebhookURL string
	Channel    string
	Username   string
	IconEmoji  string
}

// NewSlackNotifier creates a new Slack notifier
func NewSlackNotifier(config SlackConfig) *SlackNotifier {
	if config.Username == "" {
		config.Username = "PII Redactor"
	}
	if config.IconEmoji == "" {
		config.IconEmoji = ":shield:"
	}

	return &SlackNotifier{
		webhookURL: config.WebhookURL,
		channel:    config.Channel,
		username:   config.Username,
		iconEmoji:  config.IconEmoji,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Type returns the notifier type
func (s *SlackNotifier) Type() string {
	return "slack"
}

// Validate checks if the configuration is valid
func (s *SlackNotifier) Validate() error {
	if s.webhookURL == "" {
		return fmt.Errorf("slack webhook URL is required")
	}
	if !strings.HasPrefix(s.webhookURL, "https://hooks.slack.com/") &&
		!strings.HasPrefix(s.webhookURL, "https://") {
		return fmt.Errorf("invalid slack webhook URL format")
	}
	return nil
}

// Send sends an alert to Slack
func (s *SlackNotifier) Send(ctx context.Context, alert *Alert) error {
	message := s.buildMessage(alert)

	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

// slackMessage represents a Slack webhook message
type slackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

// slackAttachment represents a Slack message attachment
type slackAttachment struct {
	Color      string       `json:"color,omitempty"`
	Title      string       `json:"title,omitempty"`
	Text       string       `json:"text,omitempty"`
	Fields     []slackField `json:"fields,omitempty"`
	Footer     string       `json:"footer,omitempty"`
	FooterIcon string       `json:"footer_icon,omitempty"`
	Timestamp  int64        `json:"ts,omitempty"`
}

// slackField represents a field in a Slack attachment
type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// buildMessage builds a Slack message from an alert
func (s *SlackNotifier) buildMessage(alert *Alert) slackMessage {
	color := s.severityColor(alert.Severity)
	title := fmt.Sprintf("PII Detected: %s", alert.PatternName)

	if alert.PatternDisplayName != "" {
		title = fmt.Sprintf("PII Detected: %s", alert.PatternDisplayName)
	}

	fields := []slackField{
		{Title: "Severity", Value: strings.ToUpper(alert.Severity), Short: true},
		{Title: "Pattern", Value: alert.PatternName, Short: true},
		{Title: "Namespace", Value: alert.Namespace, Short: true},
	}

	if alert.Pod != "" {
		fields = append(fields, slackField{Title: "Pod", Value: alert.Pod, Short: true})
	}

	if alert.Container != "" {
		fields = append(fields, slackField{Title: "Container", Value: alert.Container, Short: true})
	}

	if alert.PolicyName != "" {
		fields = append(fields, slackField{Title: "Policy", Value: alert.PolicyName, Short: true})
	}

	fields = append(fields, slackField{Title: "Match Count", Value: fmt.Sprintf("%d", alert.MatchCount), Short: true})

	if alert.Source != "" {
		fields = append(fields, slackField{Title: "Source", Value: alert.Source, Short: true})
	}

	attachment := slackAttachment{
		Color:     color,
		Title:     title,
		Text:      alert.Message,
		Fields:    fields,
		Footer:    "PII Redactor",
		Timestamp: alert.Timestamp.Unix(),
	}

	return slackMessage{
		Channel:     s.channel,
		Username:    s.username,
		IconEmoji:   s.iconEmoji,
		Attachments: []slackAttachment{attachment},
	}
}

// severityColor returns the Slack color for a severity level
func (s *SlackNotifier) severityColor(severity string) string {
	switch severity {
	case SeverityCritical:
		return "#dc3545" // red
	case SeverityHigh:
		return "#fd7e14" // orange
	case SeverityMedium:
		return "#ffc107" // yellow
	case SeverityLow:
		return "#17a2b8" // blue
	default:
		return "#6c757d" // gray
	}
}

// SetHTTPClient sets a custom HTTP client (useful for testing)
func (s *SlackNotifier) SetHTTPClient(client *http.Client) {
	s.httpClient = client
}
