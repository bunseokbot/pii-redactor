package notifier

import (
	"context"
	"time"

	"github.com/bunseokbot/pii-redactor/internal/detector"
)

// Severity levels for alerts
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Alert represents a PII detection alert
type Alert struct {
	// ID is a unique identifier for this alert
	ID string `json:"id"`

	// Severity is the alert severity level
	Severity string `json:"severity"`

	// PatternName is the name of the pattern that matched
	PatternName string `json:"patternName"`

	// PatternDisplayName is the human-readable pattern name
	PatternDisplayName string `json:"patternDisplayName,omitempty"`

	// Namespace is the Kubernetes namespace where PII was detected
	Namespace string `json:"namespace"`

	// Pod is the pod name where PII was detected
	Pod string `json:"pod,omitempty"`

	// Container is the container name where PII was detected
	Container string `json:"container,omitempty"`

	// Message is a human-readable alert message
	Message string `json:"message"`

	// Timestamp is when the alert was generated
	Timestamp time.Time `json:"timestamp"`

	// Detections contains the actual detection results
	Detections []detector.DetectionResult `json:"detections,omitempty"`

	// PolicyName is the name of the policy that triggered this alert
	PolicyName string `json:"policyName,omitempty"`

	// RedactedText is the redacted version of the detected text
	RedactedText string `json:"redactedText,omitempty"`

	// MatchCount is the number of PII matches found
	MatchCount int `json:"matchCount"`

	// Source identifies where the PII was detected (e.g., "log", "configmap", "secret")
	Source string `json:"source,omitempty"`

	// Labels contains additional metadata
	Labels map[string]string `json:"labels,omitempty"`
}

// Notifier defines the interface for sending alerts
type Notifier interface {
	// Send sends an alert through this notification channel
	Send(ctx context.Context, alert *Alert) error

	// Type returns the type of this notifier (e.g., "slack", "pagerduty")
	Type() string

	// Validate checks if the notifier configuration is valid
	Validate() error
}

// NotifierConfig holds common configuration for notifiers
type NotifierConfig struct {
	// MinSeverity is the minimum severity level to send alerts for
	MinSeverity string

	// RateLimitPerMinute limits the number of alerts per minute
	RateLimitPerMinute int
}

// SeverityLevel returns numeric severity for comparison
func SeverityLevel(severity string) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ShouldAlert returns true if the alert severity meets the minimum threshold
func ShouldAlert(alertSeverity, minSeverity string) bool {
	return SeverityLevel(alertSeverity) >= SeverityLevel(minSeverity)
}

// NewAlert creates a new alert with the given parameters
func NewAlert(patternName, namespace, message string) *Alert {
	return &Alert{
		ID:          generateAlertID(),
		PatternName: patternName,
		Namespace:   namespace,
		Message:     message,
		Timestamp:   time.Now(),
		Severity:    SeverityMedium,
		Labels:      make(map[string]string),
	}
}

// generateAlertID generates a unique alert ID
func generateAlertID() string {
	return time.Now().Format("20060102150405.000000000")
}

// WithSeverity sets the severity on the alert
func (a *Alert) WithSeverity(severity string) *Alert {
	a.Severity = severity
	return a
}

// WithPod sets the pod information on the alert
func (a *Alert) WithPod(pod, container string) *Alert {
	a.Pod = pod
	a.Container = container
	return a
}

// WithDetections sets the detection results on the alert
func (a *Alert) WithDetections(detections []detector.DetectionResult) *Alert {
	a.Detections = detections
	a.MatchCount = len(detections)
	return a
}

// WithPolicy sets the policy name on the alert
func (a *Alert) WithPolicy(policyName string) *Alert {
	a.PolicyName = policyName
	return a
}

// WithSource sets the source on the alert
func (a *Alert) WithSource(source string) *Alert {
	a.Source = source
	return a
}

// AddLabel adds a label to the alert
func (a *Alert) AddLabel(key, value string) *Alert {
	if a.Labels == nil {
		a.Labels = make(map[string]string)
	}
	a.Labels[key] = value
	return a
}
