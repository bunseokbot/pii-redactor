package notifier

import (
	"testing"
)

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		severity string
		expected int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{"unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeverityLevel(tt.severity)
			if got != tt.expected {
				t.Errorf("SeverityLevel(%s) = %d, want %d", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestShouldAlert(t *testing.T) {
	tests := []struct {
		alertSeverity string
		minSeverity   string
		expected      bool
	}{
		{SeverityCritical, SeverityLow, true},
		{SeverityCritical, SeverityMedium, true},
		{SeverityCritical, SeverityHigh, true},
		{SeverityCritical, SeverityCritical, true},
		{SeverityHigh, SeverityCritical, false},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityMedium, false},
		{SeverityLow, SeverityLow, true},
	}

	for _, tt := range tests {
		t.Run(tt.alertSeverity+"_"+tt.minSeverity, func(t *testing.T) {
			got := ShouldAlert(tt.alertSeverity, tt.minSeverity)
			if got != tt.expected {
				t.Errorf("ShouldAlert(%s, %s) = %v, want %v", tt.alertSeverity, tt.minSeverity, got, tt.expected)
			}
		})
	}
}

func TestNewAlert(t *testing.T) {
	alert := NewAlert("email", "default", "PII detected")

	if alert.PatternName != "email" {
		t.Errorf("PatternName = %s, want email", alert.PatternName)
	}
	if alert.Namespace != "default" {
		t.Errorf("Namespace = %s, want default", alert.Namespace)
	}
	if alert.Message != "PII detected" {
		t.Errorf("Message = %s, want 'PII detected'", alert.Message)
	}
	if alert.Severity != SeverityMedium {
		t.Errorf("Severity = %s, want %s", alert.Severity, SeverityMedium)
	}
	if alert.ID == "" {
		t.Error("ID should not be empty")
	}
	if alert.Labels == nil {
		t.Error("Labels should be initialized")
	}
}

func TestAlertBuilder(t *testing.T) {
	alert := NewAlert("email", "default", "PII detected").
		WithSeverity(SeverityCritical).
		WithPod("test-pod", "main").
		WithPolicy("default-policy").
		WithSource("log").
		AddLabel("key", "value")

	if alert.Severity != SeverityCritical {
		t.Errorf("Severity = %s, want %s", alert.Severity, SeverityCritical)
	}
	if alert.Pod != "test-pod" {
		t.Errorf("Pod = %s, want test-pod", alert.Pod)
	}
	if alert.Container != "main" {
		t.Errorf("Container = %s, want main", alert.Container)
	}
	if alert.PolicyName != "default-policy" {
		t.Errorf("PolicyName = %s, want default-policy", alert.PolicyName)
	}
	if alert.Source != "log" {
		t.Errorf("Source = %s, want log", alert.Source)
	}
	if alert.Labels["key"] != "value" {
		t.Errorf("Labels[key] = %s, want value", alert.Labels["key"])
	}
}
