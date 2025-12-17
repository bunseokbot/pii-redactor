package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPagerDutyNotifier_Type(t *testing.T) {
	notifier := NewPagerDutyNotifier(PagerDutyConfig{
		RoutingKey: "test-routing-key",
	})

	if notifier.Type() != "pagerduty" {
		t.Errorf("Type() = %s, want pagerduty", notifier.Type())
	}
}

func TestPagerDutyNotifier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  PagerDutyConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  PagerDutyConfig{RoutingKey: "test-routing-key"},
			wantErr: false,
		},
		{
			name:    "empty routing key",
			config:  PagerDutyConfig{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := NewPagerDutyNotifier(tt.config)
			err := notifier.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPagerDutyNotifier_Send(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("Failed to decode body: %v", err)
		}

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"success","message":"Event processed","dedup_key":"test"}`))
	}))
	defer server.Close()

	notifier := NewPagerDutyNotifier(PagerDutyConfig{
		RoutingKey: "test-routing-key",
	})
	// Override the API URL for testing
	notifier.apiURL = server.URL

	alert := &Alert{
		ID:          "test-123",
		Severity:    SeverityCritical,
		PatternName: "credit-card",
		Namespace:   "payment",
		Message:     "Credit card number detected",
		Timestamp:   time.Now(),
		MatchCount:  10,
	}

	ctx := context.Background()
	if err := notifier.Send(ctx, alert); err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Verify the message was sent
	if receivedBody == nil {
		t.Error("No message received")
	}

	if receivedBody["routing_key"] != "test-routing-key" {
		t.Errorf("routing_key = %v, want test-routing-key", receivedBody["routing_key"])
	}

	if receivedBody["event_action"] != "trigger" {
		t.Errorf("event_action = %v, want trigger", receivedBody["event_action"])
	}
}

func TestPagerDutyNotifier_SendError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"error","message":"Invalid routing key"}`))
	}))
	defer server.Close()

	notifier := NewPagerDutyNotifier(PagerDutyConfig{
		RoutingKey: "invalid-key",
	})
	notifier.apiURL = server.URL

	alert := &Alert{
		PatternName: "email",
		Namespace:   "default",
		Message:     "Test",
		Timestamp:   time.Now(),
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	if err == nil {
		t.Error("Expected error for 400 response")
	}
}

func TestPagerDutySeverityMapping(t *testing.T) {
	notifier := NewPagerDutyNotifier(PagerDutyConfig{
		RoutingKey: "test",
		Severity:   "info", // default fallback severity
	})

	tests := []struct {
		alertSeverity string
		expected      string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "error"},
		{SeverityMedium, "warning"},
		{SeverityLow, "info"},
		{"unknown", "info"}, // falls back to configured severity
	}

	for _, tt := range tests {
		t.Run(tt.alertSeverity, func(t *testing.T) {
			got := notifier.mapSeverity(tt.alertSeverity)
			if got != tt.expected {
				t.Errorf("mapSeverity(%s) = %s, want %s", tt.alertSeverity, got, tt.expected)
			}
		})
	}
}
