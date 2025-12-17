package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSlackNotifier_Type(t *testing.T) {
	notifier := NewSlackNotifier(SlackConfig{
		WebhookURL: "https://hooks.slack.com/test",
	})

	if notifier.Type() != "slack" {
		t.Errorf("Type() = %s, want slack", notifier.Type())
	}
}

func TestSlackNotifier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  SlackConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  SlackConfig{WebhookURL: "https://hooks.slack.com/test"},
			wantErr: false,
		},
		{
			name:    "empty URL",
			config:  SlackConfig{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := NewSlackNotifier(tt.config)
			err := notifier.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSlackNotifier_Send(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("Failed to decode body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(SlackConfig{
		WebhookURL: server.URL,
		Channel:    "#test",
		Username:   "Test Bot",
	})

	alert := &Alert{
		ID:          "test-123",
		Severity:    SeverityCritical,
		PatternName: "email",
		Namespace:   "default",
		Message:     "PII detected",
		Timestamp:   time.Now(),
		MatchCount:  5,
	}

	ctx := context.Background()
	if err := notifier.Send(ctx, alert); err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Verify the message was sent
	if receivedBody == nil {
		t.Error("No message received")
	}

	if receivedBody["channel"] != "#test" {
		t.Errorf("channel = %v, want #test", receivedBody["channel"])
	}

	if receivedBody["username"] != "Test Bot" {
		t.Errorf("username = %v, want 'Test Bot'", receivedBody["username"])
	}
}

func TestSlackNotifier_SendError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	notifier := NewSlackNotifier(SlackConfig{
		WebhookURL: server.URL,
	})

	alert := &Alert{
		PatternName: "email",
		Namespace:   "default",
		Message:     "Test",
		Timestamp:   time.Now(),
	}

	ctx := context.Background()
	err := notifier.Send(ctx, alert)
	if err == nil {
		t.Error("Expected error for 500 response")
	}
}
