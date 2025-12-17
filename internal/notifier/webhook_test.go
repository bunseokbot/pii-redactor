package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookNotifier_Type(t *testing.T) {
	notifier := NewWebhookNotifier(WebhookConfig{
		URL: "https://example.com/webhook",
	})

	if notifier.Type() != "webhook" {
		t.Errorf("Type() = %s, want webhook", notifier.Type())
	}
}

func TestWebhookNotifier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  WebhookConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			config:  WebhookConfig{URL: "https://example.com/webhook"},
			wantErr: false,
		},
		{
			name:    "empty URL",
			config:  WebhookConfig{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := NewWebhookNotifier(tt.config)
			err := notifier.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWebhookNotifier_Send(t *testing.T) {
	var receivedBody map[string]interface{}
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		receivedHeaders = r.Header

		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("Failed to decode body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(WebhookConfig{
		URL: server.URL,
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
		},
	})

	alert := &Alert{
		ID:          "test-123",
		Severity:    SeverityHigh,
		PatternName: "ssn",
		Namespace:   "production",
		Message:     "SSN detected",
		Timestamp:   time.Now(),
		MatchCount:  3,
	}

	ctx := context.Background()
	if err := notifier.Send(ctx, alert); err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// Verify headers
	if receivedHeaders.Get("X-Custom-Header") != "test-value" {
		t.Errorf("Custom header = %s, want test-value", receivedHeaders.Get("X-Custom-Header"))
	}

	// Verify content type
	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", receivedHeaders.Get("Content-Type"))
	}

	// Verify the message was sent
	if receivedBody == nil {
		t.Error("No message received")
	}
}

func TestWebhookNotifier_SendError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	notifier := NewWebhookNotifier(WebhookConfig{
		URL: server.URL,
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
		t.Error("Expected error for 400 response")
	}
}
