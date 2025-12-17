package notifier

import (
	"strings"
	"testing"
)

func TestEmailNotifier_Type(t *testing.T) {
	notifier := NewEmailNotifier(EmailConfig{
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		From:     "alerts@example.com",
		To:       []string{"admin@example.com"},
	})

	if notifier.Type() != "email" {
		t.Errorf("Type() = %s, want email", notifier.Type())
	}
}

func TestEmailNotifier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  EmailConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: EmailConfig{
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
				From:     "alerts@example.com",
				To:       []string{"admin@example.com"},
			},
			wantErr: false,
		},
		{
			name: "empty host",
			config: EmailConfig{
				SMTPPort: 587,
				From:     "alerts@example.com",
				To:       []string{"admin@example.com"},
			},
			wantErr: true,
		},
		{
			name: "empty from",
			config: EmailConfig{
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
				To:       []string{"admin@example.com"},
			},
			wantErr: true,
		},
		{
			name: "empty to",
			config: EmailConfig{
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
				From:     "alerts@example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := NewEmailNotifier(tt.config)
			err := notifier.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEmailNotifier_BuildSubject(t *testing.T) {
	notifier := &EmailNotifier{}

	alert := &Alert{
		Severity:    SeverityCritical,
		PatternName: "ssn",
		Namespace:   "production",
	}

	subject := notifier.buildSubject(alert)
	if subject == "" {
		t.Error("Subject should not be empty")
	}

	// Check that severity and pattern are in subject
	if !strings.Contains(subject, "CRITICAL") {
		t.Errorf("Subject should contain severity, got: %s", subject)
	}

	if !strings.Contains(subject, "ssn") {
		t.Errorf("Subject should contain pattern name, got: %s", subject)
	}
}

func TestEmailNotifier_BuildBody(t *testing.T) {
	notifier := &EmailNotifier{}

	alert := &Alert{
		Severity:    SeverityHigh,
		PatternName: "email",
		Namespace:   "default",
		Pod:         "test-pod",
		Container:   "main",
		Message:     "PII detected in logs",
		MatchCount:  5,
	}

	body := notifier.buildBody(alert)

	if !strings.Contains(body, "HIGH") {
		t.Error("Body should contain severity")
	}

	if !strings.Contains(body, "email") {
		t.Error("Body should contain pattern name")
	}

	if !strings.Contains(body, "test-pod") {
		t.Error("Body should contain pod name")
	}
}
