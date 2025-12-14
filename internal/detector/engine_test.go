package detector

import (
	"context"
	"testing"
)

func TestEngine_DetectEmail(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "simple email",
			input:    "Contact us at test@example.com",
			expected: 1,
		},
		{
			name:     "multiple emails",
			input:    "From: alice@test.com To: bob@test.com",
			expected: 2,
		},
		{
			name:     "no email",
			input:    "No email here",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := engine.DetectWithPatterns(ctx, tt.input, []string{"email"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != tt.expected {
				t.Errorf("expected %d results, got %d", tt.expected, len(results))
			}
		})
	}
}

func TestEngine_DetectKoreanRRN(t *testing.T) {
	engine := NewEngine()
	// Disable validation for testing with dummy data
	engine.DisableValidation()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "valid RRN with hyphen",
			input:    "주민번호: 920101-1234567",
			expected: 1,
		},
		{
			name:     "valid RRN without hyphen",
			input:    "RRN: 9201011234567",
			expected: 1,
		},
		{
			name:     "invalid RRN format",
			input:    "Invalid: 123456-0000000",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := engine.DetectWithPatterns(ctx, tt.input, []string{"korean-rrn"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != tt.expected {
				t.Errorf("expected %d results, got %d", tt.expected, len(results))
			}
		})
	}
}

func TestEngine_DetectCreditCard(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	tests := []struct {
		name        string
		input       string
		expectMatch bool
	}{
		{
			name:        "Visa card",
			input:       "Card: 4111111111111111",
			expectMatch: true,
		},
		{
			name:        "card with dashes",
			input:       "Card: 4111-1111-1111-1111",
			expectMatch: true,
		},
		{
			name:        "invalid card (fails Luhn)",
			input:       "Not a card: 1234567890123456",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := engine.DetectWithPatterns(ctx, tt.input, []string{"credit-card"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			hasMatch := len(results) > 0
			if hasMatch != tt.expectMatch {
				t.Errorf("expected match=%v, got %d results", tt.expectMatch, len(results))
			}
		})
	}
}

func TestEngine_DetectAWSKeys(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "AWS access key",
			input:    "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE",
			expected: 1,
		},
		{
			name:     "no AWS key",
			input:    "Some random text",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := engine.DetectWithPatterns(ctx, tt.input, []string{"aws-access-key"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != tt.expected {
				t.Errorf("expected %d results, got %d", tt.expected, len(results))
			}
		})
	}
}

func TestEngine_DetectMultiplePII(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	input := "User test@example.com from 010-1234-5678 with IP 192.168.1.1"

	results, err := engine.DetectInText(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect email and phone-kr (ip-address is disabled by default)
	if len(results) < 2 {
		t.Errorf("expected at least 2 results, got %d", len(results))
	}

	// Check pattern names
	patterns := make(map[string]bool)
	for _, r := range results {
		patterns[r.PatternName] = true
	}

	if !patterns["email"] {
		t.Error("expected to detect email")
	}
	if !patterns["phone-kr"] {
		t.Error("expected to detect phone-kr")
	}
}

func TestEngine_DetectWithEnabledPattern(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Enable ip-address pattern explicitly
	engine.EnablePattern("ip-address")

	input := "Server IP: 192.168.1.1"

	results, err := engine.DetectInText(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that ip-address is detected after enabling
	found := false
	for _, r := range results {
		if r.PatternName == "ip-address" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to detect ip-address after enabling the pattern")
	}
}

func BenchmarkEngine_Detect(b *testing.B) {
	engine := NewEngine()
	ctx := context.Background()
	input := "User test@example.com from 010-1234-5678 with SSN 920101-1234567 and card 4111-1111-1111-1111"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.DetectInText(ctx, input)
	}
}
