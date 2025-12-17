package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestNewAuditEntry(t *testing.T) {
	entry := NewAuditEntry(EventTypePIIDetected, "default", "test-policy", "email")

	if entry.EventType != EventTypePIIDetected {
		t.Errorf("EventType = %s, want %s", entry.EventType, EventTypePIIDetected)
	}
	if entry.Namespace != "default" {
		t.Errorf("Namespace = %s, want default", entry.Namespace)
	}
	if entry.PolicyName != "test-policy" {
		t.Errorf("PolicyName = %s, want test-policy", entry.PolicyName)
	}
	if entry.PatternName != "email" {
		t.Errorf("PatternName = %s, want email", entry.PatternName)
	}
	if entry.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if entry.Labels == nil {
		t.Error("Labels should be initialized")
	}
}

func TestAuditEntryBuilder(t *testing.T) {
	entry := NewAuditEntry(EventTypePIIRedacted, "production", "prod-policy", "ssn").
		WithPod("test-pod", "main").
		WithSeverity("critical").
		WithAction(ActionRedact).
		WithMatchCount(5).
		WithSource("log").
		WithOriginalText("original").
		WithRedactedText("redacted").
		AddLabel("key", "value")

	if entry.Pod != "test-pod" {
		t.Errorf("Pod = %s, want test-pod", entry.Pod)
	}
	if entry.Container != "main" {
		t.Errorf("Container = %s, want main", entry.Container)
	}
	if entry.Severity != "critical" {
		t.Errorf("Severity = %s, want critical", entry.Severity)
	}
	if entry.Action != ActionRedact {
		t.Errorf("Action = %s, want %s", entry.Action, ActionRedact)
	}
	if entry.MatchCount != 5 {
		t.Errorf("MatchCount = %d, want 5", entry.MatchCount)
	}
	if entry.Source != "log" {
		t.Errorf("Source = %s, want log", entry.Source)
	}
	if entry.OriginalText != "original" {
		t.Errorf("OriginalText = %s, want original", entry.OriginalText)
	}
	if entry.RedactedText != "redacted" {
		t.Errorf("RedactedText = %s, want redacted", entry.RedactedText)
	}
	if entry.Labels["key"] != "value" {
		t.Errorf("Labels[key] = %s, want value", entry.Labels["key"])
	}
}

func TestJSONLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)

	entry := NewAuditEntry(EventTypePIIDetected, "default", "test-policy", "email").
		WithSeverity("high").
		WithMatchCount(3)

	ctx := context.Background()
	if err := logger.Log(ctx, entry); err != nil {
		t.Errorf("Log() error = %v", err)
	}

	// Parse the logged JSON
	var logged AuditEntry
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Errorf("Failed to unmarshal logged entry: %v", err)
	}

	if logged.EventType != EventTypePIIDetected {
		t.Errorf("Logged EventType = %s, want %s", logged.EventType, EventTypePIIDetected)
	}
	if logged.Namespace != "default" {
		t.Errorf("Logged Namespace = %s, want default", logged.Namespace)
	}
}

func TestJSONLogger_Close(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)

	err := logger.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestControllerRuntimeLogger_Log(t *testing.T) {
	logger := NewControllerRuntimeLogger()

	entry := NewAuditEntry(EventTypePIIDetected, "default", "test-policy", "email")

	ctx := context.Background()
	// This should not error
	if err := logger.Log(ctx, entry); err != nil {
		t.Errorf("Log() error = %v", err)
	}
}

func TestControllerRuntimeLogger_Close(t *testing.T) {
	logger := NewControllerRuntimeLogger()

	err := logger.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestMultiLogger_Log(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger1 := NewJSONLogger(&buf1)
	logger2 := NewJSONLogger(&buf2)

	multi := NewMultiLogger(logger1, logger2)

	entry := NewAuditEntry(EventTypePIIDetected, "default", "test-policy", "email")

	ctx := context.Background()
	if err := multi.Log(ctx, entry); err != nil {
		t.Errorf("Log() error = %v", err)
	}

	// Both buffers should have content
	if buf1.Len() == 0 {
		t.Error("Logger1 should have content")
	}
	if buf2.Len() == 0 {
		t.Error("Logger2 should have content")
	}
}

func TestMultiLogger_AddLogger(t *testing.T) {
	multi := NewMultiLogger()

	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	multi.AddLogger(logger)

	entry := NewAuditEntry(EventTypePIIDetected, "default", "test-policy", "email")

	ctx := context.Background()
	if err := multi.Log(ctx, entry); err != nil {
		t.Errorf("Log() error = %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Logger should have content after adding")
	}
}

func TestNoOpLogger_Log(t *testing.T) {
	logger := NewNoOpLogger()

	entry := NewAuditEntry(EventTypePIIDetected, "default", "test-policy", "email")

	ctx := context.Background()
	if err := logger.Log(ctx, entry); err != nil {
		t.Errorf("Log() error = %v", err)
	}
}

func TestNoOpLogger_Close(t *testing.T) {
	logger := NewNoOpLogger()

	err := logger.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestEventTypeConstants(t *testing.T) {
	// Verify constants are defined
	if EventTypePIIDetected == "" {
		t.Error("EventTypePIIDetected should not be empty")
	}
	if EventTypePIIRedacted == "" {
		t.Error("EventTypePIIRedacted should not be empty")
	}
	if EventTypeAlertSent == "" {
		t.Error("EventTypeAlertSent should not be empty")
	}
	if EventTypePolicyMatch == "" {
		t.Error("EventTypePolicyMatch should not be empty")
	}
}

func TestActionConstants(t *testing.T) {
	if ActionRedact == "" {
		t.Error("ActionRedact should not be empty")
	}
	if ActionAlert == "" {
		t.Error("ActionAlert should not be empty")
	}
	if ActionLog == "" {
		t.Error("ActionLog should not be empty")
	}
	if ActionBlock == "" {
		t.Error("ActionBlock should not be empty")
	}
}
