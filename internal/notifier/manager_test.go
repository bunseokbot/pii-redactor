package notifier

import (
	"context"
	"testing"
	"time"
)

// mockNotifier is a simple mock notifier for testing
type mockNotifier struct {
	typeStr   string
	sent      []*Alert
	sendError error
}

func (m *mockNotifier) Type() string {
	return m.typeStr
}

func (m *mockNotifier) Send(ctx context.Context, alert *Alert) error {
	if m.sendError != nil {
		return m.sendError
	}
	m.sent = append(m.sent, alert)
	return nil
}

func (m *mockNotifier) Validate() error {
	return nil
}

func TestManager_RegisterAndGet(t *testing.T) {
	manager := NewManager()

	mock := &mockNotifier{typeStr: "mock"}
	config := NotifierConfig{RateLimitPerMinute: 10}

	err := manager.Register("test-channel", mock, config)
	if err != nil {
		t.Errorf("Register() error = %v", err)
	}

	got, exists := manager.Get("test-channel")
	if !exists {
		t.Error("Channel should exist")
	}
	if got != mock {
		t.Error("Should return the registered notifier")
	}
}

func TestManager_Unregister(t *testing.T) {
	manager := NewManager()

	mock := &mockNotifier{typeStr: "mock"}
	config := NotifierConfig{RateLimitPerMinute: 10}

	manager.Register("test-channel", mock, config)

	manager.Unregister("test-channel")

	_, exists := manager.Get("test-channel")
	if exists {
		t.Error("Channel should not exist after unregister")
	}
}

func TestManager_SendAlert(t *testing.T) {
	manager := NewManager()

	mock := &mockNotifier{typeStr: "mock"}
	config := NotifierConfig{RateLimitPerMinute: 100}

	manager.Register("test-channel", mock, config)

	alert := &Alert{
		ID:          "test-123",
		Severity:    SeverityHigh,
		PatternName: "email",
		Namespace:   "default",
		Message:     "Test alert",
		Timestamp:   time.Now(),
	}

	ctx := context.Background()
	err := manager.SendAlert(ctx, "test-channel", alert)
	if err != nil {
		t.Errorf("SendAlert() error = %v", err)
	}

	if len(mock.sent) != 1 {
		t.Errorf("Expected 1 sent alert, got %d", len(mock.sent))
	}
}

func TestManager_SendAlertToNonexistentChannel(t *testing.T) {
	manager := NewManager()

	alert := &Alert{
		PatternName: "email",
		Namespace:   "default",
		Message:     "Test",
		Timestamp:   time.Now(),
	}

	ctx := context.Background()
	err := manager.SendAlert(ctx, "nonexistent", alert)
	if err == nil {
		t.Error("Expected error for nonexistent channel")
	}
}

func TestManager_Broadcast(t *testing.T) {
	manager := NewManager()

	mock1 := &mockNotifier{typeStr: "mock1"}
	mock2 := &mockNotifier{typeStr: "mock2"}

	config := NotifierConfig{RateLimitPerMinute: 100}

	manager.Register("channel1", mock1, config)
	manager.Register("channel2", mock2, config)

	alert := &Alert{
		ID:          "test-123",
		Severity:    SeverityHigh,
		PatternName: "email",
		Namespace:   "default",
		Message:     "Test alert",
		Timestamp:   time.Now(),
	}

	ctx := context.Background()
	errors := manager.Broadcast(ctx, alert)

	if len(errors) != 0 {
		t.Errorf("Expected no errors, got %v", errors)
	}

	if len(mock1.sent) != 1 {
		t.Errorf("mock1: Expected 1 sent alert, got %d", len(mock1.sent))
	}

	if len(mock2.sent) != 1 {
		t.Errorf("mock2: Expected 1 sent alert, got %d", len(mock2.sent))
	}
}

func TestManager_List(t *testing.T) {
	manager := NewManager()

	mock1 := &mockNotifier{typeStr: "slack"}
	mock2 := &mockNotifier{typeStr: "webhook"}

	config := NotifierConfig{RateLimitPerMinute: 10}

	manager.Register("channel1", mock1, config)
	manager.Register("channel2", mock2, config)

	channels := manager.List()

	if len(channels) != 2 {
		t.Errorf("Expected 2 channels, got %d", len(channels))
	}
}

func TestManager_SeverityFiltering(t *testing.T) {
	manager := NewManager()

	mock := &mockNotifier{typeStr: "mock"}
	config := NotifierConfig{
		RateLimitPerMinute: 100,
		MinSeverity:        SeverityHigh, // Only high and critical alerts
	}

	manager.Register("test-channel", mock, config)

	// Low severity alert should be filtered
	lowAlert := &Alert{
		ID:          "low-1",
		Severity:    SeverityLow,
		PatternName: "email",
		Namespace:   "default",
		Message:     "Low severity alert",
		Timestamp:   time.Now(),
	}

	ctx := context.Background()
	err := manager.SendAlert(ctx, "test-channel", lowAlert)
	if err != nil {
		t.Errorf("SendAlert() for low severity error = %v", err)
	}

	// Low alert should be filtered out
	if len(mock.sent) != 0 {
		t.Errorf("Low severity alert should be filtered, got %d alerts", len(mock.sent))
	}

	// High severity alert should pass
	highAlert := &Alert{
		ID:          "high-1",
		Severity:    SeverityHigh,
		PatternName: "ssn",
		Namespace:   "production",
		Message:     "High severity alert",
		Timestamp:   time.Now(),
	}

	err = manager.SendAlert(ctx, "test-channel", highAlert)
	if err != nil {
		t.Errorf("SendAlert() for high severity error = %v", err)
	}

	if len(mock.sent) != 1 {
		t.Errorf("High severity alert should pass, got %d alerts", len(mock.sent))
	}
}

func TestManager_Stats(t *testing.T) {
	manager := NewManager()

	mock := &mockNotifier{typeStr: "slack"}
	config := NotifierConfig{
		RateLimitPerMinute: 10,
		MinSeverity:        SeverityMedium,
	}

	manager.Register("test-channel", mock, config)

	stats := manager.Stats()

	channelStats, exists := stats["test-channel"]
	if !exists {
		t.Error("Stats should contain test-channel")
	}

	if channelStats.Type != "slack" {
		t.Errorf("Type = %s, want slack", channelStats.Type)
	}

	if channelStats.MinSeverity != SeverityMedium {
		t.Errorf("MinSeverity = %s, want %s", channelStats.MinSeverity, SeverityMedium)
	}
}
