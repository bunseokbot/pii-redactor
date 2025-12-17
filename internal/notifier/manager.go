package notifier

import (
	"context"
	"fmt"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Manager manages multiple notification channels
type Manager struct {
	mu           sync.RWMutex
	notifiers    map[string]Notifier
	configs      map[string]NotifierConfig
	rateLimiters *RateLimiterRegistry
}

// NewManager creates a new notification manager
func NewManager() *Manager {
	return &Manager{
		notifiers:    make(map[string]Notifier),
		configs:      make(map[string]NotifierConfig),
		rateLimiters: NewRateLimiterRegistry(),
	}
}

// Register registers a notifier with the given name
func (m *Manager) Register(name string, notifier Notifier, config NotifierConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := notifier.Validate(); err != nil {
		return fmt.Errorf("invalid notifier configuration: %w", err)
	}

	m.notifiers[name] = notifier
	m.configs[name] = config

	// Setup rate limiter
	if config.RateLimitPerMinute > 0 {
		m.rateLimiters.Update(name, config.RateLimitPerMinute)
	}

	return nil
}

// Unregister removes a notifier
func (m *Manager) Unregister(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.notifiers, name)
	delete(m.configs, name)
	m.rateLimiters.Remove(name)
}

// Get returns a notifier by name
func (m *Manager) Get(name string) (Notifier, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	notifier, exists := m.notifiers[name]
	return notifier, exists
}

// SendAlert sends an alert through the specified channel
func (m *Manager) SendAlert(ctx context.Context, channelName string, alert *Alert) error {
	logger := log.FromContext(ctx)

	m.mu.RLock()
	notifier, exists := m.notifiers[channelName]
	config, configExists := m.configs[channelName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("notifier %s not found", channelName)
	}

	// Check severity threshold
	if configExists && config.MinSeverity != "" {
		if !ShouldAlert(alert.Severity, config.MinSeverity) {
			logger.V(1).Info("Alert below severity threshold",
				"channel", channelName,
				"alertSeverity", alert.Severity,
				"minSeverity", config.MinSeverity)
			return nil
		}
	}

	// Check rate limit
	if limiter, exists := m.rateLimiters.Get(channelName); exists {
		if !limiter.Allow() {
			logger.V(1).Info("Alert rate limited", "channel", channelName)
			return &RateLimitError{Channel: channelName}
		}
	}

	// Send the alert
	if err := notifier.Send(ctx, alert); err != nil {
		return fmt.Errorf("failed to send alert via %s: %w", channelName, err)
	}

	logger.V(1).Info("Alert sent successfully", "channel", channelName, "alertID", alert.ID)
	return nil
}

// SendAlertToChannels sends an alert to multiple channels
func (m *Manager) SendAlertToChannels(ctx context.Context, channelNames []string, alert *Alert) map[string]error {
	errors := make(map[string]error)

	for _, channelName := range channelNames {
		if err := m.SendAlert(ctx, channelName, alert); err != nil {
			errors[channelName] = err
		}
	}

	return errors
}

// Broadcast sends an alert to all registered channels
func (m *Manager) Broadcast(ctx context.Context, alert *Alert) map[string]error {
	m.mu.RLock()
	channelNames := make([]string, 0, len(m.notifiers))
	for name := range m.notifiers {
		channelNames = append(channelNames, name)
	}
	m.mu.RUnlock()

	return m.SendAlertToChannels(ctx, channelNames, alert)
}

// List returns all registered channel names
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.notifiers))
	for name := range m.notifiers {
		names = append(names, name)
	}
	return names
}

// Stats returns statistics for all channels
func (m *Manager) Stats() map[string]ChannelStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]ChannelStats)
	rateLimiterStats := m.rateLimiters.AllStats()

	for name, notifier := range m.notifiers {
		channelStats := ChannelStats{
			Type: notifier.Type(),
		}
		if rlStats, exists := rateLimiterStats[name]; exists {
			channelStats.RateLimiter = &rlStats
		}
		if config, exists := m.configs[name]; exists {
			channelStats.MinSeverity = config.MinSeverity
		}
		stats[name] = channelStats
	}

	return stats
}

// UpdateConfig updates the configuration for a channel
func (m *Manager) UpdateConfig(name string, config NotifierConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.notifiers[name]; !exists {
		return fmt.Errorf("notifier %s not found", name)
	}

	m.configs[name] = config

	if config.RateLimitPerMinute > 0 {
		m.rateLimiters.Update(name, config.RateLimitPerMinute)
	}

	return nil
}

// ChannelStats holds statistics for a notification channel
type ChannelStats struct {
	Type        string
	MinSeverity string
	RateLimiter *RateLimiterStats
}

// RateLimitError is returned when an alert is rate limited
type RateLimitError struct {
	Channel string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("alert rate limited for channel: %s", e.Channel)
}

// IsRateLimitError checks if an error is a rate limit error
func IsRateLimitError(err error) bool {
	_, ok := err.(*RateLimitError)
	return ok
}
