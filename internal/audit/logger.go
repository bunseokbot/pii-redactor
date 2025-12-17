package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// AuditLogger defines the interface for audit logging
type AuditLogger interface {
	// Log logs an audit entry
	Log(ctx context.Context, entry *AuditEntry) error

	// Close closes the logger
	Close() error
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	// Timestamp is when the entry was created
	Timestamp time.Time `json:"timestamp"`

	// EventType is the type of event
	EventType string `json:"eventType"`

	// Namespace is the Kubernetes namespace
	Namespace string `json:"namespace"`

	// Pod is the pod name
	Pod string `json:"pod,omitempty"`

	// Container is the container name
	Container string `json:"container,omitempty"`

	// PolicyName is the name of the policy that triggered this entry
	PolicyName string `json:"policyName"`

	// PatternName is the pattern that matched
	PatternName string `json:"patternName"`

	// PatternDisplayName is the human-readable pattern name
	PatternDisplayName string `json:"patternDisplayName,omitempty"`

	// Severity is the severity level
	Severity string `json:"severity"`

	// Action is the action taken
	Action string `json:"action"`

	// MatchCount is the number of matches found
	MatchCount int `json:"matchCount"`

	// OriginalText is the original text (if includeOriginal is enabled)
	OriginalText string `json:"originalText,omitempty"`

	// RedactedText is the redacted text
	RedactedText string `json:"redactedText,omitempty"`

	// Source identifies where the PII was detected
	Source string `json:"source,omitempty"`

	// Labels contains additional metadata
	Labels map[string]string `json:"labels,omitempty"`
}

// EventTypes for audit logging
const (
	EventTypePIIDetected = "pii.detected"
	EventTypePIIRedacted = "pii.redacted"
	EventTypeAlertSent   = "alert.sent"
	EventTypePolicyMatch = "policy.match"
)

// Actions for audit logging
const (
	ActionRedact = "redact"
	ActionAlert  = "alert"
	ActionLog    = "log"
	ActionBlock  = "block"
)

// NewAuditEntry creates a new audit entry
func NewAuditEntry(eventType, namespace, policyName, patternName string) *AuditEntry {
	return &AuditEntry{
		Timestamp:   time.Now(),
		EventType:   eventType,
		Namespace:   namespace,
		PolicyName:  policyName,
		PatternName: patternName,
		Labels:      make(map[string]string),
	}
}

// WithPod sets the pod information
func (e *AuditEntry) WithPod(pod, container string) *AuditEntry {
	e.Pod = pod
	e.Container = container
	return e
}

// WithSeverity sets the severity
func (e *AuditEntry) WithSeverity(severity string) *AuditEntry {
	e.Severity = severity
	return e
}

// WithAction sets the action
func (e *AuditEntry) WithAction(action string) *AuditEntry {
	e.Action = action
	return e
}

// WithMatchCount sets the match count
func (e *AuditEntry) WithMatchCount(count int) *AuditEntry {
	e.MatchCount = count
	return e
}

// WithOriginalText sets the original text
func (e *AuditEntry) WithOriginalText(text string) *AuditEntry {
	e.OriginalText = text
	return e
}

// WithRedactedText sets the redacted text
func (e *AuditEntry) WithRedactedText(text string) *AuditEntry {
	e.RedactedText = text
	return e
}

// WithSource sets the source
func (e *AuditEntry) WithSource(source string) *AuditEntry {
	e.Source = source
	return e
}

// AddLabel adds a label
func (e *AuditEntry) AddLabel(key, value string) *AuditEntry {
	if e.Labels == nil {
		e.Labels = make(map[string]string)
	}
	e.Labels[key] = value
	return e
}

// JSONLogger logs audit entries as JSON to an io.Writer
type JSONLogger struct {
	mu     sync.Mutex
	writer io.Writer
	closer io.Closer
}

// NewJSONLogger creates a new JSON logger
func NewJSONLogger(w io.Writer) *JSONLogger {
	logger := &JSONLogger{
		writer: w,
	}

	// If writer is also a closer, store it
	if closer, ok := w.(io.Closer); ok {
		logger.closer = closer
	}

	return logger
}

// NewJSONFileLogger creates a new JSON logger that writes to a file
func NewJSONFileLogger(path string) (*JSONLogger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &JSONLogger{
		writer: file,
		closer: file,
	}, nil
}

// Log logs an audit entry
func (l *JSONLogger) Log(ctx context.Context, entry *AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	data = append(data, '\n')

	_, err = l.writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write audit entry: %w", err)
	}

	return nil
}

// Close closes the logger
func (l *JSONLogger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// ControllerRuntimeLogger logs audit entries using controller-runtime logger
type ControllerRuntimeLogger struct{}

// NewControllerRuntimeLogger creates a new controller-runtime logger
func NewControllerRuntimeLogger() *ControllerRuntimeLogger {
	return &ControllerRuntimeLogger{}
}

// Log logs an audit entry
func (l *ControllerRuntimeLogger) Log(ctx context.Context, entry *AuditEntry) error {
	logger := log.FromContext(ctx)

	logger.Info("audit",
		"eventType", entry.EventType,
		"namespace", entry.Namespace,
		"pod", entry.Pod,
		"container", entry.Container,
		"policyName", entry.PolicyName,
		"patternName", entry.PatternName,
		"severity", entry.Severity,
		"action", entry.Action,
		"matchCount", entry.MatchCount,
		"source", entry.Source,
	)

	return nil
}

// Close closes the logger
func (l *ControllerRuntimeLogger) Close() error {
	return nil
}

// MultiLogger logs to multiple loggers
type MultiLogger struct {
	loggers []AuditLogger
}

// NewMultiLogger creates a new multi-logger
func NewMultiLogger(loggers ...AuditLogger) *MultiLogger {
	return &MultiLogger{
		loggers: loggers,
	}
}

// AddLogger adds a logger
func (m *MultiLogger) AddLogger(logger AuditLogger) {
	m.loggers = append(m.loggers, logger)
}

// Log logs to all loggers
func (m *MultiLogger) Log(ctx context.Context, entry *AuditEntry) error {
	var lastErr error
	for _, logger := range m.loggers {
		if err := logger.Log(ctx, entry); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Close closes all loggers
func (m *MultiLogger) Close() error {
	var lastErr error
	for _, logger := range m.loggers {
		if err := logger.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// NoOpLogger is a logger that does nothing (for testing or disabled audit)
type NoOpLogger struct{}

// NewNoOpLogger creates a new no-op logger
func NewNoOpLogger() *NoOpLogger {
	return &NoOpLogger{}
}

// Log does nothing
func (l *NoOpLogger) Log(ctx context.Context, entry *AuditEntry) error {
	return nil
}

// Close does nothing
func (l *NoOpLogger) Close() error {
	return nil
}
