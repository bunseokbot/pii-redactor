package detector

import (
	"context"
	"regexp"
	"sync"

	"github.com/bunseokbot/pii-redactor/internal/detector/patterns"
	"github.com/bunseokbot/pii-redactor/internal/detector/validator"
)

// Position represents the position of a match in the text
type Position struct {
	Start int
	End   int
}

// Match represents a single regex match
type Match struct {
	Text     string
	Position Position
}

// DetectionResult represents the result of PII detection
type DetectionResult struct {
	PatternName  string
	DisplayName  string
	MatchedText  string
	Position     Position
	Confidence   string
	Severity     string
	RedactedText string
}

// LogEntry represents a log entry to be processed
type LogEntry struct {
	Namespace string
	Pod       string
	Container string
	Message   string
	Timestamp string
}

// CompiledPattern represents a compiled regex pattern with metadata
type CompiledPattern struct {
	Name            string
	DisplayName     string
	Category        string
	Patterns        []*compiledRule
	Validator       string
	MaskingStrategy patterns.MaskingStrategy
	Severity        string
	Enabled         bool
}

type compiledRule struct {
	Regex      *regexp.Regexp
	Confidence string
}

// Engine is the main PII detection engine
type Engine struct {
	patterns          map[string]*CompiledPattern
	validators        map[string]validator.Validator
	validationEnabled bool
	mu                sync.RWMutex
}

// NewEngine creates a new detection engine
func NewEngine() *Engine {
	e := &Engine{
		patterns:          make(map[string]*CompiledPattern),
		validators:        validator.Registry,
		validationEnabled: true,
	}

	// Load built-in patterns
	e.loadBuiltInPatterns()

	return e
}

// DisableValidation disables checksum validation for all patterns
func (e *Engine) DisableValidation() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.validationEnabled = false
}

// EnableValidation enables checksum validation for all patterns
func (e *Engine) EnableValidation() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.validationEnabled = true
}

// loadBuiltInPatterns loads all built-in patterns
func (e *Engine) loadBuiltInPatterns() {
	for name, spec := range patterns.BuiltInPatterns {
		compiled := &CompiledPattern{
			Name:            name,
			DisplayName:     spec.DisplayName,
			Category:        spec.Category,
			Validator:       spec.Validator,
			MaskingStrategy: spec.MaskingStrategy,
			Severity:        spec.Severity,
			Enabled:         spec.Enabled,
			Patterns:        make([]*compiledRule, 0, len(spec.Patterns)),
		}

		for _, p := range spec.Patterns {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				continue // Skip invalid patterns
			}
			compiled.Patterns = append(compiled.Patterns, &compiledRule{
				Regex:      re,
				Confidence: p.Confidence,
			})
		}

		e.patterns[name] = compiled
	}
}

// AddPattern adds a custom pattern to the engine
func (e *Engine) AddPattern(name string, spec patterns.PIIPatternSpec) error {
	compiled := &CompiledPattern{
		Name:            name,
		DisplayName:     spec.DisplayName,
		Validator:       spec.Validator,
		MaskingStrategy: spec.MaskingStrategy,
		Severity:        spec.Severity,
		Patterns:        make([]*compiledRule, 0, len(spec.Patterns)),
	}

	for _, p := range spec.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return err
		}
		compiled.Patterns = append(compiled.Patterns, &compiledRule{
			Regex:      re,
			Confidence: p.Confidence,
		})
	}

	e.mu.Lock()
	e.patterns[name] = compiled
	e.mu.Unlock()

	return nil
}

// RemovePattern removes a pattern from the engine
func (e *Engine) RemovePattern(name string) {
	e.mu.Lock()
	delete(e.patterns, name)
	e.mu.Unlock()
}

// Detect scans the log entry for PII
func (e *Engine) Detect(ctx context.Context, log LogEntry) ([]DetectionResult, error) {
	return e.DetectInText(ctx, log.Message)
}

// DetectInText scans text for PII using only enabled patterns
func (e *Engine) DetectInText(ctx context.Context, text string) ([]DetectionResult, error) {
	var results []DetectionResult

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, pattern := range e.patterns {
		// Skip disabled patterns
		if !pattern.Enabled {
			continue
		}

		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		for _, rule := range pattern.Patterns {
			matches := rule.Regex.FindAllStringIndex(text, -1)
			for _, match := range matches {
				matchedText := text[match[0]:match[1]]

				// Validate if validator is specified and validation is enabled
				if e.validationEnabled && pattern.Validator != "" {
					if v, ok := e.validators[pattern.Validator]; ok {
						if !v.Validate(matchedText) {
							continue
						}
					}
				}

				results = append(results, DetectionResult{
					PatternName: pattern.Name,
					DisplayName: pattern.DisplayName,
					MatchedText: matchedText,
					Position: Position{
						Start: match[0],
						End:   match[1],
					},
					Confidence: rule.Confidence,
					Severity:   pattern.Severity,
				})
			}
		}
	}

	return results, nil
}

// DetectWithPatterns scans text using only specified patterns
func (e *Engine) DetectWithPatterns(ctx context.Context, text string, patternNames []string) ([]DetectionResult, error) {
	var results []DetectionResult

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, name := range patternNames {
		pattern, ok := e.patterns[name]
		if !ok {
			continue
		}

		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		for _, rule := range pattern.Patterns {
			matches := rule.Regex.FindAllStringIndex(text, -1)
			for _, match := range matches {
				matchedText := text[match[0]:match[1]]

				// Validate if validator is specified and validation is enabled
				if e.validationEnabled && pattern.Validator != "" {
					if v, ok := e.validators[pattern.Validator]; ok {
						if !v.Validate(matchedText) {
							continue
						}
					}
				}

				results = append(results, DetectionResult{
					PatternName: pattern.Name,
					DisplayName: pattern.DisplayName,
					MatchedText: matchedText,
					Position: Position{
						Start: match[0],
						End:   match[1],
					},
					Confidence: rule.Confidence,
					Severity:   pattern.Severity,
				})
			}
		}
	}

	return results, nil
}

// GetPattern returns a compiled pattern by name
func (e *Engine) GetPattern(name string) (*CompiledPattern, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	pattern, ok := e.patterns[name]
	return pattern, ok
}

// ListPatterns returns all pattern names
func (e *Engine) ListPatterns() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0, len(e.patterns))
	for name := range e.patterns {
		names = append(names, name)
	}
	return names
}

// GetMaskingStrategy returns the masking strategy for a pattern
func (e *Engine) GetMaskingStrategy(patternName string) (patterns.MaskingStrategy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if pattern, ok := e.patterns[patternName]; ok {
		return pattern.MaskingStrategy, true
	}
	return patterns.MaskingStrategy{}, false
}

// EnablePattern enables a pattern by name
func (e *Engine) EnablePattern(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if pattern, ok := e.patterns[name]; ok {
		pattern.Enabled = true
		return true
	}
	return false
}

// DisablePattern disables a pattern by name
func (e *Engine) DisablePattern(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if pattern, ok := e.patterns[name]; ok {
		pattern.Enabled = false
		return true
	}
	return false
}

// IsPatternEnabled checks if a pattern is enabled
func (e *Engine) IsPatternEnabled(name string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if pattern, ok := e.patterns[name]; ok {
		return pattern.Enabled
	}
	return false
}

// EnablePatternsByCategory enables all patterns in a category
func (e *Engine) EnablePatternsByCategory(category string) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	count := 0
	for _, pattern := range e.patterns {
		if pattern.Category == category {
			pattern.Enabled = true
			count++
		}
	}
	return count
}

// DisablePatternsByCategory disables all patterns in a category
func (e *Engine) DisablePatternsByCategory(category string) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	count := 0
	for _, pattern := range e.patterns {
		if pattern.Category == category {
			pattern.Enabled = false
			count++
		}
	}
	return count
}

// ListEnabledPatterns returns names of all enabled patterns
func (e *Engine) ListEnabledPatterns() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0)
	for name, pattern := range e.patterns {
		if pattern.Enabled {
			names = append(names, name)
		}
	}
	return names
}

// ListDisabledPatterns returns names of all disabled patterns
func (e *Engine) ListDisabledPatterns() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0)
	for name, pattern := range e.patterns {
		if !pattern.Enabled {
			names = append(names, name)
		}
	}
	return names
}

// ListPatternsByCategory returns pattern names by category
func (e *Engine) ListPatternsByCategory(category string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0)
	for name, pattern := range e.patterns {
		if pattern.Category == category {
			names = append(names, name)
		}
	}
	return names
}
