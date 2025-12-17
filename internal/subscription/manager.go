package subscription

import (
	"context"
	"path/filepath"
	"strings"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/source"
)

// Manager manages rule subscriptions
type Manager struct {
	cache  *source.Cache
	engine *detector.Engine
}

// NewManager creates a new subscription manager
func NewManager(cache *source.Cache, engine *detector.Engine) *Manager {
	return &Manager{
		cache:  cache,
		engine: engine,
	}
}

// SubscriptionResult holds the result of processing a subscription
type SubscriptionResult struct {
	// SubscribedPatterns is the list of subscribed patterns
	SubscribedPatterns []piiv1alpha1.SubscribedPatternInfo

	// TotalPatterns is the total count
	TotalPatterns int

	// Errors contains any errors encountered
	Errors []string
}

// NewSubscriptionResult creates a new SubscriptionResult
func NewSubscriptionResult() *SubscriptionResult {
	return &SubscriptionResult{
		SubscribedPatterns: make([]piiv1alpha1.SubscribedPatternInfo, 0),
		Errors:             make([]string, 0),
	}
}

// Subscribe processes a subscription and returns matching patterns
func (m *Manager) Subscribe(ctx context.Context, spec piiv1alpha1.PIIRuleSubscriptionSpec) (*SubscriptionResult, error) {
	result := NewSubscriptionResult()

	// Get source from cache
	sourceKey := spec.SourceRef.Namespace + "/" + spec.SourceRef.Name
	if spec.SourceRef.Namespace == "" {
		sourceKey = spec.SourceRef.Name
	}

	cachedSource, exists := m.cache.GetSource(sourceKey)
	if !exists {
		result.Errors = append(result.Errors, "source not found: "+sourceKey)
		return result, nil
	}

	// Get maturity levels (default: stable, incubating)
	maturityLevels := spec.MaturityLevels
	if len(maturityLevels) == 0 {
		maturityLevels = []string{"stable", "incubating"}
	}
	maturitySet := make(map[string]bool)
	for _, m := range maturityLevels {
		maturitySet[m] = true
	}

	// Build override map
	overrides := make(map[string]piiv1alpha1.PatternOverride)
	for _, o := range spec.Overrides {
		overrides[o.Pattern] = o
	}

	// Process each subscription
	for _, sub := range spec.Subscribe {
		patterns := m.matchPatterns(cachedSource, sub, maturitySet)
		for _, p := range patterns {
			// Apply overrides
			overridden := false
			if override, exists := overrides[p.Name]; exists {
				p = m.applyOverride(p, override)
				overridden = true
			}

			// Add to engine
			patternSpec := p.Pattern.ToPatternSpec()
			patternKey := sourceKey + "/" + p.RuleSetName + "/" + p.Pattern.Name
			if err := m.engine.AddPattern(patternKey, patternSpec); err != nil {
				result.Errors = append(result.Errors, "failed to add pattern: "+p.Pattern.Name)
				continue
			}

			// Add to result
			info := piiv1alpha1.SubscribedPatternInfo{
				Name:       p.Pattern.Name,
				Category:   p.Pattern.Category,
				Version:    "", // Would need to track version
				Source:     sourceKey,
				Overridden: overridden,
			}
			result.SubscribedPatterns = append(result.SubscribedPatterns, info)
		}
	}

	result.TotalPatterns = len(result.SubscribedPatterns)
	return result, nil
}

// matchedPattern holds a matched pattern with context
type matchedPattern struct {
	Pattern     *source.PatternDefinition
	RuleSetName string
	Name        string
}

// matchPatterns finds patterns matching the subscription criteria
func (m *Manager) matchPatterns(cachedSource *source.CachedSource, sub piiv1alpha1.CategorySubscription, maturitySet map[string]bool) []*matchedPattern {
	var result []*matchedPattern

	// Parse version constraint
	constraints, _ := ParseConstraints(sub.Version)

	for _, rs := range cachedSource.RuleSets {
		// Check maturity level
		if len(maturitySet) > 0 && !maturitySet[rs.Maturity] {
			continue
		}

		// Check version constraint
		if constraints != nil && !constraints.MatchesString(rs.Version) {
			continue
		}

		for i := range rs.Patterns {
			pattern := &rs.Patterns[i]

			// Check category match
			if sub.Category != "" && !m.matchesCategory(pattern.Category, sub.Category) {
				continue
			}

			// Check pattern name match
			if !m.matchesPatternNames(pattern.Name, sub.Patterns) {
				continue
			}

			result = append(result, &matchedPattern{
				Pattern:     pattern,
				RuleSetName: rs.Name,
				Name:        pattern.Name,
			})
		}
	}

	return result
}

// matchesCategory checks if a pattern category matches the subscription category
func (m *Manager) matchesCategory(patternCategory, subCategory string) bool {
	if subCategory == "" || subCategory == "*" {
		return true
	}

	// Exact match
	if patternCategory == subCategory {
		return true
	}

	// Check if pattern category is under the subscription category
	return strings.HasPrefix(patternCategory, subCategory+"/")
}

// matchesPatternNames checks if a pattern name matches any of the subscription patterns
func (m *Manager) matchesPatternNames(patternName string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}

	for _, p := range patterns {
		if p == "*" {
			return true
		}

		// Check glob pattern
		matched, err := filepath.Match(p, patternName)
		if err == nil && matched {
			return true
		}

		// Check exact match
		if p == patternName {
			return true
		}
	}

	return false
}

// applyOverride applies an override to a matched pattern
func (m *Manager) applyOverride(mp *matchedPattern, override piiv1alpha1.PatternOverride) *matchedPattern {
	// Create a copy
	patternCopy := *mp.Pattern
	mp.Pattern = &patternCopy

	if override.Severity != "" {
		mp.Pattern.Severity = override.Severity
	}

	if override.Enabled != nil {
		mp.Pattern.Enabled = *override.Enabled
	}

	if override.MaskingStrategy != nil {
		mp.Pattern.MaskingStrategy.Type = override.MaskingStrategy.Type
		mp.Pattern.MaskingStrategy.ShowFirst = override.MaskingStrategy.ShowFirst
		mp.Pattern.MaskingStrategy.ShowLast = override.MaskingStrategy.ShowLast
		mp.Pattern.MaskingStrategy.MaskChar = override.MaskingStrategy.MaskChar
		mp.Pattern.MaskingStrategy.Replacement = override.MaskingStrategy.Replacement
	}

	return mp
}

// Unsubscribe removes patterns from a subscription
func (m *Manager) Unsubscribe(sourceKey string) {
	// Get all patterns for this source
	patterns := m.cache.ListPatternsForSource(sourceKey)

	// Remove from engine
	for _, patternKey := range patterns {
		m.engine.RemovePattern(patternKey)
	}
}

// GetSubscribedPatterns returns the list of patterns for a source
func (m *Manager) GetSubscribedPatterns(sourceKey string) []string {
	return m.cache.ListPatternsForSource(sourceKey)
}
