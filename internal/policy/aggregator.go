package policy

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/detector/patterns"
)

// Aggregator aggregates patterns from different sources
type Aggregator struct {
	client client.Client
	engine *detector.Engine
}

// NewAggregator creates a new Aggregator
func NewAggregator(c client.Client, engine *detector.Engine) *Aggregator {
	return &Aggregator{
		client: c,
		engine: engine,
	}
}

// AggregatePatterns collects patterns based on the selection
func (a *Aggregator) AggregatePatterns(ctx context.Context, selection piiv1alpha1.PatternSelection, policyNamespace string) (*AggregationResult, error) {
	result := &AggregationResult{
		BuiltInPatterns:   make([]string, 0),
		CustomPatterns:    make([]string, 0),
		CommunityPatterns: make([]string, 0),
		Errors:            make([]string, 0),
	}

	// Aggregate built-in patterns
	for _, patternName := range selection.BuiltIn {
		if patterns.IsBuiltInPattern(patternName) {
			result.BuiltInPatterns = append(result.BuiltInPatterns, patternName)
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("built-in pattern not found: %s", patternName))
		}
	}

	// Aggregate custom patterns
	for _, ref := range selection.Custom {
		namespace := ref.Namespace
		if namespace == "" {
			namespace = policyNamespace
		}

		// Check if pattern exists
		var pattern piiv1alpha1.PIIPattern
		key := client.ObjectKey{
			Namespace: namespace,
			Name:      ref.Name,
		}

		if err := a.client.Get(ctx, key, &pattern); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("custom pattern not found: %s/%s", namespace, ref.Name))
			continue
		}

		patternKey := fmt.Sprintf("%s/%s", namespace, ref.Name)
		result.CustomPatterns = append(result.CustomPatterns, patternKey)
	}

	// Aggregate community patterns
	for _, patternName := range selection.Community {
		// Community patterns are registered by PIIRuleSubscription
		// Check if pattern exists in engine
		if a.engine.HasPattern(patternName) {
			result.CommunityPatterns = append(result.CommunityPatterns, patternName)
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("community pattern not found: %s", patternName))
		}
	}

	result.TotalPatterns = len(result.BuiltInPatterns) + len(result.CustomPatterns) + len(result.CommunityPatterns)

	return result, nil
}

// AggregationResult holds the result of pattern aggregation
type AggregationResult struct {
	// BuiltInPatterns is the list of built-in pattern names
	BuiltInPatterns []string

	// CustomPatterns is the list of custom pattern keys (namespace/name)
	CustomPatterns []string

	// CommunityPatterns is the list of community pattern names
	CommunityPatterns []string

	// TotalPatterns is the total count of all patterns
	TotalPatterns int

	// Errors contains any errors encountered during aggregation
	Errors []string
}

// AllPatterns returns all pattern names/keys
func (r *AggregationResult) AllPatterns() []string {
	all := make([]string, 0, r.TotalPatterns)
	all = append(all, r.BuiltInPatterns...)
	all = append(all, r.CustomPatterns...)
	all = append(all, r.CommunityPatterns...)
	return all
}

// HasErrors returns true if there were any errors
func (r *AggregationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// EnablePatterns enables the aggregated patterns in the engine
func (a *Aggregator) EnablePatterns(result *AggregationResult) error {
	// Enable built-in patterns
	for _, name := range result.BuiltInPatterns {
		a.engine.EnablePattern(name)
	}

	// Custom patterns are already enabled by PIIPatternReconciler
	// Community patterns are already enabled by PIIRuleSubscriptionReconciler

	return nil
}

// DisableAllExcept disables all patterns except the specified ones
func (a *Aggregator) DisableAllExcept(keepPatterns []string) {
	keepSet := make(map[string]struct{})
	for _, p := range keepPatterns {
		keepSet[p] = struct{}{}
	}

	for _, name := range a.engine.ListPatterns() {
		if _, keep := keepSet[name]; !keep {
			a.engine.DisablePattern(name)
		}
	}
}

// GetPatternSeverity returns the severity of a pattern
func (a *Aggregator) GetPatternSeverity(patternName string) string {
	if spec := a.engine.GetPatternSpec(patternName); spec != nil {
		return spec.Severity
	}

	// Check built-in patterns
	if builtIn := patterns.GetBuiltInPattern(patternName); builtIn != nil {
		return builtIn.Severity
	}

	return "medium" // default severity
}
