package policy

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/detector"
)

func TestAggregator_AggregateBuiltInPatterns(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = piiv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	engine := detector.NewEngine()
	aggregator := NewAggregator(fakeClient, engine)

	selection := piiv1alpha1.PatternSelection{
		BuiltIn: []string{"email", "credit-card"},
	}

	ctx := context.Background()
	result, err := aggregator.AggregatePatterns(ctx, selection, "default")
	if err != nil {
		t.Errorf("AggregatePatterns() error = %v", err)
	}

	if len(result.BuiltInPatterns) != 2 {
		t.Errorf("Expected 2 built-in patterns, got %d", len(result.BuiltInPatterns))
	}

	if result.TotalPatterns != 2 {
		t.Errorf("TotalPatterns = %d, want 2", result.TotalPatterns)
	}
}

func TestAggregator_AggregateBuiltInPatterns_Invalid(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = piiv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	engine := detector.NewEngine()
	aggregator := NewAggregator(fakeClient, engine)

	selection := piiv1alpha1.PatternSelection{
		BuiltIn: []string{"email", "nonexistent-pattern"},
	}

	ctx := context.Background()
	result, err := aggregator.AggregatePatterns(ctx, selection, "default")
	if err != nil {
		t.Errorf("AggregatePatterns() error = %v", err)
	}

	// Valid patterns should still be included
	if len(result.BuiltInPatterns) != 1 {
		t.Errorf("Expected 1 built-in pattern, got %d", len(result.BuiltInPatterns))
	}

	// Should have error for invalid pattern
	if !result.HasErrors() {
		t.Error("Expected errors for invalid pattern")
	}
}

func TestAggregator_AggregateCustomPatterns(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = piiv1alpha1.AddToScheme(scheme)

	// Create a custom pattern
	customPattern := &piiv1alpha1.PIIPattern{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-email",
			Namespace: "default",
		},
		Spec: piiv1alpha1.PIIPatternSpec{
			DisplayName: "Custom Email",
			Patterns: []piiv1alpha1.PatternRule{
				{Regex: `[a-z]+@[a-z]+\.com`, Confidence: "high"},
			},
			Severity: "high",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(customPattern).
		Build()

	engine := detector.NewEngine()
	aggregator := NewAggregator(fakeClient, engine)

	selection := piiv1alpha1.PatternSelection{
		Custom: []piiv1alpha1.PatternRef{
			{Name: "custom-email", Namespace: "default"},
		},
	}

	ctx := context.Background()
	result, err := aggregator.AggregatePatterns(ctx, selection, "default")
	if err != nil {
		t.Errorf("AggregatePatterns() error = %v", err)
	}

	if len(result.CustomPatterns) != 1 {
		t.Errorf("Expected 1 custom pattern, got %d", len(result.CustomPatterns))
	}
}

func TestAggregator_AggregateCustomPatterns_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = piiv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	engine := detector.NewEngine()
	aggregator := NewAggregator(fakeClient, engine)

	selection := piiv1alpha1.PatternSelection{
		Custom: []piiv1alpha1.PatternRef{
			{Name: "nonexistent", Namespace: "default"},
		},
	}

	ctx := context.Background()
	result, err := aggregator.AggregatePatterns(ctx, selection, "default")
	if err != nil {
		t.Errorf("AggregatePatterns() error = %v", err)
	}

	if len(result.CustomPatterns) != 0 {
		t.Errorf("Expected 0 custom patterns, got %d", len(result.CustomPatterns))
	}

	if !result.HasErrors() {
		t.Error("Expected errors for missing pattern")
	}
}

func TestAggregationResult_AllPatterns(t *testing.T) {
	result := &AggregationResult{
		BuiltInPatterns:   []string{"email", "credit-card"},
		CustomPatterns:    []string{"default/custom-1"},
		CommunityPatterns: []string{"community-rule-1"},
		TotalPatterns:     4,
	}

	all := result.AllPatterns()
	if len(all) != 4 {
		t.Errorf("AllPatterns() returned %d, want 4", len(all))
	}
}

func TestAggregationResult_HasErrors(t *testing.T) {
	tests := []struct {
		name     string
		errors   []string
		expected bool
	}{
		{
			name:     "no errors",
			errors:   []string{},
			expected: false,
		},
		{
			name:     "with errors",
			errors:   []string{"error 1"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &AggregationResult{Errors: tt.errors}
			if result.HasErrors() != tt.expected {
				t.Errorf("HasErrors() = %v, want %v", result.HasErrors(), tt.expected)
			}
		})
	}
}
