package policy

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
)

func TestMatcher_MatchNamespaces_ExplicitList(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	matcher := NewMatcher(fakeClient)

	selector := piiv1alpha1.PolicySelector{
		Namespaces: []string{"default", "production"},
	}

	ctx := context.Background()
	namespaces, err := matcher.MatchNamespaces(ctx, selector)
	if err != nil {
		t.Errorf("MatchNamespaces() error = %v", err)
	}

	if len(namespaces) != 2 {
		t.Errorf("Expected 2 namespaces, got %d", len(namespaces))
	}
}

func TestMatcher_MatchNamespaces_WithExcludes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	matcher := NewMatcher(fakeClient)

	selector := piiv1alpha1.PolicySelector{
		Namespaces:        []string{"default", "production", "kube-system"},
		ExcludeNamespaces: []string{"kube-system"},
	}

	ctx := context.Background()
	namespaces, err := matcher.MatchNamespaces(ctx, selector)
	if err != nil {
		t.Errorf("MatchNamespaces() error = %v", err)
	}

	if len(namespaces) != 2 {
		t.Errorf("Expected 2 namespaces, got %d", len(namespaces))
	}

	for _, ns := range namespaces {
		if ns == "kube-system" {
			t.Error("kube-system should be excluded")
		}
	}
}

func TestMatcher_MatchNamespaces_ByLabelSelector(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	ns1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns-1",
			Labels: map[string]string{"env": "test"},
		},
	}
	ns2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns-2",
			Labels: map[string]string{"env": "test"},
		},
	}
	ns3 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "prod-ns",
			Labels: map[string]string{"env": "prod"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ns1, ns2, ns3).
		Build()

	matcher := NewMatcher(fakeClient)

	selector := piiv1alpha1.PolicySelector{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		},
	}

	ctx := context.Background()
	namespaces, err := matcher.MatchNamespaces(ctx, selector)
	if err != nil {
		t.Errorf("MatchNamespaces() error = %v", err)
	}

	if len(namespaces) != 2 {
		t.Errorf("Expected 2 namespaces, got %d: %v", len(namespaces), namespaces)
	}
}

func TestMatcher_IsPodMatched(t *testing.T) {
	matcher := &Matcher{}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-pod",
			Labels: map[string]string{"app": "web", "tier": "frontend"},
		},
	}

	tests := []struct {
		name        string
		podSelector *metav1.LabelSelector
		expected    bool
	}{
		{
			name:        "nil selector matches all",
			podSelector: nil,
			expected:    true,
		},
		{
			name: "matching labels",
			podSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			expected: true,
		},
		{
			name: "non-matching labels",
			podSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "api"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := matcher.IsPodMatched(pod, tt.podSelector)
			if err != nil {
				t.Errorf("IsPodMatched() error = %v", err)
			}
			if matched != tt.expected {
				t.Errorf("IsPodMatched() = %v, want %v", matched, tt.expected)
			}
		})
	}
}

func TestMatcher_ExcludeNamespaces(t *testing.T) {
	matcher := &Matcher{}

	tests := []struct {
		name       string
		namespaces []string
		excludes   []string
		expected   int
	}{
		{
			name:       "no excludes",
			namespaces: []string{"a", "b", "c"},
			excludes:   []string{},
			expected:   3,
		},
		{
			name:       "exclude one",
			namespaces: []string{"a", "b", "c"},
			excludes:   []string{"b"},
			expected:   2,
		},
		{
			name:       "exclude all",
			namespaces: []string{"a", "b", "c"},
			excludes:   []string{"a", "b", "c"},
			expected:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.excludeNamespaces(tt.namespaces, tt.excludes)
			if len(result) != tt.expected {
				t.Errorf("excludeNamespaces() returned %d items, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestUnique(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected int
	}{
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: 3,
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: 3,
		},
		{
			name:     "all same",
			input:    []string{"a", "a", "a"},
			expected: 1,
		},
		{
			name:     "empty",
			input:    []string{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := unique(tt.input)
			if len(result) != tt.expected {
				t.Errorf("unique() returned %d items, want %d", len(result), tt.expected)
			}
		})
	}
}
