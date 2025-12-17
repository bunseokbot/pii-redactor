package policy

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
)

// Matcher matches namespaces and pods against policy selectors
type Matcher struct {
	client client.Client
}

// NewMatcher creates a new Matcher
func NewMatcher(c client.Client) *Matcher {
	return &Matcher{client: c}
}

// MatchNamespaces returns namespaces matching the selector
func (m *Matcher) MatchNamespaces(ctx context.Context, selector piiv1alpha1.PolicySelector) ([]string, error) {
	var matchedNamespaces []string

	// If specific namespaces are listed, use them
	if len(selector.Namespaces) > 0 {
		matchedNamespaces = append(matchedNamespaces, selector.Namespaces...)
	}

	// If namespace selector is provided, match by labels
	if selector.NamespaceSelector != nil {
		labelSelector, err := metav1.LabelSelectorAsSelector(selector.NamespaceSelector)
		if err != nil {
			return nil, err
		}

		var namespaceList corev1.NamespaceList
		if err := m.client.List(ctx, &namespaceList, &client.ListOptions{
			LabelSelector: labelSelector,
		}); err != nil {
			return nil, err
		}

		for _, ns := range namespaceList.Items {
			matchedNamespaces = append(matchedNamespaces, ns.Name)
		}
	}

	// If no selectors specified, match all namespaces
	if len(selector.Namespaces) == 0 && selector.NamespaceSelector == nil {
		var namespaceList corev1.NamespaceList
		if err := m.client.List(ctx, &namespaceList); err != nil {
			return nil, err
		}

		for _, ns := range namespaceList.Items {
			matchedNamespaces = append(matchedNamespaces, ns.Name)
		}
	}

	// Remove excluded namespaces
	matchedNamespaces = m.excludeNamespaces(matchedNamespaces, selector.ExcludeNamespaces)

	// Remove duplicates
	return unique(matchedNamespaces), nil
}

// MatchPods returns pods in the namespace matching the selector
func (m *Matcher) MatchPods(ctx context.Context, namespace string, podSelector *metav1.LabelSelector) ([]corev1.Pod, error) {
	var podList corev1.PodList

	listOptions := &client.ListOptions{
		Namespace: namespace,
	}

	if podSelector != nil {
		labelSelector, err := metav1.LabelSelectorAsSelector(podSelector)
		if err != nil {
			return nil, err
		}
		listOptions.LabelSelector = labelSelector
	}

	if err := m.client.List(ctx, &podList, listOptions); err != nil {
		return nil, err
	}

	return podList.Items, nil
}

// MatchPodsInNamespaces returns pods across namespaces matching the selector
func (m *Matcher) MatchPodsInNamespaces(ctx context.Context, selector piiv1alpha1.PolicySelector) (map[string][]corev1.Pod, error) {
	namespaces, err := m.MatchNamespaces(ctx, selector)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]corev1.Pod)

	for _, ns := range namespaces {
		pods, err := m.MatchPods(ctx, ns, selector.PodSelector)
		if err != nil {
			return nil, err
		}
		if len(pods) > 0 {
			result[ns] = pods
		}
	}

	return result, nil
}

// IsNamespaceMatched checks if a namespace matches the selector
func (m *Matcher) IsNamespaceMatched(ctx context.Context, namespace string, selector piiv1alpha1.PolicySelector) (bool, error) {
	matchedNamespaces, err := m.MatchNamespaces(ctx, selector)
	if err != nil {
		return false, err
	}

	for _, ns := range matchedNamespaces {
		if ns == namespace {
			return true, nil
		}
	}

	return false, nil
}

// IsPodMatched checks if a pod matches the selector
func (m *Matcher) IsPodMatched(pod *corev1.Pod, podSelector *metav1.LabelSelector) (bool, error) {
	if podSelector == nil {
		return true, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(podSelector)
	if err != nil {
		return false, err
	}

	return selector.Matches(labels.Set(pod.Labels)), nil
}

// excludeNamespaces removes excluded namespaces from the list
func (m *Matcher) excludeNamespaces(namespaces []string, excludes []string) []string {
	if len(excludes) == 0 {
		return namespaces
	}

	excludeSet := make(map[string]struct{})
	for _, ns := range excludes {
		excludeSet[ns] = struct{}{}
	}

	var result []string
	for _, ns := range namespaces {
		if _, excluded := excludeSet[ns]; !excluded {
			result = append(result, ns)
		}
	}

	return result
}

// unique removes duplicates from a string slice
func unique(slice []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, s := range slice {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}

	return result
}

// MatchResult holds the result of a policy match
type MatchResult struct {
	// Namespaces is the list of matched namespaces
	Namespaces []string

	// Pods maps namespace to matched pods
	Pods map[string][]corev1.Pod

	// TotalPods is the total number of matched pods
	TotalPods int
}

// Match performs a full match and returns the result
func (m *Matcher) Match(ctx context.Context, selector piiv1alpha1.PolicySelector) (*MatchResult, error) {
	namespaces, err := m.MatchNamespaces(ctx, selector)
	if err != nil {
		return nil, err
	}

	pods := make(map[string][]corev1.Pod)
	totalPods := 0

	for _, ns := range namespaces {
		nsPods, err := m.MatchPods(ctx, ns, selector.PodSelector)
		if err != nil {
			return nil, err
		}
		if len(nsPods) > 0 {
			pods[ns] = nsPods
			totalPods += len(nsPods)
		}
	}

	return &MatchResult{
		Namespaces: namespaces,
		Pods:       pods,
		TotalPods:  totalPods,
	}, nil
}
