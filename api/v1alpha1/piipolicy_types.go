package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicySelector defines which workloads this policy applies to
type PolicySelector struct {
	// Namespaces is a list of namespace names to include
	Namespaces []string `json:"namespaces,omitempty"`

	// NamespaceSelector selects namespaces by labels
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector selects pods by labels
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// ExcludeNamespaces is a list of namespaces to exclude
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
}

// PatternRef references a PIIPattern
type PatternRef struct {
	// Name is the name of the PIIPattern
	Name string `json:"name"`

	// Namespace is the namespace of the PIIPattern (defaults to policy namespace)
	Namespace string `json:"namespace,omitempty"`
}

// PatternSelection defines which patterns to use
type PatternSelection struct {
	// BuiltIn is a list of built-in pattern names to use
	BuiltIn []string `json:"builtIn,omitempty"`

	// Custom is a list of custom PIIPattern references
	Custom []PatternRef `json:"custom,omitempty"`

	// Community is a list of community pattern references
	Community []string `json:"community,omitempty"`
}

// RedactAction defines redaction behavior
type RedactAction struct {
	// Enabled indicates whether redaction is enabled
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Destination is where to send redacted logs
	Destination string `json:"destination,omitempty"`
}

// DeduplicationConfig defines alert deduplication
type DeduplicationConfig struct {
	// Window is the time window for deduplication
	Window string `json:"window,omitempty"`

	// Key is the template for deduplication key
	Key string `json:"key,omitempty"`
}

// AlertAction defines alerting behavior
type AlertAction struct {
	// Enabled indicates whether alerting is enabled
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Channels is a list of alert channel names
	Channels []string `json:"channels,omitempty"`

	// Deduplication configures alert deduplication
	Deduplication *DeduplicationConfig `json:"deduplication,omitempty"`
}

// AuditAction defines audit logging behavior
type AuditAction struct {
	// Enabled indicates whether audit logging is enabled
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// IncludeOriginal indicates whether to include original (unredacted) content
	// +kubebuilder:default=false
	IncludeOriginal bool `json:"includeOriginal,omitempty"`

	// Destination is where to send audit logs
	Destination string `json:"destination,omitempty"`
}

// PolicyActions defines actions to take when PII is detected
type PolicyActions struct {
	// Redact defines redaction behavior
	Redact *RedactAction `json:"redact,omitempty"`

	// Alert defines alerting behavior
	Alert *AlertAction `json:"alert,omitempty"`

	// Audit defines audit logging behavior
	Audit *AuditAction `json:"audit,omitempty"`
}

// PerformanceConfig defines performance settings
type PerformanceConfig struct {
	// SamplingRate is the percentage of logs to process (1-100)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=100
	SamplingRate int `json:"samplingRate,omitempty"`

	// MaxLogSizeKB is the maximum log size to process
	// +kubebuilder:default=1024
	MaxLogSizeKB int `json:"maxLogSizeKB,omitempty"`

	// BatchSize is the number of logs to process in a batch
	// +kubebuilder:default=100
	BatchSize int `json:"batchSize,omitempty"`
}

// PIIPolicySpec defines the desired state of PIIPolicy
type PIIPolicySpec struct {
	// Selector defines which workloads this policy applies to
	Selector PolicySelector `json:"selector,omitempty"`

	// Patterns defines which patterns to use
	Patterns PatternSelection `json:"patterns"`

	// Actions defines what to do when PII is detected
	Actions PolicyActions `json:"actions,omitempty"`

	// Performance defines performance settings
	Performance *PerformanceConfig `json:"performance,omitempty"`
}

// PIIPolicyStatus defines the observed state of PIIPolicy
type PIIPolicyStatus struct {
	// Active indicates whether the policy is active
	Active bool `json:"active,omitempty"`

	// MatchedNamespaces is the list of namespaces this policy applies to
	MatchedNamespaces []string `json:"matchedNamespaces,omitempty"`

	// LoadedPatterns is the number of patterns loaded
	LoadedPatterns int `json:"loadedPatterns,omitempty"`

	// LastUpdated is the timestamp of last policy update
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Active",type=boolean,JSONPath=`.status.active`
// +kubebuilder:printcolumn:name="Patterns",type=integer,JSONPath=`.status.loadedPatterns`
// +kubebuilder:printcolumn:name="Namespaces",type=string,JSONPath=`.status.matchedNamespaces`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PIIPolicy is the Schema for the piipolicies API
type PIIPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PIIPolicySpec   `json:"spec,omitempty"`
	Status PIIPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PIIPolicyList contains a list of PIIPolicy
type PIIPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PIIPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PIIPolicy{}, &PIIPolicyList{})
}
