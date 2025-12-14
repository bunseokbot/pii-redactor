package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PatternRule defines a regex pattern for PII detection
type PatternRule struct {
	// Regex is the regular expression pattern for detection
	// +kubebuilder:validation:Required
	Regex string `json:"regex"`

	// Confidence is the confidence level of this pattern
	// +kubebuilder:validation:Enum=high;medium;low
	// +kubebuilder:default=medium
	Confidence string `json:"confidence,omitempty"`
}

// MaskingStrategy defines how to mask detected PII
type MaskingStrategy struct {
	// Type is the masking strategy type
	// +kubebuilder:validation:Enum=full;partial;hash;tokenize
	// +kubebuilder:default=partial
	Type string `json:"type,omitempty"`

	// ShowFirst is the number of characters to show at the beginning
	// +kubebuilder:default=0
	ShowFirst int `json:"showFirst,omitempty"`

	// ShowLast is the number of characters to show at the end
	// +kubebuilder:default=0
	ShowLast int `json:"showLast,omitempty"`

	// MaskChar is the character used for masking
	// +kubebuilder:default="*"
	MaskChar string `json:"maskChar,omitempty"`

	// Replacement is used when Type is "full" to replace the entire match
	Replacement string `json:"replacement,omitempty"`
}

// PIIPatternSpec defines the desired state of PIIPattern
type PIIPatternSpec struct {
	// DisplayName is a human-readable name for the pattern
	DisplayName string `json:"displayName,omitempty"`

	// Description provides details about this pattern
	Description string `json:"description,omitempty"`

	// Patterns is a list of regex patterns for detection
	// +kubebuilder:validation:MinItems=1
	Patterns []PatternRule `json:"patterns"`

	// Validator is an optional validation function name
	Validator string `json:"validator,omitempty"`

	// MaskingStrategy defines how to mask detected PII
	MaskingStrategy MaskingStrategy `json:"maskingStrategy,omitempty"`

	// Severity is the severity level of this PII type
	// +kubebuilder:validation:Enum=critical;high;medium;low
	// +kubebuilder:default=medium
	Severity string `json:"severity,omitempty"`

	// Enabled indicates whether this pattern is active
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// TestCases for validating the pattern
	TestCases *TestCases `json:"testCases,omitempty"`
}

// TestCases defines test cases for pattern validation
type TestCases struct {
	// ShouldMatch is a list of strings that should match the pattern
	ShouldMatch []string `json:"shouldMatch,omitempty"`

	// ShouldNotMatch is a list of strings that should not match
	ShouldNotMatch []string `json:"shouldNotMatch,omitempty"`
}

// PIIPatternStatus defines the observed state of PIIPattern
type PIIPatternStatus struct {
	// Ready indicates whether the pattern is compiled and ready
	Ready bool `json:"ready,omitempty"`

	// LastValidated is the timestamp of last validation
	LastValidated *metav1.Time `json:"lastValidated,omitempty"`

	// ValidationErrors contains any errors from pattern validation
	ValidationErrors []string `json:"validationErrors,omitempty"`

	// MatchCount is the number of matches detected (for metrics)
	MatchCount int64 `json:"matchCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Display Name",type=string,JSONPath=`.spec.displayName`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PIIPattern is the Schema for the piipatterns API
type PIIPattern struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PIIPatternSpec   `json:"spec,omitempty"`
	Status PIIPatternStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PIIPatternList contains a list of PIIPattern
type PIIPatternList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PIIPattern `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PIIPattern{}, &PIIPatternList{})
}
