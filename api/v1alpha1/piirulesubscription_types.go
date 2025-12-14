package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SourceRef references a PIICommunitySource
type SourceRef struct {
	// Name is the name of the PIICommunitySource
	Name string `json:"name"`

	// Namespace is the namespace of the PIICommunitySource (defaults to subscription namespace)
	Namespace string `json:"namespace,omitempty"`
}

// CategorySubscription defines a category subscription
type CategorySubscription struct {
	// Category is the category path (e.g., "korea", "compliance/pci-dss")
	Category string `json:"category"`

	// Version is the version constraint (e.g., ">=2.0.0", "~1.2.0")
	Version string `json:"version,omitempty"`

	// Patterns is a list of pattern names or glob patterns (e.g., "*", "phone", "aws-*")
	Patterns []string `json:"patterns"`
}

// PatternOverride defines an override for a community pattern
type PatternOverride struct {
	// Pattern is the pattern identifier (e.g., "korea/phone")
	Pattern string `json:"pattern"`

	// Severity overrides the pattern severity
	Severity string `json:"severity,omitempty"`

	// Enabled overrides whether the pattern is enabled
	Enabled *bool `json:"enabled,omitempty"`

	// MaskingStrategy overrides the masking strategy
	MaskingStrategy *MaskingStrategy `json:"maskingStrategy,omitempty"`
}

// UpdatePolicy defines automatic update settings
type UpdatePolicy struct {
	// Automatic indicates whether to automatically apply updates
	// +kubebuilder:default=true
	Automatic bool `json:"automatic,omitempty"`

	// RequireApproval lists change types that require manual approval
	// +kubebuilder:validation:Enum=majorVersion;minorVersion;newPatterns;deprecations
	RequireApproval []string `json:"requireApproval,omitempty"`

	// NotifyOn lists events to send notifications for
	NotifyOn []string `json:"notifyOn,omitempty"`
}

// PendingUpdate represents a pending pattern update
type PendingUpdate struct {
	// Pattern is the pattern identifier
	Pattern string `json:"pattern"`

	// CurrentVersion is the currently installed version
	CurrentVersion string `json:"currentVersion"`

	// AvailableVersion is the available version
	AvailableVersion string `json:"availableVersion"`

	// ChangeType is the type of change
	ChangeType string `json:"changeType"`

	// Description describes the changes
	Description string `json:"description,omitempty"`
}

// SubscribedPatternInfo contains info about a subscribed pattern
type SubscribedPatternInfo struct {
	// Name is the pattern name
	Name string `json:"name"`

	// Category is the pattern category
	Category string `json:"category"`

	// Version is the pattern version
	Version string `json:"version"`

	// Source is the source name
	Source string `json:"source"`

	// Overridden indicates if local overrides are applied
	Overridden bool `json:"overridden,omitempty"`
}

// PIIRuleSubscriptionSpec defines the desired state of PIIRuleSubscription
type PIIRuleSubscriptionSpec struct {
	// SourceRef references the community source
	SourceRef SourceRef `json:"sourceRef"`

	// MaturityLevels specifies which maturity levels to include
	// If not specified, defaults to ["stable", "incubating"]
	// +kubebuilder:validation:Enum=stable;incubating;sandbox;deprecated
	MaturityLevels []string `json:"maturityLevels,omitempty"`

	// Subscribe defines which rule sets to subscribe to
	Subscribe []CategorySubscription `json:"subscribe"`

	// Overrides defines local overrides for subscribed patterns
	Overrides []PatternOverride `json:"overrides,omitempty"`

	// UpdatePolicy defines automatic update behavior
	UpdatePolicy *UpdatePolicy `json:"updatePolicy,omitempty"`
}

// PIIRuleSubscriptionStatus defines the observed state of PIIRuleSubscription
type PIIRuleSubscriptionStatus struct {
	// SubscribedPatterns is the number of subscribed patterns
	SubscribedPatterns int `json:"subscribedPatterns,omitempty"`

	// SubscribedPatternList contains details of subscribed patterns
	SubscribedPatternList []SubscribedPatternInfo `json:"subscribedPatternList,omitempty"`

	// LastUpdated is the timestamp of the last update
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// PendingUpdates is a list of updates awaiting approval
	PendingUpdates []PendingUpdate `json:"pendingUpdates,omitempty"`

	// SyncStatus indicates the subscription sync status
	// +kubebuilder:validation:Enum=Synced;OutOfSync;Error
	SyncStatus string `json:"syncStatus,omitempty"`

	// LastError is the last error message
	LastError string `json:"lastError,omitempty"`

	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.sourceRef.name`
// +kubebuilder:printcolumn:name="Patterns",type=integer,JSONPath=`.status.subscribedPatterns`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.syncStatus`
// +kubebuilder:printcolumn:name="Pending",type=integer,JSONPath=`.status.pendingUpdates`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PIIRuleSubscription is the Schema for the piirulesubscriptions API
type PIIRuleSubscription struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PIIRuleSubscriptionSpec   `json:"spec,omitempty"`
	Status PIIRuleSubscriptionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PIIRuleSubscriptionList contains a list of PIIRuleSubscription
type PIIRuleSubscriptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PIIRuleSubscription `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PIIRuleSubscription{}, &PIIRuleSubscriptionList{})
}
