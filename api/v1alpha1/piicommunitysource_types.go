package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GitSourceConfig defines Git repository settings
type GitSourceConfig struct {
	// URL is the Git repository URL
	URL string `json:"url"`

	// Ref is the Git reference (branch, tag, or commit)
	// +kubebuilder:default=main
	Ref string `json:"ref,omitempty"`

	// Path is the subdirectory path within the repository
	// +kubebuilder:default=rules
	Path string `json:"path,omitempty"`

	// Auth contains authentication settings for private repositories
	Auth *GitAuth `json:"auth,omitempty"`
}

// GitAuth defines Git authentication settings
type GitAuth struct {
	// SecretRef references a secret containing credentials
	SecretRef *SecretKeyRef `json:"secretRef,omitempty"`

	// SSHKeyRef references a secret containing SSH private key
	SSHKeyRef *SecretKeyRef `json:"sshKeyRef,omitempty"`
}

// OCISourceConfig defines OCI registry settings
type OCISourceConfig struct {
	// Registry is the OCI registry URL
	Registry string `json:"registry"`

	// Repository is the repository name
	Repository string `json:"repository"`

	// Tag is the image tag
	// +kubebuilder:default=latest
	Tag string `json:"tag,omitempty"`

	// Auth contains authentication settings
	Auth *OCIAuth `json:"auth,omitempty"`
}

// OCIAuth defines OCI registry authentication
type OCIAuth struct {
	// SecretRef references a docker-registry type secret
	SecretRef *SecretKeyRef `json:"secretRef,omitempty"`
}

// HTTPSourceConfig defines HTTP source settings
type HTTPSourceConfig struct {
	// URL is the HTTP URL to fetch rules from
	URL string `json:"url"`

	// Headers are additional HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// SecretHeaders are headers from secrets
	SecretHeaders map[string]SecretKeyRef `json:"secretHeaders,omitempty"`
}

// SyncConfig defines synchronization settings
type SyncConfig struct {
	// Interval is the sync interval (e.g., "1h", "30m")
	// +kubebuilder:default="1h"
	Interval string `json:"interval,omitempty"`

	// Timeout is the sync timeout
	// +kubebuilder:default="5m"
	Timeout string `json:"timeout,omitempty"`
}

// TrustVerification defines signature verification settings
type TrustVerification struct {
	// Enabled indicates whether signature verification is enabled
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// PublicKey references a secret containing the public key
	PublicKey *SecretKeyRef `json:"publicKey,omitempty"`

	// CosignPublicKey is the Cosign public key for OCI artifacts
	CosignPublicKey *SecretKeyRef `json:"cosignPublicKey,omitempty"`
}

// TrustConfig defines trust settings for the source
type TrustConfig struct {
	// Verification contains signature verification settings
	Verification *TrustVerification `json:"verification,omitempty"`

	// AllowedMaintainers is a list of trusted maintainers
	AllowedMaintainers []string `json:"allowedMaintainers,omitempty"`
}

// RuleSetInfo contains information about an available rule set
type RuleSetInfo struct {
	// Name is the rule set name
	Name string `json:"name"`

	// Version is the rule set version
	Version string `json:"version"`

	// Patterns is the number of patterns in this set
	Patterns int `json:"patterns"`

	// Description is a brief description
	Description string `json:"description,omitempty"`

	// Category is the rule set category
	Category string `json:"category,omitempty"`
}

// PIICommunitySourceSpec defines the desired state of PIICommunitySource
type PIICommunitySourceSpec struct {
	// Type is the source type
	// +kubebuilder:validation:Enum=git;oci;http
	Type string `json:"type"`

	// Git contains Git repository settings
	Git *GitSourceConfig `json:"git,omitempty"`

	// OCI contains OCI registry settings
	OCI *OCISourceConfig `json:"oci,omitempty"`

	// HTTP contains HTTP source settings
	HTTP *HTTPSourceConfig `json:"http,omitempty"`

	// Sync contains synchronization settings
	Sync SyncConfig `json:"sync,omitempty"`

	// Trust contains trust and verification settings
	Trust *TrustConfig `json:"trust,omitempty"`

	// DefaultMaturityLevels specifies default maturity levels for subscriptions
	// If not specified, defaults to ["stable", "incubating"]
	DefaultMaturityLevels []string `json:"defaultMaturityLevels,omitempty"`
}

// PIICommunitySourceStatus defines the observed state of PIICommunitySource
type PIICommunitySourceStatus struct {
	// LastSyncTime is the timestamp of the last successful sync
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// SyncStatus indicates the current sync status
	// +kubebuilder:validation:Enum=Synced;Syncing;Failed;Unknown
	SyncStatus string `json:"syncStatus,omitempty"`

	// LastSyncError is the error from the last sync attempt
	LastSyncError string `json:"lastSyncError,omitempty"`

	// AvailableRuleSets is a list of available rule sets
	AvailableRuleSets []RuleSetInfo `json:"availableRuleSets,omitempty"`

	// TotalPatterns is the total number of available patterns
	TotalPatterns int `json:"totalPatterns,omitempty"`

	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.syncStatus`
// +kubebuilder:printcolumn:name="Rule Sets",type=integer,JSONPath=`.status.totalPatterns`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PIICommunitySource is the Schema for the piicommunitysources API
type PIICommunitySource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PIICommunitySourceSpec   `json:"spec,omitempty"`
	Status PIICommunitySourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PIICommunitySourceList contains a list of PIICommunitySource
type PIICommunitySourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PIICommunitySource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PIICommunitySource{}, &PIICommunitySourceList{})
}
