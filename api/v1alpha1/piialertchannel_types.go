package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretKeyRef references a key in a Secret
type SecretKeyRef struct {
	// Name is the name of the secret
	Name string `json:"name"`

	// Key is the key in the secret
	Key string `json:"key"`
}

// SlackConfig defines Slack notification settings
type SlackConfig struct {
	// WebhookURL is the Slack webhook URL (can be a secret reference)
	WebhookURL *SecretKeyRef `json:"webhookURL,omitempty"`

	// WebhookURLValue is the direct webhook URL value (not recommended for production)
	WebhookURLValue string `json:"webhookURLValue,omitempty"`

	// Channel is the Slack channel to send to
	Channel string `json:"channel,omitempty"`

	// Username is the username to display
	// +kubebuilder:default="PII Redactor"
	Username string `json:"username,omitempty"`

	// IconEmoji is the emoji to use as icon
	// +kubebuilder:default=":shield:"
	IconEmoji string `json:"iconEmoji,omitempty"`
}

// PagerDutyConfig defines PagerDuty notification settings
type PagerDutyConfig struct {
	// ServiceKey is the PagerDuty service key
	ServiceKey *SecretKeyRef `json:"serviceKey,omitempty"`

	// Severity is the PagerDuty severity level
	// +kubebuilder:validation:Enum=critical;error;warning;info
	// +kubebuilder:default=critical
	Severity string `json:"severity,omitempty"`
}

// WebhookConfig defines generic webhook notification settings
type WebhookConfig struct {
	// URL is the webhook URL
	URL string `json:"url,omitempty"`

	// URLFrom references a secret containing the URL
	URLFrom *SecretKeyRef `json:"urlFrom,omitempty"`

	// Method is the HTTP method
	// +kubebuilder:validation:Enum=POST;PUT
	// +kubebuilder:default=POST
	Method string `json:"method,omitempty"`

	// Headers are additional HTTP headers
	Headers map[string]string `json:"headers,omitempty"`

	// SecretHeaders are headers from secrets
	SecretHeaders map[string]SecretKeyRef `json:"secretHeaders,omitempty"`
}

// EmailConfig defines email notification settings
type EmailConfig struct {
	// SMTPHost is the SMTP server hostname
	SMTPHost string `json:"smtpHost"`

	// SMTPPort is the SMTP server port
	// +kubebuilder:default=587
	SMTPPort int `json:"smtpPort,omitempty"`

	// From is the sender email address
	From string `json:"from"`

	// To is the list of recipient email addresses
	To []string `json:"to"`

	// AuthSecret references the secret containing SMTP credentials
	AuthSecret *corev1.LocalObjectReference `json:"authSecret,omitempty"`

	// UseTLS indicates whether to use TLS
	// +kubebuilder:default=true
	UseTLS bool `json:"useTLS,omitempty"`
}

// PIIAlertChannelSpec defines the desired state of PIIAlertChannel
type PIIAlertChannelSpec struct {
	// Type is the alert channel type
	// +kubebuilder:validation:Enum=slack;pagerduty;webhook;email
	Type string `json:"type"`

	// Slack configuration
	Slack *SlackConfig `json:"slack,omitempty"`

	// PagerDuty configuration
	PagerDuty *PagerDutyConfig `json:"pagerduty,omitempty"`

	// Webhook configuration
	Webhook *WebhookConfig `json:"webhook,omitempty"`

	// Email configuration
	Email *EmailConfig `json:"email,omitempty"`

	// MinSeverity is the minimum severity to alert on
	// +kubebuilder:validation:Enum=critical;high;medium;low
	// +kubebuilder:default=medium
	MinSeverity string `json:"minSeverity,omitempty"`

	// RateLimitPerMinute limits alerts per minute
	// +kubebuilder:default=10
	RateLimitPerMinute int `json:"rateLimitPerMinute,omitempty"`
}

// PIIAlertChannelStatus defines the observed state of PIIAlertChannel
type PIIAlertChannelStatus struct {
	// Ready indicates whether the channel is configured and ready
	Ready bool `json:"ready,omitempty"`

	// LastAlertSent is the timestamp of the last alert sent
	LastAlertSent *metav1.Time `json:"lastAlertSent,omitempty"`

	// AlertsSentTotal is the total number of alerts sent
	AlertsSentTotal int64 `json:"alertsSentTotal,omitempty"`

	// LastError is the last error message
	LastError string `json:"lastError,omitempty"`

	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Alerts Sent",type=integer,JSONPath=`.status.alertsSentTotal`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PIIAlertChannel is the Schema for the piialertchannels API
type PIIAlertChannel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PIIAlertChannelSpec   `json:"spec,omitempty"`
	Status PIIAlertChannelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PIIAlertChannelList contains a list of PIIAlertChannel
type PIIAlertChannelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PIIAlertChannel `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PIIAlertChannel{}, &PIIAlertChannelList{})
}
