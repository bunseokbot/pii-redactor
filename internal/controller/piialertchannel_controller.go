package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/notifier"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PIIAlertChannelReconciler reconciles a PIIAlertChannel object
type PIIAlertChannelReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	NotifierManager *notifier.Manager
}

// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piialertchannels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piialertchannels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piialertchannels/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile handles PIIAlertChannel reconciliation
func (r *PIIAlertChannelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PIIAlertChannel
	var channel piiv1alpha1.PIIAlertChannel
	if err := r.Get(ctx, req.NamespacedName, &channel); err != nil {
		// Channel was deleted, remove from manager
		r.NotifierManager.Unregister(req.String())
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PIIAlertChannel", "name", channel.Name, "type", channel.Spec.Type)

	// Create notifier based on type
	var n notifier.Notifier
	var err error

	switch channel.Spec.Type {
	case "slack":
		n, err = r.createSlackNotifier(ctx, &channel)
	case "pagerduty":
		n, err = r.createPagerDutyNotifier(ctx, &channel)
	case "webhook":
		n, err = r.createWebhookNotifier(ctx, &channel)
	case "email":
		n, err = r.createEmailNotifier(ctx, &channel)
	default:
		err = fmt.Errorf("unsupported channel type: %s", channel.Spec.Type)
	}

	if err != nil {
		// Update status with error
		channel.Status.Ready = false
		channel.Status.LastError = err.Error()
		r.setCondition(&channel, "Ready", metav1.ConditionFalse, "ConfigurationError", err.Error())

		if updateErr := r.Status().Update(ctx, &channel); updateErr != nil {
			logger.Error(updateErr, "Failed to update PIIAlertChannel status")
			return ctrl.Result{}, updateErr
		}

		return ctrl.Result{}, nil
	}

	// Validate the notifier
	if err := n.Validate(); err != nil {
		channel.Status.Ready = false
		channel.Status.LastError = err.Error()
		r.setCondition(&channel, "Ready", metav1.ConditionFalse, "ValidationError", err.Error())

		if updateErr := r.Status().Update(ctx, &channel); updateErr != nil {
			logger.Error(updateErr, "Failed to update PIIAlertChannel status")
			return ctrl.Result{}, updateErr
		}

		return ctrl.Result{}, nil
	}

	// Register with manager
	config := notifier.NotifierConfig{
		MinSeverity:        channel.Spec.MinSeverity,
		RateLimitPerMinute: channel.Spec.RateLimitPerMinute,
	}

	if err := r.NotifierManager.Register(req.String(), n, config); err != nil {
		channel.Status.Ready = false
		channel.Status.LastError = err.Error()
		r.setCondition(&channel, "Ready", metav1.ConditionFalse, "RegistrationError", err.Error())

		if updateErr := r.Status().Update(ctx, &channel); updateErr != nil {
			logger.Error(updateErr, "Failed to update PIIAlertChannel status")
			return ctrl.Result{}, updateErr
		}

		return ctrl.Result{}, nil
	}

	// Update status to ready
	channel.Status.Ready = true
	channel.Status.LastError = ""
	r.setCondition(&channel, "Ready", metav1.ConditionTrue, "Configured", "Channel is configured and ready")

	if err := r.Status().Update(ctx, &channel); err != nil {
		logger.Error(err, "Failed to update PIIAlertChannel status")
		return ctrl.Result{}, err
	}

	logger.Info("PIIAlertChannel reconciled successfully", "name", channel.Name)
	return ctrl.Result{}, nil
}

// createSlackNotifier creates a Slack notifier from the channel spec
func (r *PIIAlertChannelReconciler) createSlackNotifier(ctx context.Context, channel *piiv1alpha1.PIIAlertChannel) (notifier.Notifier, error) {
	if channel.Spec.Slack == nil {
		return nil, fmt.Errorf("slack configuration is required")
	}

	var webhookURL string
	if channel.Spec.Slack.WebhookURLValue != "" {
		webhookURL = channel.Spec.Slack.WebhookURLValue
	} else if channel.Spec.Slack.WebhookURL != nil {
		var err error
		webhookURL, err = r.getSecretValue(ctx, channel.Namespace, channel.Spec.Slack.WebhookURL)
		if err != nil {
			return nil, fmt.Errorf("failed to get webhook URL from secret: %w", err)
		}
	} else {
		return nil, fmt.Errorf("either webhookURL or webhookURLValue must be specified")
	}

	config := notifier.SlackConfig{
		WebhookURL: webhookURL,
		Channel:    channel.Spec.Slack.Channel,
		Username:   channel.Spec.Slack.Username,
		IconEmoji:  channel.Spec.Slack.IconEmoji,
	}

	return notifier.NewSlackNotifier(config), nil
}

// createPagerDutyNotifier creates a PagerDuty notifier from the channel spec
func (r *PIIAlertChannelReconciler) createPagerDutyNotifier(ctx context.Context, channel *piiv1alpha1.PIIAlertChannel) (notifier.Notifier, error) {
	if channel.Spec.PagerDuty == nil {
		return nil, fmt.Errorf("pagerduty configuration is required")
	}

	if channel.Spec.PagerDuty.ServiceKey == nil {
		return nil, fmt.Errorf("pagerduty serviceKey is required")
	}

	routingKey, err := r.getSecretValue(ctx, channel.Namespace, channel.Spec.PagerDuty.ServiceKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get service key from secret: %w", err)
	}

	config := notifier.PagerDutyConfig{
		RoutingKey: routingKey,
		Severity:   channel.Spec.PagerDuty.Severity,
	}

	return notifier.NewPagerDutyNotifier(config), nil
}

// createWebhookNotifier creates a Webhook notifier from the channel spec
func (r *PIIAlertChannelReconciler) createWebhookNotifier(ctx context.Context, channel *piiv1alpha1.PIIAlertChannel) (notifier.Notifier, error) {
	if channel.Spec.Webhook == nil {
		return nil, fmt.Errorf("webhook configuration is required")
	}

	var url string
	if channel.Spec.Webhook.URL != "" {
		url = channel.Spec.Webhook.URL
	} else if channel.Spec.Webhook.URLFrom != nil {
		var err error
		url, err = r.getSecretValue(ctx, channel.Namespace, channel.Spec.Webhook.URLFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to get URL from secret: %w", err)
		}
	} else {
		return nil, fmt.Errorf("either url or urlFrom must be specified")
	}

	// Resolve secret headers
	headers := make(map[string]string)
	for k, v := range channel.Spec.Webhook.Headers {
		headers[k] = v
	}

	for headerName, secretRef := range channel.Spec.Webhook.SecretHeaders {
		value, err := r.getSecretValue(ctx, channel.Namespace, &secretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to get header %s from secret: %w", headerName, err)
		}
		headers[headerName] = value
	}

	config := notifier.WebhookConfig{
		URL:     url,
		Method:  channel.Spec.Webhook.Method,
		Headers: headers,
	}

	return notifier.NewWebhookNotifier(config), nil
}

// createEmailNotifier creates an Email notifier from the channel spec
func (r *PIIAlertChannelReconciler) createEmailNotifier(ctx context.Context, channel *piiv1alpha1.PIIAlertChannel) (notifier.Notifier, error) {
	if channel.Spec.Email == nil {
		return nil, fmt.Errorf("email configuration is required")
	}

	var username, password string
	if channel.Spec.Email.AuthSecret != nil {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Namespace: channel.Namespace,
			Name:      channel.Spec.Email.AuthSecret.Name,
		}, secret); err != nil {
			return nil, fmt.Errorf("failed to get auth secret: %w", err)
		}

		username = string(secret.Data["username"])
		password = string(secret.Data["password"])
	}

	config := notifier.EmailConfig{
		SMTPHost: channel.Spec.Email.SMTPHost,
		SMTPPort: channel.Spec.Email.SMTPPort,
		From:     channel.Spec.Email.From,
		To:       channel.Spec.Email.To,
		Username: username,
		Password: password,
		UseTLS:   channel.Spec.Email.UseTLS,
	}

	return notifier.NewEmailNotifier(config), nil
}

// getSecretValue retrieves a value from a secret
func (r *PIIAlertChannelReconciler) getSecretValue(ctx context.Context, namespace string, ref *piiv1alpha1.SecretKeyRef) (string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      ref.Name,
	}, secret); err != nil {
		return "", err
	}

	value, exists := secret.Data[ref.Key]
	if !exists {
		return "", fmt.Errorf("key %s not found in secret %s", ref.Key, ref.Name)
	}

	return string(value), nil
}

// setCondition sets a condition on the channel status
func (r *PIIAlertChannelReconciler) setCondition(channel *piiv1alpha1.PIIAlertChannel, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	// Find and update existing condition or append new one
	for i, c := range channel.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				channel.Status.Conditions[i] = condition
			}
			return
		}
	}

	channel.Status.Conditions = append(channel.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager
func (r *PIIAlertChannelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&piiv1alpha1.PIIAlertChannel{}).
		Complete(r)
}
