package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/audit"
	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/notifier"
	"github.com/bunseokbot/pii-redactor/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PIIPolicyReconciler reconciles a PIIPolicy object
type PIIPolicyReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Engine          *detector.Engine
	NotifierManager *notifier.Manager
	AuditLogger     audit.AuditLogger
	Matcher         *policy.Matcher
	Aggregator      *policy.Aggregator
}

// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piipolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piipolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piipolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile handles PIIPolicy reconciliation
func (r *PIIPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PIIPolicy
	var piiPolicy piiv1alpha1.PIIPolicy
	if err := r.Get(ctx, req.NamespacedName, &piiPolicy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PIIPolicy", "name", piiPolicy.Name)

	// Match namespaces
	matchedNamespaces, err := r.Matcher.MatchNamespaces(ctx, piiPolicy.Spec.Selector)
	if err != nil {
		logger.Error(err, "Failed to match namespaces")
		r.setCondition(&piiPolicy, "Ready", metav1.ConditionFalse, "MatchError", err.Error())
		piiPolicy.Status.Active = false
		if updateErr := r.Status().Update(ctx, &piiPolicy); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	// Aggregate patterns
	aggregationResult, err := r.Aggregator.AggregatePatterns(ctx, piiPolicy.Spec.Patterns, piiPolicy.Namespace)
	if err != nil {
		logger.Error(err, "Failed to aggregate patterns")
		r.setCondition(&piiPolicy, "Ready", metav1.ConditionFalse, "AggregationError", err.Error())
		piiPolicy.Status.Active = false
		if updateErr := r.Status().Update(ctx, &piiPolicy); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	// Log any aggregation errors
	if aggregationResult.HasErrors() {
		for _, e := range aggregationResult.Errors {
			logger.Info("Pattern aggregation warning", "warning", e)
		}
	}

	// Enable patterns based on aggregation
	if err := r.Aggregator.EnablePatterns(aggregationResult); err != nil {
		logger.Error(err, "Failed to enable patterns")
	}

	// Validate alert channels if alerting is enabled
	var validChannels []string
	if piiPolicy.Spec.Actions.Alert != nil && piiPolicy.Spec.Actions.Alert.Enabled {
		for _, channelName := range piiPolicy.Spec.Actions.Alert.Channels {
			if _, exists := r.NotifierManager.Get(channelName); exists {
				validChannels = append(validChannels, channelName)
			} else {
				logger.Info("Alert channel not found", "channel", channelName)
			}
		}
	}

	// Update status
	now := metav1.Now()
	piiPolicy.Status.Active = true
	piiPolicy.Status.MatchedNamespaces = matchedNamespaces
	piiPolicy.Status.LoadedPatterns = aggregationResult.TotalPatterns
	piiPolicy.Status.LastUpdated = &now

	if aggregationResult.TotalPatterns == 0 {
		r.setCondition(&piiPolicy, "Ready", metav1.ConditionFalse, "NoPatterns", "No patterns were loaded")
		piiPolicy.Status.Active = false
	} else if len(matchedNamespaces) == 0 {
		r.setCondition(&piiPolicy, "Ready", metav1.ConditionFalse, "NoNamespaces", "No namespaces matched the selector")
		piiPolicy.Status.Active = false
	} else {
		r.setCondition(&piiPolicy, "Ready", metav1.ConditionTrue, "Configured", "Policy is active and configured")
	}

	if err := r.Status().Update(ctx, &piiPolicy); err != nil {
		logger.Error(err, "Failed to update PIIPolicy status")
		return ctrl.Result{}, err
	}

	// Log audit entry for policy update
	if r.AuditLogger != nil {
		entry := audit.NewAuditEntry(
			audit.EventTypePolicyMatch,
			piiPolicy.Namespace,
			piiPolicy.Name,
			"",
		).WithAction(audit.ActionLog).
			WithMatchCount(aggregationResult.TotalPatterns).
			AddLabel("matchedNamespaces", joinStrings(matchedNamespaces)).
			AddLabel("validAlertChannels", joinStrings(validChannels))

		if err := r.AuditLogger.Log(ctx, entry); err != nil {
			logger.Error(err, "Failed to log audit entry")
		}
	}

	logger.Info("PIIPolicy reconciled successfully",
		"name", piiPolicy.Name,
		"matchedNamespaces", len(matchedNamespaces),
		"loadedPatterns", aggregationResult.TotalPatterns,
	)

	return ctrl.Result{}, nil
}

// setCondition sets a condition on the policy status
func (r *PIIPolicyReconciler) setCondition(piiPolicy *piiv1alpha1.PIIPolicy, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	// Find and update existing condition or append new one
	for i, c := range piiPolicy.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				piiPolicy.Status.Conditions[i] = condition
			}
			return
		}
	}

	piiPolicy.Status.Conditions = append(piiPolicy.Status.Conditions, condition)
}

// joinStrings joins strings with comma
func joinStrings(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += "," + strs[i]
	}
	return result
}

// SetupWithManager sets up the controller with the Manager
func (r *PIIPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&piiv1alpha1.PIIPolicy{}).
		Complete(r)
}
