package controller

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/source"
	"github.com/bunseokbot/pii-redactor/internal/subscription"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PIIRuleSubscriptionReconciler reconciles a PIIRuleSubscription object
type PIIRuleSubscriptionReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	Engine              *detector.Engine
	Cache               *source.Cache
	SubscriptionManager *subscription.Manager
	Updater             *subscription.Updater
}

// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piirulesubscriptions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piirulesubscriptions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piirulesubscriptions/finalizers,verbs=update
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piicommunitysources,verbs=get;list;watch

// Reconcile handles PIIRuleSubscription reconciliation
func (r *PIIRuleSubscriptionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PIIRuleSubscription
	var ruleSubscription piiv1alpha1.PIIRuleSubscription
	if err := r.Get(ctx, req.NamespacedName, &ruleSubscription); err != nil {
		// Subscription was deleted, unsubscribe
		r.SubscriptionManager.Unsubscribe(req.String())
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PIIRuleSubscription", "name", ruleSubscription.Name)

	// Resolve source reference
	sourceNamespace := ruleSubscription.Spec.SourceRef.Namespace
	if sourceNamespace == "" {
		sourceNamespace = ruleSubscription.Namespace
	}

	// Check if source exists
	var communitySource piiv1alpha1.PIICommunitySource
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: sourceNamespace,
		Name:      ruleSubscription.Spec.SourceRef.Name,
	}, &communitySource); err != nil {
		r.setErrorStatus(ctx, &ruleSubscription, fmt.Errorf("source not found: %s/%s", sourceNamespace, ruleSubscription.Spec.SourceRef.Name))
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Check if source is synced
	if communitySource.Status.SyncStatus != "Synced" {
		logger.Info("Waiting for source to sync", "source", communitySource.Name, "status", communitySource.Status.SyncStatus)
		ruleSubscription.Status.SyncStatus = "OutOfSync"
		ruleSubscription.Status.LastError = "Waiting for source to sync"
		r.setCondition(&ruleSubscription, "Ready", metav1.ConditionFalse, "SourceNotReady", "Waiting for source to sync")

		if err := r.Status().Update(ctx, &ruleSubscription); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Process subscription
	result, err := r.SubscriptionManager.Subscribe(ctx, ruleSubscription.Spec)
	if err != nil {
		r.setErrorStatus(ctx, &ruleSubscription, err)
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Check for errors in result
	if len(result.Errors) > 0 {
		logger.Info("Subscription completed with warnings", "errors", result.Errors)
	}

	// Check for updates if update policy is set
	var pendingUpdates []piiv1alpha1.PendingUpdate
	if ruleSubscription.Spec.UpdatePolicy != nil {
		updates, err := r.Updater.CheckUpdates(ctx, &ruleSubscription)
		if err != nil {
			logger.Error(err, "Failed to check updates")
		} else {
			// Filter updates by policy
			autoApply, requireApproval := r.Updater.FilterUpdatesByPolicy(updates, ruleSubscription.Spec.UpdatePolicy)

			// Auto-apply updates
			if len(autoApply) > 0 && ruleSubscription.Spec.UpdatePolicy.Automatic {
				logger.Info("Auto-applying updates", "count", len(autoApply))
				if err := r.Updater.ApplyUpdates(ctx, &ruleSubscription, autoApply); err != nil {
					logger.Error(err, "Failed to apply updates")
				}
			}

			pendingUpdates = requireApproval
		}
	}

	// Update status
	now := metav1.Now()
	ruleSubscription.Status.SubscribedPatterns = result.TotalPatterns
	ruleSubscription.Status.SubscribedPatternList = result.SubscribedPatterns
	ruleSubscription.Status.LastUpdated = &now
	ruleSubscription.Status.PendingUpdates = pendingUpdates
	ruleSubscription.Status.SyncStatus = "Synced"
	ruleSubscription.Status.LastError = ""

	if result.TotalPatterns == 0 {
		r.setCondition(&ruleSubscription, "Ready", metav1.ConditionFalse, "NoPatterns", "No patterns matched the subscription criteria")
	} else {
		r.setCondition(&ruleSubscription, "Ready", metav1.ConditionTrue, "Subscribed", fmt.Sprintf("Successfully subscribed to %d patterns", result.TotalPatterns))
	}

	if err := r.Status().Update(ctx, &ruleSubscription); err != nil {
		logger.Error(err, "Failed to update PIIRuleSubscription status")
		return ctrl.Result{}, err
	}

	logger.Info("PIIRuleSubscription reconciled successfully",
		"name", ruleSubscription.Name,
		"subscribedPatterns", result.TotalPatterns,
		"pendingUpdates", len(pendingUpdates),
	)

	// Requeue to check for updates periodically
	return ctrl.Result{RequeueAfter: 15 * time.Minute}, nil
}

// setErrorStatus sets error status on the subscription
func (r *PIIRuleSubscriptionReconciler) setErrorStatus(ctx context.Context, subscription *piiv1alpha1.PIIRuleSubscription, err error) {
	subscription.Status.SyncStatus = "Error"
	subscription.Status.LastError = err.Error()
	r.setCondition(subscription, "Ready", metav1.ConditionFalse, "Error", err.Error())

	if updateErr := r.Status().Update(ctx, subscription); updateErr != nil {
		log.FromContext(ctx).Error(updateErr, "Failed to update error status")
	}
}

// setCondition sets a condition on the subscription status
func (r *PIIRuleSubscriptionReconciler) setCondition(subscription *piiv1alpha1.PIIRuleSubscription, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	for i, c := range subscription.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				subscription.Status.Conditions[i] = condition
			}
			return
		}
	}

	subscription.Status.Conditions = append(subscription.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager
func (r *PIIRuleSubscriptionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&piiv1alpha1.PIIRuleSubscription{}).
		Complete(r)
}
