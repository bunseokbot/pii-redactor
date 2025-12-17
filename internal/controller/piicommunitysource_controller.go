package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/source"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PIICommunitySourceReconciler reconciles a PIICommunitySource object
type PIICommunitySourceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Cache  *source.Cache
}

// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piicommunitysources,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piicommunitysources/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piicommunitysources/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile handles PIICommunitySource reconciliation
func (r *PIICommunitySourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PIICommunitySource
	var communitySource piiv1alpha1.PIICommunitySource
	if err := r.Get(ctx, req.NamespacedName, &communitySource); err != nil {
		// Source was deleted, remove from cache
		r.Cache.RemoveSource(req.String())
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PIICommunitySource", "name", communitySource.Name, "type", communitySource.Spec.Type)

	// Update status to syncing
	communitySource.Status.SyncStatus = "Syncing"
	if err := r.Status().Update(ctx, &communitySource); err != nil {
		logger.Error(err, "Failed to update status to syncing")
	}

	// Create fetcher based on type
	fetcher, err := r.createFetcher(ctx, &communitySource)
	if err != nil {
		logger.Error(err, "Failed to create fetcher")
		r.setErrorStatus(ctx, &communitySource, err)
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Validate fetcher configuration
	if err := fetcher.Validate(); err != nil {
		logger.Error(err, "Invalid fetcher configuration")
		r.setErrorStatus(ctx, &communitySource, err)
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Parse timeout
	timeout := 5 * time.Minute
	if communitySource.Spec.Sync.Timeout != "" {
		if parsed, err := time.ParseDuration(communitySource.Spec.Sync.Timeout); err == nil {
			timeout = parsed
		}
	}

	// Create context with timeout
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Fetch rules
	ruleSet, err := fetcher.Fetch(fetchCtx)
	if err != nil {
		logger.Error(err, "Failed to fetch rules")
		r.setErrorStatus(ctx, &communitySource, err)
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Update cache
	r.Cache.SetSource(req.String(), []*source.RuleSet{ruleSet})

	// Update status
	now := metav1.Now()
	communitySource.Status.LastSyncTime = &now
	communitySource.Status.SyncStatus = "Synced"
	communitySource.Status.LastSyncError = ""
	communitySource.Status.TotalPatterns = len(ruleSet.Patterns)

	// Build available rule sets info
	communitySource.Status.AvailableRuleSets = []piiv1alpha1.RuleSetInfo{
		{
			Name:        ruleSet.Name,
			Version:     ruleSet.Version,
			Patterns:    len(ruleSet.Patterns),
			Description: ruleSet.Description,
			Category:    ruleSet.Category,
		},
	}

	r.setCondition(&communitySource, "Ready", metav1.ConditionTrue, "Synced", "Successfully synced rules")

	if err := r.Status().Update(ctx, &communitySource); err != nil {
		logger.Error(err, "Failed to update PIICommunitySource status")
		return ctrl.Result{}, err
	}

	logger.Info("PIICommunitySource reconciled successfully",
		"name", communitySource.Name,
		"patterns", len(ruleSet.Patterns),
	)

	// Calculate requeue interval
	requeueAfter := time.Hour
	if communitySource.Spec.Sync.Interval != "" {
		if parsed, err := time.ParseDuration(communitySource.Spec.Sync.Interval); err == nil {
			requeueAfter = parsed
		}
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// createFetcher creates the appropriate fetcher based on source type
func (r *PIICommunitySourceReconciler) createFetcher(ctx context.Context, communitySource *piiv1alpha1.PIICommunitySource) (source.Fetcher, error) {
	switch communitySource.Spec.Type {
	case "git":
		return r.createGitFetcher(ctx, communitySource)
	case "oci":
		return r.createOCIFetcher(ctx, communitySource)
	case "http":
		return r.createHTTPFetcher(ctx, communitySource)
	default:
		return nil, fmt.Errorf("unsupported source type: %s", communitySource.Spec.Type)
	}
}

// createGitFetcher creates a Git fetcher
func (r *PIICommunitySourceReconciler) createGitFetcher(ctx context.Context, communitySource *piiv1alpha1.PIICommunitySource) (source.Fetcher, error) {
	if communitySource.Spec.Git == nil {
		return nil, fmt.Errorf("git configuration is required")
	}

	config := source.GitConfig{
		URL:  communitySource.Spec.Git.URL,
		Ref:  communitySource.Spec.Git.Ref,
		Path: communitySource.Spec.Git.Path,
	}

	// Get auth credentials if provided
	if communitySource.Spec.Git.Auth != nil {
		if communitySource.Spec.Git.Auth.SecretRef != nil {
			username, password, err := r.getSecretCredentials(ctx, communitySource.Namespace, communitySource.Spec.Git.Auth.SecretRef)
			if err != nil {
				return nil, fmt.Errorf("failed to get git credentials: %w", err)
			}
			config.Username = username
			config.Password = password
		}

		if communitySource.Spec.Git.Auth.SSHKeyRef != nil {
			sshKey, err := r.getSecretValue(ctx, communitySource.Namespace, communitySource.Spec.Git.Auth.SSHKeyRef)
			if err != nil {
				return nil, fmt.Errorf("failed to get SSH key: %w", err)
			}
			config.SSHKey = sshKey
		}
	}

	return source.NewGitFetcher(config), nil
}

// createOCIFetcher creates an OCI fetcher
func (r *PIICommunitySourceReconciler) createOCIFetcher(ctx context.Context, communitySource *piiv1alpha1.PIICommunitySource) (source.Fetcher, error) {
	if communitySource.Spec.OCI == nil {
		return nil, fmt.Errorf("OCI configuration is required")
	}

	config := source.OCIConfig{
		Registry:   communitySource.Spec.OCI.Registry,
		Repository: communitySource.Spec.OCI.Repository,
		Tag:        communitySource.Spec.OCI.Tag,
	}

	// Get auth credentials if provided
	if communitySource.Spec.OCI.Auth != nil && communitySource.Spec.OCI.Auth.SecretRef != nil {
		username, password, err := r.getSecretCredentials(ctx, communitySource.Namespace, communitySource.Spec.OCI.Auth.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to get OCI credentials: %w", err)
		}
		config.Username = username
		config.Password = password
	}

	return source.NewOCIFetcher(config), nil
}

// createHTTPFetcher creates an HTTP fetcher
func (r *PIICommunitySourceReconciler) createHTTPFetcher(ctx context.Context, communitySource *piiv1alpha1.PIICommunitySource) (source.Fetcher, error) {
	if communitySource.Spec.HTTP == nil {
		return nil, fmt.Errorf("HTTP configuration is required")
	}

	config := source.HTTPConfig{
		URL:     communitySource.Spec.HTTP.URL,
		Headers: communitySource.Spec.HTTP.Headers,
	}

	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	// Resolve secret headers
	for headerName, secretRef := range communitySource.Spec.HTTP.SecretHeaders {
		value, err := r.getSecretValue(ctx, communitySource.Namespace, &secretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to get header %s from secret: %w", headerName, err)
		}
		config.Headers[headerName] = value
	}

	return source.NewHTTPFetcher(config), nil
}

// getSecretValue retrieves a value from a secret
func (r *PIICommunitySourceReconciler) getSecretValue(ctx context.Context, namespace string, ref *piiv1alpha1.SecretKeyRef) (string, error) {
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

// getSecretCredentials retrieves username and password from a secret
func (r *PIICommunitySourceReconciler) getSecretCredentials(ctx context.Context, namespace string, ref *piiv1alpha1.SecretKeyRef) (string, string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      ref.Name,
	}, secret); err != nil {
		return "", "", err
	}

	username := string(secret.Data["username"])
	password := string(secret.Data["password"])

	return username, password, nil
}

// setErrorStatus sets error status on the source
func (r *PIICommunitySourceReconciler) setErrorStatus(ctx context.Context, communitySource *piiv1alpha1.PIICommunitySource, err error) {
	communitySource.Status.SyncStatus = "Failed"
	communitySource.Status.LastSyncError = err.Error()
	r.setCondition(communitySource, "Ready", metav1.ConditionFalse, "SyncFailed", err.Error())

	r.Cache.SetSourceError(communitySource.Namespace+"/"+communitySource.Name, err.Error())

	if updateErr := r.Status().Update(ctx, communitySource); updateErr != nil {
		log.FromContext(ctx).Error(updateErr, "Failed to update error status")
	}
}

// setCondition sets a condition on the source status
func (r *PIICommunitySourceReconciler) setCondition(communitySource *piiv1alpha1.PIICommunitySource, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	for i, c := range communitySource.Status.Conditions {
		if c.Type == condType {
			if c.Status != status {
				communitySource.Status.Conditions[i] = condition
			}
			return
		}
	}

	communitySource.Status.Conditions = append(communitySource.Status.Conditions, condition)
}

// SetupWithManager sets up the controller with the Manager
func (r *PIICommunitySourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&piiv1alpha1.PIICommunitySource{}).
		Complete(r)
}
