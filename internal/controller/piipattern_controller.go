package controller

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/detector/patterns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PIIPatternReconciler reconciles a PIIPattern object
type PIIPatternReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Engine *detector.Engine
}

// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piipatterns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piipatterns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pii.namjun.kim,resources=piipatterns/finalizers,verbs=update

// Reconcile handles PIIPattern reconciliation
func (r *PIIPatternReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the PIIPattern
	var pattern piiv1alpha1.PIIPattern
	if err := r.Get(ctx, req.NamespacedName, &pattern); err != nil {
		// Pattern was deleted, remove from engine
		r.Engine.RemovePattern(req.String())
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling PIIPattern", "name", pattern.Name)

	// Validate and compile pattern
	validationErrors := r.validatePattern(&pattern)

	if len(validationErrors) > 0 {
		// Update status with errors
		pattern.Status.Ready = false
		pattern.Status.ValidationErrors = validationErrors
		now := metav1.Now()
		pattern.Status.LastValidated = &now

		if err := r.Status().Update(ctx, &pattern); err != nil {
			logger.Error(err, "Failed to update PIIPattern status")
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Check if pattern is enabled
	enabled := pattern.Spec.Enabled == nil || *pattern.Spec.Enabled

	if enabled {
		// Add pattern to engine
		spec := convertToPatternSpec(&pattern)
		if err := r.Engine.AddPattern(req.String(), spec); err != nil {
			validationErrors = append(validationErrors, err.Error())
			pattern.Status.Ready = false
			pattern.Status.ValidationErrors = validationErrors
		} else {
			pattern.Status.Ready = true
			pattern.Status.ValidationErrors = nil
		}
	} else {
		// Remove pattern from engine if disabled
		r.Engine.RemovePattern(req.String())
		pattern.Status.Ready = false
	}

	// Update status
	now := metav1.Now()
	pattern.Status.LastValidated = &now

	if err := r.Status().Update(ctx, &pattern); err != nil {
		logger.Error(err, "Failed to update PIIPattern status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// validatePattern validates the pattern specification
func (r *PIIPatternReconciler) validatePattern(pattern *piiv1alpha1.PIIPattern) []string {
	var errors []string

	// Validate regex patterns
	for i, p := range pattern.Spec.Patterns {
		_, err := regexp.Compile(p.Regex)
		if err != nil {
			errors = append(errors, fmt.Sprintf("pattern[%d]: invalid regex: %s", i, err.Error()))
		}
	}

	// Validate test cases if provided
	if pattern.Spec.TestCases != nil {
		for _, p := range pattern.Spec.Patterns {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				continue
			}

			// Check shouldMatch cases
			for _, testCase := range pattern.Spec.TestCases.ShouldMatch {
				if !re.MatchString(testCase) {
					errors = append(errors, fmt.Sprintf("test case '%s' should match but doesn't", testCase))
				}
			}

			// Check shouldNotMatch cases
			for _, testCase := range pattern.Spec.TestCases.ShouldNotMatch {
				if re.MatchString(testCase) {
					errors = append(errors, fmt.Sprintf("test case '%s' should not match but does", testCase))
				}
			}
		}
	}

	return errors
}

// convertToPatternSpec converts CRD spec to internal pattern spec
func convertToPatternSpec(pattern *piiv1alpha1.PIIPattern) patterns.PIIPatternSpec {
	spec := patterns.PIIPatternSpec{
		DisplayName: pattern.Spec.DisplayName,
		Description: pattern.Spec.Description,
		Validator:   pattern.Spec.Validator,
		Severity:    pattern.Spec.Severity,
		MaskingStrategy: patterns.MaskingStrategy{
			Type:        pattern.Spec.MaskingStrategy.Type,
			ShowFirst:   pattern.Spec.MaskingStrategy.ShowFirst,
			ShowLast:    pattern.Spec.MaskingStrategy.ShowLast,
			MaskChar:    pattern.Spec.MaskingStrategy.MaskChar,
			Replacement: pattern.Spec.MaskingStrategy.Replacement,
		},
	}

	for _, p := range pattern.Spec.Patterns {
		spec.Patterns = append(spec.Patterns, patterns.PatternRule{
			Regex:      p.Regex,
			Confidence: p.Confidence,
		})
	}

	return spec
}

// SetupWithManager sets up the controller with the Manager
func (r *PIIPatternReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&piiv1alpha1.PIIPattern{}).
		Complete(r)
}
