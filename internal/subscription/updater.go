package subscription

import (
	"context"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/source"
)

// Updater handles subscription updates
type Updater struct {
	cache   *source.Cache
	manager *Manager
}

// NewUpdater creates a new updater
func NewUpdater(cache *source.Cache, manager *Manager) *Updater {
	return &Updater{
		cache:   cache,
		manager: manager,
	}
}

// CheckUpdates checks for available updates
func (u *Updater) CheckUpdates(ctx context.Context, subscription *piiv1alpha1.PIIRuleSubscription) ([]piiv1alpha1.PendingUpdate, error) {
	var pendingUpdates []piiv1alpha1.PendingUpdate

	// Get source from cache
	sourceKey := subscription.Spec.SourceRef.Namespace + "/" + subscription.Spec.SourceRef.Name
	if subscription.Spec.SourceRef.Namespace == "" {
		sourceKey = subscription.Spec.SourceRef.Name
	}

	cachedSource, exists := u.cache.GetSource(sourceKey)
	if !exists {
		return pendingUpdates, nil
	}

	// Compare current subscribed patterns with available patterns
	for _, info := range subscription.Status.SubscribedPatternList {
		// Find the pattern in the cache
		for _, rs := range cachedSource.RuleSets {
			for _, pattern := range rs.Patterns {
				if pattern.Name == info.Name {
					// Check if version changed
					if rs.Version != info.Version && info.Version != "" {
						changeType := u.determineChangeType(info.Version, rs.Version)
						pendingUpdates = append(pendingUpdates, piiv1alpha1.PendingUpdate{
							Pattern:          info.Name,
							CurrentVersion:   info.Version,
							AvailableVersion: rs.Version,
							ChangeType:       changeType,
							Description:      "Version update available",
						})
					}
					break
				}
			}
		}
	}

	// Check for new patterns
	for _, rs := range cachedSource.RuleSets {
		for _, pattern := range rs.Patterns {
			found := false
			for _, info := range subscription.Status.SubscribedPatternList {
				if pattern.Name == info.Name {
					found = true
					break
				}
			}
			if !found {
				// Check if this pattern matches the subscription criteria
				if u.patternMatchesSubscription(pattern, subscription.Spec) {
					pendingUpdates = append(pendingUpdates, piiv1alpha1.PendingUpdate{
						Pattern:          pattern.Name,
						CurrentVersion:   "",
						AvailableVersion: rs.Version,
						ChangeType:       "newPatterns",
						Description:      "New pattern available",
					})
				}
			}
		}
	}

	return pendingUpdates, nil
}

// ApplyUpdates applies pending updates
func (u *Updater) ApplyUpdates(ctx context.Context, subscription *piiv1alpha1.PIIRuleSubscription, updates []piiv1alpha1.PendingUpdate) error {
	// Re-subscribe to get the latest patterns
	result, err := u.manager.Subscribe(ctx, subscription.Spec)
	if err != nil {
		return err
	}

	// Update status
	subscription.Status.SubscribedPatternList = result.SubscribedPatterns
	subscription.Status.SubscribedPatterns = result.TotalPatterns

	return nil
}

// ShouldAutoApply checks if an update should be automatically applied
func (u *Updater) ShouldAutoApply(update piiv1alpha1.PendingUpdate, policy *piiv1alpha1.UpdatePolicy) bool {
	if policy == nil || policy.Automatic {
		// Check if this change type requires approval
		for _, requireApproval := range policy.RequireApproval {
			if requireApproval == update.ChangeType {
				return false
			}
		}
		return true
	}
	return false
}

// ShouldNotify checks if a notification should be sent for an update
func (u *Updater) ShouldNotify(update piiv1alpha1.PendingUpdate, policy *piiv1alpha1.UpdatePolicy) bool {
	if policy == nil {
		return false
	}

	for _, notifyOn := range policy.NotifyOn {
		if notifyOn == update.ChangeType || notifyOn == "all" {
			return true
		}
	}
	return false
}

// determineChangeType determines the type of change between versions
func (u *Updater) determineChangeType(current, available string) string {
	currentVer, err1 := ParseVersion(current)
	availableVer, err2 := ParseVersion(available)

	if err1 != nil || err2 != nil {
		return "unknown"
	}

	if availableVer.Major > currentVer.Major {
		return "majorVersion"
	}
	if availableVer.Minor > currentVer.Minor {
		return "minorVersion"
	}
	if availableVer.Patch > currentVer.Patch {
		return "patchVersion"
	}

	return "unknown"
}

// patternMatchesSubscription checks if a pattern matches subscription criteria
func (u *Updater) patternMatchesSubscription(pattern source.PatternDefinition, spec piiv1alpha1.PIIRuleSubscriptionSpec) bool {
	for _, sub := range spec.Subscribe {
		// Check category
		if sub.Category != "" && sub.Category != "*" {
			if pattern.Category != sub.Category {
				continue
			}
		}

		// Check pattern names
		if len(sub.Patterns) > 0 {
			matched := false
			for _, p := range sub.Patterns {
				if p == "*" || p == pattern.Name {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		return true
	}

	return false
}

// FilterUpdatesByPolicy filters updates based on the update policy
func (u *Updater) FilterUpdatesByPolicy(updates []piiv1alpha1.PendingUpdate, policy *piiv1alpha1.UpdatePolicy) (autoApply []piiv1alpha1.PendingUpdate, requireApproval []piiv1alpha1.PendingUpdate) {
	for _, update := range updates {
		if u.ShouldAutoApply(update, policy) {
			autoApply = append(autoApply, update)
		} else {
			requireApproval = append(requireApproval, update)
		}
	}
	return
}
