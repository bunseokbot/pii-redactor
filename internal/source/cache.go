package source

import (
	"sync"
	"time"
)

// Cache stores fetched rule sets in memory
type Cache struct {
	mu       sync.RWMutex
	sources  map[string]*CachedSource
	patterns map[string]*CachedPattern
}

// CachedSource represents a cached source
type CachedSource struct {
	// Name is the source name
	Name string

	// RuleSets is the list of cached rule sets
	RuleSets []*RuleSet

	// LastSync is when the source was last synced
	LastSync time.Time

	// TotalPatterns is the total number of patterns
	TotalPatterns int

	// Error is the last error if any
	Error string
}

// CachedPattern represents a cached pattern
type CachedPattern struct {
	// SourceName is the source this pattern came from
	SourceName string

	// RuleSetName is the rule set name
	RuleSetName string

	// Pattern is the pattern definition
	Pattern *PatternDefinition

	// CachedAt is when the pattern was cached
	CachedAt time.Time
}

// NewCache creates a new cache
func NewCache() *Cache {
	return &Cache{
		sources:  make(map[string]*CachedSource),
		patterns: make(map[string]*CachedPattern),
	}
}

// SetSource stores or updates a cached source
func (c *Cache) SetSource(name string, ruleSets []*RuleSet) {
	c.mu.Lock()
	defer c.mu.Unlock()

	totalPatterns := 0
	for _, rs := range ruleSets {
		totalPatterns += len(rs.Patterns)
	}

	c.sources[name] = &CachedSource{
		Name:          name,
		RuleSets:      ruleSets,
		LastSync:      time.Now(),
		TotalPatterns: totalPatterns,
	}

	// Update pattern cache
	now := time.Now()
	for _, rs := range ruleSets {
		for i := range rs.Patterns {
			patternKey := c.patternKey(name, rs.Name, rs.Patterns[i].Name)
			c.patterns[patternKey] = &CachedPattern{
				SourceName:  name,
				RuleSetName: rs.Name,
				Pattern:     &rs.Patterns[i],
				CachedAt:    now,
			}
		}
	}
}

// SetSourceError sets an error for a source
func (c *Cache) SetSourceError(name string, err string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if source, exists := c.sources[name]; exists {
		source.Error = err
	} else {
		c.sources[name] = &CachedSource{
			Name:     name,
			LastSync: time.Now(),
			Error:    err,
		}
	}
}

// GetSource returns a cached source
func (c *Cache) GetSource(name string) (*CachedSource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	source, exists := c.sources[name]
	return source, exists
}

// GetPattern returns a cached pattern
func (c *Cache) GetPattern(sourceName, ruleSetName, patternName string) (*CachedPattern, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.patternKey(sourceName, ruleSetName, patternName)
	pattern, exists := c.patterns[key]
	return pattern, exists
}

// GetPatternByKey returns a cached pattern by its full key
func (c *Cache) GetPatternByKey(key string) (*CachedPattern, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pattern, exists := c.patterns[key]
	return pattern, exists
}

// RemoveSource removes a source from the cache
func (c *Cache) RemoveSource(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if source, exists := c.sources[name]; exists {
		// Remove associated patterns
		for _, rs := range source.RuleSets {
			for _, p := range rs.Patterns {
				key := c.patternKey(name, rs.Name, p.Name)
				delete(c.patterns, key)
			}
		}
	}

	delete(c.sources, name)
}

// ListSources returns all cached source names
func (c *Cache) ListSources() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	names := make([]string, 0, len(c.sources))
	for name := range c.sources {
		names = append(names, name)
	}
	return names
}

// ListPatterns returns all cached pattern keys
func (c *Cache) ListPatterns() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.patterns))
	for key := range c.patterns {
		keys = append(keys, key)
	}
	return keys
}

// ListPatternsForSource returns all pattern keys for a source
func (c *Cache) ListPatternsForSource(sourceName string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var keys []string
	for key, pattern := range c.patterns {
		if pattern.SourceName == sourceName {
			keys = append(keys, key)
		}
	}
	return keys
}

// GetRuleSetsForSource returns all rule sets for a source
func (c *Cache) GetRuleSetsForSource(sourceName string) []*RuleSet {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if source, exists := c.sources[sourceName]; exists {
		return source.RuleSets
	}
	return nil
}

// GetPatternsByCategory returns patterns by category
func (c *Cache) GetPatternsByCategory(sourceName, category string) []*CachedPattern {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*CachedPattern
	for _, pattern := range c.patterns {
		if pattern.SourceName == sourceName && pattern.Pattern.Category == category {
			result = append(result, pattern)
		}
	}
	return result
}

// GetPatternsByMaturity returns patterns by maturity level
func (c *Cache) GetPatternsByMaturity(sourceName string, maturityLevels []string) []*CachedPattern {
	c.mu.RLock()
	defer c.mu.RUnlock()

	maturitySet := make(map[string]bool)
	for _, m := range maturityLevels {
		maturitySet[m] = true
	}

	var result []*CachedPattern
	for _, source := range c.sources {
		if source.Name != sourceName {
			continue
		}
		for _, rs := range source.RuleSets {
			if maturitySet[rs.Maturity] {
				for key, pattern := range c.patterns {
					if pattern.RuleSetName == rs.Name && pattern.SourceName == sourceName {
						_ = key
						result = append(result, pattern)
					}
				}
			}
		}
	}
	return result
}

// patternKey generates a unique key for a pattern
func (c *Cache) patternKey(sourceName, ruleSetName, patternName string) string {
	return sourceName + "/" + ruleSetName + "/" + patternName
}

// Clear clears all cached data
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sources = make(map[string]*CachedSource)
	c.patterns = make(map[string]*CachedPattern)
}

// Stats returns cache statistics
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CacheStats{
		SourceCount:  len(c.sources),
		PatternCount: len(c.patterns),
	}
}

// CacheStats contains cache statistics
type CacheStats struct {
	SourceCount  int
	PatternCount int
}
