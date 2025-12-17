package source

import (
	"testing"
)

func TestCache_SetSourceAndGet(t *testing.T) {
	cache := NewCache()

	ruleSets := []*RuleSet{
		{
			Name:    "test-ruleset",
			Version: "1.0.0",
			Patterns: []PatternDefinition{
				{Name: "rule1", Severity: "high"},
			},
		},
	}

	cache.SetSource("test-source", ruleSets)

	got, exists := cache.GetSource("test-source")
	if !exists {
		t.Error("Expected source to exist")
	}
	if got.Name != "test-source" {
		t.Errorf("Name = %s, want test-source", got.Name)
	}
	if len(got.RuleSets) != 1 {
		t.Errorf("Expected 1 rule set, got %d", len(got.RuleSets))
	}
	if got.TotalPatterns != 1 {
		t.Errorf("TotalPatterns = %d, want 1", got.TotalPatterns)
	}
}

func TestCache_GetNonexistentSource(t *testing.T) {
	cache := NewCache()

	_, exists := cache.GetSource("nonexistent")
	if exists {
		t.Error("Expected source to not exist")
	}
}

func TestCache_RemoveSource(t *testing.T) {
	cache := NewCache()

	ruleSets := []*RuleSet{
		{
			Name:    "test-ruleset",
			Version: "1.0.0",
		},
	}

	cache.SetSource("test-source", ruleSets)
	cache.RemoveSource("test-source")

	_, exists := cache.GetSource("test-source")
	if exists {
		t.Error("Source should not exist after removal")
	}
}

func TestCache_ListSources(t *testing.T) {
	cache := NewCache()

	cache.SetSource("source1", []*RuleSet{{Name: "rs1"}})
	cache.SetSource("source2", []*RuleSet{{Name: "rs2"}})

	sources := cache.ListSources()

	if len(sources) != 2 {
		t.Errorf("Expected 2 sources, got %d", len(sources))
	}
}

func TestCache_Clear(t *testing.T) {
	cache := NewCache()

	cache.SetSource("source1", []*RuleSet{{Name: "rs1"}})
	cache.SetSource("source2", []*RuleSet{{Name: "rs2"}})

	cache.Clear()

	sources := cache.ListSources()
	if len(sources) != 0 {
		t.Errorf("Expected 0 sources after clear, got %d", len(sources))
	}
}

func TestCache_GetPattern(t *testing.T) {
	cache := NewCache()

	ruleSets := []*RuleSet{
		{
			Name: "test-ruleset",
			Patterns: []PatternDefinition{
				{Name: "pattern1", Severity: "high"},
				{Name: "pattern2", Severity: "medium"},
			},
		},
	}

	cache.SetSource("test-source", ruleSets)

	pattern, exists := cache.GetPattern("test-source", "test-ruleset", "pattern1")
	if !exists {
		t.Error("Expected pattern to exist")
	}
	if pattern.Pattern.Severity != "high" {
		t.Errorf("Severity = %s, want high", pattern.Pattern.Severity)
	}
}

func TestCache_GetPatternNonexistent(t *testing.T) {
	cache := NewCache()

	_, exists := cache.GetPattern("nonexistent", "rs", "pattern")
	if exists {
		t.Error("Expected pattern to not exist")
	}
}

func TestCache_ListPatterns(t *testing.T) {
	cache := NewCache()

	ruleSets := []*RuleSet{
		{
			Name: "test-ruleset",
			Patterns: []PatternDefinition{
				{Name: "pattern1"},
				{Name: "pattern2"},
			},
		},
	}

	cache.SetSource("test-source", ruleSets)

	patterns := cache.ListPatterns()
	if len(patterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(patterns))
	}
}

func TestCache_Stats(t *testing.T) {
	cache := NewCache()

	ruleSets := []*RuleSet{
		{
			Name: "test-ruleset",
			Patterns: []PatternDefinition{
				{Name: "pattern1"},
				{Name: "pattern2"},
			},
		},
	}

	cache.SetSource("test-source", ruleSets)

	stats := cache.Stats()
	if stats.SourceCount != 1 {
		t.Errorf("SourceCount = %d, want 1", stats.SourceCount)
	}
	if stats.PatternCount != 2 {
		t.Errorf("PatternCount = %d, want 2", stats.PatternCount)
	}
}

func TestCache_SetSourceError(t *testing.T) {
	cache := NewCache()

	cache.SetSourceError("test-source", "connection failed")

	source, exists := cache.GetSource("test-source")
	if !exists {
		t.Error("Expected source to exist")
	}
	if source.Error != "connection failed" {
		t.Errorf("Error = %s, want 'connection failed'", source.Error)
	}
}

func TestCache_GetRuleSetsForSource(t *testing.T) {
	cache := NewCache()

	ruleSets := []*RuleSet{
		{Name: "rs1", Version: "1.0.0"},
		{Name: "rs2", Version: "2.0.0"},
	}

	cache.SetSource("test-source", ruleSets)

	got := cache.GetRuleSetsForSource("test-source")
	if len(got) != 2 {
		t.Errorf("Expected 2 rule sets, got %d", len(got))
	}

	// Nonexistent source
	got = cache.GetRuleSetsForSource("nonexistent")
	if got != nil {
		t.Error("Expected nil for nonexistent source")
	}
}
