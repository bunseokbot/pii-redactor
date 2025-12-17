package source

import (
	"context"
	"time"

	"github.com/bunseokbot/pii-redactor/internal/detector/patterns"
)

// Fetcher defines the interface for fetching rules from different sources
type Fetcher interface {
	// Fetch fetches rules from the source
	Fetch(ctx context.Context) (*RuleSet, error)

	// Type returns the type of this fetcher
	Type() string

	// Validate checks if the fetcher configuration is valid
	Validate() error
}

// RuleSet represents a collection of rules fetched from a source
type RuleSet struct {
	// Name is the name of the rule set
	Name string `json:"name" yaml:"name"`

	// Version is the version of the rule set
	Version string `json:"version" yaml:"version"`

	// Description is a brief description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Category is the rule set category
	Category string `json:"category,omitempty" yaml:"category,omitempty"`

	// Maturity is the maturity level (stable, incubating, sandbox, deprecated)
	Maturity string `json:"maturity,omitempty" yaml:"maturity,omitempty"`

	// Patterns is the list of pattern definitions
	Patterns []PatternDefinition `json:"patterns" yaml:"patterns"`

	// Metadata contains additional metadata
	Metadata RuleSetMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// PatternDefinition represents a pattern definition in a rule set
type PatternDefinition struct {
	// Name is the pattern identifier
	Name string `json:"name" yaml:"name"`

	// DisplayName is the human-readable name
	DisplayName string `json:"displayName,omitempty" yaml:"displayName,omitempty"`

	// Description is the pattern description
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Category is the pattern category
	Category string `json:"category,omitempty" yaml:"category,omitempty"`

	// Patterns contains the regex rules
	Patterns []PatternRule `json:"patterns" yaml:"patterns"`

	// Validator is the validator name
	Validator string `json:"validator,omitempty" yaml:"validator,omitempty"`

	// MaskingStrategy defines how to mask detected PII
	MaskingStrategy patterns.MaskingStrategy `json:"maskingStrategy,omitempty" yaml:"maskingStrategy,omitempty"`

	// Severity is the pattern severity
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`

	// Enabled indicates if the pattern is enabled by default
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// TestCases for validation
	TestCases *TestCases `json:"testCases,omitempty" yaml:"testCases,omitempty"`
}

// PatternRule represents a regex pattern with confidence level
type PatternRule struct {
	// Regex is the regular expression
	Regex string `json:"regex" yaml:"regex"`

	// Confidence is the confidence level (high, medium, low)
	Confidence string `json:"confidence,omitempty" yaml:"confidence,omitempty"`
}

// TestCases contains test cases for pattern validation
type TestCases struct {
	// ShouldMatch is a list of strings that should match
	ShouldMatch []string `json:"shouldMatch,omitempty" yaml:"shouldMatch,omitempty"`

	// ShouldNotMatch is a list of strings that should not match
	ShouldNotMatch []string `json:"shouldNotMatch,omitempty" yaml:"shouldNotMatch,omitempty"`
}

// RuleSetMetadata contains metadata about the rule set
type RuleSetMetadata struct {
	// Author is the rule set author
	Author string `json:"author,omitempty" yaml:"author,omitempty"`

	// License is the license type
	License string `json:"license,omitempty" yaml:"license,omitempty"`

	// Homepage is the project homepage
	Homepage string `json:"homepage,omitempty" yaml:"homepage,omitempty"`

	// LastUpdated is the last update timestamp
	LastUpdated time.Time `json:"lastUpdated,omitempty" yaml:"lastUpdated,omitempty"`

	// Signature is the signature for verification
	Signature string `json:"signature,omitempty" yaml:"signature,omitempty"`

	// Maintainers is the list of maintainers
	Maintainers []string `json:"maintainers,omitempty" yaml:"maintainers,omitempty"`
}

// ToPatternSpec converts a PatternDefinition to patterns.PIIPatternSpec
func (p *PatternDefinition) ToPatternSpec() patterns.PIIPatternSpec {
	spec := patterns.PIIPatternSpec{
		DisplayName:     p.DisplayName,
		Description:     p.Description,
		Category:        p.Category,
		Validator:       p.Validator,
		MaskingStrategy: p.MaskingStrategy,
		Severity:        p.Severity,
		Enabled:         p.Enabled,
	}

	for _, rule := range p.Patterns {
		spec.Patterns = append(spec.Patterns, patterns.PatternRule{
			Regex:      rule.Regex,
			Confidence: rule.Confidence,
		})
	}

	return spec
}

// FetchResult represents the result of a fetch operation
type FetchResult struct {
	// RuleSets is the list of fetched rule sets
	RuleSets []*RuleSet

	// TotalPatterns is the total number of patterns
	TotalPatterns int

	// Errors contains any errors encountered
	Errors []string

	// Verified indicates if the content was verified
	Verified bool
}

// NewFetchResult creates a new FetchResult
func NewFetchResult() *FetchResult {
	return &FetchResult{
		RuleSets: make([]*RuleSet, 0),
		Errors:   make([]string, 0),
	}
}

// AddRuleSet adds a rule set to the result
func (r *FetchResult) AddRuleSet(rs *RuleSet) {
	r.RuleSets = append(r.RuleSets, rs)
	r.TotalPatterns += len(rs.Patterns)
}

// AddError adds an error to the result
func (r *FetchResult) AddError(err string) {
	r.Errors = append(r.Errors, err)
}

// HasErrors returns true if there are any errors
func (r *FetchResult) HasErrors() bool {
	return len(r.Errors) > 0
}
