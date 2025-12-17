package subscription

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		major   int
		minor   int
		patch   int
	}{
		{
			name:    "simple version",
			input:   "1.2.3",
			wantErr: false,
			major:   1,
			minor:   2,
			patch:   3,
		},
		{
			name:    "version with v prefix",
			input:   "v1.2.3",
			wantErr: false,
			major:   1,
			minor:   2,
			patch:   3,
		},
		{
			name:    "version with prerelease",
			input:   "1.2.3-beta.1",
			wantErr: false,
			major:   1,
			minor:   2,
			patch:   3,
		},
		{
			name:    "invalid version",
			input:   "not-a-version",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if v.Major != tt.major {
					t.Errorf("Major = %d, want %d", v.Major, tt.major)
				}
				if v.Minor != tt.minor {
					t.Errorf("Minor = %d, want %d", v.Minor, tt.minor)
				}
				if v.Patch != tt.patch {
					t.Errorf("Patch = %d, want %d", v.Patch, tt.patch)
				}
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name   string
		v1     string
		v2     string
		result int // -1, 0, 1
	}{
		{
			name:   "equal",
			v1:     "1.2.3",
			v2:     "1.2.3",
			result: 0,
		},
		{
			name:   "v1 less than v2",
			v1:     "1.2.3",
			v2:     "1.2.4",
			result: -1,
		},
		{
			name:   "v1 greater than v2",
			v1:     "2.0.0",
			v2:     "1.9.9",
			result: 1,
		},
		{
			name:   "major difference",
			v1:     "1.0.0",
			v2:     "2.0.0",
			result: -1,
		},
		{
			name:   "minor difference",
			v1:     "1.1.0",
			v2:     "1.2.0",
			result: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, _ := ParseVersion(tt.v1)
			v2, _ := ParseVersion(tt.v2)

			result := v1.Compare(v2)
			if result != tt.result {
				t.Errorf("Compare() = %d, want %d", result, tt.result)
			}
		})
	}
}

func TestParseConstraint(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		matches    bool
	}{
		{
			name:       "exact match",
			constraint: "1.2.3",
			version:    "1.2.3",
			matches:    true,
		},
		{
			name:       "caret constraint major match",
			constraint: "^1.2.3",
			version:    "1.5.0",
			matches:    true,
		},
		{
			name:       "caret constraint major mismatch",
			constraint: "^1.2.3",
			version:    "2.0.0",
			matches:    false,
		},
		{
			name:       "tilde constraint minor match",
			constraint: "~1.2.3",
			version:    "1.2.9",
			matches:    true,
		},
		{
			name:       "tilde constraint minor mismatch",
			constraint: "~1.2.3",
			version:    "1.3.0",
			matches:    false,
		},
		{
			name:       "greater than",
			constraint: ">1.0.0",
			version:    "1.0.1",
			matches:    true,
		},
		{
			name:       "greater than or equal",
			constraint: ">=1.0.0",
			version:    "1.0.0",
			matches:    true,
		},
		{
			name:       "less than",
			constraint: "<2.0.0",
			version:    "1.9.9",
			matches:    true,
		},
		{
			name:       "any version",
			constraint: "*",
			version:    "99.99.99",
			matches:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseConstraint(tt.constraint)
			if err != nil {
				t.Errorf("ParseConstraint() error = %v", err)
				return
			}

			v, err := ParseVersion(tt.version)
			if err != nil {
				t.Errorf("ParseVersion() error = %v", err)
				return
			}

			matches := c.Matches(v)
			if matches != tt.matches {
				t.Errorf("Matches() = %v, want %v", matches, tt.matches)
			}
		})
	}
}

func TestCompareVersionStrings(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{
			name:     "newer version",
			v1:       "1.0.0",
			v2:       "1.1.0",
			expected: -1,
		},
		{
			name:     "same version",
			v1:       "1.0.0",
			v2:       "1.0.0",
			expected: 0,
		},
		{
			name:     "older version",
			v1:       "2.0.0",
			v2:       "1.0.0",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareVersionStrings(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("CompareVersionStrings() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		name     string
		version  *Version
		expected string
	}{
		{
			name:     "simple version",
			version:  &Version{Major: 1, Minor: 2, Patch: 3},
			expected: "1.2.3",
		},
		{
			name:     "version with prerelease",
			version:  &Version{Major: 1, Minor: 0, Patch: 0, Pre: "beta.1"},
			expected: "1.0.0-beta.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.version.String()
			if result != tt.expected {
				t.Errorf("String() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestConstraintsMatches(t *testing.T) {
	tests := []struct {
		name        string
		constraints string
		version     string
		matches     bool
	}{
		{
			name:        "multiple constraints match",
			constraints: ">=1.0.0, <2.0.0",
			version:     "1.5.0",
			matches:     true,
		},
		{
			name:        "multiple constraints fail",
			constraints: ">=1.0.0, <2.0.0",
			version:     "2.5.0",
			matches:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := ParseConstraints(tt.constraints)
			if err != nil {
				t.Errorf("ParseConstraints() error = %v", err)
				return
			}

			matches := cs.MatchesString(tt.version)
			if matches != tt.matches {
				t.Errorf("MatchesString() = %v, want %v", matches, tt.matches)
			}
		})
	}
}

func TestConstraintString(t *testing.T) {
	c, _ := ParseConstraint(">=1.2.3")
	result := c.String()
	if result != ">=1.2.3" {
		t.Errorf("String() = %s, want >=1.2.3", result)
	}
}
