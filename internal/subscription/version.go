package subscription

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version represents a semantic version
type Version struct {
	Major int
	Minor int
	Patch int
	Pre   string
}

// ParseVersion parses a semantic version string
func ParseVersion(s string) (*Version, error) {
	s = strings.TrimPrefix(s, "v")

	// Regex for semver
	re := regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-(.+))?$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return nil, fmt.Errorf("invalid version format: %s", s)
	}

	v := &Version{}

	var err error
	v.Major, err = strconv.Atoi(matches[1])
	if err != nil {
		return nil, err
	}

	if matches[2] != "" {
		v.Minor, err = strconv.Atoi(matches[2])
		if err != nil {
			return nil, err
		}
	}

	if matches[3] != "" {
		v.Patch, err = strconv.Atoi(matches[3])
		if err != nil {
			return nil, err
		}
	}

	if matches[4] != "" {
		v.Pre = matches[4]
	}

	return v, nil
}

// String returns the string representation of the version
func (v *Version) String() string {
	if v.Pre != "" {
		return fmt.Sprintf("%d.%d.%d-%s", v.Major, v.Minor, v.Patch, v.Pre)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare compares two versions
// Returns -1 if v < other, 0 if v == other, 1 if v > other
func (v *Version) Compare(other *Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}

	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}

	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}

	// Pre-release versions have lower precedence
	if v.Pre != "" && other.Pre == "" {
		return -1
	}
	if v.Pre == "" && other.Pre != "" {
		return 1
	}
	if v.Pre < other.Pre {
		return -1
	}
	if v.Pre > other.Pre {
		return 1
	}

	return 0
}

// Constraint represents a version constraint
type Constraint struct {
	Op      string
	Version *Version
}

// ParseConstraint parses a version constraint string
// Supports: >=, >, <=, <, =, ~, ^, exact version
func ParseConstraint(s string) (*Constraint, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return nil, nil // No constraint
	}

	c := &Constraint{}

	// Detect operator
	if strings.HasPrefix(s, ">=") {
		c.Op = ">="
		s = strings.TrimPrefix(s, ">=")
	} else if strings.HasPrefix(s, "<=") {
		c.Op = "<="
		s = strings.TrimPrefix(s, "<=")
	} else if strings.HasPrefix(s, ">") {
		c.Op = ">"
		s = strings.TrimPrefix(s, ">")
	} else if strings.HasPrefix(s, "<") {
		c.Op = "<"
		s = strings.TrimPrefix(s, "<")
	} else if strings.HasPrefix(s, "~") {
		c.Op = "~"
		s = strings.TrimPrefix(s, "~")
	} else if strings.HasPrefix(s, "^") {
		c.Op = "^"
		s = strings.TrimPrefix(s, "^")
	} else if strings.HasPrefix(s, "=") {
		c.Op = "="
		s = strings.TrimPrefix(s, "=")
	} else {
		c.Op = "="
	}

	v, err := ParseVersion(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	c.Version = v

	return c, nil
}

// Matches checks if a version satisfies the constraint
func (c *Constraint) Matches(v *Version) bool {
	if c == nil || c.Version == nil {
		return true // No constraint
	}

	cmp := v.Compare(c.Version)

	switch c.Op {
	case ">=":
		return cmp >= 0
	case ">":
		return cmp > 0
	case "<=":
		return cmp <= 0
	case "<":
		return cmp < 0
	case "=":
		return cmp == 0
	case "~":
		// ~1.2.3 matches >=1.2.3 and <1.3.0
		if cmp < 0 {
			return false
		}
		return v.Major == c.Version.Major && v.Minor == c.Version.Minor
	case "^":
		// ^1.2.3 matches >=1.2.3 and <2.0.0
		if cmp < 0 {
			return false
		}
		if c.Version.Major == 0 {
			// For 0.x.y, ^ is equivalent to ~
			return v.Major == c.Version.Major && v.Minor == c.Version.Minor
		}
		return v.Major == c.Version.Major
	default:
		return cmp == 0
	}
}

// String returns the string representation of the constraint
func (c *Constraint) String() string {
	if c == nil || c.Version == nil {
		return "*"
	}
	return c.Op + c.Version.String()
}

// Constraints represents multiple version constraints
type Constraints []*Constraint

// ParseConstraints parses multiple constraints separated by spaces or commas
func ParseConstraints(s string) (Constraints, error) {
	if s == "" || s == "*" {
		return nil, nil
	}

	// Split by comma or space
	parts := regexp.MustCompile(`[,\s]+`).Split(s, -1)
	var constraints Constraints

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		c, err := ParseConstraint(part)
		if err != nil {
			return nil, err
		}
		if c != nil {
			constraints = append(constraints, c)
		}
	}

	return constraints, nil
}

// Matches checks if a version satisfies all constraints
func (cs Constraints) Matches(v *Version) bool {
	if len(cs) == 0 {
		return true
	}

	for _, c := range cs {
		if !c.Matches(v) {
			return false
		}
	}

	return true
}

// MatchesString checks if a version string satisfies all constraints
func (cs Constraints) MatchesString(versionStr string) bool {
	v, err := ParseVersion(versionStr)
	if err != nil {
		return false
	}
	return cs.Matches(v)
}

// String returns the string representation of constraints
func (cs Constraints) String() string {
	if len(cs) == 0 {
		return "*"
	}

	var parts []string
	for _, c := range cs {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, " ")
}

// CompareVersionStrings compares two version strings
func CompareVersionStrings(v1, v2 string) int {
	ver1, err1 := ParseVersion(v1)
	ver2, err2 := ParseVersion(v2)

	if err1 != nil && err2 != nil {
		return strings.Compare(v1, v2)
	}
	if err1 != nil {
		return -1
	}
	if err2 != nil {
		return 1
	}

	return ver1.Compare(ver2)
}
