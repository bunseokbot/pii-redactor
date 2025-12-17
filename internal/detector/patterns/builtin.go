package patterns

// PIIPatternSpec represents a built-in PII pattern specification
type PIIPatternSpec struct {
	DisplayName     string
	Description     string
	Category        string // Category for grouping (e.g., "korea", "usa", "global", "secrets")
	Patterns        []PatternRule
	Validator       string
	MaskingStrategy MaskingStrategy
	Severity        string
	Enabled         bool // Whether this pattern is enabled by default
}

// PatternRule defines a regex pattern with confidence level
type PatternRule struct {
	Regex      string
	Confidence string // high, medium, low
}

// MaskingStrategy defines how to mask detected PII
type MaskingStrategy struct {
	Type        string // full, partial, hash, tokenize
	ShowFirst   int
	ShowLast    int
	MaskChar    string
	Replacement string
}

// BuiltInPatterns contains all built-in PII patterns
var BuiltInPatterns = map[string]PIIPatternSpec{
	// ============================================
	// GLOBAL PATTERNS
	// ============================================

	// Email
	"email": {
		DisplayName:     "Email Address",
		Description:     "Detects email addresses",
		Category:        "global",
		Patterns:        []PatternRule{{Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 2, ShowLast: 0, MaskChar: "*"},
		Severity:        "medium",
		Enabled:         true,
	},

	// Credit Card Number
	"credit-card": {
		DisplayName: "Credit Card Number",
		Description: "Detects credit card numbers (Visa, MasterCard, Amex, Discover)",
		Category:    "global",
		Patterns: []PatternRule{
			{Regex: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`, Confidence: "high"},
			{Regex: `\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}`, Confidence: "medium"},
		},
		Validator:       "luhn",
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 4, ShowLast: 4, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// IP Address
	"ip-address": {
		DisplayName:     "IP Address",
		Description:     "Detects IPv4 addresses",
		Category:        "global",
		Patterns:        []PatternRule{{Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[IP_REDACTED]"},
		Severity:        "low",
		Enabled:         false, // Disabled by default as it may cause many false positives
	},

	// IPv6 Address
	"ipv6-address": {
		DisplayName: "IPv6 Address",
		Description: "Detects IPv6 addresses",
		Category:    "global",
		Patterns: []PatternRule{
			{Regex: `(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`, Confidence: "high"},
			{Regex: `(?:[0-9a-fA-F]{1,4}:){1,7}:`, Confidence: "medium"},
		},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[IPv6_REDACTED]"},
		Severity:        "low",
		Enabled:         false,
	},

	// IBAN (International Bank Account Number)
	"iban": {
		DisplayName:     "IBAN",
		Description:     "International Bank Account Number",
		Category:        "global",
		Patterns:        []PatternRule{{Regex: `[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}`, Confidence: "high"}},
		Validator:       "iban-checksum",
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 4, ShowLast: 4, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// MAC Address
	"mac-address": {
		DisplayName:     "MAC Address",
		Description:     "Detects MAC addresses",
		Category:        "global",
		Patterns:        []PatternRule{{Regex: `(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 8, ShowLast: 0, MaskChar: "*"},
		Severity:        "low",
		Enabled:         false,
	},

	// ============================================
	// USA PATTERNS
	// ============================================

	// US Social Security Number
	"ssn-us": {
		DisplayName: "US Social Security Number",
		Description: "US Social Security Number (XXX-XX-XXXX format)",
		Category:    "usa",
		Patterns: []PatternRule{
			{Regex: `\b\d{3}-\d{2}-\d{4}\b`, Confidence: "high"},
			{Regex: `\b\d{9}\b`, Confidence: "low"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 0, ShowLast: 4, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// US Phone Number
	"phone-us": {
		DisplayName:     "US Phone Number",
		Description:     "US phone numbers in various formats",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 3, ShowLast: 4, MaskChar: "*"},
		Severity:        "high",
		Enabled:         true,
	},

	// US Driver License (generic pattern - varies by state)
	"driver-license-us": {
		DisplayName:     "US Driver License",
		Description:     "US Driver License numbers (generic pattern)",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b[A-Z]{1,2}\d{5,8}\b`, Confidence: "medium"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 2, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         false, // Disabled by default due to potential false positives
	},

	// US Passport Number
	"passport-us": {
		DisplayName:     "US Passport Number",
		Description:     "US Passport numbers",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b[0-9]{9}\b`, Confidence: "low"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 2, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         false,
	},

	// US Bank Routing Number
	"routing-number-us": {
		DisplayName:     "US Bank Routing Number",
		Description:     "US Bank ABA Routing Transit Number",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b[0-9]{9}\b`, Confidence: "low"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 0, ShowLast: 4, MaskChar: "*"},
		Severity:        "high",
		Enabled:         false,
	},

	// US Individual Taxpayer Identification Number (ITIN)
	"itin-us": {
		DisplayName:     "US ITIN",
		Description:     "US Individual Taxpayer Identification Number",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b9\d{2}-[7-9]\d-\d{4}\b`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 0, ShowLast: 4, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// US Medicare Beneficiary Identifier (MBI)
	"medicare-us": {
		DisplayName:     "US Medicare ID",
		Description:     "US Medicare Beneficiary Identifier (MBI)",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y]{2}\d{2}\b`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 0, ShowLast: 4, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// US Employer Identification Number (EIN)
	"ein-us": {
		DisplayName:     "US EIN",
		Description:     "US Employer Identification Number",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b\d{2}-\d{7}\b`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 2, ShowLast: 0, MaskChar: "*"},
		Severity:        "high",
		Enabled:         true,
	},

	// US DEA Number
	"dea-us": {
		DisplayName:     "US DEA Number",
		Description:     "US Drug Enforcement Administration registration number",
		Category:        "usa",
		Patterns:        []PatternRule{{Regex: `\b[A-Z][A-Z9][0-9]{7}\b`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 2, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// ============================================
	// KOREA PATTERNS
	// ============================================

	// Korean Resident Registration Number
	"korean-rrn": {
		DisplayName: "Korean Resident Registration Number",
		Description: "Korean RRN (Resident Registration Number)",
		Category:    "korea",
		Patterns: []PatternRule{
			{Regex: `\d{6}-[1-4]\d{6}`, Confidence: "high"},
			{Regex: `\d{6}[1-4]\d{6}`, Confidence: "medium"},
		},
		Validator:       "rrn-checksum",
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 6, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Korean Phone Number
	"phone-kr": {
		DisplayName: "Korean Phone Number",
		Description: "Korean phone numbers (mobile and landline)",
		Category:    "korea",
		Patterns: []PatternRule{
			{Regex: `01[016789]-?\d{3,4}-?\d{4}`, Confidence: "high"},
			{Regex: `02-?\d{3,4}-?\d{4}`, Confidence: "high"},
			{Regex: `0[3-6][1-5]-?\d{3,4}-?\d{4}`, Confidence: "high"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 3, ShowLast: 4, MaskChar: "*"},
		Severity:        "high",
		Enabled:         true,
	},

	// Korean Passport Number
	"passport-kr": {
		DisplayName:     "Korean Passport Number",
		Description:     "Korean passport numbers",
		Category:        "korea",
		Patterns:        []PatternRule{{Regex: `[A-Z]{1,2}\d{7,8}`, Confidence: "medium"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 2, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Korean Driver License
	"driver-license-kr": {
		DisplayName:     "Korean Driver License",
		Description:     "Korean driver license numbers",
		Category:        "korea",
		Patterns:        []PatternRule{{Regex: `\d{2}-\d{2}-\d{6}-\d{2}`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 5, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Korean Business Registration Number
	"business-number-kr": {
		DisplayName:     "Korean Business Registration Number",
		Description:     "Korean business registration numbers",
		Category:        "korea",
		Patterns:        []PatternRule{{Regex: `\d{3}-\d{2}-\d{5}`, Confidence: "high"}},
		Validator:       "business-number-checksum",
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 3, ShowLast: 0, MaskChar: "*"},
		Severity:        "high",
		Enabled:         true,
	},

	// Korean Foreign Registration Number
	"foreign-registration-kr": {
		DisplayName: "Korean Foreign Registration Number",
		Description: "Korean foreign registration numbers",
		Category:    "korea",
		Patterns: []PatternRule{
			{Regex: `\d{6}-[5-8]\d{6}`, Confidence: "high"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 6, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// ============================================
	// SECRETS & CREDENTIALS PATTERNS
	// ============================================

	// AWS Access Key
	"aws-access-key": {
		DisplayName:     "AWS Access Key ID",
		Description:     "AWS Access Key ID",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `AKIA[0-9A-Z]{16}`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 4, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// AWS Secret Key
	"aws-secret-key": {
		DisplayName:     "AWS Secret Access Key",
		Description:     "AWS Secret Access Key",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[AWS_SECRET_REDACTED]"},
		Severity:        "critical",
		Enabled:         true,
	},

	// GitHub Token
	"github-token": {
		DisplayName: "GitHub Token",
		Description: "GitHub Personal Access Token or OAuth Token",
		Category:    "secrets",
		Patterns: []PatternRule{
			{Regex: `ghp_[0-9a-zA-Z]{36}`, Confidence: "high"},
			{Regex: `gho_[0-9a-zA-Z]{36}`, Confidence: "high"},
			{Regex: `ghu_[0-9a-zA-Z]{36}`, Confidence: "high"},
			{Regex: `ghs_[0-9a-zA-Z]{36}`, Confidence: "high"},
			{Regex: `ghr_[0-9a-zA-Z]{36}`, Confidence: "high"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 4, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// GitLab Token
	"gitlab-token": {
		DisplayName: "GitLab Token",
		Description: "GitLab Personal Access Token",
		Category:    "secrets",
		Patterns: []PatternRule{
			{Regex: `glpat-[0-9a-zA-Z\-_]{20}`, Confidence: "high"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 6, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Slack Token
	"slack-token": {
		DisplayName: "Slack Token",
		Description: "Slack Bot or User Token",
		Category:    "secrets",
		Patterns: []PatternRule{
			{Regex: `xox[baprs]-[0-9a-zA-Z]{10,48}`, Confidence: "high"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 4, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Google API Key
	"google-api-key": {
		DisplayName:     "Google API Key",
		Description:     "Google API Key",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `AIza[0-9A-Za-z\-_]{35}`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 4, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Generic API Key
	"api-key": {
		DisplayName:     "Generic API Key",
		Description:     "Detects common API key patterns",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `(?i)(?:api[_-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z]{16,64}['\"]?`, Confidence: "medium"}},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[API_KEY_REDACTED]"},
		Severity:        "high",
		Enabled:         true,
	},

	// JWT Token
	"jwt": {
		DisplayName:     "JWT Token",
		Description:     "JSON Web Token",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 10, ShowLast: 0, MaskChar: "*"},
		Severity:        "high",
		Enabled:         true,
	},

	// Private Key
	"private-key": {
		DisplayName:     "Private Key",
		Description:     "Detects private keys (RSA, DSA, EC, etc.)",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[PRIVATE_KEY_REDACTED]"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Password in URL
	"password-in-url": {
		DisplayName:     "Password in URL",
		Description:     "Detects passwords embedded in URLs",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `(?i)(?:https?://)[^:]+:([^@]+)@`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[PASSWORD_REDACTED]"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Generic Password
	"password": {
		DisplayName:     "Password",
		Description:     "Detects password assignments in code/config",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^\s'"]{8,}['\"]?`, Confidence: "medium"}},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[PASSWORD_REDACTED]"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Database Connection String
	"database-connection": {
		DisplayName:     "Database Connection String",
		Description:     "Detects database connection strings with credentials",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `(?i)(?:mongodb|postgres|mysql|redis|amqp):\/\/[^:]+:[^@]+@`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "full", Replacement: "[DB_CONNECTION_REDACTED]"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Stripe API Key
	"stripe-key": {
		DisplayName: "Stripe API Key",
		Description: "Stripe API keys (live and test)",
		Category:    "secrets",
		Patterns: []PatternRule{
			{Regex: `sk_live_[0-9a-zA-Z]{24}`, Confidence: "high"},
			{Regex: `sk_test_[0-9a-zA-Z]{24}`, Confidence: "high"},
			{Regex: `pk_live_[0-9a-zA-Z]{24}`, Confidence: "high"},
			{Regex: `pk_test_[0-9a-zA-Z]{24}`, Confidence: "high"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 7, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// SendGrid API Key
	"sendgrid-key": {
		DisplayName:     "SendGrid API Key",
		Description:     "SendGrid API keys",
		Category:        "secrets",
		Patterns:        []PatternRule{{Regex: `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`, Confidence: "high"}},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 3, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},

	// Twilio API Key
	"twilio-key": {
		DisplayName: "Twilio API Key/SID",
		Description: "Twilio Account SID and Auth Token",
		Category:    "secrets",
		Patterns: []PatternRule{
			{Regex: `AC[0-9a-fA-F]{32}`, Confidence: "high"},
			{Regex: `SK[0-9a-fA-F]{32}`, Confidence: "high"},
		},
		MaskingStrategy: MaskingStrategy{Type: "partial", ShowFirst: 2, ShowLast: 0, MaskChar: "*"},
		Severity:        "critical",
		Enabled:         true,
	},
}

// GetBuiltInPattern returns a built-in pattern by name
func GetBuiltInPattern(name string) *PIIPatternSpec {
	pattern, ok := BuiltInPatterns[name]
	if !ok {
		return nil
	}
	return &pattern
}

// IsBuiltInPattern checks if a pattern name is a built-in pattern
func IsBuiltInPattern(name string) bool {
	_, ok := BuiltInPatterns[name]
	return ok
}

// ListBuiltInPatterns returns all built-in pattern names
func ListBuiltInPatterns() []string {
	names := make([]string, 0, len(BuiltInPatterns))
	for name := range BuiltInPatterns {
		names = append(names, name)
	}
	return names
}

// ListEnabledBuiltInPatterns returns only enabled built-in pattern names
func ListEnabledBuiltInPatterns() []string {
	names := make([]string, 0)
	for name, spec := range BuiltInPatterns {
		if spec.Enabled {
			names = append(names, name)
		}
	}
	return names
}

// ListPatternsByCategory returns patterns by category
func ListPatternsByCategory(category string) []string {
	names := make([]string, 0)
	for name, spec := range BuiltInPatterns {
		if spec.Category == category {
			names = append(names, name)
		}
	}
	return names
}

// GetCategories returns all available categories
func GetCategories() []string {
	categoryMap := make(map[string]bool)
	for _, spec := range BuiltInPatterns {
		categoryMap[spec.Category] = true
	}

	categories := make([]string, 0, len(categoryMap))
	for cat := range categoryMap {
		categories = append(categories, cat)
	}
	return categories
}
