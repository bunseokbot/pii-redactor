package validator

import (
	"strconv"
	"strings"
)

// Validator is an interface for validating detected PII
type Validator interface {
	Validate(input string) bool
}

// Registry holds all registered validators
var Registry = map[string]Validator{
	"luhn":                     &LuhnValidator{},
	"rrn-checksum":             &KoreanRRNValidator{},
	"business-number-checksum": &KoreanBusinessNumberValidator{},
	"iban-checksum":            &IBANValidator{},
}

// GetValidator returns a validator by name
func GetValidator(name string) (Validator, bool) {
	v, ok := Registry[name]
	return v, ok
}

// LuhnValidator validates credit card numbers using Luhn algorithm
type LuhnValidator struct{}

// Validate implements the Luhn algorithm for credit card validation
func (v *LuhnValidator) Validate(input string) bool {
	// Remove non-digit characters
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, input)

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false

	for i := len(digits) - 1; i >= 0; i-- {
		n, _ := strconv.Atoi(string(digits[i]))

		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}

		sum += n
		alt = !alt
	}

	return sum%10 == 0
}

// KoreanRRNValidator validates Korean Resident Registration Numbers
type KoreanRRNValidator struct{}

// Validate validates Korean RRN checksum
func (v *KoreanRRNValidator) Validate(input string) bool {
	// Remove hyphen
	digits := strings.ReplaceAll(input, "-", "")

	if len(digits) != 13 {
		return false
	}

	// Validate all characters are digits
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Checksum weights
	weights := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}

	sum := 0
	for i := 0; i < 12; i++ {
		n, _ := strconv.Atoi(string(digits[i]))
		sum += n * weights[i]
	}

	checkDigit, _ := strconv.Atoi(string(digits[12]))
	expected := (11 - (sum % 11)) % 10

	return checkDigit == expected
}

// KoreanBusinessNumberValidator validates Korean Business Registration Numbers
type KoreanBusinessNumberValidator struct{}

// Validate validates Korean Business Registration Number checksum
func (v *KoreanBusinessNumberValidator) Validate(input string) bool {
	// Remove hyphens
	digits := strings.ReplaceAll(input, "-", "")

	if len(digits) != 10 {
		return false
	}

	// Validate all characters are digits
	for _, c := range digits {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Checksum weights
	weights := []int{1, 3, 7, 1, 3, 7, 1, 3, 5}

	sum := 0
	for i := 0; i < 9; i++ {
		n, _ := strconv.Atoi(string(digits[i]))
		sum += n * weights[i]
	}

	// Special calculation for the 9th digit
	n8, _ := strconv.Atoi(string(digits[8]))
	sum += (n8 * 5) / 10

	checkDigit, _ := strconv.Atoi(string(digits[9]))
	expected := (10 - (sum % 10)) % 10

	return checkDigit == expected
}

// IBANValidator validates International Bank Account Numbers
type IBANValidator struct{}

// Validate validates IBAN checksum using MOD 97-10
func (v *IBANValidator) Validate(input string) bool {
	// Remove spaces
	iban := strings.ReplaceAll(strings.ToUpper(input), " ", "")

	if len(iban) < 15 || len(iban) > 34 {
		return false
	}

	// Move first 4 characters to the end
	rearranged := iban[4:] + iban[:4]

	// Convert letters to numbers (A=10, B=11, ..., Z=35)
	var numericIBAN strings.Builder
	for _, c := range rearranged {
		if c >= 'A' && c <= 'Z' {
			numericIBAN.WriteString(strconv.Itoa(int(c - 'A' + 10)))
		} else if c >= '0' && c <= '9' {
			numericIBAN.WriteRune(c)
		} else {
			return false
		}
	}

	// Perform MOD 97 calculation
	remainder := mod97(numericIBAN.String())

	return remainder == 1
}

// mod97 calculates the remainder when dividing a large number string by 97
func mod97(numStr string) int {
	remainder := 0
	for _, c := range numStr {
		digit := int(c - '0')
		remainder = (remainder*10 + digit) % 97
	}
	return remainder
}
