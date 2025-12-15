package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/detector/patterns"
	"github.com/bunseokbot/pii-redactor/internal/redactor"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "rules":
			handleRulesCommand(os.Args[2:])
			return
		}
	}

	// Default behavior: scan mode
	handleScanCommand()
}

// RuleFile represents a PIIPattern YAML file structure
type RuleFile struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       RuleSpec `yaml:"spec"`
}

type Metadata struct {
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Maturity string `yaml:"maturity"`
}

type RuleSpec struct {
	DisplayName     string          `yaml:"displayName"`
	Description     string          `yaml:"description"`
	Category        string          `yaml:"category"`
	Patterns        []PatternDef    `yaml:"patterns"`
	MaskingStrategy MaskingStrategy `yaml:"maskingStrategy"`
	Severity        string          `yaml:"severity"`
	TestCases       TestCases       `yaml:"testCases"`
}

type PatternDef struct {
	Regex      string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
}

type MaskingStrategy struct {
	Type      string `yaml:"type"`
	ShowFirst int    `yaml:"showFirst"`
	ShowLast  int    `yaml:"showLast"`
	MaskChar  string `yaml:"maskChar"`
}

type TestCases struct {
	ShouldMatch    []string `yaml:"shouldMatch"`
	ShouldNotMatch []string `yaml:"shouldNotMatch"`
}

func handleRulesCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: pii-redactor rules <command> [args]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  test <file>    Test patterns in a rule file against its test cases")
		os.Exit(1)
	}

	switch args[0] {
	case "test":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: pii-redactor rules test <file>")
			os.Exit(1)
		}
		runRulesTest(args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown rules command: %s\n", args[0])
		os.Exit(1)
	}
}

func runRulesTest(filePath string) {
	// Read the YAML file
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filePath, err)
		os.Exit(1)
	}

	// Parse YAML
	var rule RuleFile
	if err := yaml.Unmarshal(content, &rule); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing YAML: %v\n", err)
		os.Exit(1)
	}

	// Validate required fields
	if rule.Kind != "PIIPattern" {
		fmt.Fprintf(os.Stderr, "Invalid kind: expected PIIPattern, got %s\n", rule.Kind)
		os.Exit(1)
	}

	fmt.Printf("Testing rule: %s (%s)\n", rule.Metadata.Name, rule.Spec.DisplayName)
	fmt.Printf("Patterns: %d, TestCases: %d shouldMatch, %d shouldNotMatch\n",
		len(rule.Spec.Patterns),
		len(rule.Spec.TestCases.ShouldMatch),
		len(rule.Spec.TestCases.ShouldNotMatch))
	fmt.Println()

	// Compile all patterns
	var compiledPatterns []*regexp.Regexp
	for i, p := range rule.Spec.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ Pattern %d failed to compile: %v\n", i+1, err)
			fmt.Fprintf(os.Stderr, "  Regex: %s\n", p.Regex)
			os.Exit(1)
		}
		compiledPatterns = append(compiledPatterns, re)
	}
	fmt.Printf("✓ All %d patterns compiled successfully\n", len(compiledPatterns))

	// Test shouldMatch cases
	var failures []string
	fmt.Println()
	fmt.Println("Testing shouldMatch cases:")
	for _, testCase := range rule.Spec.TestCases.ShouldMatch {
		matched := false
		for _, re := range compiledPatterns {
			if re.MatchString(testCase) {
				matched = true
				break
			}
		}
		if matched {
			fmt.Printf("  ✓ \"%s\"\n", truncate(testCase, 60))
		} else {
			fmt.Printf("  ✗ \"%s\" (no pattern matched)\n", truncate(testCase, 60))
			failures = append(failures, fmt.Sprintf("shouldMatch: %s", testCase))
		}
	}

	// Test shouldNotMatch cases
	fmt.Println()
	fmt.Println("Testing shouldNotMatch cases:")
	for _, testCase := range rule.Spec.TestCases.ShouldNotMatch {
		matched := false
		var matchedPattern string
		for i, re := range compiledPatterns {
			if re.MatchString(testCase) {
				matched = true
				matchedPattern = rule.Spec.Patterns[i].Regex
				break
			}
		}
		if !matched {
			fmt.Printf("  ✓ \"%s\"\n", truncate(testCase, 60))
		} else {
			fmt.Printf("  ✗ \"%s\" (matched by: %s)\n", truncate(testCase, 60), truncate(matchedPattern, 30))
			failures = append(failures, fmt.Sprintf("shouldNotMatch: %s", testCase))
		}
	}

	// Summary
	fmt.Println()
	totalTests := len(rule.Spec.TestCases.ShouldMatch) + len(rule.Spec.TestCases.ShouldNotMatch)

	if len(failures) == 0 {
		fmt.Printf("✓ All %d tests passed for %s\n", totalTests, rule.Metadata.Name)
	} else {
		fmt.Printf("✗ %d/%d tests failed for %s\n", len(failures), totalTests, rule.Metadata.Name)
		fmt.Println()
		fmt.Println("Failures:")
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func handleScanCommand() {
	// Command line flags
	var (
		inputFile    string
		inputText    string
		outputFormat string
		patternList  string
		listPatterns bool
		noValidate   bool
		showHelp     bool
	)

	flag.StringVar(&inputFile, "f", "", "Input file to scan")
	flag.StringVar(&inputText, "t", "", "Input text to scan")
	flag.StringVar(&outputFormat, "o", "text", "Output format: text, json")
	flag.StringVar(&patternList, "p", "", "Comma-separated list of patterns to use (empty = all)")
	flag.BoolVar(&listPatterns, "list", false, "List all available patterns")
	flag.BoolVar(&noValidate, "no-validate", false, "Skip checksum validation (for testing)")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.Parse()

	if showHelp {
		printHelp()
		return
	}

	// Create detection engine
	engine := detector.NewEngine()

	// Disable validation if requested
	if noValidate {
		engine.DisableValidation()
	}

	redact := redactor.NewRedactor(engine)

	if listPatterns {
		printPatterns(engine)
		return
	}

	// Determine input source
	var input string
	if inputText != "" {
		input = inputText
	} else if inputFile != "" {
		content, err := os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		input = string(content)
	} else {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		var lines []string
		fmt.Fprintln(os.Stderr, "Enter text to scan (Ctrl+D to finish):")
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		input = strings.Join(lines, "\n")
	}

	if input == "" {
		fmt.Fprintln(os.Stderr, "No input provided")
		os.Exit(1)
	}

	ctx := context.Background()

	// Parse pattern list
	var selectedPatterns []string
	if patternList != "" {
		selectedPatterns = strings.Split(patternList, ",")
		for i := range selectedPatterns {
			selectedPatterns[i] = strings.TrimSpace(selectedPatterns[i])
		}
	}

	// Perform detection and redaction
	var result *redactor.RedactResult
	var err error

	if len(selectedPatterns) > 0 {
		result, err = redact.RedactWithPatterns(ctx, input, selectedPatterns)
	} else {
		result, err = redact.Redact(ctx, input)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during detection: %v\n", err)
		os.Exit(1)
	}

	// Output results
	switch outputFormat {
	case "json":
		outputJSON(result)
	default:
		outputText(result)
	}
}

func printHelp() {
	fmt.Println(`PII Redactor CLI - Local testing tool

Usage:
  pii-redactor [flags]
  pii-redactor <command> [args]

Commands:
  rules test <file>    Test patterns in a rule file against its test cases

Flags:
  -t string      Input text to scan
  -f string      Input file to scan
  -o string      Output format: text, json (default "text")
  -p string      Comma-separated list of patterns to use (empty = all)
  -list          List all available patterns
  -no-validate   Skip checksum validation (for testing)
  -h             Show help

Examples:
  # Scan text
  pii-redactor -t "My email is test@example.com"

  # Scan file
  pii-redactor -f /var/log/app.log

  # Use specific patterns
  pii-redactor -t "Call me at 010-1234-5678" -p "phone-kr,email"

  # Output as JSON
  pii-redactor -t "SSN: 920101-1234567" -o json

  # Read from stdin
  echo "test@example.com" | pii-redactor

  # List all patterns
  pii-redactor -list

  # Test a rule file
  pii-redactor rules test rules/korea/rrn.yaml`)
}

func printPatterns(engine *detector.Engine) {
	fmt.Println("Available PII Patterns:")
	fmt.Println("========================")
	fmt.Println()

	for name, spec := range patterns.BuiltInPatterns {
		fmt.Printf("%-25s %s\n", name, spec.DisplayName)
		fmt.Printf("  Severity: %s\n", spec.Severity)
		fmt.Printf("  Description: %s\n", spec.Description)
		fmt.Println()
	}
}

func outputText(result *redactor.RedactResult) {
	if result.RedactedCount == 0 {
		fmt.Println("No PII detected.")
		fmt.Println()
		fmt.Println("Original text:")
		fmt.Println(result.OriginalText)
		return
	}

	fmt.Printf("Detected %d PII instance(s)\n", result.RedactedCount)
	fmt.Println("========================================")
	fmt.Println()

	// Group detections by pattern
	byPattern := make(map[string][]detector.DetectionResult)
	for _, d := range result.Detections {
		byPattern[d.PatternName] = append(byPattern[d.PatternName], d)
	}

	for pattern, detections := range byPattern {
		fmt.Printf("[%s] %s (%d found)\n", detections[0].Severity, pattern, len(detections))
		for _, d := range detections {
			fmt.Printf("  - Original: %s\n", d.MatchedText)
			fmt.Printf("    Redacted: %s\n", d.RedactedText)
			fmt.Printf("    Position: %d-%d\n", d.Position.Start, d.Position.End)
		}
		fmt.Println()
	}

	fmt.Println("========================================")
	fmt.Println("Redacted Output:")
	fmt.Println("========================================")
	fmt.Println(result.RedactedText)
}

type jsonOutput struct {
	DetectionCount int                        `json:"detection_count"`
	Detections     []detector.DetectionResult `json:"detections"`
	OriginalText   string                     `json:"original_text"`
	RedactedText   string                     `json:"redacted_text"`
}

func outputJSON(result *redactor.RedactResult) {
	output := jsonOutput{
		DetectionCount: result.RedactedCount,
		Detections:     result.Detections,
		OriginalText:   result.OriginalText,
		RedactedText:   result.RedactedText,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
