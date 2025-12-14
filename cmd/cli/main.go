package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/detector/patterns"
	"github.com/bunseokbot/pii-redactor/internal/redactor"
)

func main() {
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
  pii-redactor -list`)
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
	encoder.Encode(output)
}
