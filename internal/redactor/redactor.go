package redactor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/detector/patterns"
)

// Redactor handles masking/redaction of PII
type Redactor struct {
	engine *detector.Engine
}

// NewRedactor creates a new redactor
func NewRedactor(engine *detector.Engine) *Redactor {
	return &Redactor{
		engine: engine,
	}
}

// RedactResult represents the result of redaction
type RedactResult struct {
	OriginalText  string
	RedactedText  string
	Detections    []detector.DetectionResult
	RedactedCount int
}

// Redact detects and redacts PII from text
func (r *Redactor) Redact(ctx context.Context, text string) (*RedactResult, error) {
	// Detect PII
	detections, err := r.engine.Detect(ctx, detector.LogEntry{Message: text})
	if err != nil {
		return nil, err
	}

	if len(detections) == 0 {
		return &RedactResult{
			OriginalText:  text,
			RedactedText:  text,
			Detections:    detections,
			RedactedCount: 0,
		}, nil
	}

	// Sort detections by position (descending) to process from end to start
	sort.Slice(detections, func(i, j int) bool {
		return detections[i].Position.Start > detections[j].Position.Start
	})

	redactedText := text
	for i := range detections {
		d := &detections[i]
		strategy, ok := r.engine.GetMaskingStrategy(d.PatternName)
		if !ok {
			continue
		}

		masked := ApplyMasking(d.MatchedText, strategy)
		d.RedactedText = masked

		// Replace in text
		redactedText = redactedText[:d.Position.Start] + masked + redactedText[d.Position.End:]
	}

	return &RedactResult{
		OriginalText:  text,
		RedactedText:  redactedText,
		Detections:    detections,
		RedactedCount: len(detections),
	}, nil
}

// RedactWithPatterns redacts using only specified patterns
func (r *Redactor) RedactWithPatterns(ctx context.Context, text string, patternNames []string) (*RedactResult, error) {
	// Detect PII with specified patterns
	detections, err := r.engine.DetectWithPatterns(ctx, text, patternNames)
	if err != nil {
		return nil, err
	}

	if len(detections) == 0 {
		return &RedactResult{
			OriginalText:  text,
			RedactedText:  text,
			Detections:    detections,
			RedactedCount: 0,
		}, nil
	}

	// Sort detections by position (descending) to process from end to start
	sort.Slice(detections, func(i, j int) bool {
		return detections[i].Position.Start > detections[j].Position.Start
	})

	redactedText := text
	for i := range detections {
		d := &detections[i]
		strategy, ok := r.engine.GetMaskingStrategy(d.PatternName)
		if !ok {
			continue
		}

		masked := ApplyMasking(d.MatchedText, strategy)
		d.RedactedText = masked

		// Replace in text
		redactedText = redactedText[:d.Position.Start] + masked + redactedText[d.Position.End:]
	}

	return &RedactResult{
		OriginalText:  text,
		RedactedText:  redactedText,
		Detections:    detections,
		RedactedCount: len(detections),
	}, nil
}

// ApplyMasking applies a masking strategy to text
func ApplyMasking(text string, strategy patterns.MaskingStrategy) string {
	switch strategy.Type {
	case "full":
		if strategy.Replacement != "" {
			return strategy.Replacement
		}
		return strings.Repeat(getMaskChar(strategy), len(text))

	case "partial":
		return applyPartialMasking(text, strategy)

	case "hash":
		return hashText(text)

	case "tokenize":
		return tokenize(text)

	default:
		return applyPartialMasking(text, strategy)
	}
}

// applyPartialMasking applies partial masking strategy
func applyPartialMasking(text string, strategy patterns.MaskingStrategy) string {
	runes := []rune(text)
	length := len(runes)

	showFirst := strategy.ShowFirst
	showLast := strategy.ShowLast
	maskChar := getMaskChar(strategy)

	// Adjust if total visible characters exceed length
	if showFirst+showLast >= length {
		return strings.Repeat(maskChar, length)
	}

	var result strings.Builder

	// Show first N characters
	if showFirst > 0 {
		result.WriteString(string(runes[:showFirst]))
	}

	// Mask middle characters
	maskLength := length - showFirst - showLast
	result.WriteString(strings.Repeat(maskChar, maskLength))

	// Show last N characters
	if showLast > 0 {
		result.WriteString(string(runes[length-showLast:]))
	}

	return result.String()
}

// getMaskChar returns the masking character
func getMaskChar(strategy patterns.MaskingStrategy) string {
	if strategy.MaskChar != "" {
		return strategy.MaskChar
	}
	return "*"
}

// hashText returns a SHA-256 hash of the text (truncated)
func hashText(text string) string {
	hash := sha256.Sum256([]byte(text))
	return "[HASH:" + hex.EncodeToString(hash[:8]) + "]"
}

// tokenize creates a token placeholder
func tokenize(text string) string {
	hash := sha256.Sum256([]byte(text))
	return "[TOKEN:" + hex.EncodeToString(hash[:4]) + "]"
}

// CustomMasking applies custom masking with explicit parameters
func CustomMasking(text string, maskType string, showFirst, showLast int, maskChar, replacement string) string {
	strategy := patterns.MaskingStrategy{
		Type:        maskType,
		ShowFirst:   showFirst,
		ShowLast:    showLast,
		MaskChar:    maskChar,
		Replacement: replacement,
	}
	return ApplyMasking(text, strategy)
}
