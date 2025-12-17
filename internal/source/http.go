package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HTTPFetcher fetches rules from an HTTP endpoint
type HTTPFetcher struct {
	url        string
	headers    map[string]string
	httpClient *http.Client
}

// HTTPConfig holds configuration for HTTPFetcher
type HTTPConfig struct {
	URL     string
	Headers map[string]string
}

// NewHTTPFetcher creates a new HTTP fetcher
func NewHTTPFetcher(config HTTPConfig) *HTTPFetcher {
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	return &HTTPFetcher{
		url:     config.URL,
		headers: config.Headers,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Type returns the fetcher type
func (h *HTTPFetcher) Type() string {
	return "http"
}

// Validate checks if the configuration is valid
func (h *HTTPFetcher) Validate() error {
	if h.url == "" {
		return fmt.Errorf("HTTP URL is required")
	}
	if !strings.HasPrefix(h.url, "http://") && !strings.HasPrefix(h.url, "https://") {
		return fmt.Errorf("invalid HTTP URL format")
	}
	return nil
}

// Fetch fetches rules from the HTTP endpoint
func (h *HTTPFetcher) Fetch(ctx context.Context) (*RuleSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for key, value := range h.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("User-Agent", "PII-Redactor/1.0")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed: status %d", resp.StatusCode)
	}

	// Read content
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Detect content type and process
	contentType := resp.Header.Get("Content-Type")
	return h.processContent(data, contentType)
}

// processContent processes the downloaded content
func (h *HTTPFetcher) processContent(data []byte, contentType string) (*RuleSet, error) {
	// Try to detect format by content-type header
	switch {
	case strings.Contains(contentType, "application/x-tar"):
		return h.processTar(data)
	case strings.Contains(contentType, "application/gzip"),
		strings.Contains(contentType, "application/x-gzip"):
		return h.processGzip(data)
	case strings.Contains(contentType, "application/zip"):
		return h.processZip(data)
	case strings.Contains(contentType, "application/yaml"),
		strings.Contains(contentType, "application/x-yaml"),
		strings.Contains(contentType, "text/yaml"):
		return h.processYAML(data)
	case strings.Contains(contentType, "application/json"):
		return h.processYAML(data) // YAML parser can handle JSON
	}

	// Try to detect format by content
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		return h.processGzip(data)
	}

	// Try tar magic
	if len(data) > 262 && string(data[257:262]) == "ustar" {
		return h.processTar(data)
	}

	// Try zip magic
	if len(data) > 4 && data[0] == 0x50 && data[1] == 0x4b {
		return h.processZip(data)
	}

	// Default to YAML/JSON
	return h.processYAML(data)
}

// processYAML processes YAML content
func (h *HTTPFetcher) processYAML(data []byte) (*RuleSet, error) {
	ruleSet := &RuleSet{
		Name:     "http-source",
		Patterns: make([]PatternDefinition, 0),
	}

	// Try parsing as rule set
	if err := yaml.Unmarshal(data, ruleSet); err == nil && len(ruleSet.Patterns) > 0 {
		return ruleSet, nil
	}

	// Try parsing as pattern list
	var patterns []PatternDefinition
	if err := yaml.Unmarshal(data, &patterns); err == nil && len(patterns) > 0 {
		ruleSet.Patterns = patterns
		return ruleSet, nil
	}

	// Try parsing as single pattern
	var single PatternDefinition
	if err := yaml.Unmarshal(data, &single); err == nil && single.Name != "" {
		ruleSet.Patterns = []PatternDefinition{single}
		return ruleSet, nil
	}

	return nil, fmt.Errorf("failed to parse content as YAML")
}

// processGzip processes gzip compressed content
func (h *HTTPFetcher) processGzip(data []byte) (*RuleSet, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	// Try as tar
	if ruleSet, err := h.processTar(decompressed); err == nil {
		return ruleSet, nil
	}

	// Try as YAML
	return h.processYAML(decompressed)
}

// processTar processes tar archive content
func (h *HTTPFetcher) processTar(data []byte) (*RuleSet, error) {
	ruleSet := &RuleSet{
		Name:     "http-source",
		Patterns: make([]PatternDefinition, 0),
	}

	reader := tar.NewReader(bytes.NewReader(data))

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		if !isYAMLFile(header.Name) {
			continue
		}

		content, err := io.ReadAll(reader)
		if err != nil {
			continue
		}

		patterns, err := h.parsePatternContent(content)
		if err != nil {
			continue
		}
		ruleSet.Patterns = append(ruleSet.Patterns, patterns...)
	}

	return ruleSet, nil
}

// processZip processes zip archive content
func (h *HTTPFetcher) processZip(data []byte) (*RuleSet, error) {
	ruleSet := &RuleSet{
		Name:     "http-source",
		Patterns: make([]PatternDefinition, 0),
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		if !isYAMLFile(file.Name) {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		patterns, err := h.parsePatternContent(content)
		if err != nil {
			continue
		}
		ruleSet.Patterns = append(ruleSet.Patterns, patterns...)
	}

	return ruleSet, nil
}

// parsePatternContent parses pattern content from bytes
func (h *HTTPFetcher) parsePatternContent(data []byte) ([]PatternDefinition, error) {
	var single PatternDefinition
	if err := yaml.Unmarshal(data, &single); err == nil && single.Name != "" {
		return []PatternDefinition{single}, nil
	}

	var patterns []PatternDefinition
	if err := yaml.Unmarshal(data, &patterns); err == nil {
		return patterns, nil
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err == nil {
		return ruleSet.Patterns, nil
	}

	return nil, fmt.Errorf("failed to parse pattern content")
}

// SetHTTPClient sets a custom HTTP client
func (h *HTTPFetcher) SetHTTPClient(client *http.Client) {
	h.httpClient = client
}

// AddHeader adds or updates a header
func (h *HTTPFetcher) AddHeader(key, value string) {
	h.headers[key] = value
}

// FetchToDir fetches and extracts content to a directory (for archive types)
func (h *HTTPFetcher) FetchToDir(ctx context.Context, targetDir string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return err
	}

	for key, value := range h.headers {
		req.Header.Set(key, value)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return h.extractToDir(data, targetDir)
}

// extractToDir extracts archive content to a directory
func (h *HTTPFetcher) extractToDir(data []byte, targetDir string) error {
	// Try gzip+tar
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer reader.Close()
		return h.extractTarToDir(reader, targetDir)
	}

	// Try zip
	if len(data) > 4 && data[0] == 0x50 && data[1] == 0x4b {
		return h.extractZipToDir(data, targetDir)
	}

	// Try tar
	return h.extractTarToDir(bytes.NewReader(data), targetDir)
}

// extractTarToDir extracts a tar archive to a directory
func (h *HTTPFetcher) extractTarToDir(reader io.Reader, targetDir string) error {
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		targetPath := filepath.Join(targetDir, header.Name)

		if !strings.HasPrefix(targetPath, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}
			file, err := os.Create(targetPath)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return err
			}
			file.Close()
		}
	}

	return nil
}

// extractZipToDir extracts a zip archive to a directory
func (h *HTTPFetcher) extractZipToDir(data []byte, targetDir string) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	for _, file := range reader.File {
		targetPath := filepath.Join(targetDir, file.Name)

		if !strings.HasPrefix(targetPath, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			continue
		}

		if file.FileInfo().IsDir() {
			os.MkdirAll(targetPath, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}

		rc, err := file.Open()
		if err != nil {
			return err
		}

		outFile, err := os.Create(targetPath)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
