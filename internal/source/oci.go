package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// OCIFetcher fetches rules from an OCI registry
type OCIFetcher struct {
	registry   string
	repository string
	tag        string
	username   string
	password   string
	httpClient *http.Client
}

// OCIConfig holds configuration for OCIFetcher
type OCIConfig struct {
	Registry   string
	Repository string
	Tag        string
	Username   string
	Password   string
}

// NewOCIFetcher creates a new OCI fetcher
func NewOCIFetcher(config OCIConfig) *OCIFetcher {
	if config.Tag == "" {
		config.Tag = "latest"
	}

	return &OCIFetcher{
		registry:   config.Registry,
		repository: config.Repository,
		tag:        config.Tag,
		username:   config.Username,
		password:   config.Password,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Type returns the fetcher type
func (o *OCIFetcher) Type() string {
	return "oci"
}

// Validate checks if the configuration is valid
func (o *OCIFetcher) Validate() error {
	if o.registry == "" {
		return fmt.Errorf("OCI registry is required")
	}
	if o.repository == "" {
		return fmt.Errorf("OCI repository is required")
	}
	return nil
}

// Fetch fetches rules from the OCI registry
func (o *OCIFetcher) Fetch(ctx context.Context) (*RuleSet, error) {
	// Get manifest
	manifest, err := o.getManifest(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}

	// Download and extract layers
	tmpDir, err := os.MkdirTemp("", "pii-rules-oci-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, layer := range manifest.Layers {
		if err := o.downloadLayer(ctx, layer.Digest, tmpDir); err != nil {
			return nil, fmt.Errorf("failed to download layer: %w", err)
		}
	}

	// Read rules from extracted content
	ruleSet, err := o.readRules(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules: %w", err)
	}

	return ruleSet, nil
}

// ociManifest represents an OCI manifest
type ociManifest struct {
	SchemaVersion int         `json:"schemaVersion"`
	MediaType     string      `json:"mediaType"`
	Config        ociLayer    `json:"config"`
	Layers        []ociLayer  `json:"layers"`
	Annotations   interface{} `json:"annotations,omitempty"`
}

// ociLayer represents a layer in the manifest
type ociLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// getManifest retrieves the OCI manifest
func (o *OCIFetcher) getManifest(ctx context.Context) (*ociManifest, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", o.registry, o.repository, o.tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
	o.setAuth(req)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get manifest: status %d", resp.StatusCode)
	}

	var manifest ociManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// downloadLayer downloads and extracts a layer
func (o *OCIFetcher) downloadLayer(ctx context.Context, digest string, targetDir string) error {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", o.registry, o.repository, digest)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	o.setAuth(req)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download layer: status %d", resp.StatusCode)
	}

	// Extract tar.gz
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		// Try as plain tar
		return o.extractTar(resp.Body, targetDir)
	}
	defer gzReader.Close()

	return o.extractTar(gzReader, targetDir)
}

// extractTar extracts a tar archive
func (o *OCIFetcher) extractTar(reader io.Reader, targetDir string) error {
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

		// Security: prevent path traversal
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

// readRules reads rules from extracted content
func (o *OCIFetcher) readRules(rulesPath string) (*RuleSet, error) {
	ruleSet := &RuleSet{
		Name:     o.repository,
		Version:  o.tag,
		Patterns: make([]PatternDefinition, 0),
	}

	err := filepath.Walk(rulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !isYAMLFile(path) {
			return nil
		}

		patterns, err := o.readPatternFile(path)
		if err != nil {
			return nil
		}
		ruleSet.Patterns = append(ruleSet.Patterns, patterns...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return ruleSet, nil
}

// readPatternFile reads patterns from a YAML file
func (o *OCIFetcher) readPatternFile(path string) ([]PatternDefinition, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

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

	return nil, fmt.Errorf("failed to parse pattern file: %s", path)
}

// setAuth sets authentication headers
func (o *OCIFetcher) setAuth(req *http.Request) {
	if o.username != "" && o.password != "" {
		req.SetBasicAuth(o.username, o.password)
	}
}

// SetHTTPClient sets a custom HTTP client
func (o *OCIFetcher) SetHTTPClient(client *http.Client) {
	o.httpClient = client
}
