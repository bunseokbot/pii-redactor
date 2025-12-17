package source

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// GitFetcher fetches rules from a Git repository
type GitFetcher struct {
	url      string
	ref      string
	path     string
	username string
	password string
	sshKey   string
}

// GitConfig holds configuration for GitFetcher
type GitConfig struct {
	URL      string
	Ref      string
	Path     string
	Username string
	Password string
	SSHKey   string
}

// NewGitFetcher creates a new Git fetcher
func NewGitFetcher(config GitConfig) *GitFetcher {
	if config.Ref == "" {
		config.Ref = "main"
	}
	if config.Path == "" {
		config.Path = "rules"
	}

	return &GitFetcher{
		url:      config.URL,
		ref:      config.Ref,
		path:     config.Path,
		username: config.Username,
		password: config.Password,
		sshKey:   config.SSHKey,
	}
}

// Type returns the fetcher type
func (g *GitFetcher) Type() string {
	return "git"
}

// Validate checks if the configuration is valid
func (g *GitFetcher) Validate() error {
	if g.url == "" {
		return fmt.Errorf("git URL is required")
	}
	return nil
}

// Fetch fetches rules from the Git repository
func (g *GitFetcher) Fetch(ctx context.Context) (*RuleSet, error) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "pii-rules-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Clone repository
	if err := g.cloneRepo(ctx, tmpDir); err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Read rules from the path
	rulesPath := filepath.Join(tmpDir, g.path)
	ruleSet, err := g.readRules(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules: %w", err)
	}

	return ruleSet, nil
}

// cloneRepo clones the Git repository
func (g *GitFetcher) cloneRepo(ctx context.Context, targetDir string) error {
	args := []string{"clone", "--depth", "1", "--branch", g.ref, g.url, targetDir}

	cmd := exec.CommandContext(ctx, "git", args...)

	// Set up authentication if provided
	if g.username != "" && g.password != "" {
		// Use credential helper
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("GIT_ASKPASS=%s", "echo"),
			fmt.Sprintf("GIT_USERNAME=%s", g.username),
			fmt.Sprintf("GIT_PASSWORD=%s", g.password),
		)
	}

	if g.sshKey != "" {
		// Write SSH key to temp file
		sshKeyFile, err := os.CreateTemp("", "ssh-key-*")
		if err != nil {
			return err
		}
		defer os.Remove(sshKeyFile.Name())

		if _, err := sshKeyFile.WriteString(g.sshKey); err != nil {
			return err
		}
		sshKeyFile.Close()
		os.Chmod(sshKeyFile.Name(), 0600)

		cmd.Env = append(os.Environ(),
			fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no", sshKeyFile.Name()),
		)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %s: %w", string(output), err)
	}

	return nil
}

// readRules reads rules from the specified path
func (g *GitFetcher) readRules(rulesPath string) (*RuleSet, error) {
	ruleSet := &RuleSet{
		Name:     filepath.Base(g.url),
		Patterns: make([]PatternDefinition, 0),
	}

	// Check if path exists
	info, err := os.Stat(rulesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ruleSet, nil // Empty rule set
		}
		return nil, err
	}

	if info.IsDir() {
		// Read all YAML files in directory
		err = filepath.Walk(rulesPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !isYAMLFile(path) {
				return nil
			}

			patterns, err := g.readPatternFile(path)
			if err != nil {
				// Log error but continue
				return nil
			}
			ruleSet.Patterns = append(ruleSet.Patterns, patterns...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		// Single file
		patterns, err := g.readPatternFile(rulesPath)
		if err != nil {
			return nil, err
		}
		ruleSet.Patterns = patterns
	}

	return ruleSet, nil
}

// readPatternFile reads patterns from a YAML file
func (g *GitFetcher) readPatternFile(path string) ([]PatternDefinition, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Try parsing as a single pattern first
	var single PatternDefinition
	if err := yaml.Unmarshal(data, &single); err == nil && single.Name != "" {
		return []PatternDefinition{single}, nil
	}

	// Try parsing as pattern list
	var patterns []PatternDefinition
	if err := yaml.Unmarshal(data, &patterns); err == nil {
		return patterns, nil
	}

	// Try parsing as rule set
	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err == nil {
		return ruleSet.Patterns, nil
	}

	return nil, fmt.Errorf("failed to parse pattern file: %s", path)
}

// isYAMLFile checks if a file is a YAML file
func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
