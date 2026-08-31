package investigator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const DefaultTimeout = 10 * time.Minute

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)(api[_ -]?key|token|secret)\s*[:=]\s*[^,;\s]+`),
	regexp.MustCompile(`\b(?:sk|sess|key)-[A-Za-z0-9_-]{12,}\b`),
}

type Process struct {
	Python      string
	ProjectRoot string
	Timeout     time.Duration
}

func NewProcess(projectRoot string) *Process {
	python := os.Getenv("JAQ_PYTHON")
	if python == "" {
		python = "python3"
	}
	return &Process{Python: python, ProjectRoot: projectRoot, Timeout: DefaultTimeout}
}

// RuntimeVersions records the exact Python and installed LiteLLM versions
// without importing LiteLLM or reading provider credentials.
func (p *Process) RuntimeVersions(ctx context.Context) (string, string, error) {
	python := p.Python
	if python == "" {
		python = "python3"
	}
	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	code := "import importlib.metadata,platform; print(platform.python_version());\ntry: print(importlib.metadata.version('litellm'))\nexcept importlib.metadata.PackageNotFoundError: print('not-installed')"
	cmd := exec.CommandContext(versionCtx, python, "-c", code)
	cmd.Stdin = nil
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("query Python runtime versions: %w: %s", err, strings.TrimSpace(RedactSensitive(output.String())))
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || lines[0] == "" || lines[1] == "" {
		return "", "", errors.New("query Python runtime versions: unexpected response")
	}
	return lines[0], lines[1], nil
}

func (p *Process) Investigate(ctx context.Context, evidenceDir string) error {
	if os.Getenv("JAQ_INVESTIGATOR_MODEL") == "" {
		return errors.New("JAQ_INVESTIGATOR_MODEL is required (LiteLLM provider/model string)")
	}
	if !filepath.IsAbs(evidenceDir) {
		return errors.New("evidence directory must be absolute")
	}
	python := p.Python
	if python == "" {
		python = "python3"
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	stageCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(stageCtx, python, "-m", "jaq_investigator",
		"--evidence", filepath.Join(evidenceDir, "observations.jsonl"),
		"--output", evidenceDir)
	cmd.Stdin = nil
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	env := os.Environ()
	if p.ProjectRoot != "" {
		pythonPath := filepath.Join(p.ProjectRoot, "python")
		if existing := os.Getenv("PYTHONPATH"); existing != "" {
			pythonPath += string(os.PathListSeparator) + existing
		}
		env = append(env, "PYTHONPATH="+pythonPath)
	}
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		if errors.Is(stageCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("investigator timed out after %s: %w", timeout, stageCtx.Err())
		}
		message := RedactSensitive(output.String())
		if len(message) > 64*1024 {
			message = message[:64*1024]
		}
		return fmt.Errorf("investigator failed: %w: %s", err, strings.TrimSpace(message))
	}
	return nil
}

// RedactSensitive removes credential-shaped text and the values of
// credential environment variables before diagnostics cross a persistence
// or logging boundary.
func RedactSensitive(message string) string {
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if !ok || len(value) < 6 || !strings.Contains(upper, "KEY") &&
			!strings.Contains(upper, "TOKEN") && !strings.Contains(upper, "SECRET") &&
			!strings.Contains(upper, "PASSWORD") && !strings.Contains(upper, "CREDENTIAL") {
			continue
		}
		message = strings.ReplaceAll(message, value, "[redacted]")
	}
	for _, pattern := range credentialPatterns {
		message = pattern.ReplaceAllString(message, "[redacted]")
	}
	return message
}

func FindProjectRoot(start string) (string, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if info, err := os.Stat(filepath.Join(current, "python", "jaq_investigator")); err == nil && info.IsDir() {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("could not find project root containing python/jaq_investigator")
		}
		current = parent
	}
}
