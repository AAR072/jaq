package investigator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const DefaultTimeout = 30 * time.Minute
const progressPrefix = "JAQ_PROGRESS "

var progressLinePattern = regexp.MustCompile(`^\[(research|report|harvest)\] (started|model calls=[0-9]+ tools=[0-9]+ cost=\$[0-9]+\.[0-9]{5}|tool #[0-9]+: [A-Za-z][A-Za-z0-9_]{0,99}|inactivity timeout; preserving evidence|budget reached; recording final findings at cost=\$[0-9]+\.[0-9]{5}|preparing (checkpoint|final summary) at cost=\$[0-9]+\.[0-9]{5}|submission attempt #[0-9]+|submission rejected; correcting|submission accepted|checkpoint compiled locally from persisted evidence|dossier compiled locally from [0-9]+ recorded findings|completed calls=[0-9]+ tools=[0-9]+ cost=\$[0-9]+\.[0-9]{5})$`)

type progressFilter struct {
	mu          sync.Mutex
	pending     []byte
	diagnostics bytes.Buffer
	display     io.Writer
}

var screeningProgressPattern = regexp.MustCompile(`^\[screening\] (checking request #[0-9]+|qualified|unsupported|insufficient_evidence|completed requests=[0-9]+ qualified=[0-9]+ held=[0-9]+)$`)

func newProgressFilter(display io.Writer) *progressFilter {
	return &progressFilter{display: display}
}

func (w *progressFilter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, data...)
	for {
		newline := bytes.IndexByte(w.pending, '\n')
		if newline < 0 {
			break
		}
		line := append([]byte(nil), w.pending[:newline]...)
		w.pending = w.pending[newline+1:]
		w.handle(line)
	}
	if len(w.pending) > 64*1024 {
		w.handle(w.pending[:64*1024])
		w.pending = nil
	}
	return len(data), nil
}

func (w *progressFilter) handle(line []byte) {
	text := strings.TrimSuffix(string(line), "\r")
	payload := strings.TrimPrefix(text, progressPrefix)
	if strings.HasPrefix(text, progressPrefix) && len(text) <= 600 && (progressLinePattern.MatchString(payload) || screeningProgressPattern.MatchString(payload)) {
		_, _ = fmt.Fprintln(w.display, "jaq:", payload)
		return
	}
	if w.diagnostics.Len() < 64*1024 {
		remaining := 64*1024 - w.diagnostics.Len()
		if len(line)+1 > remaining {
			line = line[:max(0, remaining-1)]
		}
		w.diagnostics.Write(line)
		w.diagnostics.WriteByte('\n')
	}
}

func (w *progressFilter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) > 0 {
		w.handle(w.pending)
		w.pending = nil
	}
}

func (w *progressFilter) Diagnostics() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.diagnostics.String()
}

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)(api[_ -]?key|token|secret)\s*[:=]\s*[^,;\s]+`),
	regexp.MustCompile(`\b(?:sk|sess|key)-[A-Za-z0-9_-]{12,}\b`),
}

type Process struct {
	Python           string
	Node             string
	ProjectRoot      string
	Timeout          time.Duration
	SandboxContainer string
	SampleSHA256     string
	RadareVersion    string
	MCPVersion       string
}

// ConfigureSandbox binds the host-side investigator to one controller-owned
// offline container. No sample host path or provider credential is passed.
func (p *Process) ConfigureSandbox(containerName, sampleSHA256, radareVersion, mcpVersion string) {
	p.SandboxContainer = containerName
	p.SampleSHA256 = sampleSHA256
	p.RadareVersion = radareVersion
	p.MCPVersion = mcpVersion
}

func NewProcess(projectRoot string) *Process {
	python := os.Getenv("JAQ_PYTHON")
	if python == "" {
		python = "python3"
	}
	node := os.Getenv("JAQ_NODE")
	if node == "" {
		node = "node"
	}
	return &Process{Python: python, Node: node, ProjectRoot: projectRoot, Timeout: DefaultTimeout}
}

type RuntimeVersionInfo struct {
	Python  string
	LiteLLM string
	Node    string
	Pi      string
}

// RuntimeVersions records the exact host harness versions without importing
// providers, reading credentials, or making a model request.
func (p *Process) RuntimeVersions(ctx context.Context) (RuntimeVersionInfo, error) {
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
		return RuntimeVersionInfo{}, fmt.Errorf("query Python runtime versions: %w: %s", err, strings.TrimSpace(RedactSensitive(output.String())))
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || lines[0] == "" || lines[1] == "" {
		return RuntimeVersionInfo{}, errors.New("query Python runtime versions: unexpected response")
	}
	node := p.Node
	if node == "" {
		node = "node"
	}
	nodeCmd := exec.CommandContext(versionCtx, node, "--version")
	nodeCmd.Stdin = nil
	var nodeOutput bytes.Buffer
	nodeCmd.Stdout = &nodeOutput
	nodeCmd.Stderr = &nodeOutput
	if err := nodeCmd.Run(); err != nil {
		return RuntimeVersionInfo{}, fmt.Errorf("query Node runtime version: %w: %s", err, strings.TrimSpace(RedactSensitive(nodeOutput.String())))
	}
	projectRoot := p.ProjectRoot
	if projectRoot == "" {
		var rootErr error
		projectRoot, rootErr = FindProjectRoot(".")
		if rootErr != nil {
			return RuntimeVersionInfo{}, fmt.Errorf("locate Pi SDK package: %w", rootErr)
		}
	}
	piPackage := filepath.Join(projectRoot, "node_modules", "@earendil-works", "pi-coding-agent", "package.json")
	packageContents, err := os.ReadFile(piPackage)
	if err != nil {
		return RuntimeVersionInfo{}, fmt.Errorf("read Pi SDK package metadata: %w", err)
	}
	var metadata struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(packageContents, &metadata); err != nil || metadata.Version == "" {
		return RuntimeVersionInfo{}, errors.New("read Pi SDK package metadata: invalid version")
	}
	return RuntimeVersionInfo{
		Python: lines[0], LiteLLM: lines[1], Node: strings.TrimSpace(nodeOutput.String()), Pi: metadata.Version,
	}, nil
}

func (p *Process) Investigate(ctx context.Context, evidenceDir string) error {
	if os.Getenv("JAQ_INVESTIGATOR_MODEL") == "" {
		return errors.New("JAQ_INVESTIGATOR_MODEL is required (LiteLLM provider/model string)")
	}
	if !filepath.IsAbs(evidenceDir) {
		return errors.New("evidence directory must be absolute")
	}
	if p.SandboxContainer == "" || p.SampleSHA256 == "" {
		return errors.New("static sandbox session is not configured")
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
	var stdout bytes.Buffer
	progress := newProgressFilter(os.Stderr)
	cmd.Stdout = &stdout
	cmd.Stderr = progress
	env := os.Environ()
	if p.ProjectRoot != "" {
		pythonPath := filepath.Join(p.ProjectRoot, "python")
		if existing := os.Getenv("PYTHONPATH"); existing != "" {
			pythonPath += string(os.PathListSeparator) + existing
		}
		env = append(env, "PYTHONPATH="+pythonPath)
	}
	cmd.Env = env
	cmd.Env = append(cmd.Env,
		"JAQ_PROJECT_ROOT="+p.ProjectRoot,
		"JAQ_SANDBOX_CONTAINER="+p.SandboxContainer,
		"JAQ_SAMPLE_SHA256="+p.SampleSHA256,
		"JAQ_RADARE2_VERSION="+p.RadareVersion,
		"JAQ_R2MCP_VERSION="+p.MCPVersion,
		"JAQ_PROGRESS_TRANSPORT=1",
	)
	if err := cmd.Run(); err != nil {
		progress.Flush()
		// Finalization must survive a killed/stalled model process. Recovery is
		// bounded local compilation; it never invokes a model or the sandbox.
		recoveryErr := p.CompilePersisted(evidenceDir)
		recoveryNote := "; partial dossier saved to " + filepath.Join(evidenceDir, "report.md")
		if recoveryErr != nil {
			recoveryNote = "; local recovery failed: " + recoveryErr.Error()
		}
		if errors.Is(stageCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("investigator timed out after %s: %w%s", timeout, stageCtx.Err(), recoveryNote)
		}
		message := RedactSensitive(stdout.String() + progress.Diagnostics())
		if len(message) > 64*1024 {
			message = message[:64*1024]
		}
		return fmt.Errorf("investigator failed: %w: %s%s", err, strings.TrimSpace(message), recoveryNote)
	}
	progress.Flush()
	return nil
}

// CompilePersisted uses no provider configuration and preserves existing output
// files. A fresh context lets local recovery finish after the run is cancelled.
func (p *Process) CompilePersisted(evidenceDir string) error {
	if !filepath.IsAbs(evidenceDir) {
		return errors.New("evidence directory must be absolute")
	}
	python := p.Python
	if python == "" {
		python = "python3"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-m", "jaq_investigator",
		"--evidence", filepath.Join(evidenceDir, "observations.jsonl"),
		"--output", evidenceDir, "--compile-only")
	cmd.Env = os.Environ()
	if p.ProjectRoot != "" {
		cmd.Env = append(cmd.Env, "PYTHONPATH="+filepath.Join(p.ProjectRoot, "python"))
	}
	progress := newProgressFilter(os.Stderr)
	cmd.Stdout = io.Discard
	cmd.Stderr = progress
	err := cmd.Run()
	progress.Flush()
	if err != nil {
		return fmt.Errorf("compile saved evidence: %w: %s", err, strings.TrimSpace(RedactSensitive(progress.Diagnostics())))
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
