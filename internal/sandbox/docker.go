// Package sandbox owns the controller-side lifecycle for the persistent,
// network-disabled static-analysis container.  The package deliberately does
// not expose a host shell or a host filesystem to a model.  Docker commands
// are controller-owned argv invocations behind an injected Executor so tests
// can audit the complete runtime contract without contacting a daemon.
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultImage is the image expected to contain the pinned radare2/MCP
	// static-analysis toolchain.  Start runs the resolved immutable digest, not
	// this mutable convenience tag.
	DefaultImage = "jaq-radare2:6.2.0-mcp1.8.6"

	DefaultTimeout = 20 * time.Minute
	MaxTimeout     = 20 * time.Minute

	MaxSampleCopySize = int64(512 << 20)
	CleanupTimeout    = 15 * time.Second
)

// Executor is the only runtime side effect the package performs.  Production
// uses a direct argv invocation of the Docker CLI; tests inject a recorder.
// No caller-provided command is interpreted through a shell.
type Executor func(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error

// Docker is a controller-owned Docker runtime. Execute and Cleanup are
// injectable for tests; Image and ResolvedImageID are kept separate so a tag
// can never silently become the image used by a started session.
type Docker struct {
	Image           string
	Timeout         time.Duration
	Execute         Executor
	Cleanup         Executor
	ResolvedImageID string

	mu sync.RWMutex
}

// Session identifies one persistent container and its private staged sample.
// The sample is not exposed through a writable host mount. Close is idempotent
// and removes both the named container and the private stage.
type Session struct {
	containerName string
	imageID       string
	stageDir      string
	cleanup       Executor

	closeMu sync.Mutex
	closed  bool
}

// NewDocker returns the default local runtime. The image is not pulled by
// this package; callers/build tooling must provision it locally.
func NewDocker() *Docker {
	return &Docker{
		Image:   DefaultImage,
		Timeout: DefaultTimeout,
		Execute: execute,
		Cleanup: execute,
	}
}

// ImageID resolves the configured local image tag to an immutable content ID.
// It rejects non-local Docker endpoints before invoking image inspection and
// stores the sha256 ID for the next Start call.
func (d *Docker) ImageID(ctx context.Context) (string, error) {
	if d == nil {
		return "", errors.New("nil Docker runtime")
	}
	if ctx == nil {
		return "", errors.New("nil Docker context")
	}
	image := d.imageRef()
	executor := d.executor()
	inspectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := validateLocalContext(inspectCtx, executor); err != nil {
		return "", err
	}
	var output limitedBuffer
	output.max = 4096
	output.Reset()
	if err := executor(inspectCtx, "docker", []string{
		"image", "inspect", "--format={{.Id}}", image,
	}, &output, &output); err != nil {
		return "", fmt.Errorf("inspect analyzer image %q: %w: %s", image, err, strings.TrimSpace(output.String()))
	}
	id := strings.TrimSpace(output.String())
	if !validImageID(id) {
		return "", fmt.Errorf("inspect analyzer image %q: invalid image ID %q", image, id)
	}
	d.mu.Lock()
	d.ResolvedImageID = id
	d.mu.Unlock()
	return id, nil
}

// Start stages an inert sample, verifies its content hash, and starts a
// persistent detached container by immutable image ID. If expectedSHA256 is
// empty the staged copy's hash is still computed and used as the session's
// binding; a supplied value must match exactly.
func (d *Docker) Start(ctx context.Context, samplePath, expectedSHA256 string) (*Session, error) {
	if d == nil {
		return nil, errors.New("nil Docker runtime")
	}
	if ctx == nil {
		return nil, errors.New("nil Docker context")
	}
	if !filepath.IsAbs(samplePath) {
		return nil, errors.New("sample path must be absolute")
	}
	if strings.ContainsAny(samplePath, ",\x00") {
		return nil, errors.New("Docker sample paths cannot contain commas or NUL bytes")
	}
	if expectedSHA256 != "" && !validDigest(expectedSHA256, 64) {
		return nil, errors.New("expected sample SHA-256 must be 64 lowercase hexadecimal characters")
	}
	info, err := os.Stat(samplePath)
	if err != nil {
		return nil, fmt.Errorf("stat sample: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("sample must be a regular file")
	}

	stageDir, err := os.MkdirTemp("", ".jaq-sandbox-")
	if err != nil {
		return nil, fmt.Errorf("create private sandbox stage: %w", err)
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = os.RemoveAll(stageDir)
		}
	}()
	stagedSample := filepath.Join(stageDir, "sample.exe")
	copiedSHA256, err := copyReadOnly(samplePath, stagedSample)
	if err != nil {
		return nil, err
	}
	if expectedSHA256 != "" && copiedSHA256 != expectedSHA256 {
		return nil, errors.New("sample changed before sandbox start; refusing inconsistent analyzer input")
	}
	imageID, err := d.resolvedImageID(ctx)
	if err != nil {
		return nil, err
	}
	containerName, err := newContainerName()
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	startCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	executor := d.executor()
	args := d.args(imageID, stagedSample, containerName)
	var diagnostics limitedBuffer
	diagnostics.max = 64 * 1024
	if err := executor(startCtx, "docker", args, io.Discard, &diagnostics); err != nil {
		cleanupErr := d.cleanupContainer(context.Background(), containerName)
		_ = os.RemoveAll(stageDir)
		if errors.Is(startCtx.Err(), context.DeadlineExceeded) {
			if cleanupErr != nil {
				return nil, fmt.Errorf("sandbox start timed out after %s; cleanup failed: %v", timeout, cleanupErr)
			}
			return nil, fmt.Errorf("sandbox start timed out after %s: %w", timeout, startCtx.Err())
		}
		if cleanupErr != nil {
			return nil, fmt.Errorf("start sandbox: %w; cleanup failed: %v", err, cleanupErr)
		}
		return nil, fmt.Errorf("start sandbox: %w: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	keepStage = true
	return &Session{
		containerName: containerName,
		imageID:       imageID,
		stageDir:      stageDir,
		cleanup:       d.cleanupExecutor(),
	}, nil
}

// ContainerName returns the stable Docker name allocated for this session.
func (s *Session) ContainerName() string {
	if s == nil {
		return ""
	}
	return s.containerName
}

// ImageID returns the immutable image content ID used to start this session.
func (s *Session) ImageID() string {
	if s == nil {
		return ""
	}
	return s.imageID
}

// Close force-removes the named container and removes the private staged
// sample. It is safe to call more than once. A transient cleanup failure is
// returned without marking the session closed so a later call can retry.
func (s *Session) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	// A caller's canceled context must not strand a container. Cleanup is
	// deliberately independent and bounded; callers observe its result.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), CleanupTimeout)
	defer cancel()
	if s.cleanup != nil && s.containerName != "" {
		var diagnostics limitedBuffer
		diagnostics.max = 4096
		if err := s.cleanup(cleanupCtx, "docker", []string{"rm", "--force", s.containerName}, &diagnostics, &diagnostics); err != nil && !isContainerGone(err, diagnostics.String()) {
			return fmt.Errorf("remove sandbox container %q: %w", s.containerName, err)
		}
	}
	if err := os.RemoveAll(s.stageDir); err != nil {
		return fmt.Errorf("remove sandbox stage: %w", err)
	}
	s.closed = true
	return nil
}

func (d *Docker) resolvedImageID(ctx context.Context) (string, error) {
	d.mu.RLock()
	resolved := d.ResolvedImageID
	d.mu.RUnlock()
	if resolved != "" {
		if !validImageID(resolved) {
			return "", errors.New("configured resolved image ID is invalid")
		}
		contextCheck, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := validateLocalContext(contextCheck, d.executor()); err != nil {
			return "", err
		}
		return resolved, nil
	}
	return d.ImageID(ctx)
}

func validateLocalContext(ctx context.Context, executor Executor) error {
	if configured := os.Getenv("DOCKER_HOST"); configured != "" && !isLocalDockerEndpoint(configured) {
		return fmt.Errorf("refusing non-local DOCKER_HOST %q", configured)
	}
	var output limitedBuffer
	output.max = 4096
	if err := executor(ctx, "docker", []string{
		"context", "inspect", "--format={{(index .Endpoints \"docker\").Host}}",
	}, &output, &output); err != nil {
		return fmt.Errorf("inspect Docker context: %w: %s", err, strings.TrimSpace(output.String()))
	}
	endpoint := strings.TrimSpace(output.String())
	if !isLocalDockerEndpoint(endpoint) {
		return fmt.Errorf("refusing non-local Docker endpoint %q", endpoint)
	}
	return nil
}

func (d *Docker) imageRef() string {
	d.mu.RLock()
	image := d.Image
	d.mu.RUnlock()
	if image == "" {
		return DefaultImage
	}
	return image
}

func (d *Docker) executor() Executor {
	if d.Execute != nil {
		return d.Execute
	}
	return execute
}

func (d *Docker) cleanupExecutor() Executor {
	if d.Cleanup != nil {
		return d.Cleanup
	}
	if d.Execute != nil {
		return d.Execute
	}
	return execute
}

func (d *Docker) cleanupContainer(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	executor := d.cleanupExecutor()
	cleanupCtx, cancel := context.WithTimeout(ctx, CleanupTimeout)
	defer cancel()
	var diagnostics limitedBuffer
	diagnostics.max = 4096
	if err := executor(cleanupCtx, "docker", []string{"rm", "--force", name}, &diagnostics, &diagnostics); err != nil && !isContainerGone(err, diagnostics.String()) {
		return err
	}
	return nil
}

// args intentionally contains one and only one mount: the read-only staged
// sample. Container writable state lives in tmpfs; no host output or env is
// forwarded. Omitting a command preserves the image entrypoint's persistent
// session behavior.
func (d *Docker) args(imageID, stagedSample, containerName string) []string {
	return []string{
		"run", "--detach", "--rm",
		"--pull=never",
		"--platform=linux/amd64",
		"--network=none",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--pids-limit=256",
		"--memory=4g",
		"--cpus=2",
		"--user=65532:65532",
		"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=2g,mode=700,uid=65532,gid=65532",
		"--tmpfs=/work:rw,exec,nosuid,nodev,size=1g,mode=700,uid=65532,gid=65532",
		"--workdir=/work",
		"--mount=type=bind,src=" + stagedSample + ",dst=/input/sample.exe,readonly",
		"--name=" + containerName,
		imageID,
	}
}

func newContainerName() (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("create sandbox container name: %w", err)
	}
	return "jaq-sandbox-" + hex.EncodeToString(random[:]), nil
}

func copyReadOnly(sourcePath, destinationPath string) (string, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("open sample for sandbox stage: %w", err)
	}
	defer source.Close()
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return "", fmt.Errorf("create staged sample: %w", err)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(source, MaxSampleCopySize+1))
	if copyErr != nil {
		_ = destination.Close()
		return "", fmt.Errorf("copy sample into sandbox stage: %w", copyErr)
	}
	if written > MaxSampleCopySize {
		_ = destination.Close()
		return "", fmt.Errorf("sample exceeds %d-byte sandbox limit", MaxSampleCopySize)
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		return "", fmt.Errorf("sync staged sample: %w", err)
	}
	if err := destination.Close(); err != nil {
		return "", fmt.Errorf("close staged sample: %w", err)
	}
	if err := os.Chmod(destinationPath, 0o444); err != nil {
		return "", fmt.Errorf("make staged sample read-only: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func validImageID(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validDigest(strings.TrimPrefix(value, "sha256:"), 64)
}

func validDigest(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func isLocalDockerEndpoint(endpoint string) bool {
	return strings.HasPrefix(endpoint, "unix://") || strings.HasPrefix(endpoint, "npipe://")
}

func isContainerGone(err error, diagnostics ...string) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error() + " " + strings.Join(diagnostics, " "))
	return strings.Contains(message, "no such container") || strings.Contains(message, "is not running")
}

func execute(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	command.Env = os.Environ()
	return command.Run()
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	remaining := b.max - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return written, nil
}
