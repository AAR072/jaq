package analyzer

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
	"time"
)

const (
	DefaultImage             = "jaq-ghidra:12.1.3"
	DefaultTimeout           = 20 * time.Minute
	MaxTimeout               = 20 * time.Minute
	MaxRawEvidenceSize int64 = 256 << 20
	MaxSampleCopySize  int64 = 512 << 20
)

type Executor func(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error

type Docker struct {
	Image           string
	Timeout         time.Duration
	Execute         Executor
	Cleanup         Executor
	ResolvedImageID string
}

func NewDocker() *Docker {
	return &Docker{
		Image:   DefaultImage,
		Timeout: timeoutFromEnv("JAQ_ANALYZER_TIMEOUT", DefaultTimeout),
		Execute: execute,
		Cleanup: execute,
	}
}

// ImageID resolves the local immutable image content ID used for the run.
func (d *Docker) ImageID(ctx context.Context) (string, error) {
	image := d.Image
	if image == "" {
		image = DefaultImage
	}
	executor := d.Execute
	if executor == nil {
		executor = execute
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var output limitedBuffer
	output.max = 4096
	if configured := os.Getenv("DOCKER_HOST"); configured != "" && !isLocalDockerEndpoint(configured) {
		return "", fmt.Errorf("refusing non-local DOCKER_HOST %q", configured)
	}
	if err := executor(inspectCtx, "docker", []string{"context", "inspect", "--format={{(index .Endpoints \"docker\").Host}}"}, &output, &output); err != nil {
		return "", fmt.Errorf("inspect Docker context: %w: %s", err, strings.TrimSpace(output.String()))
	}
	endpoint := strings.TrimSpace(output.String())
	if !isLocalDockerEndpoint(endpoint) {
		return "", fmt.Errorf("refusing non-local Docker endpoint %q", endpoint)
	}
	output.Reset()
	if err := executor(inspectCtx, "docker", []string{"image", "inspect", "--format={{.Id}}", image}, &output, &output); err != nil {
		return "", fmt.Errorf("inspect pinned analyzer image %q: %w: %s", image, err, strings.TrimSpace(output.String()))
	}
	id := strings.TrimSpace(output.String())
	if !strings.HasPrefix(id, "sha256:") || len(id) != len("sha256:")+64 {
		return "", fmt.Errorf("inspect pinned analyzer image %q: invalid image ID %q", image, id)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, "sha256:")); err != nil {
		return "", fmt.Errorf("inspect pinned analyzer image %q: invalid image ID", image)
	}
	d.ResolvedImageID = id
	return id, nil
}

func isLocalDockerEndpoint(endpoint string) bool {
	return strings.HasPrefix(endpoint, "unix://") || strings.HasPrefix(endpoint, "npipe://")
}

func (d *Docker) Analyze(ctx context.Context, samplePath, evidenceDir string) error {
	return d.AnalyzeExpected(ctx, samplePath, evidenceDir, "")
}

// AnalyzeExpected binds the inert copy to the controller-recorded artifact
// hash, closing path replacement races between orchestration stages.
func (d *Docker) AnalyzeExpected(ctx context.Context, samplePath, evidenceDir, expectedSHA256 string) error {
	if !filepath.IsAbs(samplePath) || !filepath.IsAbs(evidenceDir) {
		return errors.New("analyzer paths must be absolute")
	}
	if strings.ContainsAny(samplePath, ",\x00") || strings.ContainsAny(evidenceDir, ",\x00") {
		return errors.New("Docker bind-mount paths cannot contain commas or NUL bytes")
	}
	info, err := os.Stat(samplePath)
	if err != nil {
		return fmt.Errorf("stat sample: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("sample must be a regular file")
	}
	if err := os.MkdirAll(evidenceDir, 0o700); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	stagingDir, err := os.MkdirTemp(evidenceDir, ".ghidra-stage-")
	if err != nil {
		return fmt.Errorf("create isolated analyzer staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir)
	stagedSample := filepath.Join(stagingDir, "sample.exe")
	copiedSHA256, err := copyReadOnly(samplePath, stagedSample)
	if err != nil {
		return err
	}
	if expectedSHA256 != "" && copiedSHA256 != expectedSHA256 {
		return errors.New("sample changed after controller validation; refusing inconsistent analyzer input")
	}
	stagedOutput := filepath.Join(stagingDir, "raw-observations.jsonl")
	outputFile, err := os.OpenFile(stagedOutput, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create staged analyzer output: %w", err)
	}
	defer outputFile.Close()

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	executor := d.Execute
	if executor == nil {
		executor = execute
	}

	containerName, err := newContainerName()
	if err != nil {
		return err
	}
	args := d.args(stagedSample, containerName)
	stageCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var diagnostics limitedBuffer
	diagnostics.max = 64 * 1024
	boundedOutput := &limitedWriter{writer: outputFile, max: MaxRawEvidenceSize}
	if err := executor(stageCtx, "docker", args, boundedOutput, &diagnostics); err != nil {
		cleanupErr := d.cleanupContainer(containerName)
		if errors.Is(stageCtx.Err(), context.DeadlineExceeded) {
			if cleanupErr != nil {
				return fmt.Errorf("Ghidra analyzer timed out after %s and container cleanup failed: %v", timeout, cleanupErr)
			}
			return fmt.Errorf("Ghidra analyzer timed out after %s: %w", timeout, stageCtx.Err())
		}
		if cleanupErr != nil {
			return fmt.Errorf("Ghidra analyzer failed: %w; container cleanup failed: %v: %s", err, cleanupErr, strings.TrimSpace(diagnostics.String()))
		}
		return fmt.Errorf("Ghidra analyzer failed: %w: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	if boundedOutput.exceeded {
		return fmt.Errorf("Ghidra analyzer output exceeds %d-byte limit", MaxRawEvidenceSize)
	}
	if err := outputFile.Sync(); err != nil {
		return fmt.Errorf("sync analyzer output: %w", err)
	}
	if err := outputFile.Close(); err != nil {
		return fmt.Errorf("close analyzer output: %w", err)
	}
	outputInfo, err := os.Lstat(stagedOutput)
	if err != nil {
		return fmt.Errorf("Ghidra analyzer did not produce raw-observations.jsonl: %w", err)
	}
	if !outputInfo.Mode().IsRegular() || outputInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("Ghidra analyzer output is not a regular file")
	}
	if outputInfo.Size() > MaxRawEvidenceSize {
		return fmt.Errorf("Ghidra analyzer output exceeds %d-byte limit", MaxRawEvidenceSize)
	}
	finalOutput := filepath.Join(evidenceDir, "raw-observations.jsonl")
	if _, err := os.Lstat(finalOutput); err == nil {
		return errors.New("refusing to overwrite existing raw-observations.jsonl")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect analyzer output destination: %w", err)
	}
	if err := os.Chmod(stagedOutput, 0o600); err != nil {
		return fmt.Errorf("protect analyzer output: %w", err)
	}
	if err := os.Rename(stagedOutput, finalOutput); err != nil {
		return fmt.Errorf("publish analyzer output: %w", err)
	}
	return nil
}

func (d *Docker) Args(samplePath string) []string {
	return d.args(samplePath, "")
}

func (d *Docker) args(samplePath, containerName string) []string {
	image := d.ResolvedImageID
	if image == "" {
		image = d.Image
	}
	if image == "" {
		image = DefaultImage
	}
	args := []string{
		"run", "--rm",
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
		"--tmpfs=/tmp:rw,nosuid,nodev,size=2g,mode=700,uid=65532,gid=65532",
		"--mount=type=bind,src=" + samplePath + ",dst=/input/sample.exe,readonly",
	}
	if containerName != "" {
		args = append(args, "--name="+containerName)
	}
	return append(args, image)
}

func newContainerName() (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("create analyzer container name: %w", err)
	}
	return "jaq-analysis-" + hex.EncodeToString(random[:]), nil
}

func (d *Docker) cleanupContainer(name string) error {
	if d.Cleanup == nil || name == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Cleanup(ctx, "docker", []string{"rm", "--force", name}, io.Discard, io.Discard); err != nil {
		return err
	}
	return nil
}

func copyReadOnly(sourcePath, destinationPath string) (string, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("open sample for isolated copy: %w", err)
	}
	defer source.Close()
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
	if err != nil {
		return "", fmt.Errorf("create isolated sample copy: %w", err)
	}
	copyHash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, copyHash), io.LimitReader(source, MaxSampleCopySize+1))
	if err != nil {
		_ = destination.Close()
		return "", fmt.Errorf("copy sample for analyzer: %w", err)
	}
	if written > MaxSampleCopySize {
		_ = destination.Close()
		return "", fmt.Errorf("sample exceeds %d-byte analyzer copy limit", MaxSampleCopySize)
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		return "", fmt.Errorf("sync isolated sample copy: %w", err)
	}
	if err := destination.Close(); err != nil {
		return "", fmt.Errorf("close isolated sample copy: %w", err)
	}
	if err := os.Chmod(destinationPath, 0o444); err != nil {
		return "", fmt.Errorf("make isolated sample copy read-only: %w", err)
	}
	verification, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("reopen sample after isolated copy: %w", err)
	}
	verificationHash := sha256.New()
	verifiedBytes, hashErr := io.Copy(verificationHash, io.LimitReader(verification, MaxSampleCopySize+1))
	closeErr := verification.Close()
	if hashErr != nil {
		return "", fmt.Errorf("verify isolated sample copy: %w", hashErr)
	}
	if verifiedBytes > MaxSampleCopySize {
		return "", fmt.Errorf("sample exceeds %d-byte analyzer verification limit", MaxSampleCopySize)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close sample verification: %w", closeErr)
	}
	if !bytes.Equal(copyHash.Sum(nil), verificationHash.Sum(nil)) {
		return "", errors.New("sample changed while preparing isolated analyzer copy")
	}
	return hex.EncodeToString(copyHash.Sum(nil)), nil
}

func execute(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func timeoutFromEnv(name string, fallback time.Duration) time.Duration {
	if value := os.Getenv(name); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			if parsed > MaxTimeout {
				return MaxTimeout
			}
			return parsed
		}
	}
	return fallback
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

type limitedWriter struct {
	writer   io.Writer
	written  int64
	max      int64
	exceeded bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.max - w.written
	if remaining <= 0 || int64(len(p)) > remaining {
		w.exceeded = true
		return 0, fmt.Errorf("analyzer output exceeds %d bytes", w.max)
	}
	n, err := w.writer.Write(p)
	w.written += int64(n)
	return n, err
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
