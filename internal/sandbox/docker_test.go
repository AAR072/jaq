package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type invocation struct {
	name string
	args []string
}

type fakeRuntime struct {
	mu            sync.Mutex
	invocations   []invocation
	startErr      error
	blockStart    bool
	cleanupErr    error
	cleanupCtx    context.Context
	cleanupCtxErr error
}

func (f *fakeRuntime) Execute(ctx context.Context, name string, args []string, stdout, stderr io.Writer) error {
	f.mu.Lock()
	f.invocations = append(f.invocations, invocation{name: name, args: append([]string(nil), args...)})
	startErr := f.startErr
	blockStart := f.blockStart
	f.mu.Unlock()
	isStart := len(args) > 0 && args[0] == "run"
	if blockStart && isStart {
		<-ctx.Done()
		return ctx.Err()
	}
	if startErr != nil && isStart {
		return startErr
	}
	if len(args) > 0 && args[0] == "context" {
		_, _ = io.WriteString(stdout, "unix:///var/run/docker.sock\n")
		return nil
	}
	if len(args) > 0 && args[0] == "image" {
		_, _ = io.WriteString(stdout, "sha256:"+strings.Repeat("a", 64)+"\n")
		return nil
	}
	return nil
}

func (f *fakeRuntime) Cleanup(ctx context.Context, name string, args []string, _, _ io.Writer) error {
	f.mu.Lock()
	f.invocations = append(f.invocations, invocation{name: name, args: append([]string(nil), args...)})
	f.cleanupCtx = ctx
	f.cleanupCtxErr = ctx.Err()
	err := f.cleanupErr
	f.mu.Unlock()
	return err
}

func (f *fakeRuntime) calls() []invocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]invocation, len(f.invocations))
	copy(result, f.invocations)
	return result
}

func TestImageIDRejectsRemoteContextAndStoresImmutableID(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://remote.example:2376")
	fake := &fakeRuntime{}
	docker := &Docker{Image: DefaultImage, Execute: fake.Execute, Cleanup: fake.Cleanup}
	if _, err := docker.ImageID(context.Background()); err == nil || !strings.Contains(err.Error(), "non-local") {
		t.Fatalf("expected non-local context rejection, got %v", err)
	}
	if len(fake.calls()) != 0 {
		t.Fatal("remote Docker context was contacted")
	}

	t.Setenv("DOCKER_HOST", "")
	id, err := docker.ImageID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "sha256:"+strings.Repeat("a", 64) || docker.ResolvedImageID != id {
		t.Fatalf("immutable image ID was not stored: %q %#v", id, docker)
	}
}

func TestStartUsesBoundedReadOnlyArtifactAndImmutableImage(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	data := []byte("inert PE bytes are staged as data")
	if err := os.WriteFile(sample, data, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	expected := hex.EncodeToString(hash[:])
	fake := &fakeRuntime{}
	imageID := "sha256:" + strings.Repeat("b", 64)
	docker := &Docker{Image: "mutable-tag", ResolvedImageID: imageID, Execute: fake.Execute, Cleanup: fake.Cleanup}
	session, err := docker.Start(context.Background(), sample, expected)
	if err != nil {
		t.Fatal(err)
	}
	if session.ContainerName() == "" || session.ImageID() != imageID {
		t.Fatalf("unexpected session identity: %q %q", session.ContainerName(), session.ImageID())
	}
	stageInfo, err := os.Stat(filepath.Join(session.stageDir, "sample.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if stageInfo.Mode().Perm() != 0o444 {
		t.Fatalf("staged PE mode = %o, want 0444", stageInfo.Mode().Perm())
	}

	calls := fake.calls()
	if len(calls) != 2 || calls[0].args[0] != "context" {
		t.Fatalf("unexpected runtime calls: %#v", calls)
	}
	if err := assertSandboxArgs(calls[1].args, imageID, session.ContainerName(), session.stageDir); err != nil {
		t.Fatal(err)
	}

	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("idempotent close returned a different error: %v", err)
	}
	if _, err := os.Stat(session.stageDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private stage remains after close: %v", err)
	}
	calls = fake.calls()
	if len(calls) != 3 || calls[2].name != "docker" || len(calls[2].args) != 3 || calls[2].args[0] != "rm" || calls[2].args[1] != "--force" || calls[2].args[2] != session.ContainerName() {
		t.Fatalf("unexpected cleanup calls: %#v", calls)
	}
}

func assertSandboxArgs(args []string, imageID, containerName, stageDir string) error {
	joined := strings.Join(args, " ")
	for _, required := range []string{
		"run", "--detach", "--rm", "--pull=never", "--platform=linux/amd64",
		"--network=none", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--pids-limit=256", "--memory=4g",
		"--cpus=2", "--user=65532:65532", "--tmpfs=/tmp:", "--tmpfs=/work:",
		"--workdir=/work", "--mount=type=bind,src=" + filepath.Join(stageDir, "sample.exe") + ",dst=/input/sample.exe,readonly",
		"--name=" + containerName, imageID,
	} {
		if !strings.Contains(joined, required) {
			return errors.New("missing sandbox argument " + required + " in " + joined)
		}
	}
	if strings.Contains(joined, "--env") || strings.Contains(joined, "dst=/work") || strings.Contains(joined, "dst=/output") {
		return errors.New("sandbox args expose host environment or writable mounts: " + joined)
	}
	if strings.Count(joined, "--mount=") != 1 {
		return errors.New("sandbox must have exactly one mount: " + joined)
	}
	if args[len(args)-1] != imageID {
		return errors.New("sandbox did not use immutable image ID as final image argument")
	}
	return nil
}

func TestStartRejectsArtifactHashBeforeContainer(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	if err := os.WriteFile(sample, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRuntime{}
	docker := &Docker{ResolvedImageID: "sha256:" + strings.Repeat("a", 64), Execute: fake.Execute, Cleanup: fake.Cleanup}
	if _, err := docker.Start(context.Background(), sample, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "sample changed") {
		t.Fatalf("expected sample hash rejection, got %v", err)
	}
	if len(fake.calls()) != 0 {
		t.Fatal("container started after artifact hash mismatch")
	}
}

func TestStartResolvesImageWhenNoIDWasPreloaded(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	if err := os.WriteFile(sample, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRuntime{}
	docker := &Docker{Image: DefaultImage, Execute: fake.Execute, Cleanup: fake.Cleanup}
	session, err := docker.Start(context.Background(), sample, "")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(context.Background())
	if session.ImageID() != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("Start did not resolve immutable image ID: %q", session.ImageID())
	}
	calls := fake.calls()
	if len(calls) != 3 || calls[0].args[0] != "context" || calls[1].args[0] != "image" || calls[2].args[0] != "run" {
		t.Fatalf("unexpected image resolution/start calls: %#v", calls)
	}
	if calls[2].args[len(calls[2].args)-1] != session.ImageID() {
		t.Fatalf("start did not use resolved image ID: %#v", calls[2].args)
	}
}

func TestStartCleansContainerAndStageOnRuntimeFailure(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	if err := os.WriteFile(sample, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRuntime{startErr: errors.New("docker start failed")}
	docker := &Docker{ResolvedImageID: "sha256:" + strings.Repeat("a", 64), Execute: fake.Execute, Cleanup: fake.Cleanup}
	if _, err := docker.Start(context.Background(), sample, ""); err == nil || !strings.Contains(err.Error(), "docker start failed") {
		t.Fatalf("expected start failure, got %v", err)
	}
	calls := fake.calls()
	if len(calls) != 3 || len(calls[2].args) != 3 || calls[2].args[0] != "rm" {
		t.Fatalf("partial start did not force cleanup: %#v", calls)
	}
}

func TestCloseUsesIndependentCleanupContext(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	if err := os.WriteFile(sample, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRuntime{}
	docker := &Docker{ResolvedImageID: "sha256:" + strings.Repeat("a", 64), Execute: fake.Execute, Cleanup: fake.Cleanup}
	session, err := docker.Start(context.Background(), sample, "")
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.Close(canceled); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	cleanupCtxErr := fake.cleanupCtxErr
	fake.mu.Unlock()
	if cleanupCtxErr != nil {
		t.Fatalf("cleanup inherited canceled context: %v", cleanupCtxErr)
	}
}

func TestStartTimeoutCleansNamedContainer(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	if err := os.WriteFile(sample, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRuntime{blockStart: true}
	docker := &Docker{ResolvedImageID: "sha256:" + strings.Repeat("a", 64), Timeout: time.Millisecond, Execute: fake.Execute, Cleanup: fake.Cleanup}
	if _, err := docker.Start(context.Background(), sample, ""); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected bounded start timeout, got %v", err)
	}
	calls := fake.calls()
	if len(calls) != 3 || calls[2].args[0] != "rm" {
		t.Fatalf("timeout did not invoke force cleanup: %#v", calls)
	}
}

func TestCloseRetriesTransientContainerCleanupFailure(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	if err := os.WriteFile(sample, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeRuntime{}
	docker := &Docker{ResolvedImageID: "sha256:" + strings.Repeat("a", 64), Execute: fake.Execute, Cleanup: fake.Cleanup}
	session, err := docker.Start(context.Background(), sample, "")
	if err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.cleanupErr = errors.New("temporary Docker failure")
	fake.mu.Unlock()
	if err := session.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "temporary Docker failure") {
		t.Fatalf("expected transient cleanup failure, got %v", err)
	}
	if _, err := os.Stat(session.stageDir); err != nil {
		t.Fatalf("stage removed before container cleanup could be retried: %v", err)
	}
	fake.mu.Lock()
	fake.cleanupErr = nil
	fake.mu.Unlock()
	if err := session.Close(context.Background()); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if _, err := os.Stat(session.stageDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage remains after successful retry: %v", err)
	}
}

func TestStartRechecksLocalContextWithPreloadedImageID(t *testing.T) {
	directory := t.TempDir()
	sample := filepath.Join(directory, "sample.exe")
	if err := os.WriteFile(sample, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "tcp://remote.example:2376")
	fake := &fakeRuntime{}
	docker := &Docker{ResolvedImageID: "sha256:" + strings.Repeat("a", 64), Execute: fake.Execute, Cleanup: fake.Cleanup}
	if _, err := docker.Start(context.Background(), sample, ""); err == nil || !strings.Contains(err.Error(), "non-local") {
		t.Fatalf("expected local-context recheck failure, got %v", err)
	}
	if len(fake.calls()) != 0 {
		t.Fatal("remote Docker context was contacted")
	}
}
