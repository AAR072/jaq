package analyzer

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerArgsEnforceIsolation(t *testing.T) {
	d := &Docker{Image: "test-image"}
	args := strings.Join(d.Args("/safe/sample.exe"), " ")
	for _, required := range []string{
		"--pull=never", "--platform=linux/amd64", "--network=none", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--user=65532:65532",
		"src=/safe/sample.exe,dst=/input/sample.exe,readonly",
		"--tmpfs=/tmp:rw,nosuid,nodev", "test-image",
	} {
		if !strings.Contains(args, required) {
			t.Errorf("missing isolation argument %q in %s", required, args)
		}
	}
	if strings.Contains(args, "http://") || strings.Contains(args, "https://") {
		t.Fatalf("runtime arguments contain a network destination: %s", args)
	}
	if strings.Contains(args, "dst=/output") || strings.Count(args, "--mount=") != 1 {
		t.Fatalf("container received an unexpected writable host mount: %s", args)
	}
}

func TestImageIDIsRecordedFromLocalDocker(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	d := &Docker{Image: "test-image", Execute: func(_ context.Context, name string, args []string, stdout, _ io.Writer) error {
		command := strings.Join(args, " ")
		if name != "docker" {
			return errors.New("unexpected inspect command")
		}
		var value string
		switch command {
		case `context inspect --format={{(index .Endpoints "docker").Host}}`:
			value = "unix:///local/docker.sock\n"
		case "image inspect --format={{.Id}} test-image":
			value = "sha256:" + strings.Repeat("a", 64) + "\n"
		default:
			return errors.New("unexpected inspect command")
		}
		_, err := stdout.Write([]byte(value))
		return err
	}}
	id, err := d.ImageID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("unexpected image ID %q", id)
	}
	args := d.Args("/safe/sample.exe")
	if args[len(args)-1] != id {
		t.Fatalf("analyzer did not switch to immutable image ID: %v", args)
	}
}

func TestImageIDRejectsRemoteDockerContext(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://remote.example:2376")
	d := &Docker{Image: "test-image", Execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
		t.Fatal("Docker must not be contacted for a remote DOCKER_HOST")
		return nil
	}}
	if _, err := d.ImageID(context.Background()); err == nil || !strings.Contains(err.Error(), "non-local") {
		t.Fatalf("expected remote context rejection, got %v", err)
	}
}

func TestDockerAnalyzePropagatesCrash(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(sample, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Docker{Image: "test", Timeout: time.Second,
		Execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
			return errors.New("exit 17")
		},
	}
	err := d.Analyze(context.Background(), sample, filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "exit 17") {
		t.Fatalf("expected analyzer crash, got %v", err)
	}
}

func TestDockerAnalyzeTimeout(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(sample, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleaned := false
	d := &Docker{Image: "test", Timeout: time.Millisecond,
		Execute: func(ctx context.Context, _ string, _ []string, _, _ io.Writer) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Cleanup: func(_ context.Context, name string, args []string, _, _ io.Writer) error {
			cleaned = name == "docker" && len(args) == 3 && args[0] == "rm" && args[1] == "--force" && strings.HasPrefix(args[2], "jaq-analysis-")
			return nil
		},
	}
	err := d.Analyze(context.Background(), sample, filepath.Join(dir, "out"))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if !cleaned {
		t.Fatal("timed-out daemon-side container was not force-cleaned")
	}
}

func TestDockerAnalyzeUsesReadOnlySampleCopyAndNoWritableMount(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.exe")
	evidenceDir := filepath.Join(dir, "evidence")
	if err := os.WriteFile(sample, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(evidenceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidenceDir, "run-manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mountedSample string
	d := &Docker{Image: "test", Timeout: time.Second,
		Execute: func(_ context.Context, _ string, args []string, stdout, _ io.Writer) error {
			for _, argument := range args {
				if strings.Contains(argument, "dst=/input/sample.exe") {
					for _, part := range strings.Split(strings.TrimPrefix(argument, "--mount="), ",") {
						if strings.HasPrefix(part, "src=") {
							mountedSample = strings.TrimPrefix(part, "src=")
						}
					}
				}
			}
			if mountedSample == "" {
				return errors.New("missing sample mount")
			}
			info, err := os.Stat(mountedSample)
			if err != nil {
				return err
			}
			if info.Mode().Perm() != 0o444 {
				return errors.New("staged sample is not mode 0444")
			}
			_, err = stdout.Write([]byte("{}\n"))
			return err
		},
	}
	if err := d.Analyze(context.Background(), sample, evidenceDir); err != nil {
		t.Fatal(err)
	}
	if mountedSample == sample || !strings.HasPrefix(mountedSample, evidenceDir+string(os.PathSeparator)) {
		t.Fatalf("container did not receive an isolated sample copy: %q", mountedSample)
	}
	if _, err := os.Stat(filepath.Join(evidenceDir, "raw-observations.jsonl")); err != nil {
		t.Fatalf("staged evidence was not published: %v", err)
	}
}

func TestDockerAnalyzeExpectedRejectsChangedArtifact(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.exe")
	if err := os.WriteFile(sample, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Docker{Image: "test", Timeout: time.Second, Execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
		t.Fatal("container must not run for a hash mismatch")
		return nil
	}}
	err := d.AnalyzeExpected(context.Background(), sample, filepath.Join(dir, "evidence"), strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "sample changed") {
		t.Fatalf("expected artifact identity rejection, got %v", err)
	}
}
