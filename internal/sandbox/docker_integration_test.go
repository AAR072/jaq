//go:build integration

package sandbox_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaq-project/jaq/internal/evidence"
	"github.com/jaq-project/jaq/internal/sandbox"
	"github.com/jaq-project/jaq/internal/testutil"
)

type containerInspect struct {
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode    string   `json:"NetworkMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapDrop        []string `json:"CapDrop"`
		Memory         int64    `json:"Memory"`
		NanoCPUs       int64    `json:"NanoCpus"`
		PidsLimit      int64    `json:"PidsLimit"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
		Type        string `json:"Type"`
	} `json:"Mounts"`
}

func TestPersistentSandboxRuntimeContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	root := t.TempDir()
	sample := filepath.Join(root, "sample.exe")
	fixture := testutil.HarmlessPEFixture()
	if err := os.WriteFile(sample, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixture)
	runner := sandbox.NewDocker()
	imageID, err := runner.ImageID(ctx)
	if err != nil {
		t.Fatalf("image %s is not available locally: %v", sandbox.DefaultImage, err)
	}
	session, err := runner.Start(ctx, sample, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = session.Close(context.Background())
		}
	}()
	if session.ImageID() != imageID || !strings.HasPrefix(session.ImageID(), "sha256:") {
		t.Fatalf("session image identity is not immutable: %q %q", session.ImageID(), imageID)
	}

	var inspect []containerInspect
	if err := dockerJSON(ctx, &inspect, "inspect", session.ContainerName()); err != nil {
		t.Fatal(err)
	}
	if len(inspect) != 1 {
		t.Fatalf("docker inspect returned %d containers", len(inspect))
	}
	state := inspect[0]
	if !state.State.Running {
		t.Fatal("sandbox entrypoint exited instead of keeping the container alive")
	}
	if state.Config.User != "65532:65532" {
		t.Fatalf("container user = %q", state.Config.User)
	}
	if state.HostConfig.NetworkMode != "none" {
		t.Fatalf("container has network access: mode=%q networks=%v", state.HostConfig.NetworkMode, state.NetworkSettings.Networks)
	}
	if !state.HostConfig.ReadonlyRootfs {
		t.Fatal("container root filesystem is writable")
	}
	if !contains(state.HostConfig.CapDrop, "ALL") {
		t.Fatalf("container capabilities were not dropped: %v", state.HostConfig.CapDrop)
	}
	if state.HostConfig.Memory != 4<<30 || state.HostConfig.NanoCPUs != 2_000_000_000 || state.HostConfig.PidsLimit != 256 {
		t.Fatalf("container resource limits are not bounded as expected: %#v", state.HostConfig)
	}
	sampleMounts := 0
	for _, mount := range state.Mounts {
		if mount.Destination == "/input/sample.exe" {
			sampleMounts++
			if mount.Type != "bind" || mount.RW {
				t.Fatalf("unexpected sample mount contract: %#v", mount)
			}
		}
		if mount.Type == "bind" && mount.RW {
			t.Fatalf("unexpected writable host bind mount: %#v", mount)
		}
	}
	if sampleMounts != 1 {
		t.Fatalf("expected exactly one sample mount, got %d: %#v", sampleMounts, state.Mounts)
	}

	for _, binary := range []string{"python3", "objdump", "r2", "r2mcp"} {
		if _, err := dockerExec(ctx, session.ContainerName(), "sh", "-c", "command -v "+binary); err != nil {
			t.Fatalf("required sandbox binary %s is unavailable: %v", binary, err)
		}
	}
	plugins, err := dockerExec(ctx, session.ContainerName(), "r2", "-L")
	if err != nil {
		t.Fatalf("could not audit Radare I/O plugins: %v", err)
	}
	for _, forbidden := range []string{"fd", "procpid", "pvm", "r2k", "r2web", "reg", "self", "gdb", "http", "ptrace", "socket", "winedbg", "winkd"} {
		for _, line := range strings.Split(string(plugins), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 && fields[1] == forbidden {
				t.Fatalf("forbidden Radare I/O plugin %q is present: %s", forbidden, line)
			}
		}
	}
	debuggers, err := dockerExec(ctx, session.ContainerName(), "r2", "-N", "-n", "-q0", "-c", "dLq", "/bin/true")
	if err != nil || strings.Trim(string(debuggers), "\x00\r\n ") != "null" {
		t.Fatalf("unexpected Radare debugger backends: %q err=%v", debuggers, err)
	}
	if _, err := dockerExec(ctx, session.ContainerName(), "sh", "-c", "touch /work/.probe && test -w /work"); err != nil {
		t.Fatalf("/work is not writable: %v", err)
	}
	if _, err := dockerExec(ctx, session.ContainerName(), "sh", "-c", "printf '#!/bin/sh\\nexit 0\\n' >/work/helper.sh && chmod 700 /work/helper.sh && /work/helper.sh"); err != nil {
		t.Fatalf("helper program could not execute from /work: %v", err)
	}
	if _, err := dockerExec(ctx, session.ContainerName(), "sh", "-c", "touch /input/sample.exe"); err == nil {
		t.Fatal("read-only sample mount accepted a write")
	}
	if _, err := dockerExec(ctx, session.ContainerName(), "sh", "-c", "cp /input/sample.exe /work/sample.exe && chmod 700 /work/sample.exe && /work/sample.exe"); err == nil {
		t.Fatal("PE unexpectedly executed natively from scratch")
	}

	evidencePath := filepath.Join(root, "observations.jsonl")
	base := evidence.NewObservation(
		"artifact.hash.sha256", hex.EncodeToString(digest[:]), hex.EncodeToString(digest[:]),
		evidence.ArtifactLocation{Artifact: "sample"},
		evidence.AnalyzerIdentity{Name: "jaq-pe", Version: "0.1.0"},
		evidence.Provenance{Source: "fixture", InputSHA256: hex.EncodeToString(digest[:])},
	)
	if err := evidence.WriteObservationsFile(evidencePath, []evidence.Observation{base}); err != nil {
		t.Fatal(err)
	}
	projectRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	pythonCode := `
import sys
from jaq_investigator.evidence import EvidenceStore
from jaq_investigator.runtime import StaticToolRuntime
s = EvidenceStore(sys.argv[2])
r = StaticToolRuntime(container=sys.argv[1], evidence=s, sample_sha256=sys.argv[3], radare_version="6.2.0", mcp_version="1.8.6")
try:
    a = r.execute("r2_analyze", {"level": 1, "timeout_seconds": 30})
    i = r.execute("r2_show_info", {})
    c = r.execute("run_static_command", {"command": "python3 -c 'print(\"offline-helper-ok\")'"})
    assert a["observation_id"] and i["observation_id"] and c["observation_id"]
finally:
    r.close()
`
	command := exec.CommandContext(ctx, "python3", "-c", pythonCode, session.ContainerName(), evidencePath, hex.EncodeToString(digest[:]))
	command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(projectRoot, "python"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("live MCP/static-command lifecycle failed: %v: %s", err, output)
	}
	if observations, err := evidence.ReadObservationsFile(evidencePath); err != nil {
		t.Fatalf("Go rejected live Python tool evidence: %v", err)
	} else if len(observations) != 11 { // base + request/result for version, open, analyze, info, command
		t.Fatalf("live tool ledger contains %d observations, want 11", len(observations))
	}

	if err := session.Close(ctx); err != nil {
		t.Fatal(err)
	}
	closed = true
	if output, err := dockerOutput(ctx, "ps", "-a", "--filter", "name=^"+session.ContainerName()+"$", "--format", "{{.Names}}"); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(output)) != "" {
		t.Fatalf("container remains after Close: %q", output)
	}
}

func dockerJSON(ctx context.Context, value any, args ...string) error {
	output, err := dockerOutput(ctx, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(output, value); err != nil {
		return fmt.Errorf("decode docker JSON: %w: %s", err, output)
	}
	return nil
}

func dockerExec(ctx context.Context, container string, args ...string) ([]byte, error) {
	return dockerOutput(ctx, append([]string{"exec", container}, args...)...)
}

func dockerOutput(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
