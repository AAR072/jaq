package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxImagePinsStaticToolchainAndExcludesDynamicRuntimes(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "analysis", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"radare2-6.2.0.tar.xz",
		"098488a3a0a4c11b893ae9e74496cf65561d17cefd9b7f2661a48b4be97b663a",
		"d74b6b9855622c9a7070165b1961262afd686a3f",
		"org.opencontainers.image.r2mcp.version=\"1.8.6\"",
		"USER 65532:65532",
		"binutils build-essential file",
		"--disable-debugger --without-ptrace-wrap --disable-loadlibs",
		"--without-qjs",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("Dockerfile missing %q", required)
		}
	}
}

func TestSandboxEntrypointOnlyKeepsControllerSessionAlive(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "analysis", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	if !strings.Contains(text, "sleep infinity") {
		t.Fatal("entrypoint does not preserve the controller-owned session")
	}
	for _, forbidden := range []string{"sample.exe", "r2 ", "r2mcp", "python", "objdump", "curl", "wget"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("entrypoint performs analysis/network action %q", forbidden)
		}
	}
}
