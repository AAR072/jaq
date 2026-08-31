package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzerImageIsPinnedAndRootless(t *testing.T) {
	dockerfile := filepath.Join("..", "..", "analysis", "Dockerfile")
	contents, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{
		"Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip",
		"93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54",
		"sha256sum --check --strict",
		"USER 65532:65532",
		"eclipse-temurin:21-jdk-jammy@sha256:ce5767b7222312d42395f5bab033cd91f09e44032a2f21bdfd7b5b912dbe1e77",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("Dockerfile missing %q", required)
		}
	}
}

func TestEntrypointOnlyImportsSample(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "analysis", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, required := range []string{"-import", "/input/sample.exe", "-postScript", "-deleteProject"} {
		if !strings.Contains(text, required) {
			t.Errorf("entrypoint missing %q", required)
		}
	}
	for _, forbidden := range []string{"curl ", "wget ", "powershell", "wine "} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("entrypoint contains forbidden runtime operation %q", forbidden)
		}
	}
}
