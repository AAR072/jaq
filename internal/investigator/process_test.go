package investigator

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestProgressFilterDisplaysOnlyValidatedProgressLines(t *testing.T) {
	var display bytes.Buffer
	filter := newProgressFilter(&display)
	chunks := []string{
		"provider warning\nJAQ_PROG",
		"RESS [research] started\nJAQ_PROGRESS [research] investigation cap reached; recording final findings at cost=$0.10000\nJAQ_PROGRESS [research] preparing final summary at cost=$0.10400\nJAQ_PROGRESS [research] dossier compiled locally from 3 recorded findings\nJAQ_PROGRESS sample-derived text\n",
		"JAQ_PROGRESS [research] tool #5: r2_decompile_function\npartial diagnostic",
	}
	for _, chunk := range chunks {
		if _, err := filter.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	filter.Flush()
	shown := display.String()
	if !strings.Contains(shown, "jaq: [research] started") ||
		!strings.Contains(shown, "jaq: [research] investigation cap reached; recording final findings at cost=$0.10000") ||
		!strings.Contains(shown, "jaq: [research] preparing final summary at cost=$0.10400") ||
		!strings.Contains(shown, "jaq: [research] dossier compiled locally from 3 recorded findings") ||
		!strings.Contains(shown, "jaq: [research] tool #5: r2_decompile_function") ||
		strings.Contains(shown, "sample-derived") || strings.Contains(shown, "provider warning") {
		t.Fatalf("unexpected displayed progress: %q", shown)
	}
	diagnostics := filter.Diagnostics()
	if !strings.Contains(diagnostics, "provider warning") ||
		!strings.Contains(diagnostics, "sample-derived text") ||
		!strings.Contains(diagnostics, "partial diagnostic") {
		t.Fatalf("unexpected buffered diagnostics: %q", diagnostics)
	}
	if _, err := filter.Write(bytes.Repeat([]byte("x"), 70*1024)); err != nil {
		t.Fatal(err)
	}
	if len(filter.pending) != 0 || len(filter.Diagnostics()) > 64*1024 {
		t.Fatal("unterminated diagnostic input was not bounded")
	}
}

func TestProcessRequiresModel(t *testing.T) {
	t.Setenv("JAQ_INVESTIGATOR_MODEL", "")
	p := NewProcess("")
	err := p.Investigate(context.Background(), filepath.Join(t.TempDir(), "evidence"))
	if err == nil || !strings.Contains(err.Error(), "JAQ_INVESTIGATOR_MODEL") {
		t.Fatalf("expected missing-model error, got %v", err)
	}
}

func TestRuntimeVersionsAreExplicit(t *testing.T) {
	t.Setenv("JAQ_PYTHON", "")
	p := NewProcess("")
	versions, err := p.RuntimeVersions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if versions.Python == "" || versions.LiteLLM == "" || versions.Node == "" || versions.Pi == "" {
		t.Fatalf("incomplete runtime versions: %#v", versions)
	}
}

func TestRedactSensitiveRemovesProviderCredential(t *testing.T) {
	secret := "ds-secret-value-123456"
	t.Setenv("DEEPSEEK_API_KEY", secret)
	message := RedactSensitive("provider failed api_key=" + secret + " Authorization: Bearer token-123456789012")
	if strings.Contains(message, secret) || strings.Contains(message, "token-123456789012") {
		t.Fatalf("credential remained in diagnostic: %q", message)
	}
}

func TestConfigureSandboxStoresOnlyLogicalSessionMetadata(t *testing.T) {
	p := NewProcess("")
	p.ConfigureSandbox("jaq-sandbox-test", strings.Repeat("a", 64), "6.2.0", "1.8.6")
	if p.SandboxContainer != "jaq-sandbox-test" || p.SampleSHA256 != strings.Repeat("a", 64) || p.RadareVersion != "6.2.0" || p.MCPVersion != "1.8.6" {
		t.Fatalf("sandbox configuration mismatch: %#v", p)
	}
}
