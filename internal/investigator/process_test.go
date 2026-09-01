package investigator

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

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
