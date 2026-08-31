package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaq-project/jaq/internal/evidence"
	peinfo "github.com/jaq-project/jaq/internal/pe"
	"github.com/jaq-project/jaq/internal/testutil"
)

type staticAnalyzerFunc func(context.Context, string, string) error

func (fn staticAnalyzerFunc) Analyze(ctx context.Context, sample, output string) error {
	return fn(ctx, sample, output)
}

type investigatorFunc func(context.Context, string) error

func (fn investigatorFunc) Investigate(ctx context.Context, output string) error {
	return fn(ctx, output)
}

func TestControllerCompletesMockedEndToEndRun(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(sample, testutil.HarmlessPEFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "run")
	controller := mockedController(t, nil)
	if err := controller.Analyze(context.Background(), sample, output); err != nil {
		t.Fatal(err)
	}
	for _, name := range persistedOutputs {
		if info, err := os.Stat(filepath.Join(output, name)); err != nil || info.Size() == 0 {
			t.Errorf("missing nonempty %s: info=%v err=%v", name, info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(output, "raw-observations.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transient raw evidence remains: %v", err)
	}
	manifest, err := evidence.ReadManifest(filepath.Join(output, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "completed" || manifest.Versions["ghidra"] != "12.1.3" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	observations, err := evidence.ReadObservationsFile(filepath.Join(output, "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) < 10 {
		t.Fatalf("expected rich native and Ghidra evidence, got %d", len(observations))
	}
	claims, err := evidence.ReadClaims(filepath.Join(output, "claims.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.ValidateClaims(claims, observations); err != nil {
		t.Fatal(err)
	}
}

func TestControllerRecordsAnalyzerFailure(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(sample, testutil.HarmlessPEFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "run")
	controller := mockedController(t, errors.New("synthetic analyzer crash"))
	err := controller.Analyze(context.Background(), sample, output)
	if err == nil || !strings.Contains(err.Error(), "synthetic analyzer crash") {
		t.Fatalf("expected analyzer error, got %v", err)
	}
	manifest, readErr := evidence.ReadManifest(filepath.Join(output, "run-manifest.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if manifest.Status != "failed" || !strings.Contains(manifest.Error, "synthetic analyzer crash") {
		t.Fatalf("failure was not recorded: %#v", manifest)
	}
}

func TestControllerRedactsCredentialFromFailureManifest(t *testing.T) {
	secret := "deepseek-secret-value-123456"
	t.Setenv("DEEPSEEK_API_KEY", secret)
	sample := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(sample, testutil.HarmlessPEFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "run")
	controller := mockedController(t, errors.New("provider echoed "+secret))
	if err := controller.Analyze(context.Background(), sample, output); err == nil {
		t.Fatal("expected analyzer failure")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("credential leaked in returned error: %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(output, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), secret) {
		t.Fatalf("credential leaked into manifest: %s", contents)
	}
}

func TestControllerRejectsMissingModelBeforeAnalyzer(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(sample, testutil.HarmlessPEFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	controller := mockedController(t, nil)
	controller.Config.InvestigatorModel = ""
	controller.Analyzer = staticAnalyzerFunc(func(context.Context, string, string) error {
		called = true
		return nil
	})
	output := filepath.Join(t.TempDir(), "run")
	err := controller.Analyze(context.Background(), sample, output)
	if err == nil || !strings.Contains(err.Error(), "JAQ_INVESTIGATOR_MODEL") {
		t.Fatalf("expected missing-model error, got %v", err)
	}
	if called {
		t.Fatal("expensive analyzer ran before model configuration was validated")
	}
	if _, statErr := os.Stat(filepath.Join(output, "run-manifest.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("configuration failure unexpectedly created a run manifest: %v", statErr)
	}
}

func TestControllerRejectsNonPE(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "not-pe.txt")
	if err := os.WriteFile(sample, []byte("plain inert text"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := mockedController(t, nil)
	err := controller.Analyze(context.Background(), sample, filepath.Join(t.TempDir(), "run"))
	if err == nil || !strings.Contains(err.Error(), "Portable Executable") {
		t.Fatalf("expected PE rejection, got %v", err)
	}
}

func TestIdenticalInputsProduceIdenticalEvidence(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(sample, testutil.HarmlessPEFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := mockedController(t, nil)
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	if err := controller.Analyze(context.Background(), sample, first); err != nil {
		t.Fatal(err)
	}
	if err := controller.Analyze(context.Background(), sample, second); err != nil {
		t.Fatal(err)
	}
	firstEvidence, _ := os.ReadFile(filepath.Join(first, "observations.jsonl"))
	secondEvidence, _ := os.ReadFile(filepath.Join(second, "observations.jsonl"))
	if string(firstEvidence) != string(secondEvidence) {
		t.Fatal("identical inputs and analyzers produced different evidence packages")
	}
}

func TestChangingModelDoesNotChangeStaticEvidence(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(sample, testutil.HarmlessPEFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	firstController := mockedController(t, nil)
	secondController := mockedController(t, nil)
	secondController.Config.InvestigatorModel = "another-provider/another-model"
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	if err := firstController.Analyze(context.Background(), sample, first); err != nil {
		t.Fatal(err)
	}
	if err := secondController.Analyze(context.Background(), sample, second); err != nil {
		t.Fatal(err)
	}
	firstEvidence, _ := os.ReadFile(filepath.Join(first, "observations.jsonl"))
	secondEvidence, _ := os.ReadFile(filepath.Join(second, "observations.jsonl"))
	if string(firstEvidence) != string(secondEvidence) {
		t.Fatal("model selection changed deterministic static evidence IDs or content")
	}
}

func mockedController(t *testing.T, analyzerError error) *Controller {
	t.Helper()
	promptHash := strings.Repeat("a", 64)
	controller := &Controller{
		AnalyzePE: func(path string) (*peinfo.Analysis, error) { return peinfo.AnalyzeFile(path) },
		Config: Config{
			AnalyzerImage: "jaq-ghidra:12.1.3", InvestigatorModel: "mock/investigator",
			PromptHashes: map[string]string{"investigator": promptHash, "judge": promptHash},
		},
	}
	controller.Analyzer = staticAnalyzerFunc(func(_ context.Context, _, output string) error {
		if analyzerError != nil {
			return analyzerError
		}
		line := `{"type":"ghidra.function","raw_value":"int entry(void)","normalized_value":"entry","artifact_location":"va:00401000","analyzer":{"name":"ghidra","version":"12.1.3"},"provenance":{"source":"function-manager"}}` + "\n"
		return os.WriteFile(filepath.Join(output, "raw-observations.jsonl"), []byte(line), 0o600)
	})
	controller.Investigator = investigatorFunc(func(_ context.Context, output string) error {
		observations, err := evidence.ReadObservationsFile(filepath.Join(output, "observations.jsonl"))
		if err != nil {
			return err
		}
		claim := evidence.NewClaim("claim-1", "capability", "The fixture contains deterministic static evidence.", 0.8, []string{observations[0].ID})
		claim.AssetRole = "fixture"
		claims := []evidence.Claim{claim}
		if err := evidence.WriteClaims(filepath.Join(output, "claims.json"), claims); err != nil {
			return err
		}
		confidence := 0.8
		score := evidence.Score{
			SchemaVersion: evidence.ScoreSchemaVersion, Accepted: 1,
			VerificationResults: []evidence.ClaimVerification{{
				SchemaVersion: evidence.ScoreSchemaVersion, ClaimID: claim.ID, Status: "accepted",
				Accepted: true, EvidenceIDs: claim.EvidenceIDs, Confidence: &confidence,
			}}, Confidence: confidence, Usage: map[string]any{"investigator": map[string]any{"total_tokens": 10}},
		}
		if err := evidence.WriteScore(filepath.Join(output, "score.json"), score, claims, observations); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(output, "report.md"), []byte("# JAQ Intelligence Dossier\n\nAccepted claim `claim-1`.\n"), 0o600)
	})
	return controller
}
