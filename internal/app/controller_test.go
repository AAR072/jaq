package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaq-project/jaq/internal/evidence"
	peinfo "github.com/jaq-project/jaq/internal/pe"
	"github.com/jaq-project/jaq/internal/testutil"
)

type fakeSession struct {
	name    string
	imageID string
	closed  bool
}

func (s *fakeSession) ContainerName() string { return s.name }
func (s *fakeSession) ImageID() string {
	if s.imageID != "" {
		return s.imageID
	}
	return "sha256:" + strings.Repeat("b", 64)
}
func (s *fakeSession) Close(context.Context) error {
	s.closed = true
	return nil
}

type fakeInvestigator struct {
	configured bool
	run        func(context.Context, string) error
}

func (f *fakeInvestigator) ConfigureSandbox(container, sampleSHA, radare, mcp string) {
	f.configured = strings.HasPrefix(container, "jaq-sandbox-") && len(sampleSHA) == 64 && radare == "6.2.0" && mcp == "1.8.6"
}

func (f *fakeInvestigator) Investigate(ctx context.Context, output string) error {
	if !f.configured {
		return errors.New("sandbox was not configured")
	}
	return f.run(ctx, output)
}

func TestControllerCompletesMockedEndToEndRun(t *testing.T) {
	sample := writeFixture(t)
	output := filepath.Join(t.TempDir(), "run")
	controller, session := mockedController(t, nil)
	if err := controller.Analyze(context.Background(), sample, output); err != nil {
		t.Fatal(err)
	}
	for _, name := range persistedOutputs {
		if info, err := os.Stat(filepath.Join(output, name)); err != nil || info.Size() == 0 {
			t.Errorf("missing nonempty %s: info=%v err=%v", name, info, err)
		}
	}
	manifest, err := evidence.ReadManifest(filepath.Join(output, "run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "completed" || manifest.Versions["radare2"] != "6.2.0" || manifest.Versions["radare2_mcp"] != "1.8.6" {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if role, ok := manifest.ModelRoles["harvester"]; !ok || role.Model != "investigator" || role.Provider != "mock" {
		t.Fatalf("missing harvester model role: %#v", manifest.ModelRoles)
	}
	if !session.closed {
		t.Fatal("sandbox session was not closed")
	}
	observations, err := evidence.ReadObservationsFile(filepath.Join(output, "observations.jsonl"))
	if err != nil || len(observations) < 10 {
		t.Fatalf("expected deterministic native evidence: count=%d err=%v", len(observations), err)
	}
}

func TestControllerRetainsNativeEvidenceOnSandboxFailure(t *testing.T) {
	sample := writeFixture(t)
	output := filepath.Join(t.TempDir(), "run")
	controller, _ := mockedController(t, errors.New("synthetic sandbox crash"))
	err := controller.Analyze(context.Background(), sample, output)
	if err == nil || !strings.Contains(err.Error(), "synthetic sandbox crash") {
		t.Fatalf("expected sandbox error, got %v", err)
	}
	manifest, readErr := evidence.ReadManifest(filepath.Join(output, "run-manifest.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if manifest.Status != "partial" || fileSize(filepath.Join(output, "observations.jsonl")) == 0 {
		t.Fatalf("native partial evidence was not retained: %#v", manifest)
	}
}

func TestControllerClosesSessionReturnedWithStartError(t *testing.T) {
	controller, _ := mockedController(t, nil)
	session := &fakeSession{name: "jaq-sandbox-leaked"}
	controller.StartSandbox = func(context.Context, string, string) (SandboxSession, error) {
		return session, errors.New("synthetic partial start")
	}
	err := controller.Analyze(context.Background(), writeFixture(t), filepath.Join(t.TempDir(), "run"))
	if err == nil || !strings.Contains(err.Error(), "synthetic partial start") || !session.closed {
		t.Fatalf("partial start session was not closed: closed=%v err=%v", session.closed, err)
	}
}

func TestControllerRejectsStartedImageMismatch(t *testing.T) {
	controller, _ := mockedController(t, nil)
	session := &fakeSession{
		name: "jaq-sandbox-mismatch", imageID: "sha256:" + strings.Repeat("c", 64),
	}
	controller.StartSandbox = func(context.Context, string, string) (SandboxSession, error) {
		return session, nil
	}
	err := controller.Analyze(context.Background(), writeFixture(t), filepath.Join(t.TempDir(), "run"))
	if err == nil || !strings.Contains(err.Error(), "image mismatch") || !session.closed {
		t.Fatalf("image mismatch was not rejected and closed: closed=%v err=%v", session.closed, err)
	}
}

func TestControllerRedactsCredentialFromFailure(t *testing.T) {
	secret := "deepseek-secret-value-123456"
	t.Setenv("DEEPSEEK_API_KEY", secret)
	controller, _ := mockedController(t, errors.New("provider echoed "+secret))
	output := filepath.Join(t.TempDir(), "run")
	err := controller.Analyze(context.Background(), writeFixture(t), output)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("credential leaked in error: %v", err)
	}
	contents, readErr := os.ReadFile(filepath.Join(output, "run-manifest.json"))
	if readErr != nil || strings.Contains(string(contents), secret) {
		t.Fatalf("credential leaked in manifest: %v %s", readErr, contents)
	}
}

func TestControllerRejectsMissingModelBeforeSandbox(t *testing.T) {
	controller, _ := mockedController(t, nil)
	controller.Config.InvestigatorModel = ""
	called := false
	controller.StartSandbox = func(context.Context, string, string) (SandboxSession, error) {
		called = true
		return nil, nil
	}
	err := controller.Analyze(context.Background(), writeFixture(t), filepath.Join(t.TempDir(), "run"))
	if err == nil || !strings.Contains(err.Error(), "JAQ_INVESTIGATOR_MODEL") || called {
		t.Fatalf("expected fail-fast missing model, called=%v err=%v", called, err)
	}
}

func TestControllerRejectsNonPE(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "not-pe.txt")
	if err := os.WriteFile(sample, []byte("plain inert text"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller, _ := mockedController(t, nil)
	err := controller.Analyze(context.Background(), sample, filepath.Join(t.TempDir(), "run"))
	if err == nil || !strings.Contains(err.Error(), "Portable Executable") {
		t.Fatalf("expected PE rejection, got %v", err)
	}
}

func TestModelSelectionDoesNotChangeNativeEvidence(t *testing.T) {
	sample := writeFixture(t)
	firstController, _ := mockedController(t, nil)
	secondController, _ := mockedController(t, nil)
	secondController.Config.InvestigatorModel = "another-provider/another-model"
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	if err := firstController.Analyze(context.Background(), sample, first); err != nil {
		t.Fatal(err)
	}
	if err := secondController.Analyze(context.Background(), sample, second); err != nil {
		t.Fatal(err)
	}
	left, _ := os.ReadFile(filepath.Join(first, "observations.jsonl"))
	right, _ := os.ReadFile(filepath.Join(second, "observations.jsonl"))
	if string(left) != string(right) {
		t.Fatal("model selection changed native static evidence")
	}
}

func mockedController(t *testing.T, sandboxError error) (*Controller, *fakeSession) {
	t.Helper()
	promptHash := strings.Repeat("a", 64)
	session := &fakeSession{name: "jaq-sandbox-test"}
	investigator := &fakeInvestigator{run: writeMockDossier}
	controller := &Controller{
		Investigator:        investigator,
		AnalyzePE:           func(path string) (*peinfo.Analysis, error) { return peinfo.AnalyzeFile(path) },
		ResolveSandboxImage: func(context.Context) (string, error) { return "sha256:" + strings.Repeat("b", 64), nil },
		StartSandbox: func(context.Context, string, string) (SandboxSession, error) {
			if sandboxError != nil {
				return nil, sandboxError
			}
			return session, nil
		},
		Config: Config{
			SandboxImage: "jaq-radare2:6.2.0-mcp1.8.6", InvestigatorModel: "mock/investigator",
			PromptHashes:  map[string]string{"investigator": promptHash, "judge": promptHash},
			PythonVersion: "3.test", LiteLLMVersion: "mock", NodeVersion: "vtest", PiVersion: "0.test",
		},
	}
	return controller, session
}

func writeMockDossier(_ context.Context, output string) error {
	observations, err := evidence.ReadObservationsFile(filepath.Join(output, "observations.jsonl"))
	if err != nil {
		return err
	}
	checkpoint := fmt.Sprintf("{\"schema_version\":\"1.0\",\"research_complete\":true,\"summary\":\"Fixture research complete.\",\"important_evidence_ids\":[%q],\"unresolved_questions\":[]}\n", observations[0].ID)
	if err := os.WriteFile(filepath.Join(output, "research.json"), []byte(checkpoint), 0o600); err != nil {
		return err
	}
	claim := evidence.NewClaim("claim-1", "capability", "The fixture contains deterministic static evidence.", 0.8, []string{observations[0].ID})
	claim.AssetRole = "fixture"
	claims := []evidence.Claim{claim}
	if err := evidence.WriteClaims(filepath.Join(output, "claims.json"), claims); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "assets.json"), []byte("{\"schema_version\":\"1.0\",\"assets\":[]}\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "requests.json"), []byte("{\"schema_version\":\"1.0\",\"action_requests\":[]}\n"), 0o600); err != nil {
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
}

func writeFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(path, testutil.HarmlessPEFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
