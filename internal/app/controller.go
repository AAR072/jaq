package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jaq-project/jaq/internal/evidence"
	invprocess "github.com/jaq-project/jaq/internal/investigator"
	peinfo "github.com/jaq-project/jaq/internal/pe"
	sandboxruntime "github.com/jaq-project/jaq/internal/sandbox"
)

const Version = "0.2.0"

const (
	radare2Version       = "6.2.0"
	radare2ArchiveSHA256 = "098488a3a0a4c11b893ae9e74496cf65561d17cefd9b7f2661a48b4be97b663a"
	r2MCPVersion         = "1.8.6"
	r2MCPCommit          = "d74b6b9855622c9a7070165b1961262afd686a3f"
	sandboxBaseDigest    = "sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"
)

type Investigator interface {
	Investigate(ctx context.Context, evidenceDir string) error
}

type sandboxAwareInvestigator interface {
	ConfigureSandbox(containerName, sampleSHA256, radareVersion, mcpVersion string)
}

type SandboxSession interface {
	ContainerName() string
	ImageID() string
	Close(ctx context.Context) error
}

type Config struct {
	SandboxImage      string
	InvestigatorModel string
	HarvesterModel    string
	JudgeModel        string
	PromptHashes      map[string]string
	PythonVersion     string
	LiteLLMVersion    string
	NodeVersion       string
	PiVersion         string
}

type Controller struct {
	Investigator        Investigator
	AnalyzePE           func(string) (*peinfo.Analysis, error)
	ResolveSandboxImage func(context.Context) (string, error)
	StartSandbox        func(context.Context, string, string) (SandboxSession, error)
	Now                 func() time.Time
	Config              Config
}

func NewController(projectRoot string) (*Controller, error) {
	basePromptHash, err := hashFile(filepath.Join(projectRoot, "python", "jaq_investigator", "prompts.py"))
	if err != nil {
		return nil, fmt.Errorf("hash investigator prompts: %w", err)
	}
	piHarnessHash, err := hashFile(filepath.Join(projectRoot, "agent", "pi_harness.mjs"))
	if err != nil {
		return nil, fmt.Errorf("hash Pi harness: %w", err)
	}
	piBrokerHash, err := hashFile(filepath.Join(projectRoot, "python", "jaq_investigator", "pi_harness.py"))
	if err != nil {
		return nil, fmt.Errorf("hash Pi broker: %w", err)
	}
	promptHash, err := contentHash(map[string]string{
		"prompts": basePromptHash, "pi_harness": piHarnessHash, "pi_broker": piBrokerHash,
	})
	if err != nil {
		return nil, fmt.Errorf("hash investigator harness configuration: %w", err)
	}
	process := invprocess.NewProcess(projectRoot)
	runtimeVersions, err := process.RuntimeVersions(context.Background())
	if err != nil {
		return nil, err
	}
	sandbox := sandboxruntime.NewDocker()
	harvesterModel := os.Getenv("JAQ_HARVESTER_MODEL")
	if harvesterModel == "" {
		harvesterModel = os.Getenv("JAQ_INVESTIGATOR_MODEL")
	}
	return &Controller{
		Investigator:        process,
		AnalyzePE:           peinfo.AnalyzeFile,
		ResolveSandboxImage: sandbox.ImageID,
		StartSandbox: func(ctx context.Context, sample, expectedSHA256 string) (SandboxSession, error) {
			return sandbox.Start(ctx, sample, expectedSHA256)
		},
		Now: time.Now,
		Config: Config{
			SandboxImage:      sandbox.Image,
			InvestigatorModel: os.Getenv("JAQ_INVESTIGATOR_MODEL"),
			HarvesterModel:    harvesterModel,
			JudgeModel:        os.Getenv("JAQ_JUDGE_MODEL"),
			PromptHashes: map[string]string{
				"investigator": promptHash,
				"harvester":    promptHash,
				"judge":        promptHash,
			},
			PythonVersion:  runtimeVersions.Python,
			LiteLLMVersion: runtimeVersions.LiteLLM,
			NodeVersion:    runtimeVersions.Node,
			PiVersion:      runtimeVersions.Pi,
		},
	}, nil
}

func (c *Controller) Analyze(ctx context.Context, samplePath, outputPath string) (resultErr error) {
	if !filepath.IsAbs(samplePath) {
		return errors.New("--sample must be an absolute path")
	}
	info, err := os.Stat(samplePath)
	if err != nil {
		return fmt.Errorf("inspect sample: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("sample must be a regular file")
	}
	if c.AnalyzePE == nil {
		return errors.New("PE extractor is not configured")
	}
	peResult, err := c.AnalyzePE(samplePath)
	if err != nil {
		return fmt.Errorf("reject sample: %w", err)
	}
	if strings.TrimSpace(c.Config.InvestigatorModel) == "" {
		return errors.New("JAQ_INVESTIGATOR_MODEL is required (LiteLLM provider/model string)")
	}
	if c.Investigator == nil || c.ResolveSandboxImage == nil || c.StartSandbox == nil {
		return errors.New("static sandbox stages are not configured")
	}
	harvesterModel := c.Config.HarvesterModel
	if strings.TrimSpace(harvesterModel) == "" {
		harvesterModel = c.Config.InvestigatorModel
	}
	harvesterPromptHash := c.Config.PromptHashes["harvester"]
	if harvesterPromptHash == "" {
		harvesterPromptHash = c.Config.PromptHashes["investigator"]
	}
	sandboxImageID, err := c.ResolveSandboxImage(ctx)
	if err != nil {
		return err
	}
	outputDir, err := prepareOutput(outputPath)
	if err != nil {
		return err
	}

	nativeConfigHash, err := contentHash(map[string]any{
		"schema_version": evidence.SchemaVersion, "analyzer": "jaq-pe", "version": nativeAnalyzerVersion,
		"file_size_limit": peinfo.MaxPEFileSize,
		"string_limits":   map[string]int{"count": peinfo.MaxStrings, "length": peinfo.MaxStringLength},
	})
	if err != nil {
		return fmt.Errorf("hash native analyzer configuration: %w", err)
	}
	sandboxConfigHash, err := contentHash(map[string]any{
		"jaq_version": Version, "image": c.Config.SandboxImage, "image_id": sandboxImageID,
		"base_digest": sandboxBaseDigest,
		"radare2":     radare2Version, "radare2_archive_sha256": radare2ArchiveSHA256,
		"radare2_mcp": r2MCPVersion, "radare2_mcp_commit": r2MCPCommit,
		"network": "none", "sample": "read-only", "scratch": "tmpfs",
	})
	if err != nil {
		return fmt.Errorf("hash static sandbox configuration: %w", err)
	}
	pipelineConfigHash, err := contentHash(map[string]any{
		"schema_version":     evidence.SchemaVersion,
		"native_config_hash": nativeConfigHash, "sandbox_config_hash": sandboxConfigHash,
		"investigator_model": c.Config.InvestigatorModel,
		"harvester_model":    harvesterModel, "judge_model": c.Config.JudgeModel,
	})
	if err != nil {
		return fmt.Errorf("hash pipeline configuration: %w", err)
	}

	started := c.now().UTC()
	runID := "run-" + peResult.Hashes.SHA256[:16] + "-" + pipelineConfigHash[:8]
	manifest := evidence.NewRunManifest(runID, evidence.ArtifactMetadata{
		Name: filepath.Base(samplePath), Size: peResult.Size, Hashes: peResult.Hashes,
	}, started)
	manifest.Versions = map[string]string{
		"jaq": Version, "schema": evidence.SchemaVersion,
		"go": runtime.Version(), "go_platform": runtime.GOOS + "/" + runtime.GOARCH,
		"native_pe_analyzer": nativeAnalyzerVersion,
		"radare2":            radare2Version, "radare2_archive_sha256": radare2ArchiveSHA256,
		"radare2_mcp": r2MCPVersion, "radare2_mcp_commit": r2MCPCommit,
		"sandbox_base_digest": sandboxBaseDigest,
		"sandbox_image":       c.Config.SandboxImage, "sandbox_image_id": sandboxImageID,
		"python": c.Config.PythonVersion, "python_package": "jaq-investigator/" + Version,
		"node": c.Config.NodeVersion, "pi_sdk": c.Config.PiVersion,
		"litellm": c.Config.LiteLLMVersion,
	}
	manifest.ConfigurationHashes["native_pe"] = nativeConfigHash
	manifest.ConfigurationHashes["static_sandbox"] = sandboxConfigHash
	manifest.ConfigurationHashes["pipeline"] = pipelineConfigHash
	for role, hash := range c.Config.PromptHashes {
		manifest.PromptHashes[role] = hash
	}
	manifest.ModelRoles["investigator"] = modelRole(c.Config.InvestigatorModel, c.Config.PromptHashes["investigator"])
	manifest.ModelRoles["harvester"] = modelRole(harvesterModel, harvesterPromptHash)
	if c.Config.JudgeModel != "" {
		manifest.ModelRoles["judge"] = modelRole(c.Config.JudgeModel, c.Config.PromptHashes["judge"])
	}
	manifestPath := filepath.Join(outputDir, "run-manifest.json")
	if err := writeJSONAtomic(manifestPath, manifest); err != nil {
		return fmt.Errorf("write initial run manifest: %w", err)
	}
	defer func() {
		if resultErr == nil {
			return
		}
		resultErr = errors.New(invprocess.RedactSensitive(resultErr.Error()))
		if fileSize(filepath.Join(outputDir, "observations.jsonl")) > 0 {
			manifest.Status = "partial"
		} else {
			manifest.Status = "failed"
		}
		manifest.Error = sanitizeManifestError(resultErr.Error())
		manifest.FinishedAt = c.now().UTC()
		if writeErr := writeJSONAtomic(manifestPath, manifest); writeErr != nil {
			resultErr = fmt.Errorf("%w (also failed to update manifest: %v)", resultErr, writeErr)
		}
	}()

	nativeStarted := c.now().UTC()
	observations := nativeObservations(peResult, nativeConfigHash)
	observationsPath := filepath.Join(outputDir, "observations.jsonl")
	if err := evidence.WriteObservationsFile(observationsPath, observations); err != nil {
		return fmt.Errorf("write native evidence package: %w", err)
	}
	if err := os.Chmod(observationsPath, 0o600); err != nil {
		return fmt.Errorf("protect evidence package: %w", err)
	}
	manifest.StageUsage["native_pe"] = stageUsage(nativeStarted, c.now().UTC(), peResult.Size, fileSize(observationsPath))

	sandboxStarted := c.now().UTC()
	session, err := c.StartSandbox(ctx, samplePath, peResult.Hashes.SHA256)
	if err != nil {
		if session != nil {
			_ = session.Close(context.Background())
		}
		return fmt.Errorf("start static sandbox: %w", err)
	}
	if session == nil {
		return errors.New("start static sandbox returned no session")
	}
	if session.ImageID() != sandboxImageID {
		_ = session.Close(context.Background())
		return fmt.Errorf("static sandbox image mismatch: resolved %s, started %s", sandboxImageID, session.ImageID())
	}
	closed := false
	defer func() {
		if !closed {
			_ = session.Close(context.Background())
		}
	}()
	configured, ok := c.Investigator.(sandboxAwareInvestigator)
	if !ok {
		return errors.New("investigator cannot accept a static sandbox session")
	}
	configured.ConfigureSandbox(session.ContainerName(), peResult.Hashes.SHA256, radare2Version, r2MCPVersion)
	manifest.StageUsage["static_sandbox"] = stageUsage(sandboxStarted, c.now().UTC(), peResult.Size, 0)

	investigatorStarted := c.now().UTC()
	if err := c.Investigator.Investigate(ctx, outputDir); err != nil {
		manifest.StageUsage["investigator"] = stageUsage(investigatorStarted, c.now().UTC(), fileSize(observationsPath), 0)
		return err
	}
	observations, err = evidence.ReadObservationsFile(observationsPath)
	if err != nil {
		return fmt.Errorf("validate interactive evidence package: %w", err)
	}
	if err := evidence.WriteObservationsFile(observationsPath, observations); err != nil {
		return fmt.Errorf("canonicalize interactive evidence package: %w", err)
	}
	if err := validateInvestigatorOutputs(outputDir, observations, c.Config.JudgeModel != ""); err != nil {
		manifest.StageUsage["investigator"] = stageUsage(investigatorStarted, c.now().UTC(), fileSize(observationsPath), outputSize(outputDir))
		return err
	}
	manifest.StageUsage["investigator"] = stageUsage(investigatorStarted, c.now().UTC(), fileSize(observationsPath), outputSize(outputDir))
	if err := session.Close(context.Background()); err != nil {
		return fmt.Errorf("close static sandbox: %w", err)
	}
	closed = true

	manifest.Status = "completed"
	var requestDocument map[string]any
	if readErr := readJSONStrict(filepath.Join(outputDir, "requests.json"), &requestDocument); readErr == nil {
		if requests, ok := requestDocument["action_requests"].([]any); ok && len(requests) > 0 {
			manifest.Status = "awaiting_authorization"
		}
	}
	manifest.FinishedAt = c.now().UTC()
	manifest.Error = ""
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("validate completed manifest: %w", err)
	}
	if err := writeJSONAtomic(manifestPath, manifest); err != nil {
		return fmt.Errorf("write completed manifest: %w", err)
	}
	return nil
}

func validateInvestigatorOutputs(outputDir string, observations []evidence.Observation, judgeRequired bool) error {
	if err := validateResearchCheckpoint(filepath.Join(outputDir, "research.json"), observations); err != nil {
		return err
	}
	claims, err := evidence.ReadClaims(filepath.Join(outputDir, "claims.json"))
	if err != nil {
		return fmt.Errorf("reject investigator claims: %w", err)
	}
	if err := evidence.ValidateClaims(claims, observations); err != nil {
		return fmt.Errorf("reject investigator claims: %w", err)
	}
	score, err := evidence.ReadScore(filepath.Join(outputDir, "score.json"), claims, observations)
	if err != nil {
		return fmt.Errorf("reject investigator score: %w", err)
	}
	if judgeRequired && len(score.Judgments) != len(claims) {
		return fmt.Errorf("reject investigator score: configured judge returned %d judgments for %d claims", len(score.Judgments), len(claims))
	}
	for _, name := range []string{"assets.json", "requests.json"} {
		info, statErr := os.Stat(filepath.Join(outputDir, name))
		if statErr != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<20 {
			return fmt.Errorf("reject investigator output: %s must be a nonempty bounded regular file", name)
		}
	}
	if err := validateOperationalReferences(outputDir, observations); err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(outputDir, "report.md"))
	if err != nil {
		return fmt.Errorf("reject investigator report: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<20 {
		return errors.New("reject investigator report: report.md must be a nonempty bounded regular file")
	}
	return nil
}

type researchCheckpoint struct {
	SchemaVersion        string           `json:"schema_version"`
	ResearchComplete     bool             `json:"research_complete"`
	Summary              string           `json:"summary"`
	ImportantEvidenceIDs []string         `json:"important_evidence_ids"`
	UnresolvedQuestions  []string         `json:"unresolved_questions"`
	Coverage             researchCoverage `json:"coverage"`
}

type researchFunctionCoverage struct {
	Name        string   `json:"name"`
	Address     string   `json:"address"`
	Purpose     string   `json:"purpose,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type researchEntrypointCoverage struct {
	Name        string   `json:"name"`
	Address     string   `json:"address"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type researchDeobfuscationCoverage struct {
	Technique   string   `json:"technique"`
	Status      string   `json:"status"`
	Outcome     string   `json:"outcome"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type researchArtifactCoverage struct {
	Description string   `json:"description"`
	Path        string   `json:"path"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type researchCoverage struct {
	ApplicationEntrypoints []researchEntrypointCoverage    `json:"application_entrypoints"`
	AnalyzedFunctions      []researchFunctionCoverage      `json:"analyzed_functions"`
	CallGraphEvidenceIDs   []string                        `json:"call_graph_evidence_ids"`
	DeobfuscationAttempts  []researchDeobfuscationCoverage `json:"deobfuscation_attempts"`
	RecoveredArtifacts     []researchArtifactCoverage      `json:"recovered_artifacts"`
}

func validateResearchCheckpoint(path string, observations []evidence.Observation) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 1<<20 {
		return errors.New("reject research.json: must be a nonempty bounded regular file")
	}
	var checkpoint researchCheckpoint
	if err := readJSONStrict(path, &checkpoint); err != nil {
		return fmt.Errorf("reject research.json: %w", err)
	}
	if checkpoint.SchemaVersion != evidence.SchemaVersion || !checkpoint.ResearchComplete ||
		strings.TrimSpace(checkpoint.Summary) == "" || len(checkpoint.Summary) > 16000 ||
		len(checkpoint.ImportantEvidenceIDs) > 200 || len(checkpoint.UnresolvedQuestions) > 100 {
		return errors.New("reject research.json: invalid research checkpoint")
	}
	if len(checkpoint.Coverage.ApplicationEntrypoints) < 1 || len(checkpoint.Coverage.ApplicationEntrypoints) > 20 ||
		len(checkpoint.Coverage.AnalyzedFunctions) < 3 || len(checkpoint.Coverage.AnalyzedFunctions) > 100 ||
		len(checkpoint.Coverage.CallGraphEvidenceIDs) < 1 || len(checkpoint.Coverage.CallGraphEvidenceIDs) > 100 ||
		len(checkpoint.Coverage.DeobfuscationAttempts) < 1 || len(checkpoint.Coverage.DeobfuscationAttempts) > 50 ||
		len(checkpoint.Coverage.RecoveredArtifacts) > 50 {
		return errors.New("reject research.json: incomplete reverse-engineering coverage")
	}
	known := make(map[string]bool, len(observations))
	for _, observation := range observations {
		known[observation.ID] = true
	}
	seen := make(map[string]bool, len(checkpoint.ImportantEvidenceIDs))
	for _, id := range checkpoint.ImportantEvidenceIDs {
		if seen[id] || !known[id] {
			return errors.New("reject research.json: invalid evidence reference")
		}
		seen[id] = true
	}
	for _, question := range checkpoint.UnresolvedQuestions {
		if strings.TrimSpace(question) == "" || len(question) > 1000 {
			return errors.New("reject research.json: invalid unresolved question")
		}
	}
	coverageIDs := make([]string, 0)
	for _, item := range checkpoint.Coverage.ApplicationEntrypoints {
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Address) == "" || len(item.EvidenceIDs) == 0 {
			return errors.New("reject research.json: invalid function coverage")
		}
		coverageIDs = append(coverageIDs, item.EvidenceIDs...)
	}
	for _, item := range checkpoint.Coverage.AnalyzedFunctions {
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Address) == "" ||
			strings.TrimSpace(item.Purpose) == "" || len(item.EvidenceIDs) == 0 {
			return errors.New("reject research.json: invalid function coverage")
		}
		coverageIDs = append(coverageIDs, item.EvidenceIDs...)
	}
	coverageIDs = append(coverageIDs, checkpoint.Coverage.CallGraphEvidenceIDs...)
	validStatuses := map[string]bool{"recovered": true, "partial": true, "failed": true, "not_needed": true}
	for _, item := range checkpoint.Coverage.DeobfuscationAttempts {
		if strings.TrimSpace(item.Technique) == "" || strings.TrimSpace(item.Outcome) == "" ||
			!validStatuses[item.Status] || len(item.EvidenceIDs) == 0 {
			return errors.New("reject research.json: invalid deobfuscation coverage")
		}
		coverageIDs = append(coverageIDs, item.EvidenceIDs...)
	}
	for _, item := range checkpoint.Coverage.RecoveredArtifacts {
		if strings.TrimSpace(item.Description) == "" || strings.TrimSpace(item.Path) == "" || len(item.EvidenceIDs) == 0 {
			return errors.New("reject research.json: invalid recovered artifact coverage")
		}
		coverageIDs = append(coverageIDs, item.EvidenceIDs...)
	}
	important := make(map[string]bool, len(checkpoint.ImportantEvidenceIDs))
	for _, id := range checkpoint.ImportantEvidenceIDs {
		important[id] = true
	}
	for _, id := range coverageIDs {
		if !known[id] || !important[id] {
			return errors.New("reject research.json: coverage evidence is missing or not important")
		}
	}
	return nil
}

func validateOperationalReferences(outputDir string, observations []evidence.Observation) error {
	ids := map[string]bool{}
	for _, item := range observations {
		ids[item.ID] = true
	}
	for _, spec := range []struct{ name, key string }{{"assets.json", "assets"}, {"requests.json", "action_requests"}} {
		var document map[string]any
		if err := readJSONStrict(filepath.Join(outputDir, spec.name), &document); err != nil {
			return fmt.Errorf("reject %s: %w", spec.name, err)
		}
		if document["schema_version"] != "1.0" {
			return fmt.Errorf("reject %s: unsupported schema", spec.name)
		}
		records, ok := document[spec.key].([]any)
		if !ok {
			return fmt.Errorf("reject %s: missing %s array", spec.name, spec.key)
		}
		for _, raw := range records {
			record, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("reject %s: record must be object", spec.name)
			}
			refs, ok := record["evidence_ids"].([]any)
			if !ok || len(refs) == 0 {
				return fmt.Errorf("reject %s: evidence_ids required", spec.name)
			}
			for _, ref := range refs {
				text, ok := ref.(string)
				if !ok || !ids[text] {
					return fmt.Errorf("reject %s: missing evidence reference", spec.name)
				}
			}
			if spec.name == "requests.json" && record["status"] != "pending_authorization" {
				return errors.New("reject requests.json: initial requests must be pending_authorization")
			}
		}
	}
	return nil
}

func (c *Controller) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func modelRole(value, promptHash string) evidence.ModelRole {
	provider, model := "configured", value
	if before, after, ok := strings.Cut(value, "/"); ok && before != "" && after != "" {
		provider, model = before, after
	}
	return evidence.ModelRole{Provider: provider, Model: model, PromptHash: promptHash}
}

func stageUsage(started, finished time.Time, inputBytes, outputBytes int64) evidence.ResourceUsage {
	return evidence.ResourceUsage{
		StartedAt: started, FinishedAt: finished,
		DurationMS: finished.Sub(started).Milliseconds(), InputBytes: inputBytes, OutputBytes: outputBytes,
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func outputSize(directory string) int64 {
	var total int64
	for _, name := range []string{"research.json", "claims.json", "assets.json", "requests.json", "score.json", "report.md"} {
		total += fileSize(filepath.Join(directory, name))
	}
	return total
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func sanitizeManifestError(message string) string {
	message = invprocess.RedactSensitive(message)
	message = strings.Map(func(r rune) rune {
		if r == '\x00' {
			return -1
		}
		return r
	}, message)
	if len(message) > 8192 {
		message = message[:8192] + " [truncated]"
	}
	return message
}
