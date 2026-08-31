package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jaq-project/jaq/internal/analyzer"
	"github.com/jaq-project/jaq/internal/evidence"
	invprocess "github.com/jaq-project/jaq/internal/investigator"
	peinfo "github.com/jaq-project/jaq/internal/pe"
)

const Version = "0.1.0"

const ghidraArchiveSHA256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
const analyzerBaseDigest = "sha256:ce5767b7222312d42395f5bab033cd91f09e44032a2f21bdfd7b5b912dbe1e77"

type StaticAnalyzer interface {
	Analyze(ctx context.Context, samplePath, evidenceDir string) error
}

type Investigator interface {
	Investigate(ctx context.Context, evidenceDir string) error
}

type imageIdentifier interface {
	ImageID(ctx context.Context) (string, error)
}

type artifactBoundAnalyzer interface {
	AnalyzeExpected(ctx context.Context, samplePath, evidenceDir, expectedSHA256 string) error
}

type Config struct {
	AnalyzerImage     string
	InvestigatorModel string
	JudgeModel        string
	PromptHashes      map[string]string
	PythonVersion     string
	LiteLLMVersion    string
}

type Controller struct {
	Analyzer     StaticAnalyzer
	Investigator Investigator
	AnalyzePE    func(string) (*peinfo.Analysis, error)
	Now          func() time.Time
	Config       Config
}

func NewController(projectRoot string) (*Controller, error) {
	docker := analyzer.NewDocker()
	promptHash, err := hashFile(filepath.Join(projectRoot, "python", "jaq_investigator", "prompts.py"))
	if err != nil {
		return nil, fmt.Errorf("hash investigator prompts: %w", err)
	}
	process := invprocess.NewProcess(projectRoot)
	pythonVersion, liteLLMVersion, err := process.RuntimeVersions(context.Background())
	if err != nil {
		return nil, err
	}
	return &Controller{
		Analyzer:     docker,
		Investigator: process,
		AnalyzePE:    peinfo.AnalyzeFile,
		Now:          time.Now,
		Config: Config{
			AnalyzerImage:     docker.Image,
			InvestigatorModel: os.Getenv("JAQ_INVESTIGATOR_MODEL"),
			JudgeModel:        os.Getenv("JAQ_JUDGE_MODEL"),
			PromptHashes: map[string]string{
				"investigator": promptHash,
				"judge":        promptHash,
			},
			PythonVersion:  pythonVersion,
			LiteLLMVersion: liteLLMVersion,
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
	if c.Analyzer == nil || c.Investigator == nil {
		return errors.New("analysis stages are not configured")
	}
	analyzerImageID := "not-reported-by-analyzer"
	if identifier, ok := c.Analyzer.(imageIdentifier); ok {
		analyzerImageID, err = identifier.ImageID(ctx)
		if err != nil {
			return err
		}
	}
	outputDir, err := prepareOutput(outputPath)
	if err != nil {
		return err
	}

	nativeConfigHash, err := contentHash(map[string]any{
		"schema_version":  evidence.SchemaVersion,
		"analyzer":        "jaq-pe",
		"version":         nativeAnalyzerVersion,
		"file_size_limit": peinfo.MaxPEFileSize,
		"string_limits":   map[string]int{"count": peinfo.MaxStrings, "length": peinfo.MaxStringLength},
	})
	if err != nil {
		return fmt.Errorf("hash native analyzer configuration: %w", err)
	}
	ghidraConfigHash, err := contentHash(map[string]any{
		"jaq_version": Version, "ghidra_version": "12.1.3",
		"ghidra_archive_sha256": ghidraArchiveSHA256, "analyzer_image": c.Config.AnalyzerImage,
		"base_image_digest": analyzerBaseDigest,
		"runtime_image_id":  analyzerImageID,
	})
	if err != nil {
		return fmt.Errorf("hash Ghidra analyzer configuration: %w", err)
	}
	pipelineConfigHash, err := contentHash(map[string]any{
		"schema_version": evidence.SchemaVersion, "native_config_hash": nativeConfigHash,
		"ghidra_config_hash": ghidraConfigHash, "investigator_model": c.Config.InvestigatorModel,
		"judge_model": c.Config.JudgeModel,
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
		"jaq":                   Version,
		"schema":                evidence.SchemaVersion,
		"go":                    runtime.Version(),
		"go_platform":           runtime.GOOS + "/" + runtime.GOARCH,
		"native_pe_analyzer":    nativeAnalyzerVersion,
		"ghidra":                "12.1.3",
		"ghidra_archive_sha256": ghidraArchiveSHA256,
		"analyzer_image":        c.Config.AnalyzerImage,
		"analyzer_base_digest":  analyzerBaseDigest,
		"analyzer_image_id":     analyzerImageID,
		"python":                c.Config.PythonVersion,
		"python_package":        "jaq-investigator/" + Version,
		"litellm":               c.Config.LiteLLMVersion,
	}
	manifest.ConfigurationHashes["native_pe"] = nativeConfigHash
	manifest.ConfigurationHashes["ghidra"] = ghidraConfigHash
	manifest.ConfigurationHashes["pipeline"] = pipelineConfigHash
	for role, hash := range c.Config.PromptHashes {
		manifest.PromptHashes[role] = hash
	}
	if c.Config.InvestigatorModel != "" {
		manifest.ModelRoles["investigator"] = modelRole(c.Config.InvestigatorModel, c.Config.PromptHashes["investigator"])
	}
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
		manifest.Status = "failed"
		manifest.Error = sanitizeManifestError(resultErr.Error())
		manifest.FinishedAt = c.now().UTC()
		if writeErr := writeJSONAtomic(manifestPath, manifest); writeErr != nil {
			resultErr = fmt.Errorf("%w (also failed to update manifest: %v)", resultErr, writeErr)
		}
	}()

	nativeStarted := c.now().UTC()
	observations := nativeObservations(peResult, nativeConfigHash)
	manifest.StageUsage["native_pe"] = stageUsage(nativeStarted, c.now().UTC(), peResult.Size, 0)

	ghidraStarted := c.now().UTC()
	if err := verifySampleHash(samplePath, peResult.Hashes.SHA256); err != nil {
		return err
	}
	var analyzerErr error
	if bound, ok := c.Analyzer.(artifactBoundAnalyzer); ok {
		analyzerErr = bound.AnalyzeExpected(ctx, samplePath, outputDir, peResult.Hashes.SHA256)
	} else {
		analyzerErr = c.Analyzer.Analyze(ctx, samplePath, outputDir)
	}
	if analyzerErr != nil {
		manifest.StageUsage["ghidra"] = stageUsage(ghidraStarted, c.now().UTC(), peResult.Size, 0)
		return analyzerErr
	}
	if err := verifySampleHash(samplePath, peResult.Hashes.SHA256); err != nil {
		return err
	}
	rawPath := filepath.Join(outputDir, "raw-observations.jsonl")
	ghidraObservations, err := readRawObservations(rawPath, peResult.Hashes.SHA256, ghidraConfigHash)
	if err != nil {
		manifest.StageUsage["ghidra"] = stageUsage(ghidraStarted, c.now().UTC(), peResult.Size, fileSize(rawPath))
		return err
	}
	observations = append(observations, ghidraObservations...)
	observations, err = evidence.DeduplicateObservations(observations)
	if err != nil {
		return fmt.Errorf("validate merged evidence: %w", err)
	}
	observationsPath := filepath.Join(outputDir, "observations.jsonl")
	if err := evidence.WriteObservationsFile(observationsPath, observations); err != nil {
		return fmt.Errorf("write evidence package: %w", err)
	}
	if err := os.Chmod(observationsPath, 0o600); err != nil {
		return fmt.Errorf("protect evidence package: %w", err)
	}
	manifest.StageUsage["ghidra"] = stageUsage(ghidraStarted, c.now().UTC(), peResult.Size, fileSize(observationsPath))
	if err := os.Remove(rawPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove transient Ghidra output: %w", err)
	}

	investigatorStarted := c.now().UTC()
	if err := c.Investigator.Investigate(ctx, outputDir); err != nil {
		manifest.StageUsage["investigator"] = stageUsage(investigatorStarted, c.now().UTC(), fileSize(observationsPath), 0)
		return err
	}
	if err := validateInvestigatorOutputs(outputDir, observations, c.Config.JudgeModel != ""); err != nil {
		manifest.StageUsage["investigator"] = stageUsage(investigatorStarted, c.now().UTC(), fileSize(observationsPath), outputSize(outputDir))
		return err
	}
	manifest.StageUsage["investigator"] = stageUsage(investigatorStarted, c.now().UTC(), fileSize(observationsPath), outputSize(outputDir))

	manifest.Status = "completed"
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
	reportPath := filepath.Join(outputDir, "report.md")
	info, err := os.Stat(reportPath)
	if err != nil {
		return fmt.Errorf("reject investigator report: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<20 {
		return errors.New("reject investigator report: report.md must be a nonempty bounded regular file")
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
	for _, name := range []string{"claims.json", "score.json", "report.md"} {
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

func verifySampleHash(path, expectedSHA256 string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("reopen sample for consistency check: %w", err)
	}
	hashes, size, hashErr := evidence.HashReader(io.LimitReader(file, peinfo.MaxPEFileSize+1))
	closeErr := file.Close()
	if hashErr != nil {
		return fmt.Errorf("hash sample consistency check: %w", hashErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close sample consistency check: %w", closeErr)
	}
	if size > peinfo.MaxPEFileSize {
		return errors.New("sample grew beyond the configured PE size limit")
	}
	if hashes.SHA256 != expectedSHA256 {
		return errors.New("sample changed after initial validation; refusing inconsistent analysis")
	}
	return nil
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
