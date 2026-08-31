package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jaq-project/jaq/internal/analyzer"
	"github.com/jaq-project/jaq/internal/evidence"
)

const rawLineLimit = 16 << 20

type rawObservation struct {
	Type            string                    `json:"type"`
	RawValue        any                       `json:"raw_value"`
	NormalizedValue any                       `json:"normalized_value"`
	Artifact        json.RawMessage           `json:"artifact_location"`
	Analyzer        evidence.AnalyzerIdentity `json:"analyzer"`
	Provenance      evidence.Provenance       `json:"provenance"`
	Relationships   map[string]any            `json:"relationships,omitempty"`
}

func readRawObservations(path, inputSHA256, analyzerConfigHash string) ([]evidence.Observation, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open raw Ghidra observations: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat raw Ghidra observations: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > analyzer.MaxRawEvidenceSize {
		return nil, fmt.Errorf("raw Ghidra observations must be a regular file no larger than %d bytes", analyzer.MaxRawEvidenceSize)
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), rawLineLimit)
	var observations []evidence.Observation
	var relationships []map[string]any
	line := 0
	for scanner.Scan() {
		line++
		data := bytes.TrimSpace(scanner.Bytes())
		if len(data) == 0 {
			continue
		}
		var raw rawObservation
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("raw Ghidra observation line %d: %w", line, err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("raw Ghidra observation line %d contains trailing JSON", line)
		}
		if raw.Type == "" {
			return nil, fmt.Errorf("raw Ghidra observation line %d has empty type", line)
		}
		location, err := decodeRawLocation(raw.Artifact)
		if err != nil {
			return nil, fmt.Errorf("raw Ghidra observation line %d: %w", line, err)
		}
		if raw.Analyzer.Name == "" {
			raw.Analyzer = evidence.AnalyzerIdentity{Name: "ghidra", Version: "12.1.3"}
		}
		if raw.Analyzer.Version != "12.1.3" || raw.Analyzer.Name != "ghidra" {
			return nil, fmt.Errorf("raw Ghidra observation line %d has unexpected analyzer identity", line)
		}
		raw.Analyzer.Build = ghidraArchiveSHA256
		raw.Analyzer.ConfigHash = analyzerConfigHash
		if raw.Provenance.Source == "" {
			raw.Provenance.Source = "ghidra"
		}
		raw.Provenance.Stage = "ghidra-static-analysis"
		raw.Provenance.InputSHA256 = inputSHA256
		observations = append(observations, evidence.NewObservation(
			raw.Type, raw.RawValue, raw.NormalizedValue, location, raw.Analyzer, raw.Provenance,
		))
		relationships = append(relationships, raw.Relationships)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read raw Ghidra observations: %w", err)
	}
	if len(observations) == 0 {
		return nil, errors.New("Ghidra produced no observations")
	}
	linkRawRelationships(observations, relationships)
	return observations, nil
}

func linkRawRelationships(observations []evidence.Observation, relationships []map[string]any) {
	addressToObservation := make(map[string]string)
	for _, observation := range observations {
		if observation.Type == "ghidra.function" && observation.Artifact.Path != "" {
			addressToObservation[observation.Artifact.Path] = observation.ID
		}
	}
	for _, observation := range observations {
		if (observation.Type == "ghidra.entrypoint" || observation.Type == "ghidra.symbol" || observation.Type == "pe.import.symbol") && observation.Artifact.Path != "" {
			if _, exists := addressToObservation[observation.Artifact.Path]; !exists {
				addressToObservation[observation.Artifact.Path] = observation.ID
			}
		}
	}
	for index, relation := range relationships {
		if len(relation) == 0 || index >= len(observations) {
			continue
		}
		sourceAddress, sourceOK := relation["source_address"].(string)
		targetAddress, targetOK := relation["target_address"].(string)
		sourceID, hasSource := addressToObservation[sourceAddress]
		targetID, hasTarget := addressToObservation[targetAddress]
		if !sourceOK || !targetOK || !hasSource || !hasTarget {
			continue
		}
		kind, _ := relation["kind"].(string)
		observations[index].Relationships = map[string]any{
			"kind": kind, "source_id": sourceID, "target_id": targetID,
		}
		observations[index].ID = observations[index].ContentID()
	}
}

func decodeRawLocation(data json.RawMessage) (evidence.ArtifactLocation, error) {
	if len(data) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return evidence.ArtifactLocation{Artifact: "sample"}, nil
	}
	var location evidence.ArtifactLocation
	if err := json.Unmarshal(data, &location); err == nil && location.Artifact != "" {
		return location, nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return evidence.ArtifactLocation{}, errors.New("artifact_location must be a string or location object")
	}
	return evidence.ArtifactLocation{Artifact: "sample", Path: value}, nil
}
