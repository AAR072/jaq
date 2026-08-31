package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// ClaimsDocument is the versioned top-level representation of claims.json.
// Keeping the schema marker beside the array lets Python and Go reject output
// from an incompatible investigator before accepting any individual claim.
type ClaimsDocument struct {
	SchemaVersion string  `json:"schema_version"`
	Claims        []Claim `json:"claims"`
}

// ValidateObservation is the functional form of Observation.Validate.
func ValidateObservation(observation Observation) error { return observation.Validate() }

// ValidateManifest is the functional form of RunManifest.Validate.
func ValidateManifest(manifest RunManifest) error { return manifest.Validate() }

// ValidateClaim is the functional form of Claim.Validate.
func ValidateClaim(claim Claim) error { return claim.Validate() }

// ValidateScore is the functional form of Score.Validate.
func ValidateScore(score Score, claims []Claim, observations []Observation) error {
	return score.Validate(claims, observations)
}

func marshalIndented(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeJSON(path string, value any) error {
	if path == "" {
		return errors.New("empty JSON path")
	}
	data, err := marshalIndented(value)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write JSON %q: %w", path, err)
	}
	return nil
}

func readJSON(path string, value any) error {
	if path == "" {
		return errors.New("empty JSON path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read JSON %q: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode JSON %q: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode JSON %q: multiple top-level values", path)
		}
		return fmt.Errorf("decode JSON %q: %w", path, err)
	}
	return nil
}

// MarshalManifest returns the stable indented JSON representation of a
// validated manifest.
func MarshalManifest(manifest RunManifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return marshalIndented(manifest)
}

func WriteManifest(path string, manifest RunManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	return writeJSON(path, manifest)
}

func ReadManifest(path string) (RunManifest, error) {
	var manifest RunManifest
	if err := readJSON(path, &manifest); err != nil {
		return RunManifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return RunManifest{}, err
	}
	return manifest, nil
}

// MarshalClaims returns a versioned document containing a sorted array of
// validated claims. Claims keep their caller-provided IDs; sorting only affects
// persisted order.
func MarshalClaims(claims []Claim) ([]byte, error) {
	copyClaims := append([]Claim(nil), claims...)
	sort.SliceStable(copyClaims, func(i, j int) bool { return copyClaims[i].ID < copyClaims[j].ID })
	seen := map[string]struct{}{}
	for _, claim := range copyClaims {
		if err := claim.Validate(); err != nil {
			return nil, err
		}
		if _, ok := seen[claim.ID]; ok {
			return nil, fmt.Errorf("duplicate claim id %q", claim.ID)
		}
		seen[claim.ID] = struct{}{}
	}
	return marshalIndented(ClaimsDocument{SchemaVersion: ClaimSchemaVersion, Claims: copyClaims})
}

func WriteClaims(path string, claims []Claim) error {
	data, err := MarshalClaims(claims)
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("empty claims path")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write claims %q: %w", path, err)
	}
	return nil
}

func ReadClaims(path string) ([]Claim, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read claims %q: %w", path, err)
	}
	var document ClaimsDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode claims %q: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode claims %q: multiple top-level values", path)
		}
		return nil, fmt.Errorf("decode claims %q trailing data: %w", path, err)
	}
	if document.SchemaVersion != ClaimSchemaVersion {
		return nil, fmt.Errorf("claims document has unsupported schema_version %q", document.SchemaVersion)
	}
	if document.Claims == nil {
		return nil, errors.New("claims document claims must be an array")
	}
	if _, err := MarshalClaims(document.Claims); err != nil {
		return nil, err
	}
	return document.Claims, nil
}

// MarshalScore returns a validated score JSON document.  It is separate from
// MarshalClaims because verification needs the complete evidence context.
func MarshalScore(score Score, claims []Claim, observations []Observation) ([]byte, error) {
	if err := score.Validate(claims, observations); err != nil {
		return nil, err
	}
	return marshalIndented(score)
}

func WriteScore(path string, score Score, claims []Claim, observations []Observation) error {
	data, err := MarshalScore(score, claims, observations)
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("empty score path")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write score %q: %w", path, err)
	}
	return nil
}

func ReadScore(path string, claims []Claim, observations []Observation) (Score, error) {
	var score Score
	if err := readJSON(path, &score); err != nil {
		return Score{}, err
	}
	if err := score.Validate(claims, observations); err != nil {
		return Score{}, err
	}
	return score, nil
}

// MarshalJudgments returns a sorted JSON array of independently validated
// judgments.
func MarshalJudgments(judgments []Judgment, claims []Claim, observations []Observation) ([]byte, error) {
	copyJudgments := append([]Judgment(nil), judgments...)
	sort.SliceStable(copyJudgments, func(i, j int) bool { return copyJudgments[i].ClaimID < copyJudgments[j].ClaimID })
	seen := map[string]struct{}{}
	for _, judgment := range copyJudgments {
		if err := ValidateJudgment(judgment, claims, observations); err != nil {
			return nil, err
		}
		if _, ok := seen[judgment.ClaimID]; ok {
			return nil, fmt.Errorf("duplicate judgment for claim %q", judgment.ClaimID)
		}
		seen[judgment.ClaimID] = struct{}{}
	}
	return marshalIndented(copyJudgments)
}
