package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// DefaultJSONLLineLimit prevents an accidentally enormous model- or
	// sample-derived value from turning a JSONL reader into an unbounded
	// allocation.  Callers that need larger records can use ReadObservations
	// with a reader that emits bounded records or the configurable helper.
	DefaultJSONLLineLimit = 16 << 20
)

// WriteObservations writes a validated, sorted, deduplicated JSONL evidence
// package.  There is exactly one object per line and no trailing metadata line.
func WriteObservations(w io.Writer, observations []Observation) error {
	if w == nil {
		return errors.New("nil observation writer")
	}
	unique, err := DeduplicateObservations(observations)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	for _, observation := range unique {
		if err := encoder.Encode(observation); err != nil {
			return fmt.Errorf("encode observation %q: %w", observation.ID, err)
		}
	}
	return nil
}

// MarshalObservations returns the canonical JSONL representation in memory.
func MarshalObservations(observations []Observation) ([]byte, error) {
	var buffer bytes.Buffer
	if err := WriteObservations(&buffer, observations); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// ReadObservations reads and validates a JSONL evidence package.  Blank lines
// are ignored to make hand-inspection friendly packages safe to consume.
func ReadObservations(r io.Reader) ([]Observation, error) {
	return ReadObservationsLimit(r, DefaultJSONLLineLimit)
}

// ReadObservationsLimit is ReadObservations with an explicit per-line cap.
func ReadObservationsLimit(r io.Reader, lineLimit int) ([]Observation, error) {
	if r == nil {
		return nil, errors.New("nil observation reader")
	}
	if lineLimit < 1024 {
		return nil, errors.New("observation line limit must be at least 1024 bytes")
	}
	scanner := bufio.NewScanner(r)
	// Scanner's token limit includes the line ending.  The default 64 KiB is
	// too small for decompiler observations, so use the explicit bounded cap.
	scanner.Buffer(make([]byte, 64*1024), lineLimit)
	result := make([]Observation, 0)
	line := 0
	for scanner.Scan() {
		line++
		data := bytes.TrimSpace(scanner.Bytes())
		if len(data) == 0 {
			continue
		}
		var observation Observation
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&observation); err != nil {
			return nil, fmt.Errorf("observation JSONL line %d: %w", line, err)
		}
		if err := observation.Validate(); err != nil {
			return nil, fmt.Errorf("observation JSONL line %d: %w", line, err)
		}
		result = append(result, observation)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read observations: %w", err)
	}
	if _, err := DeduplicateObservations(result); err != nil {
		return nil, fmt.Errorf("validate observation package: %w", err)
	}
	return SortObservations(result), nil
}

// WriteObservationsFile creates/truncates a single output file and writes a
// canonical evidence package.  Parent directory creation is intentionally the
// controller's responsibility so this helper cannot unexpectedly broaden its
// filesystem scope.
func WriteObservationsFile(path string, observations []Observation) error {
	if path == "" {
		return errors.New("empty observations path")
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create observations file: %w", err)
	}
	if err := WriteObservations(file, observations); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close observations file: %w", err)
	}
	return nil
}

// ReadObservationsFile reads a canonical evidence package from path.
func ReadObservationsFile(path string) ([]Observation, error) {
	if path == "" {
		return nil, errors.New("empty observations path")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open observations file: %w", err)
	}
	observations, readErr := ReadObservations(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close observations file: %w", closeErr)
	}
	return observations, nil
}

// MarshalJSONValue is a small helper for callers that need to calculate the
// same JSON representation used by content-derived IDs.
func MarshalJSONValue(value any) ([]byte, error) {
	return json.Marshal(value)
}
