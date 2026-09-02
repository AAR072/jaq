package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var persistedOutputs = []string{
	"run-manifest.json",
	"observations.jsonl",
	"findings.jsonl",
	"research.json",
	"claims.json",
	"assets.json",
	"requests.json",
	"score.json",
	"report.md",
}

func prepareOutput(path string) (string, error) {
	if path == "" {
		return "", errors.New("output directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve output directory: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect output directory: %w", err)
		}
		if err := os.MkdirAll(absolute, 0o700); err != nil {
			return "", fmt.Errorf("create output directory: %w", err)
		}
		return absolute, nil
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("output must be a real directory, not a file or symlink")
	}
	entries, err := os.ReadDir(absolute)
	if err != nil {
		return "", fmt.Errorf("read output directory: %w", err)
	}
	if len(entries) != 0 {
		return "", errors.New("output directory must be empty; refusing to expose existing host files to the analyzer")
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return "", fmt.Errorf("protect output directory: %w", err)
	}
	return absolute, nil
}

func writeJSONAtomic(path string, value any) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".jaq-json-*")
	if err != nil {
		return fmt.Errorf("create temporary JSON file: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set JSON file permissions: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync JSON: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close JSON: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish JSON: %w", err)
	}
	keep = true
	return nil
}

func readJSONStrict(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", filepath.Base(path))
		}
		return fmt.Errorf("decode %s trailing data: %w", filepath.Base(path), err)
	}
	return nil
}

func contentHash(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}
