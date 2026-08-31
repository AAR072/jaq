package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareOutputRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "claims.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareOutput(dir); err == nil {
		t.Fatal("expected existing output rejection")
	}
}

func TestJSONAtomicRoundTripAndStrictRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value.json")
	input := struct {
		Value string `json:"value"`
	}{Value: "evidence"}
	if err := writeJSONAtomic(path, input); err != nil {
		t.Fatal(err)
	}
	var output struct {
		Value string `json:"value"`
	}
	if err := readJSONStrict(path, &output); err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Fatalf("round trip mismatch: %#v", output)
	}
}
