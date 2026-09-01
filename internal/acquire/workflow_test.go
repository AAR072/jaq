package acquire

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDynamicApprovalWritesOnlyHandoff(t *testing.T) {
	run := t.TempDir()
	contents := `{"schema_version":"1.0","action_requests":[{"schema_version":"1.0","id":"request-1","kind":"dynamic_analysis","status":"pending_authorization","reason":"runtime evidence","evidence_ids":["obs-1"],"target":{},"requested_observations":["processes"]}]}`
	if err := os.WriteFile(filepath.Join(run, "requests.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "run-manifest.json"), []byte("{\"status\":\"awaiting_authorization\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	approved, err := Approve(context.Background(), run, "request-1")
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != "approved" {
		t.Fatalf("unexpected approval: %#v", approved)
	}
	results, err := Resume(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	if result.Status != "handoff_pending" || result.HandoffPath == "" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if _, err := os.Stat(result.HandoffPath); err != nil {
		t.Fatal(err)
	}
}

func TestFetchRejectsUnsafeLocatorBeforeDocker(t *testing.T) {
	if _, err := Fetch(context.Background(), "sha256:"+string(make([]byte, 64)), "file:///tmp/payload"); err == nil {
		t.Fatal("unsafe fetch locator accepted")
	}
}
