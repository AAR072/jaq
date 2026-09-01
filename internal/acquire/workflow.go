package acquire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaq-project/jaq/internal/sandbox"
)

type ApprovalResult struct {
	RequestID    string `json:"request_id"`
	Kind         string `json:"kind"`
	Status       string `json:"status"`
	ArtifactPath string `json:"artifact_path,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	HandoffPath  string `json:"handoff_path,omitempty"`
}

func writeRequests(path string, value RequestFile) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func updateManifestStatus(runDir, status string) error {
	path := filepath.Join(runDir, "run-manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	value["status"] = status
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func decide(runDir, requestID, status string) (ApprovalResult, error) {
	if !filepath.IsAbs(runDir) || requestID == "" || strings.ContainsAny(requestID, "/\\\x00") {
		return ApprovalResult{}, errors.New("decision requires absolute run directory and simple request ID")
	}
	path := filepath.Join(runDir, "requests.json")
	requests, err := ReadRequests(path)
	if err != nil {
		return ApprovalResult{}, err
	}
	for index := range requests.ActionRequests {
		item := &requests.ActionRequests[index]
		if item.ID != requestID {
			continue
		}
		if item.Status != "pending_authorization" {
			return ApprovalResult{}, errors.New("request already decided")
		}
		item.Status = status
		item.Decision = &RequestDecision{Actor: "operator", At: time.Now().UTC()}
		if err := writeRequests(path, requests); err != nil {
			return ApprovalResult{}, err
		}
		statusAfter := "completed"
		for _, candidate := range requests.ActionRequests {
			if candidate.Status == "pending_authorization" {
				statusAfter = "awaiting_authorization"
				break
			}
			if candidate.Status == "approved" || candidate.Status == "running" {
				statusAfter = "awaiting_handoff"
			}
		}
		if err := updateManifestStatus(runDir, statusAfter); err != nil {
			return ApprovalResult{}, err
		}
		return ApprovalResult{RequestID: item.ID, Kind: item.Kind, Status: status}, nil
	}
	return ApprovalResult{}, errors.New("pending request not found")
}

func Approve(_ context.Context, runDir, requestID string) (ApprovalResult, error) {
	return decide(runDir, requestID, "approved")
}
func Deny(runDir, requestID string) (ApprovalResult, error) {
	return decide(runDir, requestID, "denied")
}

func Resume(ctx context.Context, runDir string) ([]ApprovalResult, error) {
	path := filepath.Join(runDir, "requests.json")
	requests, err := ReadRequests(path)
	if err != nil {
		return nil, err
	}
	results := []ApprovalResult{}
	for index := range requests.ActionRequests {
		item := &requests.ActionRequests[index]
		if item.Status != "approved" && item.Status != "running" {
			continue
		}
		item.Status = "running"
		if err := writeRequests(path, requests); err != nil {
			return results, err
		}
		result := ApprovalResult{RequestID: item.ID, Kind: item.Kind}
		dir := filepath.Join(runDir, "acquisitions", item.ID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return results, err
		}
		switch item.Kind {
		case "fetch_remote_payload":
			locator, _ := item.Target["url"].(string)
			runtime := sandbox.NewDocker()
			imageID, fetchErr := runtime.ImageID(ctx)
			var data []byte
			if fetchErr == nil {
				data, fetchErr = Fetch(ctx, imageID, locator)
			}
			if fetchErr == nil {
				sum := sha256.Sum256(data)
				result.SHA256 = hex.EncodeToString(sum[:])
				result.ArtifactPath = filepath.Join(dir, "payload.bin")
				fetchErr = os.WriteFile(result.ArtifactPath, data, 0o400)
			}
			if fetchErr != nil {
				item.Status = "failed"
				item.Outcome = &RequestOutcome{At: time.Now().UTC(), Error: "bounded fetch failed"}
				if writeErr := writeRequests(path, requests); writeErr != nil {
					return results, writeErr
				}
				return results, fmt.Errorf("request %s: %w", item.ID, fetchErr)
			}
			item.Status = "fetched"
			result.Status = item.Status
			item.Outcome = &RequestOutcome{At: time.Now().UTC(), ArtifactPath: result.ArtifactPath, ArtifactSHA256: result.SHA256}
		case "dynamic_analysis", "memory_dump", "network_capture":
			item.Status = "handoff_pending"
			result.Status = item.Status
			result.HandoffPath = filepath.Join(dir, "handoff.json")
			payload := map[string]any{"schema_version": "1.0", "request": item, "status": item.Status}
			encoded, _ := json.MarshalIndent(payload, "", "  ")
			if err := os.WriteFile(result.HandoffPath, append(encoded, '\n'), 0o600); err != nil {
				return results, err
			}
			item.Outcome = &RequestOutcome{At: time.Now().UTC(), HandoffPath: result.HandoffPath}
		default:
			item.Status = "handoff_pending"
			result.Status = item.Status
			item.Outcome = &RequestOutcome{At: time.Now().UTC()}
		}
		if err := writeRequests(path, requests); err != nil {
			return results, err
		}
		results = append(results, result)
	}
	statusAfter := "completed"
	for _, candidate := range requests.ActionRequests {
		if candidate.Status == "pending_authorization" {
			statusAfter = "awaiting_authorization"
			break
		}
		if candidate.Status == "handoff_pending" {
			statusAfter = "awaiting_handoff"
		}
	}
	if err := updateManifestStatus(runDir, statusAfter); err != nil {
		return results, err
	}
	return results, nil
}

func RecordChild(runDir, requestID, childRun string) error {
	path := filepath.Join(runDir, "requests.json")
	requests, err := ReadRequests(path)
	if err != nil {
		return err
	}
	for index := range requests.ActionRequests {
		item := &requests.ActionRequests[index]
		if item.ID == requestID {
			if item.Outcome == nil {
				item.Outcome = &RequestOutcome{At: time.Now().UTC()}
			}
			item.Outcome.ChildRun = childRun
			return writeRequests(path, requests)
		}
	}
	return errors.New("request not found")
}
