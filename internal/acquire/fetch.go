package acquire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

const MaxArtifactBytes = 64 << 20

const fetchScript = `import sys,urllib.request,urllib.parse,socket,ipaddress
u=sys.stdin.read(4096).strip()
p=urllib.parse.urlsplit(u)
if p.port not in (None,80,443): raise RuntimeError("port refused")
for info in socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=="https" else 80),type=socket.SOCK_STREAM):
 a=ipaddress.ip_address(info[4][0])
 if not a.is_global: raise RuntimeError("non-public address refused")
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k): raise RuntimeError("redirect refused")
r=urllib.request.build_opener(NoRedirect).open(u,timeout=30)
if int(r.headers.get("Content-Length","0") or 0)>67108864: raise RuntimeError("artifact too large")
n=0
while True:
 b=r.read(65536)
 if not b: break
 n+=len(b)
 if n>67108864: raise RuntimeError("artifact too large")
 sys.stdout.buffer.write(b)
`

func Fetch(ctx context.Context, imageID, locator string) ([]byte, error) {
	parsed, err := url.Parse(locator)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("approved fetch target must be an absolute HTTP(S) URL without userinfo")
	}
	if !strings.HasPrefix(imageID, "sha256:") {
		return nil, errors.New("fetcher requires an immutable image ID")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	args := []string{"run", "--rm", "-i", "--pull=never", "--platform=linux/amd64", "--network=bridge", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=64", "--memory=256m", "--cpus=1", "--user=65532:65532", "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m", "--entrypoint=/usr/bin/python3", imageID, "-c", fetchScript}
	cmd := exec.CommandContext(fetchCtx, "docker", args...)
	cmd.Stdin = strings.NewReader(locator)
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	cmd.Stdout = &limitedWriter{Writer: &output, Remaining: MaxArtifactBytes + 1}
	cmd.Stderr = &limitedWriter{Writer: &diagnostics, Remaining: 4096}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("isolated fetch failed: %w: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	if output.Len() > MaxArtifactBytes {
		return nil, errors.New("isolated fetch exceeded artifact size limit")
	}
	return output.Bytes(), nil
}

type limitedWriter struct {
	io.Writer
	Remaining int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	original := len(p)
	if w.Remaining <= 0 {
		return original, nil
	}
	if len(p) > w.Remaining {
		p = p[:w.Remaining]
	}
	_, _ = w.Writer.Write(p)
	w.Remaining -= len(p)
	return original, nil
}

type RequestDecision struct {
	Actor string    `json:"actor"`
	At    time.Time `json:"at"`
	Note  string    `json:"note,omitempty"`
}
type RequestOutcome struct {
	At             time.Time      `json:"at"`
	Error          string         `json:"error,omitempty"`
	ArtifactPath   string         `json:"artifact_path,omitempty"`
	ArtifactSHA256 string         `json:"artifact_sha256,omitempty"`
	HandoffPath    string         `json:"handoff_path,omitempty"`
	ChildRun       string         `json:"child_run,omitempty"`
	Execution      map[string]any `json:"execution,omitempty"`
}
type ActionRequest struct {
	SchemaVersion         string           `json:"schema_version"`
	ID                    string           `json:"id"`
	Kind                  string           `json:"kind"`
	Status                string           `json:"status"`
	Reason                string           `json:"reason"`
	EvidenceIDs           []string         `json:"evidence_ids"`
	Target                map[string]any   `json:"target"`
	RequestedObservations []string         `json:"requested_observations"`
	Justification         map[string]any   `json:"justification,omitempty"`
	Screening             map[string]any   `json:"screening,omitempty"`
	Execution             map[string]any   `json:"execution,omitempty"`
	Decision              *RequestDecision `json:"decision,omitempty"`
	Outcome               *RequestOutcome  `json:"outcome,omitempty"`
}

// Legacy dossiers predate screening and retain their explicit operator flow.
// New dossiers always carry a verdict for supported acquisition request kinds.
func (r ActionRequest) ScreeningQualified() bool {
	return r.Screening == nil || r.Screening["verdict"] == "qualified"
}

type RequestFile struct {
	SchemaVersion  string          `json:"schema_version"`
	ActionRequests []ActionRequest `json:"action_requests"`
}

func ReadRequests(path string) (RequestFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RequestFile{}, err
	}
	var value RequestFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return RequestFile{}, err
	}
	if value.SchemaVersion != "1.0" {
		return RequestFile{}, errors.New("unsupported requests schema")
	}
	seen := map[string]bool{}
	for _, item := range value.ActionRequests {
		if item.ID == "" || seen[item.ID] {
			return RequestFile{}, errors.New("invalid request ID")
		}
		if item.SchemaVersion != "1.0" || item.Reason == "" || len(item.EvidenceIDs) == 0 || item.Target == nil {
			return RequestFile{}, errors.New("invalid action request")
		}
		switch item.Status {
		case "pending_authorization", "approved", "denied", "running", "fetched", "handoff_pending", "failed":
		default:
			return RequestFile{}, errors.New("invalid request status")
		}
		seen[item.ID] = true
	}
	return value, nil
}
