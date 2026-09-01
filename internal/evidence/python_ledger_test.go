package evidence

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPythonToolLedgerIDsValidateInGo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	base := testObservation("base")
	if err := WriteObservationsFile(path, []Observation{base}); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	code := `
import sys
from jaq_investigator.evidence import EvidenceStore
s = EvidenceStore(sys.argv[1])
r = s.append_tool_request(source="static-sandbox", version="1.0", tool_name="python", arguments={"timeout": 1.0, "code": "print(<x>)"}, sample_sha256="a"*64, sequence=1)
s.append_tool_result(request_id=r.id, source="static-sandbox", version="1.0", tool_name="python", result={"returncode": 0, "ratio": 0.25, "stdout": "<x>"}, sample_sha256="a"*64, sequence=1, status="ok", duration_ms=2)
`
	command := exec.Command("python3", "-c", code, path)
	command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(root, "python"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Python ledger helper failed: %v: %s", err, output)
	}
	observations, err := ReadObservationsFile(path)
	if err != nil {
		file, _ := os.Open(path)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var observation Observation
			if json.Unmarshal(scanner.Bytes(), &observation) == nil {
				t.Logf("id=%s go_content_id=%s json=%s", observation.ID, observation.ContentID(), scanner.Text())
			}
		}
		_ = file.Close()
		t.Fatalf("Go rejected Python-generated observation IDs: %v", err)
	}
	if len(observations) != 3 {
		t.Fatalf("got %d observations, want 3", len(observations))
	}
}
