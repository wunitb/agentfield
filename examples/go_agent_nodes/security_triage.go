package main

import (
	"archive/tar"
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	securityTriageArchivePath = "/input/source.tar"
	maxArchiveBytes           = 32 << 20
	maxScannedFileBytes       = 2 << 20
	maxScannedTotalBytes      = 64 << 20
	maxScannedFiles           = 10_000
	maxSecurityFindings       = 200
)

var securityTriageSourceCommit string

type securityTriageTask struct {
	SchemaVersion            string `json:"schemaVersion"`
	RequestID                string `json:"requestId"`
	Scope                    string `json:"scope"`
	SourceArchiveSHA256      string `json:"sourceArchiveSha256"`
	SourceTreeManifestSHA256 string `json:"sourceTreeManifestSha256"`
	SourceCommit             string `json:"sourceCommit"`
}

type securityTriageFinding struct {
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Description string `json:"description"`
}

type securityTriageSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type securityTriageReport struct {
	SchemaVersion            string                  `json:"schemaVersion"`
	RuleSetVersion           string                  `json:"ruleSetVersion"`
	ScannerSourceCommit      string                  `json:"scannerSourceCommit"`
	RequestID                string                  `json:"requestId"`
	Scope                    string                  `json:"scope"`
	SourceArchiveSHA256      string                  `json:"sourceArchiveSha256"`
	SourceTreeManifestSHA256 string                  `json:"sourceTreeManifestSha256"`
	SourceCommit             string                  `json:"sourceCommit"`
	Status                   string                  `json:"status"`
	ScannedFiles             int                     `json:"scannedFiles"`
	ScannedBytes             int64                   `json:"scannedBytes"`
	Summary                  securityTriageSummary   `json:"summary"`
	Findings                 []securityTriageFinding `json:"findings"`
}

type securityRule struct {
	id          string
	severity    string
	description string
	match       func(string, string) bool
}

type sourceTreeEntry struct {
	mode string
	oid  string
	size int64
	path string
}

var (
	sha256RefPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	commitPattern     = regexp.MustCompile(`^[a-f0-9]{40}$`)
	requestIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	defaultCredential = regexp.MustCompile(`(?i)(?:password|token|api[_-]?key)\s*[:=]\s*["']?(?:admin|password|changeme|secret|test|demo|example)(?:["'\s,]|$)`)
	remotePipe        = regexp.MustCompile(`(?i)(?:curl|wget)[^|]{0,256}\|\s*(?:ba)?sh\b`)
	imageSetting      = regexp.MustCompile(`^\s*image:\s*([^\s#]+)`)
	workflowUse       = regexp.MustCompile(`^\s*-?\s*uses:\s*([^\s#]+)`)
)

var securityRules = []securityRule{
	{
		id:          "PRIVATE_KEY_MATERIAL",
		severity:    "critical",
		description: "tracked text contains a private-key PEM header",
		match: func(_ string, line string) bool {
			return strings.Contains(line, "-----BEGIN ") && strings.Contains(line, "PRIVATE KEY-----")
		},
	},
	{
		id:          "DIRECT_OPENROUTER_EGRESS",
		severity:    "high",
		description: "tracked text references OpenRouter directly instead of the mandated gateway",
		match: func(_ string, line string) bool {
			return strings.Contains(strings.ToLower(line), "https://openrouter.ai/api/v1")
		},
	},
	{
		id:          "REMOTE_SCRIPT_PIPE",
		severity:    "high",
		description: "tracked text pipes a remote download directly into a shell",
		match: func(_ string, line string) bool {
			return remotePipe.MatchString(line)
		},
	},
	{
		id:          "DEFAULT_CREDENTIAL_LITERAL",
		severity:    "high",
		description: "tracked text appears to assign a default or placeholder credential",
		match: func(_ string, line string) bool {
			return defaultCredential.MatchString(line)
		},
	},
	{
		id:          "UNPINNED_WORKFLOW_ACTION",
		severity:    "high",
		description: "GitHub workflow action is not pinned to an exact commit",
		match: func(name string, line string) bool {
			if !strings.HasPrefix(name, ".github/workflows/") {
				return false
			}
			match := workflowUse.FindStringSubmatch(line)
			if len(match) != 2 || strings.HasPrefix(match[1], "./") {
				return false
			}
			parts := strings.Split(match[1], "@")
			return len(parts) != 2 || !commitPattern.MatchString(parts[1])
		},
	},
	{
		id:          "MUTABLE_EXTERNAL_IMAGE",
		severity:    "medium",
		description: "container configuration references an image without an immutable digest",
		match: func(name string, line string) bool {
			if !(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
				return false
			}
			match := imageSetting.FindStringSubmatch(line)
			if len(match) != 2 {
				return false
			}
			return !strings.Contains(strings.Trim(match[1], `"'`), "@sha256:")
		},
	},
	{
		id:          "WILDCARD_LISTEN_ADDRESS",
		severity:    "medium",
		description: "tracked text contains a wildcard IPv4 listen address requiring trust-boundary review",
		match: func(_ string, line string) bool {
			return strings.Contains(line, "0.0.0.0")
		},
	},
}

func runSecurityTriage(input map[string]any, archivePath string) (securityTriageReport, error) {
	task, err := parseSecurityTriageTask(input)
	if err != nil {
		return securityTriageReport{}, err
	}
	if !commitPattern.MatchString(securityTriageSourceCommit) {
		return securityTriageReport{}, errors.New("security triage scanner provenance unavailable")
	}

	archive, err := os.Open(archivePath)
	if err != nil {
		return securityTriageReport{}, errors.New("security triage archive unavailable")
	}
	defer archive.Close()

	info, err := archive.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		return securityTriageReport{}, errors.New("security triage archive rejected")
	}

	digest := sha256.New()
	if _, err := io.Copy(digest, archive); err != nil {
		return securityTriageReport{}, errors.New("security triage archive unreadable")
	}
	actualDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	if actualDigest != task.SourceArchiveSHA256 {
		return securityTriageReport{}, errors.New("security triage archive digest mismatch")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return securityTriageReport{}, errors.New("security triage archive unreadable")
	}

	report := securityTriageReport{
		SchemaVersion:            "bee.security-triage-report.v1",
		RuleSetVersion:           "bee.security-triage-rules.v2",
		ScannerSourceCommit:      securityTriageSourceCommit,
		RequestID:                task.RequestID,
		Scope:                    task.Scope,
		SourceArchiveSHA256:      actualDigest,
		SourceTreeManifestSHA256: task.SourceTreeManifestSHA256,
		SourceCommit:             task.SourceCommit,
		Status:                   "clean",
		Findings:                 []securityTriageFinding{},
	}
	seen := make(map[string]struct{})
	directories := make(map[string]struct{})
	treeEntries := make([]sourceTreeEntry, 0)
	reader := tar.NewReader(archive)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return securityTriageReport{}, errors.New("security triage archive malformed")
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if header.Typeflag == tar.TypeDir {
			name, ok := safeArchivePath(strings.TrimSuffix(header.Name, "/"))
			if !ok {
				return securityTriageReport{}, errors.New("security triage archive path rejected")
			}
			if _, duplicate := seen[name]; duplicate {
				return securityTriageReport{}, errors.New("security triage archive has duplicate paths")
			}
			seen[name] = struct{}{}
			directories[name] = struct{}{}
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxScannedFileBytes {
			return securityTriageReport{}, errors.New("security triage archive entry rejected")
		}
		name, ok := safeArchivePath(header.Name)
		if !ok {
			return securityTriageReport{}, errors.New("security triage archive path rejected")
		}
		if _, duplicate := seen[name]; duplicate {
			return securityTriageReport{}, errors.New("security triage archive has duplicate paths")
		}
		seen[name] = struct{}{}
		report.ScannedFiles++
		report.ScannedBytes += header.Size
		if report.ScannedFiles > maxScannedFiles || report.ScannedBytes > maxScannedTotalBytes {
			return securityTriageReport{}, errors.New("security triage scan budget exceeded")
		}
		contents, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(contents)) != header.Size {
			return securityTriageReport{}, errors.New("security triage archive entry unreadable")
		}
		if !utf8.Valid(contents) || strings.IndexByte(string(contents), 0) >= 0 {
			return securityTriageReport{}, errors.New("security triage archive entry is not text")
		}
		treeEntries = append(treeEntries, sourceTreeEntry{
			mode: sourceTreeMode(header.Mode),
			oid:  gitBlobSHA1(contents),
			size: header.Size,
			path: name,
		})
		findings, err := scanSecurityFile(name, string(contents))
		if err != nil {
			return securityTriageReport{}, err
		}
		report.Findings = append(report.Findings, findings...)
		if len(report.Findings) > maxSecurityFindings {
			return securityTriageReport{}, errors.New("security triage finding budget exceeded")
		}
	}
	if report.ScannedFiles == 0 {
		return securityTriageReport{}, errors.New("security triage archive contains no files")
	}
	expectedDirectories := make(map[string]struct{})
	for _, entry := range treeEntries {
		for directory := pathpkg.Dir(entry.path); directory != "."; directory = pathpkg.Dir(directory) {
			expectedDirectories[directory] = struct{}{}
		}
	}
	if len(directories) != len(expectedDirectories) {
		return securityTriageReport{}, errors.New("security triage archive directory set mismatch")
	}
	for directory := range directories {
		if _, expected := expectedDirectories[directory]; !expected {
			return securityTriageReport{}, errors.New("security triage archive directory set mismatch")
		}
	}
	if sourceTreeManifestDigest(treeEntries) != task.SourceTreeManifestSHA256 {
		return securityTriageReport{}, errors.New("security triage source tree manifest mismatch")
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		left, right := report.Findings[i], report.Findings[j]
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		return left.RuleID < right.RuleID
	})
	for _, finding := range report.Findings {
		switch finding.Severity {
		case "critical":
			report.Summary.Critical++
		case "high":
			report.Summary.High++
		case "medium":
			report.Summary.Medium++
		case "low":
			report.Summary.Low++
		}
	}
	if len(report.Findings) > 0 {
		report.Status = "findings"
	}
	return report, nil
}

func parseSecurityTriageTask(input map[string]any) (securityTriageTask, error) {
	message, ok := input["message"].(string)
	if !ok || len(message) == 0 || len(message) > 2_048 {
		return securityTriageTask{}, errors.New("security triage task rejected")
	}
	decoder := json.NewDecoder(strings.NewReader(message))
	decoder.DisallowUnknownFields()
	var task securityTriageTask
	if err := decoder.Decode(&task); err != nil {
		return securityTriageTask{}, errors.New("security triage task rejected")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return securityTriageTask{}, errors.New("security triage task rejected")
	}
	if task.SchemaVersion != "bee.security-triage-task.v1" || task.Scope != "tracked-source" ||
		!requestIDPattern.MatchString(task.RequestID) || !sha256RefPattern.MatchString(task.SourceArchiveSHA256) ||
		!sha256RefPattern.MatchString(task.SourceTreeManifestSHA256) || !commitPattern.MatchString(task.SourceCommit) {
		return securityTriageTask{}, errors.New("security triage task rejected")
	}
	return task, nil
}

func safeArchivePath(name string) (string, bool) {
	if name == "" || len(name) > 512 || !utf8.ValidString(name) || strings.ContainsRune(name, '\x00') || strings.HasPrefix(name, "/") {
		return "", false
	}
	cleaned := pathpkg.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != name {
		return "", false
	}
	return cleaned, true
}

func gitBlobSHA1(contents []byte) string {
	digest := sha1.New()
	_, _ = fmt.Fprintf(digest, "blob %d\x00", len(contents))
	_, _ = digest.Write(contents)
	return hex.EncodeToString(digest.Sum(nil))
}

func sourceTreeMode(mode int64) string {
	if mode&0o111 != 0 {
		return "100755"
	}
	return "100644"
}

func sourceTreeManifestDigest(entries []sourceTreeEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	digest := sha256.New()
	for _, entry := range entries {
		_, _ = fmt.Fprintf(digest, "%s blob %s %d\t%s\x00", entry.mode, entry.oid, entry.size, entry.path)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func hasShellLineContinuation(line string) bool {
	trailingBackslashes := 0
	for index := len(line) - 1; index >= 0 && line[index] == '\\'; index-- {
		trailingBackslashes++
	}
	return trailingBackslashes%2 == 1
}

func scanSecurityFile(name string, contents string) ([]securityTriageFinding, error) {
	findings := []securityTriageFinding{}
	scanner := bufio.NewScanner(strings.NewReader(contents))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var logicalLine strings.Builder
	logicalStartLine := 0
	lineNumber := 0

	scanLogicalLine := func() {
		line := logicalLine.String()
		for _, rule := range securityRules {
			if rule.match(name, line) {
				findings = append(findings, securityTriageFinding{
					RuleID:      rule.id,
					Severity:    rule.severity,
					Path:        name,
					Line:        logicalStartLine,
					Description: rule.description,
				})
			}
		}
		logicalLine.Reset()
		logicalStartLine = 0
	}

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if logicalStartLine == 0 {
			logicalStartLine = lineNumber
		}
		continued := hasShellLineContinuation(line)
		if continued {
			line = line[:len(line)-1]
		}
		if logicalLine.Len()+len(line) > 1<<20 {
			return nil, errors.New("security triage logical line rejected")
		}
		_, _ = logicalLine.WriteString(line)
		if !continued {
			scanLogicalLine()
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("security triage line rejected: %w", err)
	}
	if logicalStartLine != 0 {
		scanLogicalLine()
	}
	return findings, nil
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}
