package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/lowerbundle"
	"github.com/dimasma0305/php-parser-go/parsetree"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type semgrepPayload struct {
	Results []semgrepResult `json:"results"`
	Errors  []any           `json:"errors"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message string `json:"message"`
	} `json:"extra"`
}

type countedRule struct {
	ID      string
	Count   int
	Message string
}

func main() {
	var target string
	var outputDir string
	var semgrepBin string
	var timeout int
	var timeoutThreshold int
	var phparserWorkers int
	var configs multiFlag
	var excludes multiFlag

	flag.StringVar(&target, "target", "", "plugin or source directory to scan")
	flag.StringVar(&outputDir, "output-dir", "", "output directory; defaults to tmp/phparser-semgrep-bundle-<timestamp>")
	flag.StringVar(&semgrepBin, "semgrep-bin", "semgrep", "Semgrep binary to execute")
	flag.IntVar(&timeout, "timeout", 0, "Semgrep per-rule timeout in seconds")
	flag.IntVar(&timeoutThreshold, "timeout-threshold", 0, "Semgrep file timeout threshold")
	flag.IntVar(&phparserWorkers, "phparser-workers", 0, "worker count for native Go parsing")
	flag.Var(&configs, "config", "Semgrep config file(s). Repeatable.")
	flag.Var(&excludes, "exclude-dir", "directory name to exclude while scanning and building the parse manifest. Repeatable.")
	flag.Parse()

	if target == "" {
		fmt.Fprintln(os.Stderr, "-target is required")
		os.Exit(2)
	}
	if len(configs) == 0 {
		fmt.Fprintln(os.Stderr, "at least one -config is required")
		os.Exit(2)
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve target: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(absTarget)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "target not found or not a directory: %s\n", absTarget)
		os.Exit(1)
	}

	if outputDir == "" {
		outputDir = filepath.Join("tmp", "phparser-semgrep-bundle-"+time.Now().UTC().Format("20060102-150405"))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir output dir: %v\n", err)
		os.Exit(1)
	}

	excluded := append(defaultExcludedDirs(), excludes...)
	manifest, err := parsetree.BuildManifestForRoot(absTarget, excluded, phparserWorkers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build phparser manifest: %v\n", err)
		os.Exit(1)
	}
	manifestPayload, err := parsetree.MarshalManifest(manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode manifest: %v\n", err)
		os.Exit(1)
	}

	manifestPath := filepath.Join(outputDir, "phparser-parse-manifest.json")
	fileListPath := filepath.Join(outputDir, "phparser-parseable-files.txt")
	if err := os.WriteFile(manifestPath, manifestPayload, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write manifest: %v\n", err)
		os.Exit(1)
	}
	if err := parsetree.WriteRelativeFileList(fileListPath, manifest.Files); err != nil {
		fmt.Fprintf(os.Stderr, "write parseable file list: %v\n", err)
		os.Exit(1)
	}

	targetRawJSONPath := filepath.Join(outputDir, "semgrep-target-raw.json")
	targetRawTextPath := filepath.Join(outputDir, "semgrep-target.txt")
	targetConsolePath := filepath.Join(outputDir, "semgrep-target-console.txt")
	targetPayloadBytes, err := runSemgrep(semgrepBin, configs, excluded, absTarget, targetRawJSONPath, targetRawTextPath, targetConsolePath, timeout, timeoutThreshold)
	if err != nil {
		fmt.Fprintf(os.Stderr, "target semgrep: %v\n", err)
		os.Exit(1)
	}
	targetPayload, err := decodeSemgrepPayload(targetPayloadBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode target semgrep json: %v\n", err)
		os.Exit(1)
	}

	bundlePath := filepath.Join(outputDir, "lowered-bundle.php")
	mappingPath := filepath.Join(outputDir, "lowered-mapping.json")
	loweredResult, lowerErr := lowerbundle.BuildForRoot(absTarget, excluded, bundlePath, mappingPath, phparserWorkers)
	coverageNote := "merged target scan + native Go lowered bundle scan"
	loweredPayload := semgrepPayload{}
	loweredRawJSONPath := filepath.Join(outputDir, "semgrep-lowered-raw.json")
	loweredRawTextPath := filepath.Join(outputDir, "semgrep-lowered.txt")
	loweredConsolePath := filepath.Join(outputDir, "semgrep-lowered-console.txt")
	if lowerErr == nil {
		loweredBytes, err := runSemgrep(semgrepBin, configs, nil, bundlePath, loweredRawJSONPath, loweredRawTextPath, loweredConsolePath, timeout, timeoutThreshold)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lowered semgrep: %v\n", err)
			os.Exit(1)
		}
		loweredPayload, err = decodeSemgrepPayload(loweredBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode lowered semgrep json: %v\n", err)
			os.Exit(1)
		}
	} else {
		coverageNote = "target scan only; native Go lowered bundle build failed"
		_ = os.WriteFile(loweredConsolePath, []byte(lowerErr.Error()+"\n"), 0o644)
	}

	merged := mergeSemgrepPayloads(targetPayload, loweredPayload)
	resultsPayload, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode merged results: %v\n", err)
		os.Exit(1)
	}
	resultsPath := filepath.Join(outputDir, "semgrep-results.json")
	if err := os.WriteFile(resultsPath, append(resultsPayload, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write merged results: %v\n", err)
		os.Exit(1)
	}

	humanSummaryPath := filepath.Join(outputDir, "human-summary.md")
	if err := os.WriteFile(humanSummaryPath, []byte(buildHumanSummary(absTarget, outputDir, manifest, merged, len(targetPayload.Results), len(loweredPayload.Results), coverageNote)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write human summary: %v\n", err)
		os.Exit(1)
	}

	readmePath := filepath.Join(outputDir, "README.md")
	skippedCount := 0
	if loweredResult != nil {
		skippedCount = len(loweredResult.SkippedFiles)
	}
	if err := os.WriteFile(readmePath, []byte(buildReadme(absTarget, manifestPath, fileListPath, targetRawJSONPath, targetRawTextPath, targetConsolePath, bundlePath, mappingPath, loweredRawJSONPath, loweredRawTextPath, loweredConsolePath, resultsPath, humanSummaryPath, skippedCount, coverageNote)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write readme: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(outputDir)
}

func defaultExcludedDirs() []string {
	return []string{
		"vendor",
		"vendor-prefixed",
		"vendor_prefixed",
		"node_modules",
		"bower_components",
		"tests",
		"test",
		"spec",
	}
}

func runSemgrep(semgrepBin string, configs []string, excludes []string, target string, rawJSONPath string, rawTextPath string, consolePath string, timeout int, timeoutThreshold int) ([]byte, error) {
	command := []string{
		semgrepBin,
		"scan",
		"--no-git-ignore",
		"--no-rewrite-rule-ids",
		"--dataflow-traces",
		"--max-target-bytes",
		"0",
		"--timeout",
		fmt.Sprintf("%d", timeout),
		"--timeout-threshold",
		fmt.Sprintf("%d", timeoutThreshold),
		"--jobs",
		"1",
	}
	for _, config := range configs {
		command = append(command, "--config", config)
	}
	for _, exclude := range excludes {
		command = append(command, "--exclude", fmt.Sprintf("**/%s/**", exclude))
	}
	command = append(
		command,
		"--json-output", rawJSONPath,
		"--text-output", rawTextPath,
		target,
	)

	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(consolePath, output, 0o644); writeErr != nil {
		return nil, writeErr
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			return nil, err
		}
	}
	return os.ReadFile(rawJSONPath)
}

func decodeSemgrepPayload(payloadBytes []byte) (semgrepPayload, error) {
	var payload semgrepPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return semgrepPayload{}, err
	}
	return payload, nil
}

func mergeSemgrepPayloads(payloads ...semgrepPayload) semgrepPayload {
	merged := semgrepPayload{
		Results: make([]semgrepResult, 0),
		Errors:  make([]any, 0),
	}
	for _, payload := range payloads {
		merged.Results = append(merged.Results, payload.Results...)
		merged.Errors = append(merged.Errors, payload.Errors...)
	}
	return merged
}

func buildHumanSummary(target string, outputDir string, manifest *parsetree.Manifest, payload semgrepPayload, targetFindings int, loweredFindings int, coverageNote string) string {
	ruleCounts := make(map[string]int)
	ruleMessages := make(map[string]string)
	fileCounts := make(map[string]int)
	for _, result := range payload.Results {
		ruleCounts[result.CheckID]++
		fileCounts[result.Path]++
		if ruleMessages[result.CheckID] == "" {
			ruleMessages[result.CheckID] = result.Extra.Message
		}
	}

	sortedRules := make([]countedRule, 0, len(ruleCounts))
	for id, count := range ruleCounts {
		sortedRules = append(sortedRules, countedRule{ID: id, Count: count, Message: ruleMessages[id]})
	}
	sort.Slice(sortedRules, func(i int, j int) bool {
		if sortedRules[i].Count != sortedRules[j].Count {
			return sortedRules[i].Count > sortedRules[j].Count
		}
		return sortedRules[i].ID < sortedRules[j].ID
	})

	type fileHit struct {
		Path  string
		Count int
	}
	sortedFiles := make([]fileHit, 0, len(fileCounts))
	for path, count := range fileCounts {
		sortedFiles = append(sortedFiles, fileHit{Path: path, Count: count})
	}
	sort.Slice(sortedFiles, func(i int, j int) bool {
		if sortedFiles[i].Count != sortedFiles[j].Count {
			return sortedFiles[i].Count > sortedFiles[j].Count
		}
		return sortedFiles[i].Path < sortedFiles[j].Path
	})

	lines := []string{
		"# phparser Semgrep Bundle Scan",
		"",
		fmt.Sprintf("- Target: `%s`", target),
		fmt.Sprintf("- Output dir: `%s`", outputDir),
		fmt.Sprintf("- Findings: `%d`", len(payload.Results)),
		fmt.Sprintf("- Target findings: `%d`", targetFindings),
		fmt.Sprintf("- Lowered findings: `%d`", loweredFindings),
		fmt.Sprintf("- Semgrep errors: `%d`", len(payload.Errors)),
		fmt.Sprintf("- phparser parseable PHP files: `%d/%d`", manifest.Counts.Parsed, manifest.Counts.Total),
		fmt.Sprintf("- Coverage: `%s`", coverageNote),
		"",
		"## Top Rules",
	}
	if len(sortedRules) == 0 {
		lines = append(lines, "- No findings")
	} else {
		for _, rule := range sortedRules[:min(10, len(sortedRules))] {
			line := fmt.Sprintf("- `%s`: `%d` findings", rule.ID, rule.Count)
			if rule.Message != "" {
				line += " - " + rule.Message
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, "", "## Top Files")
	if len(sortedFiles) == 0 {
		lines = append(lines, "- No files hit")
	} else {
		for _, file := range sortedFiles[:min(10, len(sortedFiles))] {
			lines = append(lines, fmt.Sprintf("- `%s`: `%d` findings", file.Path, file.Count))
		}
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func buildReadme(target, manifestPath, fileListPath, targetRawJSONPath, targetRawTextPath, targetConsolePath, bundlePath, mappingPath, loweredRawJSONPath, loweredRawTextPath, loweredConsolePath, resultsPath, humanSummaryPath string, skippedFiles int, coverageNote string) string {
	lines := []string{
		"# phparser Semgrep Bundle Scan",
		"",
		fmt.Sprintf("- Target: `%s`", target),
		fmt.Sprintf("- phparser parse manifest: `%s`", manifestPath),
		fmt.Sprintf("- phparser parseable file list: `%s`", fileListPath),
		fmt.Sprintf("- Raw target Semgrep JSON: `%s`", targetRawJSONPath),
		fmt.Sprintf("- Raw target Semgrep text: `%s`", targetRawTextPath),
		fmt.Sprintf("- Raw target Semgrep console: `%s`", targetConsolePath),
		fmt.Sprintf("- Lowered bundle: `%s`", bundlePath),
		fmt.Sprintf("- Lowered mapping: `%s`", mappingPath),
		fmt.Sprintf("- Raw lowered Semgrep JSON: `%s`", loweredRawJSONPath),
		fmt.Sprintf("- Raw lowered Semgrep text: `%s`", loweredRawTextPath),
		fmt.Sprintf("- Raw lowered Semgrep console: `%s`", loweredConsolePath),
		fmt.Sprintf("- Results JSON: `%s`", resultsPath),
		fmt.Sprintf("- Human summary: `%s`", humanSummaryPath),
		fmt.Sprintf("- Lowerer skipped files: `%d`", skippedFiles),
		fmt.Sprintf("- Coverage: `%s`", coverageNote),
		"",
		"Notes:",
		"- This is the first pure-Go combined wrapper under `phparser`.",
		"- The lowered stage currently emits original functions plus lowered methods; bridge families are still a separate migration step.",
		"",
	}
	return strings.Join(lines, "\n")
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
