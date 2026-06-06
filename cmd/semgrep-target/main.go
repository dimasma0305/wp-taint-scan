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
	flag.StringVar(&outputDir, "output-dir", "", "output directory; defaults to tmp/phparser-semgrep-target-<timestamp>")
	flag.StringVar(&semgrepBin, "semgrep-bin", "semgrep", "Semgrep binary to execute")
	flag.IntVar(&timeout, "timeout", 0, "Semgrep per-rule timeout in seconds")
	flag.IntVar(&timeoutThreshold, "timeout-threshold", 0, "Semgrep file timeout threshold")
	flag.IntVar(&phparserWorkers, "phparser-workers", 0, "worker count for the phparser parse-tree manifest")
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
		outputDir = filepath.Join("tmp", "phparser-semgrep-target-"+time.Now().UTC().Format("20060102-150405"))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir output dir: %v\n", err)
		os.Exit(1)
	}

	manifest, err := parsetree.BuildManifestForRoot(absTarget, excludes, phparserWorkers)
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

	rawJSONPath := filepath.Join(outputDir, "semgrep-target-raw.json")
	rawTextPath := filepath.Join(outputDir, "semgrep-target.txt")
	consolePath := filepath.Join(outputDir, "semgrep-target-console.txt")

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
	for _, exclude := range append(defaultExcludedDirs(), excludes...) {
		command = append(command, "--exclude", fmt.Sprintf("**/%s/**", exclude))
	}
	command = append(
		command,
		"--json-output", rawJSONPath,
		"--text-output", rawTextPath,
		absTarget,
	)

	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			_ = os.WriteFile(consolePath, output, 0o644)
			fmt.Fprintf(os.Stderr, "semgrep failed: %v\n", err)
			os.Exit(1)
		}
	}
	if err := os.WriteFile(consolePath, output, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write console log: %v\n", err)
		os.Exit(1)
	}

	payloadBytes, err := os.ReadFile(rawJSONPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read semgrep json: %v\n", err)
		os.Exit(1)
	}
	var payload semgrepPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "decode semgrep json: %v\n", err)
		os.Exit(1)
	}

	resultsPath := filepath.Join(outputDir, "semgrep-results.json")
	if err := os.WriteFile(resultsPath, payloadBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write merged results: %v\n", err)
		os.Exit(1)
	}

	humanSummaryPath := filepath.Join(outputDir, "human-summary.md")
	if err := os.WriteFile(humanSummaryPath, []byte(buildHumanSummary(absTarget, outputDir, manifest, payload)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write human summary: %v\n", err)
		os.Exit(1)
	}

	readmePath := filepath.Join(outputDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(buildReadme(absTarget, manifestPath, fileListPath, rawJSONPath, rawTextPath, consolePath, resultsPath, humanSummaryPath)), 0o644); err != nil {
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

func buildHumanSummary(target string, outputDir string, manifest *parsetree.Manifest, payload semgrepPayload) string {
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
		"# phparser Semgrep Target Scan",
		"",
		fmt.Sprintf("- Target: `%s`", target),
		fmt.Sprintf("- Output dir: `%s`", outputDir),
		fmt.Sprintf("- Findings: `%d`", len(payload.Results)),
		fmt.Sprintf("- Semgrep errors: `%d`", len(payload.Errors)),
		fmt.Sprintf("- phparser parseable PHP files: `%d/%d`", manifest.Counts.Parsed, manifest.Counts.Total),
		fmt.Sprintf("- phparser parse failures filtered from future lowering work: `%d`", manifest.Counts.Failed),
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

func buildReadme(target, manifestPath, fileListPath, rawJSONPath, rawTextPath, consolePath, resultsPath, humanSummaryPath string) string {
	lines := []string{
		"# phparser Semgrep Target Scan",
		"",
		fmt.Sprintf("- Target: `%s`", target),
		fmt.Sprintf("- phparser parse manifest: `%s`", manifestPath),
		fmt.Sprintf("- phparser parseable file list: `%s`", fileListPath),
		fmt.Sprintf("- Raw target Semgrep JSON: `%s`", rawJSONPath),
		fmt.Sprintf("- Raw target Semgrep text: `%s`", rawTextPath),
		fmt.Sprintf("- Raw target Semgrep console: `%s`", consolePath),
		fmt.Sprintf("- Results JSON: `%s`", resultsPath),
		fmt.Sprintf("- Human summary: `%s`", humanSummaryPath),
		"",
		"Notes:",
		"- This is the Go-side target scan wrapper slice under `phparser`.",
		"- It already replaces parser-side file discovery with the native Go parser manifest.",
		"- The lowered bundle builder is still a separate migration phase tracked in `SEMGREP_LOWERING_MIGRATION_CHECKLIST.md`.",
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
