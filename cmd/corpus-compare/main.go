package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/corpuscompare"
	"github.com/dimasma0305/wp-taint-scan/internal/taintscan"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type caseSummary struct {
	CaseID     string                    `json:"case_id"`
	Target     string                    `json:"target,omitempty"`
	Status     corpuscompare.Status      `json:"status"`
	Reason     string                    `json:"reason,omitempty"`
	SinkOps    []string                  `json:"sink_ops,omitempty"`
	Findings   int                       `json:"findings,omitempty"`
	Errors     int                       `json:"errors,omitempty"`
	DurationMS int64                     `json:"duration_ms,omitempty"`
	AllocMB    float64                   `json:"alloc_mb,omitempty"`
	Comparison *corpuscompare.Comparison `json:"comparison,omitempty"`
}

type summaryPayload struct {
	ManifestPath string        `json:"manifest_path"`
	GeneratedAt  string        `json:"generated_at"`
	TotalMS      int64         `json:"total_ms,omitempty"`
	TotalAllocMB float64       `json:"total_alloc_mb,omitempty"`
	PeakRSSMB    float64       `json:"peak_rss_mb,omitempty"`
	Cases        []caseSummary `json:"cases"`
}

func main() {
	repoRoot := defaultRepoRoot()
	var manifestPath string
	var outputDir string
	var workers int
	var excludes multiFlag
	var sinkOps multiFlag
	var caseIDs multiFlag
	var slugs multiFlag
	var maxPasses int

	flag.StringVar(&manifestPath, "manifest", filepath.Join(repoRoot, "test", "semgrep_bundle_corpus", "corpus.json"), "corpus manifest path")
	flag.StringVar(&outputDir, "output-dir", filepath.Join(repoRoot, "tmp", "phparser-corpus-compare-"+time.Now().UTC().Format("20060102-150405")), "output directory")
	flag.IntVar(&workers, "phparser-workers", 0, "worker count for native Go parsing")
	flag.IntVar(&maxPasses, "max-passes", 0, "maximum fixpoint passes for taint analysis; 0 uses the default")
	flag.Var(&excludes, "exclude-dir", "directory name to exclude while collecting PHP files. Repeatable.")
	flag.Var(&sinkOps, "sink-op", "override sink operation to include. Repeatable.")
	flag.Var(&caseIDs, "case-id", "restrict to a case ID. Repeatable.")
	flag.Var(&slugs, "slug", "restrict to a slug. Repeatable.")
	flag.Parse()

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir output dir: %v\n", err)
		os.Exit(1)
	}

	cases, err := corpuscompare.LoadManifest(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load manifest: %v\n", err)
		os.Exit(1)
	}

	selectedIDs := toSet(caseIDs)
	selectedSlugs := toSet(slugs)
	roots := []string{
		filepath.Join(repoRoot, "bugbounty-note", "wordpress", "wp_install", "plugins"),
		filepath.Join(repoRoot, "test", "semgrep_bundle_corpus", "plugins"),
	}
	baseOptions := taintscan.Options{MaxPasses: maxPasses}
	overrideOps := []string(nil)
	if len(sinkOps) != 0 {
		overrideOps = append(overrideOps, sinkOps...)
		baseOptions.AllowedSinkOps = toOpSet(sinkOps)
	}

	summaries := make([]caseSummary, 0, len(cases))
	selectedCases := 0
	for _, c := range cases {
		if len(selectedIDs) != 0 {
			if _, ok := selectedIDs[c.CaseID]; !ok {
				continue
			}
		}
		if len(selectedSlugs) != 0 {
			if _, ok := selectedSlugs[c.Slug]; !ok {
				continue
			}
		}
		selectedCases++
	}

	processedCases := 0
	for _, c := range cases {
		if len(selectedIDs) != 0 {
			if _, ok := selectedIDs[c.CaseID]; !ok {
				continue
			}
		}
		if len(selectedSlugs) != 0 {
			if _, ok := selectedSlugs[c.Slug]; !ok {
				continue
			}
		}

		summary := caseSummary{CaseID: c.CaseID, Status: corpuscompare.StatusNotComparableYet}
		processedCases++
		target := corpuscompare.ResolvePluginDir(c, roots)
		if target == "" {
			summary.Reason = "no local plugin tree found for case"
			summaries = append(summaries, summary)
			writeProgress(outputDir, processedCases, selectedCases, summary, manifestPath, summaries)
			continue
		}
		summary.Target = target

		options := baseOptions
		if maxPasses == 0 && c.MaxPasses > 0 {
			options.MaxPasses = c.MaxPasses
		}

		ops := overrideOps
		if len(ops) == 0 {
			comparison, skip := corpuscompare.PreScanComparison(c)
			summary.SinkOps = append([]string(nil), comparison.SinkOps...)
			if skip {
				summary.Status = comparison.Status
				summary.Reason = comparison.Reason
				summary.Comparison = &comparison
				summaries = append(summaries, summary)
				writeProgress(outputDir, processedCases, selectedCases, summary, manifestPath, summaries)
				continue
			}
			ops = append([]string(nil), comparison.SinkOps...)
			options.AllowedSinkOps = toOpSet(ops)
		} else {
			summary.SinkOps = append([]string(nil), ops...)
		}

		var msBefore, msAfter runtime.MemStats
		runtime.ReadMemStats(&msBefore)
		started := time.Now()
		result, err := taintscan.AnalyzeRootWithOptions(target, append(defaultExcludedDirs(), excludes...), workers, options)
		finishedAt := time.Now()
		duration := finishedAt.Sub(started)
		runtime.ReadMemStats(&msAfter)
		summary.DurationMS = duration.Milliseconds()
		summary.AllocMB = float64(msAfter.TotalAlloc-msBefore.TotalAlloc) / (1024 * 1024)
		if err != nil {
			summary.Reason = err.Error()
			summaries = append(summaries, summary)
			writeProgress(outputDir, processedCases, selectedCases, summary, manifestPath, summaries)
			continue
		}
		result.Payload = taintscan.EnrichPayload(result.Payload, finishedAt, duration)
		summary.Findings = len(result.Payload.Results)
		summary.Errors = len(result.Payload.Errors)

		caseDir := filepath.Join(outputDir, c.CaseID)
		if err := os.MkdirAll(caseDir, 0o755); err == nil {
			_ = writeJSON(filepath.Join(caseDir, "taint-results.json"), result.Payload)
		}

		comparison := corpuscompare.CompareCase(c, result.Payload)
		summary.Status = comparison.Status
		summary.Reason = comparison.Reason
		summary.Comparison = &comparison
		if err := os.MkdirAll(caseDir, 0o755); err == nil {
			_ = writeJSON(filepath.Join(caseDir, "comparison.json"), comparison)
		}
		summaries = append(summaries, summary)
		writeProgress(outputDir, processedCases, selectedCases, summary, manifestPath, summaries)
	}

	sort.Slice(summaries, func(i int, j int) bool {
		return summaries[i].CaseID < summaries[j].CaseID
	})
	var totalMS int64
	var totalAllocMB float64
	for _, s := range summaries {
		totalMS += s.DurationMS
		totalAllocMB += s.AllocMB
	}
	var peakRSSMB float64
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err == nil {
		peakRSSMB = float64(rusage.Maxrss) / 1024 // Linux: Maxrss in KB
	}
	payload := summaryPayload{
		ManifestPath: manifestPath,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		TotalMS:      totalMS,
		TotalAllocMB: totalAllocMB,
		PeakRSSMB:    peakRSSMB,
		Cases:        summaries,
	}
	if err := writeJSON(filepath.Join(outputDir, "summary.json"), payload); err != nil {
		fmt.Fprintf(os.Stderr, "write summary: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "human-summary.md"), []byte(buildHumanSummary(payload)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write human summary: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(outputDir)
}

func writeProgress(outputDir string, processed, total int, summary caseSummary, manifestPath string, summaries []caseSummary) {
	line := fmt.Sprintf("[%d/%d] %s status=%s", processed, total, summary.CaseID, summary.Status)
	if summary.Target != "" {
		line += fmt.Sprintf(" target=%s", summary.Target)
	}
	if summary.Findings != 0 || summary.Errors != 0 || summary.DurationMS != 0 {
		line += fmt.Sprintf(" findings=%d errors=%d duration_ms=%d alloc_mb=%.1f", summary.Findings, summary.Errors, summary.DurationMS, summary.AllocMB)
	}
	if summary.Reason != "" {
		line += " reason=" + summary.Reason
	}
	line += "\n"
	_ = appendFile(filepath.Join(outputDir, "progress.log"), []byte(line))

	payload := summaryPayload{
		ManifestPath: manifestPath,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Cases:        append([]caseSummary(nil), summaries...),
	}
	_ = writeJSON(filepath.Join(outputDir, "summary.partial.json"), payload)
	_ = os.WriteFile(filepath.Join(outputDir, "human-summary.partial.md"), []byte(buildHumanSummary(payload)), 0o644)
}

func defaultRepoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "..", ".."))
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

func toSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}

func toOpSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}

func writeJSON(path string, payload any) error {
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

func appendFile(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(payload)
	return err
}

func buildHumanSummary(payload summaryPayload) string {
	counts := map[corpuscompare.Status]int{}
	for _, item := range payload.Cases {
		counts[item.Status]++
	}
	lines := []string{
		"# phparser Direct Corpus Compare",
		"",
		fmt.Sprintf("- Manifest: `%s`", payload.ManifestPath),
		fmt.Sprintf("- Cases: `%d`", len(payload.Cases)),
		fmt.Sprintf("- Match: `%d`", counts[corpuscompare.StatusMatch]),
		fmt.Sprintf("- Miss: `%d`", counts[corpuscompare.StatusMiss]),
		fmt.Sprintf("- Not Comparable Yet: `%d`", counts[corpuscompare.StatusNotComparableYet]),
		fmt.Sprintf("- Total CPU: `%.1fs`", float64(payload.TotalMS)/1000),
		fmt.Sprintf("- Total Alloc: `%.0f MB`", payload.TotalAllocMB),
		fmt.Sprintf("- Peak RSS: `%.0f MB`", payload.PeakRSSMB),
		"",
		"## Cases",
	}
	if len(payload.Cases) == 0 {
		lines = append(lines, "- No cases selected")
		return strings.Join(lines, "\n") + "\n"
	}
	for _, item := range payload.Cases {
		line := fmt.Sprintf("- `%s`: `%s`", item.CaseID, item.Status)
		if item.Reason != "" {
			line += " - " + item.Reason
		}
		if item.Target != "" {
			line += fmt.Sprintf(" (`%s`)", item.Target)
		}
		if item.Findings != 0 || item.Errors != 0 {
			line += fmt.Sprintf(" findings=%d errors=%d duration_ms=%d alloc_mb=%.1f", item.Findings, item.Errors, item.DurationMS, item.AllocMB)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n"
}
