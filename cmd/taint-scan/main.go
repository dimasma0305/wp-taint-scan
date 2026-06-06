package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strings"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/taintscan"
)

type multiFlag []string

type sinkGroup struct {
	RuleID       string
	Path         string
	Line         int
	Findings     []taintscan.Finding
	SourceKeys   map[string]struct{}
	CallableKeys map[string]struct{}
	EntryKeys    map[string]taintscan.EntryPoint
}

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	var target string
	var outputDir string
	var workers int
	var excludes multiFlag
	var sinkOps multiFlag
	var cpuProfile string
	var memProfile string
	var traceFile string
	var maxPasses int
	var memLimitMB int

	flag.StringVar(&target, "target", "", "plugin or source directory to scan")
	flag.IntVar(&memLimitMB, "mem-limit-mb", 6144, "soft heap ceiling (MiB): in-flight callable analysis aborts under pressure to reduce OOM risk on mega-plugins; also sets GOMEMLIMIT. NOTE: a fast single-statement allocation burst can still exceed this (Go cannot abort mid-allocation) — for a hard guarantee run each plugin in a memory-capped subprocess. 0 disables (legacy 3 GiB guard).")
	flag.StringVar(&outputDir, "output-dir", "", "output directory; defaults to tmp/phparser-taint-scan-<timestamp>")
	flag.IntVar(&workers, "phparser-workers", 0, "worker count for native Go parsing")
	flag.IntVar(&maxPasses, "max-passes", 0, "maximum fixpoint passes for taint analysis; 0 uses the default")
	flag.Var(&excludes, "exclude-dir", "directory name to exclude while collecting PHP files. Repeatable.")
	flag.Var(&sinkOps, "sink-op", "sink operation to include. Repeatable. Supported: read, open, delete, include, output, write, call, sql, action, surface")
	flag.StringVar(&cpuProfile, "cpuprofile", "", "write CPU profile to file")
	flag.StringVar(&memProfile, "memprofile", "", "write heap profile to file")
	flag.StringVar(&traceFile, "trace", "", "write Go runtime trace to file")
	flag.Parse()

	if target == "" {
		fmt.Fprintln(os.Stderr, "-target is required")
		os.Exit(2)
	}
	if outputDir == "" {
		outputDir = filepath.Join("tmp", "phparser-taint-scan-"+time.Now().UTC().Format("20060102-150405"))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir output dir: %v\n", err)
		os.Exit(1)
	}
	if cpuProfile != "" {
		profileFile, err := os.Create(cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create cpu profile: %v\n", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(profileFile); err != nil {
			profileFile.Close()
			fmt.Fprintf(os.Stderr, "start cpu profile: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = profileFile.Close()
		}()
	}
	if traceFile != "" {
		traceHandle, err := os.Create(traceFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create trace file: %v\n", err)
			os.Exit(1)
		}
		if err := trace.Start(traceHandle); err != nil {
			_ = traceHandle.Close()
			fmt.Fprintf(os.Stderr, "start trace: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			trace.Stop()
			_ = traceHandle.Close()
		}()
	}

	options := taintscan.Options{}
	if len(sinkOps) != 0 {
		options.AllowedSinkOps = map[string]struct{}{}
		for _, op := range sinkOps {
			options.AllowedSinkOps[strings.ToLower(strings.TrimSpace(op))] = struct{}{}
		}
	}
	options.MaxPasses = maxPasses
	options.Instrumentation = cpuProfile != "" || traceFile != ""
	if memLimitMB > 0 {
		limitBytes := uint64(memLimitMB) * 1024 * 1024
		options.MemoryLimitBytes = limitBytes
		// Give the GC ~25% headroom above the abort threshold so it reclaims the
		// aborted callables' garbage before hitting a hard ceiling.
		debug.SetMemoryLimit(int64(limitBytes + limitBytes/4))
	}

	started := time.Now()
	result, err := taintscan.AnalyzeRootWithOptions(target, append(defaultExcludedDirs(), excludes...), workers, options)
	finishedAt := time.Now()
	if err != nil {
		fmt.Fprintf(os.Stderr, "taint scan: %v\n", err)
		os.Exit(1)
	}
	result.Payload = taintscan.EnrichPayload(result.Payload, finishedAt, finishedAt.Sub(started))

	resultsPath := filepath.Join(outputDir, "taint-results.json")
	payload, err := json.MarshalIndent(result.Payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode results: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(resultsPath, append(payload, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write results: %v\n", err)
		os.Exit(1)
	}

	humanSummaryPath := filepath.Join(outputDir, "human-summary.md")
	if err := os.WriteFile(humanSummaryPath, []byte(buildHumanSummary(result)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write human summary: %v\n", err)
		os.Exit(1)
	}

	readmePath := filepath.Join(outputDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(buildReadme(result.Target, resultsPath, humanSummaryPath)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write readme: %v\n", err)
		os.Exit(1)
	}
	if memProfile != "" {
		profileFile, err := os.Create(memProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create heap profile: %v\n", err)
			os.Exit(1)
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(profileFile); err != nil {
			_ = profileFile.Close()
			fmt.Fprintf(os.Stderr, "write heap profile: %v\n", err)
			os.Exit(1)
		}
		if err := profileFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close heap profile: %v\n", err)
			os.Exit(1)
		}
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
		// Ubiquitous bundled third-party SDK — out of plugin scope and a large
		// source of noise + parse time (thousands of files per plugin).
		"freemius",
	}
}

func buildHumanSummary(result *taintscan.Result) string {
	type ruleCount struct {
		ID    string
		Count int
	}
	type fileCount struct {
		Path  string
		Count int
	}

	ruleCounts := map[string]int{}
	fileCounts := map[string]int{}
	sinkGroups := map[string]*sinkGroup{}
	for _, finding := range result.Payload.Results {
		ruleCounts[finding.CheckID]++
		fileCounts[finding.Path]++
		key := fmt.Sprintf("%s|%s|%d", finding.CheckID, finding.Path, finding.Start.Line)
		group := sinkGroups[key]
		if group == nil {
			group = &sinkGroup{
				RuleID:       finding.CheckID,
				Path:         finding.Path,
				Line:         finding.Start.Line,
				SourceKeys:   map[string]struct{}{},
				CallableKeys: map[string]struct{}{},
				EntryKeys:    map[string]taintscan.EntryPoint{},
			}
			sinkGroups[key] = group
		}
		group.Findings = append(group.Findings, finding)
		group.SourceKeys[sourceKey(finding)] = struct{}{}
		if finding.Extra.Trace.Callable != "" {
			group.CallableKeys[finding.Extra.Trace.Callable] = struct{}{}
		}
		for _, entry := range finding.Extra.Context.EntryPoints {
			group.EntryKeys[entryKey(entry)] = entry
		}
	}
	rules := make([]ruleCount, 0, len(ruleCounts))
	for id, count := range ruleCounts {
		rules = append(rules, ruleCount{ID: id, Count: count})
	}
	sort.Slice(rules, func(i int, j int) bool {
		if rules[i].Count != rules[j].Count {
			return rules[i].Count > rules[j].Count
		}
		return rules[i].ID < rules[j].ID
	})
	files := make([]fileCount, 0, len(fileCounts))
	for path, count := range fileCounts {
		files = append(files, fileCount{Path: path, Count: count})
	}
	sort.Slice(files, func(i int, j int) bool {
		if files[i].Count != files[j].Count {
			return files[i].Count > files[j].Count
		}
		return files[i].Path < files[j].Path
	})
	groupList := make([]*sinkGroup, 0, len(sinkGroups))
	for _, group := range sinkGroups {
		groupList = append(groupList, group)
	}
	sort.Slice(groupList, func(i int, j int) bool {
		if len(groupList[i].Findings) != len(groupList[j].Findings) {
			return len(groupList[i].Findings) > len(groupList[j].Findings)
		}
		if groupList[i].Path != groupList[j].Path {
			return groupList[i].Path < groupList[j].Path
		}
		return groupList[i].Line < groupList[j].Line
	})

	lines := []string{
		"# phparser Direct Taint Scan",
		"",
		fmt.Sprintf("- Target: `%s`", result.Target),
		fmt.Sprintf("- Findings: `%d`", len(result.Payload.Results)),
		fmt.Sprintf("- Unique sinks: `%d`", len(groupList)),
		fmt.Sprintf("- Errors: `%d`", len(result.Payload.Errors)),
		fmt.Sprintf("- Parseable PHP files: `%d/%d`", result.Manifest.Counts.Parsed, result.Manifest.Counts.Total),
		fmt.Sprintf("- Callables analyzed: `%d`", result.Callables),
		"",
		"## Top Rules",
	}
	if len(rules) == 0 {
		lines = append(lines, "- No findings")
	} else {
		for _, item := range rules {
			lines = append(lines, fmt.Sprintf("- `%s`: `%d` findings", item.ID, item.Count))
		}
	}
	lines = append(lines, "", "## Top Files")
	if len(files) == 0 {
		lines = append(lines, "- No files hit")
	} else {
		for _, item := range files[:min(10, len(files))] {
			lines = append(lines, fmt.Sprintf("- `%s`: `%d` findings", item.Path, item.Count))
		}
	}
	lines = append(lines, "", "## Sink Groups")
	if len(groupList) == 0 {
		lines = append(lines, "- No sink groups")
	} else {
		for _, group := range groupList {
			bits := []string{
				fmt.Sprintf("`%d` findings", len(group.Findings)),
				fmt.Sprintf("`%d` unique sources", len(group.SourceKeys)),
			}
			if len(group.CallableKeys) != 0 {
				bits = append(bits, fmt.Sprintf("`%d` callables", len(group.CallableKeys)))
			}
			entries := sortedEntryLabels(group.EntryKeys)
			if len(entries) != 0 {
				bits = append(bits, "entrypoints=`"+strings.Join(entries[:min(3, len(entries))], "`, `")+"`")
				if len(entries) > 3 {
					bits = append(bits, fmt.Sprintf("`+%d` more entrypoints", len(entries)-3))
				}
			}
			lines = append(lines, fmt.Sprintf("- `%s` at `%s:%d`: %s", group.RuleID, group.Path, group.Line, strings.Join(bits, ", ")))
			for _, source := range topSourceLabels(group, 5) {
				lines = append(lines, fmt.Sprintf("  source: `%s`", source))
			}
			if len(group.SourceKeys) > 5 {
				lines = append(lines, fmt.Sprintf("  source: `+%d` more unique sources", len(group.SourceKeys)-5))
			}
		}
	}
	lines = append(lines, "", "## Findings")
	if len(result.Payload.Results) == 0 {
		lines = append(lines, "- No findings")
	} else {
		// Present findings most-exploitable-first (unauthenticated/low-priv above
		// admin-gated noise) so triage starts with the highest-value bugs. This
		// reorders the human summary only; the machine-readable results JSON keeps
		// its stable path/line ordering.
		ranked := make([]taintscan.Finding, len(result.Payload.Results))
		copy(ranked, result.Payload.Results)
		sort.SliceStable(ranked, func(i int, j int) bool {
			return taintscan.FindingExploitabilityScore(ranked[i]) > taintscan.FindingExploitabilityScore(ranked[j])
		})
		for _, finding := range ranked {
			contextBits := make([]string, 0, 5)
			if finding.Extra.Context.Access != "" {
				contextBits = append(contextBits, "access="+finding.Extra.Context.Access)
			}
			if len(finding.Extra.Context.EntryPoints) > 0 {
				first := finding.Extra.Context.EntryPoints[0]
				label := first.Kind
				if first.Name != "" {
					label += ":" + first.Name
				} else if first.Route != "" {
					label += ":" + first.Route
				}
				contextBits = append(contextBits, "entrypoint="+label)
			}
			if len(finding.Extra.Context.CapabilityChecks) > 0 {
				contextBits = append(contextBits, fmt.Sprintf("cap_checks=%d", len(finding.Extra.Context.CapabilityChecks)))
			}
			if len(finding.Extra.Context.NonceChecks) > 0 {
				contextBits = append(contextBits, fmt.Sprintf("nonce_checks=%d", len(finding.Extra.Context.NonceChecks)))
			}
			if len(finding.Extra.Context.ValidationChecks) > 0 {
				contextBits = append(contextBits, fmt.Sprintf("validator_checks=%d", len(finding.Extra.Context.ValidationChecks)))
			}
			if len(finding.Extra.Context.UnauthChecks) > 0 {
				contextBits = append(contextBits, fmt.Sprintf("unauth_checks=%d", len(finding.Extra.Context.UnauthChecks)))
			}
			if len(finding.Extra.Context.AdminChecks) > 0 {
				contextBits = append(contextBits, fmt.Sprintf("admin_checks=%d", len(finding.Extra.Context.AdminChecks)))
			}
			if len(finding.Extra.Context.AjaxChecks) > 0 {
				contextBits = append(contextBits, fmt.Sprintf("ajax_checks=%d", len(finding.Extra.Context.AjaxChecks)))
			}
			if hasMeaningfulStoredWriteContext(finding.Extra.StoredWriteContext) {
				contextBits = append(contextBits, "stored_access="+finding.Extra.StoredWriteContext.Access)
				if len(finding.Extra.StoredWriteContext.EntryPoints) > 0 {
					first := finding.Extra.StoredWriteContext.EntryPoints[0]
					label := first.Kind
					if first.Name != "" {
						label += ":" + first.Name
					} else if first.Route != "" {
						label += ":" + first.Route
					}
					contextBits = append(contextBits, "stored_entrypoint="+label)
				}
			}
			suffix := ""
			if len(contextBits) > 0 {
				suffix = " [" + strings.Join(contextBits, ", ") + "]"
			}
			lines = append(lines, fmt.Sprintf("- `%s` at `%s:%d` from `%s:%d` via `%s`%s", finding.CheckID, finding.Path, finding.Start.Line, finding.Extra.Trace.Source.Path, finding.Extra.Trace.Source.Line, finding.Extra.Trace.Callable, suffix))
		}
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func sourceKey(finding taintscan.Finding) string {
	return finding.Extra.Trace.Source.Path + ":" + fmt.Sprintf("%d", finding.Extra.Trace.Source.Line)
}

func entryKey(entry taintscan.EntryPoint) string {
	return strings.Join([]string{
		entry.Kind,
		entry.Name,
		entry.Route,
		entry.Access,
		entry.Location.Path,
		fmt.Sprintf("%d", entry.Location.Line),
	}, "|")
}

func sortedEntryLabels(items map[string]taintscan.EntryPoint) []string {
	labels := make([]string, 0, len(items))
	for _, entry := range items {
		label := entry.Kind
		switch {
		case entry.Name != "":
			label += ":" + entry.Name
		case entry.Route != "":
			label += ":" + entry.Route
		}
		if entry.Access != "" {
			label += ":" + entry.Access
		}
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

func topSourceLabels(group *sinkGroup, limit int) []string {
	type sourceCount struct {
		label string
		count int
	}
	counts := map[string]int{}
	for _, finding := range group.Findings {
		label := sourceKey(finding)
		counts[label]++
	}
	items := make([]sourceCount, 0, len(counts))
	for label, count := range counts {
		items = append(items, sourceCount{label: label, count: count})
	}
	sort.Slice(items, func(i int, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].label < items[j].label
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	labels := make([]string, 0, len(items))
	for _, item := range items {
		if item.count > 1 {
			labels = append(labels, fmt.Sprintf("%s (%dx)", item.label, item.count))
			continue
		}
		labels = append(labels, item.label)
	}
	return labels
}

func hasMeaningfulStoredWriteContext(ctx taintscan.FlowContext) bool {
	if ctx.Access != "" && ctx.Access != "unknown" {
		return true
	}
	return len(ctx.EntryPoints) > 0 ||
		len(ctx.CapabilityChecks) > 0 ||
		len(ctx.NonceChecks) > 0 ||
		len(ctx.ValidationChecks) > 0 ||
		len(ctx.AuthChecks) > 0 ||
		len(ctx.UnauthChecks) > 0 ||
		len(ctx.AdminChecks) > 0 ||
		len(ctx.AjaxChecks) > 0
}

func buildReadme(target string, resultsPath string, humanSummaryPath string) string {
	return strings.Join([]string{
		"# phparser Direct Taint Scan",
		"",
		fmt.Sprintf("- Target: `%s`", target),
		fmt.Sprintf("- Results JSON: `%s`", resultsPath),
		fmt.Sprintf("- Human summary: `%s`", humanSummaryPath),
		"",
		"Notes:",
		"- This is the first direct phparser taint engine slice.",
		"- It uses request-origin sources and direct file/include sinks modeled from the Semgrep rules.",
		"- It reports real source and sink file locations without generating lowered PHP.",
		"",
	}, "\n")
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
