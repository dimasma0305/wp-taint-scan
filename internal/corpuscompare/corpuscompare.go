package corpuscompare

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dimasma0305/wp-taint-scan/internal/taintscan"
)

type Manifest struct {
	Cases []Case `json:"cases"`
}

type Case struct {
	CaseID          string   `json:"case_id"`
	Slug            string   `json:"slug"`
	FixtureDir      string   `json:"fixture_dir"`
	LocalCandidates []string `json:"local_candidates"`
	Configs         []string `json:"configs"`
	DirectSinkOps   []string `json:"direct_sink_ops"`
	MaxPasses       int      `json:"max_passes,omitempty"`
	Coverage        Coverage `json:"coverage"`
}

type Coverage struct {
	SourceStringsAny             []string `json:"source_strings_any"`
	FindingPathsAny              []string `json:"finding_paths_any"`
	FindingRuleIDsAny            []string `json:"finding_rule_ids_any"`
	TraceSourceStringsAny        []string `json:"trace_source_strings_any"`
	TraceSinkStringsAny          []string `json:"trace_sink_strings_any"`
	TraceSinkLocationsAny        []string `json:"trace_sink_locations_any"`
	StoredWriteEntryLocationsAny []string `json:"stored_write_entry_locations_any"`
	AdvisoryPathsAny             []string `json:"advisory_paths_any"`
	BundleStringsAny             []string `json:"bundle_strings_any"`
	BridgeReadLocationsAny       []string `json:"bridge_read_locations_any"`
}

type Status string

const (
	StatusMatch            Status = "match"
	StatusMiss             Status = "miss"
	StatusNotComparableYet Status = "not_comparable_yet"
)

type Comparison struct {
	Status         Status          `json:"status"`
	Reason         string          `json:"reason,omitempty"`
	SinkOps        []string        `json:"sink_ops,omitempty"`
	MatchedFinding *MatchedFinding `json:"matched_finding,omitempty"`
}

type MatchedFinding struct {
	CheckID            string                `json:"check_id"`
	Path               string                `json:"path"`
	Line               int                   `json:"line"`
	Source             taintscan.Location    `json:"source"`
	Sink               taintscan.Location    `json:"sink"`
	Callable           string                `json:"callable,omitempty"`
	StoredWriteContext taintscan.FlowContext `json:"stored_write_context,omitempty"`
}

func LoadManifest(path string) ([]Case, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	return manifest.Cases, nil
}

func ResolvePluginDir(c Case, roots []string) string {
	fixture := strings.TrimSpace(c.FixtureDir)
	if fixture != "" {
		for _, root := range roots {
			path := filepath.Join(root, fixture)
			info, err := os.Stat(path)
			if err == nil && info.IsDir() {
				return path
			}
		}
	}
	for _, root := range roots {
		for _, candidate := range nonFixtureCaseDirCandidates(c) {
			path := filepath.Join(root, candidate)
			info, err := os.Stat(path)
			if err == nil && info.IsDir() {
				return path
			}
		}
	}
	return ""
}

func CompareCase(c Case, payload taintscan.Payload) Comparison {
	base, skip := PreScanComparison(c)
	if skip {
		return base
	}
	sinkOps := base.SinkOps
	var best *taintscan.Finding
	bestScore := -1
	for _, finding := range payload.Results {
		if !findingMatchesCoverage(finding, c.Coverage) {
			continue
		}
		score := matchedFindingScore(finding, c.Coverage)
		if best == nil || score > bestScore {
			copyFinding := finding
			best = &copyFinding
			bestScore = score
		}
	}
	if best != nil {
		return Comparison{
			Status:  StatusMatch,
			SinkOps: sinkOps,
			MatchedFinding: &MatchedFinding{
				CheckID:            best.CheckID,
				Path:               best.Path,
				Line:               best.Start.Line,
				Source:             best.Extra.Trace.Source,
				Sink:               best.Extra.Trace.Sink,
				Callable:           best.Extra.Trace.Callable,
				StoredWriteContext: best.Extra.StoredWriteContext,
			},
		}
	}
	return Comparison{
		Status:  StatusMiss,
		Reason:  fmt.Sprintf("no single finding satisfied the manifest contract across %d direct-engine findings", len(payload.Results)),
		SinkOps: sinkOps,
	}
}

func matchedFindingScore(f taintscan.Finding, c Coverage) int {
	score := 0
	score += 100 * countNeedleMatches(sourceTraceTexts(f), c.TraceSourceStringsAny)
	score += 40 * countNeedleMatches(sourceContractTexts(f), c.SourceStringsAny)
	score += 20 * countNeedleMatches(sinkTexts(f), c.TraceSinkStringsAny)
	score += 10 * countNeedleMatches([]string{f.Extra.Trace.Callable}, c.TraceSourceStringsAny)
	score += 5 * countNeedleMatches([]string{f.Extra.Trace.Callable}, c.SourceStringsAny)
	if len(c.StoredWriteEntryLocationsAny) == 0 && hasStoredWriteContext(f) {
		score--
	}
	return score
}

func PreScanComparison(c Case) (Comparison, bool) {
	sinkOps, ok, reason := EffectiveSinkOps(c)
	if !ok {
		return Comparison{Status: StatusNotComparableYet, Reason: reason}, true
	}
	if ok, reason := CoverageComparable(c.Coverage); !ok {
		return Comparison{Status: StatusNotComparableYet, Reason: reason, SinkOps: sinkOps}, true
	}
	if !hasComparableCoverage(c.Coverage) {
		return Comparison{Status: StatusNotComparableYet, Reason: "case has no direct-engine comparable coverage contract", SinkOps: sinkOps}, true
	}
	return Comparison{SinkOps: sinkOps}, false
}

func EffectiveSinkOps(c Case) ([]string, bool, string) {
	if len(c.DirectSinkOps) != 0 {
		ops := make([]string, 0, len(c.DirectSinkOps))
		seen := map[string]struct{}{}
		for _, op := range c.DirectSinkOps {
			op = strings.ToLower(strings.TrimSpace(op))
			if op == "" {
				continue
			}
			if _, ok := seen[op]; ok {
				continue
			}
			seen[op] = struct{}{}
			ops = append(ops, op)
		}
		sort.Strings(ops)
		if len(ops) == 0 {
			return nil, false, "direct_sink_ops provided but empty after normalization"
		}
		return ops, true, ""
	}
	return SupportedSinkOps(c.Configs)
}

func SupportedSinkOps(configs []string) ([]string, bool, string) {
	opsSet := map[string]struct{}{}
	for _, config := range configs {
		switch filepath.Base(config) {
		case "path-transversal.yaml":
			for _, op := range []string{"include", "read", "open", "delete"} {
				opsSet[op] = struct{}{}
			}
		case "privilege-escalation.yaml":
			for _, op := range []string{"action", "output", "write", "call"} {
				opsSet[op] = struct{}{}
			}
		case "sqli.yaml":
			opsSet["sql"] = struct{}{}
		case "file-upload.yaml":
			for _, op := range []string{"write", "read", "open", "delete"} {
				opsSet[op] = struct{}{}
			}
		case "unsafe-use.yaml":
			opsSet["call"] = struct{}{}
		case "xss.yaml":
			opsSet["output"] = struct{}{}
		default:
			return nil, false, fmt.Sprintf("unsupported config for direct-engine compare: %s", filepath.Base(config))
		}
	}
	ops := make([]string, 0, len(opsSet))
	for op := range opsSet {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	return ops, true, ""
}

func CoverageComparable(c Coverage) (bool, string) {
	if len(c.AdvisoryPathsAny) != 0 {
		return false, "advisory_paths_any is lowered-bundle specific"
	}
	if len(c.BundleStringsAny) != 0 {
		return false, "bundle_strings_any is lowered-bundle specific"
	}
	if len(c.BridgeReadLocationsAny) != 0 {
		return false, "bridge_read_locations_any is lowered-bundle specific"
	}
	return true, ""
}

func caseDirCandidates(c Case) []string {
	seen := map[string]struct{}{}
	var candidates []string
	appendCandidate := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}
	appendCandidate(c.FixtureDir)
	for _, candidate := range nonFixtureCaseDirCandidates(c) {
		appendCandidate(candidate)
	}
	return candidates
}

func nonFixtureCaseDirCandidates(c Case) []string {
	seen := map[string]struct{}{}
	var candidates []string
	appendCandidate := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}
	appendCandidate(c.Slug)
	for _, candidate := range c.LocalCandidates {
		appendCandidate(candidate)
	}
	return candidates
}

func hasComparableCoverage(c Coverage) bool {
	return len(c.SourceStringsAny) != 0 ||
		len(c.FindingPathsAny) != 0 ||
		len(c.FindingRuleIDsAny) != 0 ||
		len(c.TraceSourceStringsAny) != 0 ||
		len(c.TraceSinkStringsAny) != 0 ||
		len(c.TraceSinkLocationsAny) != 0 ||
		len(c.StoredWriteEntryLocationsAny) != 0
}

func findingMatchesCoverage(f taintscan.Finding, c Coverage) bool {
	if len(c.FindingRuleIDsAny) != 0 && !ruleIDMatchesAny(c.FindingRuleIDsAny, f.CheckID) {
		return false
	}
	if len(c.FindingPathsAny) != 0 && !findingPathMatchesAny(f, c.FindingPathsAny) {
		return false
	}
	if len(c.TraceSinkLocationsAny) != 0 && !locationMatchesAny(f.Extra.Trace.Sink.Path, f.Extra.Trace.Sink.Line, c.TraceSinkLocationsAny) {
		return false
	}
	if len(c.TraceSourceStringsAny) != 0 && !textMatchesAny(sourceTexts(f), c.TraceSourceStringsAny) {
		return false
	}
	if len(c.TraceSinkStringsAny) != 0 && !textMatchesAny(sinkTexts(f), c.TraceSinkStringsAny) {
		return false
	}
	if len(c.StoredWriteEntryLocationsAny) != 0 && !storedWriteEntryMatchesAny(f, c.StoredWriteEntryLocationsAny) {
		return false
	}
	if len(c.SourceStringsAny) != 0 && !sourceContractMatches(f, c.SourceStringsAny) {
		return false
	}
	return true
}

func sourceTexts(f taintscan.Finding) []string {
	return []string{
		f.Extra.Trace.Source.Snippet,
		f.Extra.Trace.Source.Path,
		f.Extra.Trace.Callable,
	}
}

func sourceTraceTexts(f taintscan.Finding) []string {
	return []string{
		f.Extra.Trace.Source.Snippet,
		f.Extra.Trace.Source.Path,
	}
}

func sourceContractTexts(f taintscan.Finding) []string {
	return []string{
		f.Extra.Trace.Source.Snippet,
		f.Extra.Trace.Source.Path,
		f.Extra.Trace.Sink.Snippet,
		f.Extra.Trace.Sink.Path,
		f.Path,
	}
}

func sinkTexts(f taintscan.Finding) []string {
	return []string{
		f.Extra.Trace.Sink.Snippet,
		f.Extra.Trace.Sink.Path,
		f.Path,
		f.Extra.Trace.Callable,
	}
}

func sourceContractMatches(f taintscan.Finding, needles []string) bool {
	texts := []string{
		f.Extra.Trace.Source.Snippet,
		f.Extra.Trace.Source.Path,
		f.Extra.Trace.Sink.Snippet,
		f.Extra.Trace.Sink.Path,
		f.Path,
		f.Extra.Trace.Callable,
	}
	for _, needle := range needles {
		if textMatchesAny(texts, []string{needle}) {
			return true
		}
		name := functionNameNeedle(needle)
		if name == "" {
			continue
		}
		if strings.Contains(strings.ToLower(f.Extra.Trace.Callable), name) {
			return true
		}
		if strings.Contains(strings.ToLower(f.Extra.Trace.Source.Snippet), name) {
			return true
		}
		if strings.Contains(strings.ToLower(f.Extra.Trace.Sink.Snippet), name) {
			return true
		}
	}
	return false
}

func functionNameNeedle(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasPrefix(value, "function ") {
		value = strings.TrimSpace(strings.TrimPrefix(value, "function "))
	}
	if idx := strings.Index(value, "("); idx > 0 {
		value = strings.TrimSpace(value[:idx])
	}
	value = strings.Trim(value, "$\\ ")
	if value == "" || strings.Contains(value, " ") {
		return ""
	}
	return value
}

func ruleIDMatchesAny(options []string, candidate string) bool {
	if containsAny(options, candidate) {
		return true
	}
	for _, option := range options {
		for _, alias := range directRuleIDAliases(option) {
			if candidate == alias {
				return true
			}
		}
	}
	return false
}

func directRuleIDAliases(ruleID string) []string {
	switch strings.TrimSpace(ruleID) {
	case "file-download-upload", "upload-api-surface", "wordpress-upload-helper-surface":
		return []string{
			"wp-request-file-upload-without-cap-check",
			"wp-request-file-delete-without-cap-check",
			"request-path-read-delete",
		}
	case "wp-ajax-financial-action-without-cap-check":
		return []string{
			"wp-request-sensitive-action-without-cap-check",
		}
	default:
		return nil
	}
}

func findingPathMatchesAny(f taintscan.Finding, options []string) bool {
	for _, candidate := range []string{
		f.Path,
		f.Extra.Trace.Sink.Path,
		f.Extra.Trace.Source.Path,
	} {
		if pathMatchesAny(candidate, options) {
			return true
		}
	}
	return false
}

func storedWriteEntryMatchesAny(f taintscan.Finding, options []string) bool {
	for _, entry := range f.Extra.StoredWriteContext.EntryPoints {
		if locationMatchesAny(entry.Location.Path, entry.Location.Line, options) {
			return true
		}
	}
	return false
}

func containsAny(options []string, candidate string) bool {
	for _, option := range options {
		if candidate == option {
			return true
		}
	}
	return false
}

func pathMatchesAny(candidate string, options []string) bool {
	candidate = normalizePath(candidate)
	for _, option := range options {
		option = normalizePath(option)
		if strings.HasSuffix(candidate, option) {
			return true
		}
	}
	return false
}

func locationMatchesAny(path string, line int, options []string) bool {
	path = normalizePath(path)
	for _, option := range options {
		option = normalizePath(option)
		idx := strings.LastIndex(option, ":")
		if idx <= 0 || idx == len(option)-1 {
			continue
		}
		optionPath := option[:idx]
		optionLine, err := strconv.Atoi(option[idx+1:])
		if err != nil {
			continue
		}
		if optionLine == line && strings.HasSuffix(path, optionPath) {
			return true
		}
	}
	return false
}

func textMatchesAny(texts []string, needles []string) bool {
	loweredTexts := make([]string, 0, len(texts))
	for _, text := range texts {
		if text == "" {
			continue
		}
		loweredTexts = append(loweredTexts, strings.ToLower(text))
	}
	for _, needle := range needles {
		needle = strings.ToLower(strings.TrimSpace(needle))
		if needle == "" {
			continue
		}
		for _, text := range loweredTexts {
			if strings.Contains(text, needle) {
				return true
			}
		}
	}
	return false
}

func countNeedleMatches(texts []string, needles []string) int {
	loweredTexts := make([]string, 0, len(texts))
	for _, text := range texts {
		if text == "" {
			continue
		}
		loweredTexts = append(loweredTexts, strings.ToLower(text))
	}
	matches := 0
	for _, needle := range needles {
		needle = strings.ToLower(strings.TrimSpace(needle))
		if needle == "" {
			continue
		}
		for _, text := range loweredTexts {
			if strings.Contains(text, needle) {
				matches++
				break
			}
		}
	}
	return matches
}

func hasStoredWriteContext(f taintscan.Finding) bool {
	ctx := f.Extra.StoredWriteContext
	return len(ctx.EntryPoints) != 0 ||
		len(ctx.NonceChecks) != 0 ||
		len(ctx.AdminChecks) != 0 ||
		len(ctx.AuthChecks) != 0 ||
		len(ctx.CapabilityChecks) != 0 ||
		len(ctx.ValidationChecks) != 0 ||
		len(ctx.UnauthChecks) != 0 ||
		ctx.Access != ""
}

func normalizePath(path string) string {
	return filepath.ToSlash(strings.TrimSpace(path))
}
