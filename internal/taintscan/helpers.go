package taintscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// accessTierWeight scores attacker reachability of a finding's access label.
// Higher means more reachable (and therefore higher triage priority).
func accessTierWeight(access string) int {
	switch access {
	case "unauthenticated":
		return 1000
	case "permission_callback":
		return 700
	case "nonce_only":
		return 600
	case "authenticated":
		return 400
	case "unknown":
		return 200
	case "capability_checked":
		return 50
	default:
		return 100
	}
}

// FindingExploitabilityScore ranks a finding by how reachable it is to an
// attacker so triagers can review the real unauthenticated/low-privilege bugs
// before admin-gated noise. Stored findings are scored by who can plant the
// payload (the more-accessible of the sink context and the stored-write
// context). Heuristic *-surface signals rank below proven taint flows. This is
// a presentation/ordering aid only and never changes which findings are
// reported.
func FindingExploitabilityScore(f Finding) int {
	access := f.Extra.Context.Access
	if sw := f.Extra.StoredWriteContext.Access; sw != "" && accessTierWeight(sw) > accessTierWeight(access) {
		access = sw
	}
	score := accessTierWeight(access)
	if strings.HasSuffix(f.CheckID, "-surface") {
		score -= 150
	}
	score += findingRuleSpecificScore(f)
	return score
}

func findingRecordKey(record findingRecord) string {
	return strings.Join([]string{
		record.RuleID,
		record.Source.Path,
		fmt.Sprintf("%d", record.Source.Line),
		record.Sink.Path,
		fmt.Sprintf("%d", record.Sink.Line),
		record.Callable,
	}, "|")
}

func finalFindingKey(f Finding) string {
	if hasConcreteLocation(f.Extra.Trace.Source) && !shouldCollapseFindingSources(f.CheckID) {
		return "exact|" + findingKey(f)
	}
	if hasConcreteLocation(f.Extra.Trace.Source) && shouldKeepDistinctSourceFindingKey(f.CheckID) {
		return "exact|" + findingKey(f)
	}
	if shouldKeepCallableInCollapsedFinalFinding(f.CheckID) {
		return "visible|" + finalFindingSiteKey(f) + "|" + normalizedFindingCallable(f.Extra.Trace.Callable)
	}
	return "visible|" + finalFindingSiteKey(f)
}

func finalFindingSiteKey(f Finding) string {
	if shouldCollapseFindingCallables(f.CheckID) {
		return strings.Join([]string{
			f.CheckID,
			f.Path,
			f.Extra.Message,
			normalizedFindingCallable(f.Extra.Trace.Callable),
		}, "|")
	}
	return strings.Join([]string{
		f.CheckID,
		f.Path,
		fmt.Sprintf("%d", f.Start.Line),
		f.Extra.Message,
		f.Extra.Trace.Sink.Path,
		fmt.Sprintf("%d", f.Extra.Trace.Sink.Line),
	}, "|")
}

func hasConcreteLocation(loc Location) bool {
	return loc.Path != "" || loc.Line != 0 || loc.Snippet != ""
}

func mergeFindings(existing Finding, next Finding) Finding {
	preferred := existing
	other := next
	if findingScore(next) > findingScore(existing) {
		preferred = next
		other = existing
	}
	out := preferred
	out.Extra.Context = mergeFlowContext(existing.Extra.Context, next.Extra.Context)
	if sameTraceSource(existing.Extra.Trace.Source, next.Extra.Trace.Source) {
		out.Extra.StoredWriteContext = mergeOptionalFlowContext(existing.Extra.StoredWriteContext, next.Extra.StoredWriteContext)
	} else if !hasMeaningfulFlowContext(out.Extra.StoredWriteContext) {
		out.Extra.StoredWriteContext = other.Extra.StoredWriteContext
	}
	if normalizedFindingCallable(out.Extra.Trace.Callable) == "" && normalizedFindingCallable(other.Extra.Trace.Callable) != "" {
		out.Extra.Trace.Callable = other.Extra.Trace.Callable
	}
	return out
}

func sameTraceSource(a Location, b Location) bool {
	return a.Path == b.Path && a.Line == b.Line && a.Snippet == b.Snippet
}

func findingScore(f Finding) int {
	score := findingTraceScore(f.Extra.Trace)
	score += findingRuleSpecificScore(f)
	score += storedWriteContextScore(f.Extra.StoredWriteContext)
	return score
}

func findingRuleSpecificScore(f Finding) int {
	switch f.CheckID {
	case "render-callback-execution":
		lower := strings.ToLower(f.Extra.Trace.Source.Snippet)
		score := 0
		if strings.Contains(lower, "apply_filters(") ||
			strings.Contains(lower, "apply_filters_ref_array(") {
			score += 160
		} else if strings.Contains(lower, "apply_filters_deprecated(") {
			score += 80
		}
		if strings.Contains(lower, "prepare_post_data(") ||
			strings.Contains(lower, "stripslashes_deep($_post['data'])") ||
			strings.Contains(lower, "stripslashes_deep( $_post['data'] )") {
			score += 48
		}
		return score
	case "wp-request-tainted-privilege-mutation":
		return privilegeMutationSourceSignalScore(f.Extra.Trace.Source.Snippet)
	case "unsafe-deserialization":
		return unsafeDeserializationSourceSignalScore(f.Extra.Trace.Source.Snippet)
	case "wp-request-record-read-to-output-without-cap-check",
		"wp-stored-xss-persistent-read-to-output":
		return outputSinkSignalScore(f.Extra.Trace.Sink.Snippet)
	case "wp-request-file-delete-without-cap-check",
		"request-path-read-delete":
		return fileDeleteSourceSignalScore(f.Extra.Trace.Source.Snippet)
	case "path-transversal":
		score := fileDeleteSourceSignalScore(f.Extra.Trace.Source.Snippet)
		if f.Extra.Trace.Source.Path != "" && f.Extra.Trace.Sink.Path != "" &&
			f.Extra.Trace.Source.Path != f.Extra.Trace.Sink.Path {
			score += 32
		}
		return score
	default:
		return 0
	}
}

func outputSinkSignalScore(snippet string) int {
	if snippet == "" {
		return 0
	}
	lower := strings.ToLower(snippet)
	score := 0
	if strings.Contains(lower, "preg_replace(") {
		score += 160
	}
	if strings.Contains(lower, "call_user_func(") || strings.Contains(lower, "call_user_func_array(") {
		score += 144
	}
	if strings.Contains(lower, "<?php echo $") ||
		strings.Contains(lower, "echo $") ||
		strings.Contains(lower, "<?= $") ||
		strings.Contains(lower, "print $") {
		score += 112
	}
	if strings.Contains(lower, "href=\"<?php echo") ||
		strings.Contains(lower, "src=\"<?php echo") ||
		strings.Contains(lower, "title=\"<?php echo") {
		score += 48
	}
	if strings.Contains(lower, "esc_url(") || strings.Contains(lower, "esc_attr(") {
		score += 24
	}
	if strings.Contains(lower, "esc_html(") || strings.Contains(lower, "number_format_i18n(") {
		score -= 16
	}
	return score
}

func fileDeleteSourceSignalScore(snippet string) int {
	if snippet == "" {
		return 0
	}
	lower := strings.ToLower(snippet)
	score := 0
	if strings.Contains(lower, "file_path") ||
		strings.Contains(lower, "tmp_name") ||
		strings.Contains(lower, "filepath") {
		score += 96
	}
	if strings.Contains(lower, "path") || strings.Contains(lower, "file") {
		score += 40
	}
	if strings.Contains(lower, "text") {
		score -= 24
	}
	return score
}

func privilegeMutationSourceSignalScore(snippet string) int {
	if snippet == "" {
		return 0
	}
	lower := strings.ToLower(snippet)
	score := 0
	if strings.Contains(lower, "json_decode(") &&
		(strings.Contains(lower, "$_post") || strings.Contains(lower, "$_request")) {
		score += 96
	}
	if strings.Contains(lower, "new_role") || strings.Contains(lower, "['role']") || strings.Contains(lower, "\"role\"") {
		score += 72
	}
	if strings.Contains(lower, "file_get_contents(") && strings.Contains(lower, "$_files") {
		score -= 64
	}
	return score
}

func unsafeDeserializationSourceSignalScore(snippet string) int {
	if snippet == "" {
		return 0
	}
	lower := strings.TrimSpace(strings.ToLower(snippet))
	score := 0
	if strings.HasPrefix(lower, "function ") {
		score -= 128
	}
	return score
}

func findingTraceScore(trace Trace) int {
	score := 0
	if hasConcreteLocation(trace.Source) {
		score += 4
	}
	if hasConcreteLocation(trace.Sink) {
		score += 2
	}
	if normalizedFindingCallable(trace.Callable) != "" {
		score += 2
	} else if trace.Callable != "" {
		score++
	}
	score += findingSourceSignalScore(trace.Source.Snippet)
	return score
}

func shouldCollapseFindingSources(ruleID string) bool {
	switch ruleID {
	case "wp-request-tainted-privilege-mutation",
		"predictable-security-identifier-surface",
		"upload-api-surface",
		"wp-issued-auth-link-surface",
		"wp-reflected-xss-direct-request-output",
		"stored-xss",
		"path-transversal",
		"request-path-read-delete",
		"render-callback-execution",
		"unsafe-deserialization",
		"unsafe-use",
		"tainted-sql-string",
		"wp-stored-xss-persistent-read-to-output",
		"wp-ajax-financial-action-without-cap-check",
		"wp-request-file-upload-without-cap-check",
		"wp-request-record-read-to-output-without-cap-check",
		"wp-request-file-delete-without-cap-check",
		"wp-rest-token-issuance-surface",
		"wp-rest-public-data-disclosure-surface",
		"wp-request-sensitive-action-without-cap-check":
		return true
	default:
		return false
	}
}

func shouldKeepDistinctSourceFindingKey(ruleID string) bool {
	return false
}

func shouldCollapseFindingCallables(ruleID string) bool {
	switch ruleID {
	case "wp-request-sensitive-action-without-cap-check":
		return true
	default:
		return false
	}
}

func shouldKeepCallableInCollapsedFinalFinding(ruleID string) bool {
	switch ruleID {
	case "wp-stored-xss-persistent-read-to-output",
		"unsafe-use",
		"wp-request-record-read-to-output-without-cap-check",
		"render-callback-execution":
		// render-callback: the vulnerability is at the sink (dynamic callback
		// execution). Multiple callables reaching the same sink are the same
		// issue — including the callable in the key inflates finding count.
		return false
	default:
		return true
	}
}

func collapsedFindingSourceSiteKey(f Finding) string {
	switch f.CheckID {
	case "wp-request-tainted-privilege-mutation":
		return finalFindingSiteKey(f)
	case "wp-request-sensitive-action-without-cap-check":
		if shouldCollapseSensitiveActionSameSinkSnippetCluster(f) {
			return strings.Join([]string{
				f.CheckID,
				f.Path,
				f.Extra.Message,
				f.Extra.Trace.Sink.Path,
				f.Extra.Trace.Sink.Snippet,
			}, "|")
		}
		return strings.Join([]string{
			f.CheckID,
			f.Path,
			fmt.Sprintf("%d", f.Start.Line),
			f.Extra.Message,
			f.Extra.Trace.Sink.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Sink.Line),
		}, "|")
	case "wp-request-file-delete-without-cap-check":
		if shouldCollapseFileDeleteSameSinkSnippetCluster(f) {
			return strings.Join([]string{
				f.CheckID,
				f.Path,
				f.Extra.Message,
				f.Extra.Trace.Sink.Path,
				fmt.Sprintf("%d", f.Extra.Trace.Sink.Line),
				f.Extra.Trace.Sink.Snippet,
			}, "|")
		}
		return finalFindingSiteKey(f)
	case "path-transversal",
		"request-path-read-delete":
		return strings.Join([]string{
			f.CheckID,
			f.Path,
			fmt.Sprintf("%d", f.Start.Line),
			f.Extra.Message,
			f.Extra.Trace.Sink.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Sink.Line),
		}, "|")
	case "render-callback-execution":
		if !shouldCollapseRenderCallbackSameSourceSite(f) {
			return finalFindingSiteKey(f)
		}
		return strings.Join([]string{
			f.CheckID,
			f.Path,
			fmt.Sprintf("%d", f.Start.Line),
			f.Extra.Message,
			f.Extra.Trace.Sink.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Sink.Line),
			f.Extra.Trace.Source.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Source.Line),
			f.Extra.Trace.Source.Snippet,
		}, "|")
	case "wp-request-record-read-to-output-without-cap-check",
		"wp-stored-xss-persistent-read-to-output":
		if !shouldCollapseRendererLineFinding(f) {
			return finalFindingSiteKey(f)
		}
		return strings.Join([]string{
			f.CheckID,
			f.Path,
			f.Extra.Message,
			normalizedFindingCallable(f.Extra.Trace.Callable),
			f.Extra.Trace.Source.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Source.Line),
		}, "|")
	case "unsafe-use":
		if !shouldCollapseUnsafeUseAssertCluster(f) {
			return finalFindingSiteKey(f)
		}
		return strings.Join([]string{
			f.CheckID,
			f.Path,
			f.Extra.Message,
			normalizedFindingCallable(f.Extra.Trace.Callable),
			f.Extra.Trace.Source.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Source.Line),
			f.Extra.Trace.Sink.Path,
		}, "|")
	case "unsafe-deserialization":
		if !shouldCollapseUnsafeDeserializationSameSourceCluster(f) {
			return finalFindingSiteKey(f)
		}
		return strings.Join([]string{
			f.CheckID,
			f.Path,
			fmt.Sprintf("%d", f.Start.Line),
			f.Extra.Message,
			f.Extra.Trace.Sink.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Sink.Line),
			f.Extra.Trace.Source.Path,
			fmt.Sprintf("%d", f.Extra.Trace.Source.Line),
			f.Extra.Trace.Source.Snippet,
		}, "|")
	default:
		return finalFindingSiteKey(f)
	}
}

func shouldCollapseVisibleCallablesAtFindingSite(f Finding) bool {
	switch f.CheckID {
	case "wp-request-tainted-privilege-mutation":
		return true
	case "wp-request-sensitive-action-without-cap-check":
		return true
	case "path-transversal":
		return true
	case "request-path-read-delete":
		return true
	case "tainted-sql-string":
		return true
	case "wp-request-file-delete-without-cap-check":
		return shouldCollapseFileDeleteSameSinkSnippetCluster(f)
	case "upload-api-surface":
		return true
	case "wp-request-record-read-to-output-without-cap-check",
		"wp-stored-xss-persistent-read-to-output":
		return shouldCollapseRendererLineFinding(f)
	case "wp-request-file-upload-without-cap-check":
		return true
	case "unsafe-deserialization":
		return isUnsafeDeserializationHelperDefinitionSource(f.Extra.Trace.Source.Snippet) ||
			(f.Extra.Trace.Source.Path != "" && f.Extra.Trace.Sink.Path != "" && f.Extra.Trace.Source.Path != f.Extra.Trace.Sink.Path) ||
			shouldCollapseUnsafeDeserializationSameSourceCluster(f)
	case "render-callback-execution":
		return shouldCollapseRenderCallbackSameSourceSite(f)
	case "unsafe-use":
		return shouldCollapseUnsafeUseAssertCluster(f)
	default:
		return false
	}
}

func normalizedFindingCallable(callable string) string {
	if strings.HasPrefix(callable, "file::") {
		return ""
	}
	return callable
}

func shouldCollapseRendererLineFinding(f Finding) bool {
	if normalizedFindingCallable(f.Extra.Trace.Callable) == "" {
		return true
	}
	if !hasConcreteLocation(f.Extra.Trace.Source) || !hasConcreteLocation(f.Extra.Trace.Sink) {
		return false
	}
	switch f.CheckID {
	case "wp-request-record-read-to-output-without-cap-check",
		"wp-stored-xss-persistent-read-to-output":
		return true
	default:
		return pathsReferToSameFile(f.Extra.Trace.Source.Path, f.Extra.Trace.Sink.Path)
	}
}

func shouldCollapseUnsafeUseAssertCluster(f Finding) bool {
	if f.CheckID != "unsafe-use" {
		return false
	}
	if normalizedFindingCallable(f.Extra.Trace.Callable) == "" {
		return false
	}
	if !hasConcreteLocation(f.Extra.Trace.Source) || !hasConcreteLocation(f.Extra.Trace.Sink) {
		return false
	}
	snippet := strings.TrimSpace(strings.ToLower(f.Extra.Trace.Sink.Snippet))
	if !strings.HasPrefix(snippet, "assert") {
		return false
	}
	return f.Extra.Trace.Source.Path != "" &&
		f.Extra.Trace.Sink.Path != "" &&
		f.Extra.Trace.Source.Path != f.Extra.Trace.Sink.Path
}

func shouldCollapseSensitiveActionSameSinkSnippetCluster(f Finding) bool {
	if f.CheckID != "wp-request-sensitive-action-without-cap-check" {
		return false
	}
	if !hasConcreteLocation(f.Extra.Trace.Source) || !hasConcreteLocation(f.Extra.Trace.Sink) {
		return false
	}
	if strings.TrimSpace(f.Extra.Trace.Sink.Snippet) == "" {
		return false
	}
	return pathsReferToSameFile(f.Path, f.Extra.Trace.Sink.Path)
}

func shouldCollapsePrivilegeMutationSameSourceSinkSnippet(f Finding) bool {
	if f.CheckID != "wp-request-tainted-privilege-mutation" {
		return false
	}
	if normalizedFindingCallable(f.Extra.Trace.Callable) == "" {
		return false
	}
	if !hasConcreteLocation(f.Extra.Trace.Source) || !hasConcreteLocation(f.Extra.Trace.Sink) {
		return false
	}
	return strings.TrimSpace(f.Extra.Trace.Source.Snippet) != "" &&
		strings.TrimSpace(f.Extra.Trace.Sink.Snippet) != ""
}

func shouldCollapseFileDeleteSameSinkSnippetCluster(f Finding) bool {
	if f.CheckID != "wp-request-file-delete-without-cap-check" {
		return false
	}
	if !hasConcreteLocation(f.Extra.Trace.Source) || !hasConcreteLocation(f.Extra.Trace.Sink) {
		return false
	}
	if strings.TrimSpace(f.Extra.Trace.Sink.Snippet) == "" {
		return false
	}
	return pathsReferToSameFile(f.Path, f.Extra.Trace.Sink.Path)
}

func shouldCollapseUnsafeDeserializationSameSourceCluster(f Finding) bool {
	if f.CheckID != "unsafe-deserialization" {
		return false
	}
	if normalizedFindingCallable(f.Extra.Trace.Callable) == "" {
		return false
	}
	if !hasConcreteLocation(f.Extra.Trace.Source) || !hasConcreteLocation(f.Extra.Trace.Sink) {
		return false
	}
	if isUnsafeDeserializationHelperDefinitionSource(f.Extra.Trace.Source.Snippet) {
		return false
	}
	return f.Extra.Trace.Source.Path != "" &&
		f.Extra.Trace.Source.Path == f.Extra.Trace.Sink.Path &&
		f.Extra.Trace.Source.Line != 0
}

func collapsedFindingAlternateSiteKeys(f Finding) []string {
	switch f.CheckID {
	case "wp-request-tainted-privilege-mutation":
		if !shouldCollapsePrivilegeMutationSameSourceSinkSnippet(f) {
			return nil
		}
		return []string{strings.Join([]string{
			f.CheckID,
			f.Extra.Message,
			f.Extra.Trace.Source.Snippet,
			f.Extra.Trace.Sink.Snippet,
		}, "|")}
	default:
		return nil
	}
}

func shouldCollapseRenderCallbackSameSourceSite(f Finding) bool {
	if f.CheckID != "render-callback-execution" {
		return false
	}
	if !hasConcreteLocation(f.Extra.Trace.Source) || !hasConcreteLocation(f.Extra.Trace.Sink) {
		return false
	}
	return f.Extra.Trace.Source.Path != "" &&
		f.Extra.Trace.Sink.Path != "" &&
		f.Extra.Trace.Source.Line != 0 &&
		f.Extra.Trace.Sink.Line != 0
}

func isUnsafeDeserializationHelperDefinitionSource(snippet string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(snippet)), "function ")
}

func shouldSuppressFinalFinding(f Finding) bool {
	return shouldSuppressFindingForContext(f.CheckID, f.Extra.Context, f.Extra.Trace.Sink)
}

func shouldSuppressFindingForContext(checkID string, ctx FlowContext, sink Location) bool {
	switch checkID {
	case "wp-request-sensitive-action-without-cap-check":
		return definitelyCapabilityGuardedForActionAtSink(ctx, sink)
	case "wp-request-file-delete-without-cap-check":
		return definitelyCapabilityGuardedForActionAtSink(ctx, sink)
	default:
		return false
	}
}

func findingSourceSignalScore(snippet string) int {
	if snippet == "" {
		return 0
	}
	lower := strings.ToLower(snippet)
	score := 4
	if strings.Contains(lower, "$_get") ||
		strings.Contains(lower, "$_post") ||
		strings.Contains(lower, "$_request") ||
		strings.Contains(lower, "$_files") ||
		strings.Contains(lower, "$_cookie") ||
		strings.Contains(lower, "$_server") ||
		strings.Contains(lower, "php://input") {
		score += 64
	}
	if strings.Contains(lower, "filter_input(") {
		score += 48
	}
	if strings.Contains(lower, "sanitize_text_field(") ||
		strings.Contains(lower, "sanitize_textarea_field(") ||
		strings.Contains(lower, "sanitize_key(") ||
		strings.Contains(lower, "wp_unslash(") {
		score += 16
	}
	return score
}

func storedWriteContextScore(ctx FlowContext) int {
	if !hasMeaningfulFlowContext(ctx) {
		return 0
	}
	score := 64
	switch ctx.Access {
	case "unauthenticated":
		score += 112
	case "nonce_only":
		score += 96
	case "authenticated":
		score += 32
	case "capability_checked":
		score -= 32
	}
	if len(ctx.EntryPoints) != 0 {
		score += 16
	}
	if len(ctx.NonceChecks) != 0 {
		score += 12
	}
	if len(ctx.UnauthChecks) != 0 {
		score += 8
	}
	return score
}

func sinkTemplateKey(template sinkTemplate) string {
	return strings.Join([]string{
		template.RuleID,
		template.Sink.Path,
		fmt.Sprintf("%d", template.Sink.Line),
		template.Callable,
		template.ParamPath,
		template.ReceiverPath,
	}, "|")
}

func locationKey(loc Location) string {
	return loc.Path + ":" + strconv.Itoa(loc.Line) + ":" + loc.Snippet
}

func sortedLocations(items map[string]Location) []Location {
	out := make([]Location, 0, len(items))
	for _, loc := range items {
		out = append(out, loc)
	}
	sort.Slice(out, func(i int, j int) bool {
		return lessLocation(out[i], out[j])
	})
	return out
}

func lessLocation(a Location, b Location) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Snippet < b.Snippet
}

func sortedKeys[T any](items map[string]T) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysTemplate(items map[string]sinkTemplate) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func lastSegment(text string) string {
	if idx := strings.LastIndex(text, "::"); idx >= 0 {
		return text[idx+2:]
	}
	if idx := strings.LastIndex(text, `\`); idx >= 0 {
		return text[idx+1:]
	}
	return text
}
