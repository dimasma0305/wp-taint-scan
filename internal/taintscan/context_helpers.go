package taintscan

import (
	"regexp"
	"sort"
	"strings"
)

// capabilityToMinRole maps WordPress capabilities to the minimum default role
// that holds the capability. This follows the WordPress default role/capability
// matrix. Capabilities held by subscriber (the lowest role) are most interesting
// for bounty triage because ANY authenticated user has them.
var capabilityToMinRole = map[string]string{
	// Subscriber (any logged-in user)
	"read": "subscriber",

	// Contributor
	"edit_posts":           "contributor",
	"delete_posts":         "contributor",

	// Author
	"upload_files":         "author",
	"publish_posts":        "author",
	"edit_published_posts": "author",
	"delete_published_posts": "author",

	// Editor
	"edit_others_posts":        "editor",
	"delete_others_posts":      "editor",
	"edit_pages":               "editor",
	"edit_others_pages":        "editor",
	"publish_pages":            "editor",
	"delete_pages":             "editor",
	"delete_others_pages":      "editor",
	"edit_published_pages":     "editor",
	"delete_published_pages":   "editor",
	"manage_categories":        "editor",
	"manage_links":             "editor",
	"moderate_comments":        "editor",
	"read_private_posts":       "editor",
	"read_private_pages":       "editor",
	"unfiltered_html":          "editor",

	// Administrator
	"manage_options":       "administrator",
	"activate_plugins":     "administrator",
	"install_plugins":      "administrator",
	"delete_plugins":       "administrator",
	"edit_plugins":         "administrator",
	"install_themes":       "administrator",
	"edit_themes":          "administrator",
	"switch_themes":        "administrator",
	"delete_themes":        "administrator",
	"edit_theme_options":   "administrator",
	"manage_network":       "administrator",
	"manage_network_options": "administrator",
	"update_plugins":       "administrator",
	"update_themes":        "administrator",
	"update_core":          "administrator",
	"create_users":         "administrator",
	"delete_users":         "administrator",
	"edit_users":           "administrator",
	"list_users":           "administrator",
	"promote_users":        "administrator",
	"remove_users":         "administrator",
	"import":               "administrator",
	"export":               "administrator",
	"edit_dashboard":       "administrator",
	"manage_privacy_options": "administrator",

	// Common plugin-defined admin caps
	"manage_woocommerce":   "shop_manager",
	"view_woocommerce_reports": "shop_manager",
}

// roleHierarchy defines the privilege level of each role.
// Lower number = more accessible = higher bounty priority.
var roleHierarchy = map[string]int{
	"subscriber":    1,
	"customer":      1,
	"student":       1,
	"contributor":   2,
	"author":        3,
	"shop_manager":  4,
	"editor":        4,
	"administrator": 5,
	"super_admin":   6,
}

var capExtractRe = regexp.MustCompile(`current_user_can\s*\(\s*['"]([\w_]+)['"]`)

// resolveCapabilityAndRole extracts the required capability from CapabilityChecks
// snippets and maps it to a minimum WordPress role.
func resolveCapabilityAndRole(ctx *FlowContext) {
	if len(ctx.CapabilityChecks) == 0 {
		return
	}

	bestCap := ""
	bestRoleLevel := 99

	for _, loc := range ctx.CapabilityChecks {
		matches := capExtractRe.FindStringSubmatch(loc.Snippet)
		if len(matches) < 2 {
			continue
		}
		cap := strings.ToLower(matches[1])
		role, known := capabilityToMinRole[cap]
		if !known {
			// Unknown capability — assume it requires at least authentication
			if bestCap == "" {
				bestCap = cap
			}
			continue
		}
		level := roleHierarchy[role]
		if level < bestRoleLevel {
			bestRoleLevel = level
			bestCap = cap
			ctx.RequiredCapability = cap
			ctx.MinimumRole = role
		}
	}

	// If we found a capability but couldn't map it to a known role
	if ctx.RequiredCapability == "" && bestCap != "" {
		ctx.RequiredCapability = bestCap
		ctx.MinimumRole = "unknown_role"
	}
}

// capabilityCheckIsPrivileged reports whether a current_user_can(...) snippet
// requires a capability above the subscriber/customer tier. A low-privilege cap
// such as 'read' is held by ANY logged-in user, so it is only an authentication
// check, not an authorization gate — it must not suppress the *-without-cap
// findings. Dynamic/unknown caps are treated as privileged so a real gate is
// never lost.
func capabilityCheckIsPrivileged(snippet string) bool {
	matches := capExtractRe.FindStringSubmatch(snippet)
	if len(matches) < 2 {
		return true
	}
	cap := strings.ToLower(matches[1])
	role, known := capabilityToMinRole[cap]
	if !known {
		return true
	}
	return roleHierarchy[role] > roleHierarchy["subscriber"]
}

// ctxHasPrivilegedCapabilityCheck reports whether any capability check in the
// context requires more than subscriber-level access.
func ctxHasPrivilegedCapabilityCheck(ctx FlowContext) bool {
	for _, loc := range ctx.CapabilityChecks {
		if capabilityCheckIsPrivileged(loc.Snippet) {
			return true
		}
	}
	return false
}

const (
	maxFlowContextEntryPoints = 8
	maxFlowContextLocations   = 16
)

func mergeFlowContext(a FlowContext, b FlowContext) FlowContext {
	out := FlowContext{
		EntryPoints:      mergeCappedEntryPoints(a.EntryPoints, b.EntryPoints, maxFlowContextEntryPoints),
		CapabilityChecks: mergeCappedLocations(a.CapabilityChecks, b.CapabilityChecks, maxFlowContextLocations),
		NonceChecks:      mergeCappedLocations(a.NonceChecks, b.NonceChecks, maxFlowContextLocations),
		ValidationChecks: mergeCappedLocations(a.ValidationChecks, b.ValidationChecks, maxFlowContextLocations),
		AuthChecks:       mergeCappedLocations(a.AuthChecks, b.AuthChecks, maxFlowContextLocations),
		UnauthChecks:     mergeCappedLocations(a.UnauthChecks, b.UnauthChecks, maxFlowContextLocations),
		AdminChecks:      mergeCappedLocations(a.AdminChecks, b.AdminChecks, maxFlowContextLocations),
		AjaxChecks:       mergeCappedLocations(a.AjaxChecks, b.AjaxChecks, maxFlowContextLocations),
	}
	out.Access = deriveAccess(out)
	resolveCapabilityAndRole(&out)
	return out
}

func normalizeFlowContext(ctx FlowContext) FlowContext {
	ctx.EntryPoints = uniqueEntryPoints(ctx.EntryPoints)
	ctx.CapabilityChecks = uniqueLocations(ctx.CapabilityChecks)
	ctx.NonceChecks = uniqueLocations(ctx.NonceChecks)
	ctx.ValidationChecks = uniqueLocations(ctx.ValidationChecks)
	ctx.AuthChecks = uniqueLocations(ctx.AuthChecks)
	ctx.UnauthChecks = uniqueLocations(ctx.UnauthChecks)
	ctx.AdminChecks = uniqueLocations(ctx.AdminChecks)
	ctx.AjaxChecks = uniqueLocations(ctx.AjaxChecks)
	ctx.Access = deriveAccess(ctx)
	resolveCapabilityAndRole(&ctx)
	return ctx
}

func uniqueEntryPoints(items []EntryPoint) []EntryPoint {
	if isUniqueSortedEntryPoints(items) {
		if len(items) == 0 {
			return nil
		}
		return items[:len(items):len(items)]
	}
	return mergeUniqueEntryPoints(nil, items, maxFlowContextEntryPoints)
}

// isUniqueSortedEntryPoints reports whether items is already sorted (strictly) and
// has no duplicates. When true, uniqueEntryPoints can return items directly with
// no allocation — the common case once the fixpoint loop has stabilised.
func isUniqueSortedEntryPoints(items []EntryPoint) bool {
	for i := 1; i < len(items); i++ {
		if !lessEntryPoint(items[i-1], items[i]) {
			return false
		}
	}
	return true
}

func mergeCappedEntryPoints(a []EntryPoint, b []EntryPoint, limit int) []EntryPoint {
	// Fast paths: seal capacity so future appends on the result always reallocate
	// (prevents aliasing into the original backing array without copying).
	if len(b) == 0 {
		if len(a) == 0 {
			return nil
		}
		return a[:len(a):len(a)]
	}
	if len(a) == 0 {
		return b[:len(b):len(b)]
	}
	// Subset check: if b adds nothing new, return a as-is (sealed).
	// Very common in fixpoint passes once the analysis has stabilised.
	bSubsetOfA := true
	for _, item := range b {
		if !entryPointSliceContains(a, item) {
			bSubsetOfA = false
			break
		}
	}
	if bSubsetOfA && (limit <= 0 || len(a) <= limit) {
		return a[:len(a):len(a)]
	}
	// General case: linear dedup — limit is always maxFlowContextEntryPoints (8).
	// Capacity matches original: len(a)+len(b) (both inputs are already ≤ limit).
	out := make([]EntryPoint, 0, len(a)+len(b))
	for _, items := range [][]EntryPoint{a, b} {
		for _, item := range items {
			if entryPointSliceContains(out, item) {
				continue
			}
			if limit > 0 && len(out) >= limit {
				return out
			}
			out = append(out, item)
		}
	}
	return out
}

func mergeUniqueEntryPoints(a []EntryPoint, b []EntryPoint, limit int) []EntryPoint {
	// Linear dedup + sort. make([]EntryPoint, 0, ...) always returns a non-nil slice,
	// preserving the nil-vs-empty semantics callers depend on.
	out := make([]EntryPoint, 0, len(a)+len(b))
outer_ep:
	for _, items := range [][]EntryPoint{a, b} {
		for _, item := range items {
			if entryPointSliceContains(out, item) {
				continue
			}
			if limit > 0 && len(out) >= limit {
				break outer_ep
			}
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i int, j int) bool {
		return lessEntryPoint(out[i], out[j])
	})
	return out
}

// entryPointSliceContains reports whether item is present in eps using a linear scan.
// Callers guarantee len(eps) ≤ maxFlowContextEntryPoints (8), so O(N²) is acceptable.
func entryPointSliceContains(eps []EntryPoint, item EntryPoint) bool {
	for _, e := range eps {
		if e == item {
			return true
		}
	}
	return false
}

func uniqueLocations(items []Location) []Location {
	if isUniqueSortedLocations(items) {
		if len(items) == 0 {
			return nil
		}
		return items[:len(items):len(items)]
	}
	return mergeUniqueLocations(nil, items, maxFlowContextLocations)
}

// isUniqueSortedLocations reports whether items is already sorted (strictly) and
// has no duplicates. When true, uniqueLocations can return items directly with
// no allocation — the common case once the fixpoint loop has stabilised.
func isUniqueSortedLocations(items []Location) bool {
	for i := 1; i < len(items); i++ {
		if !lessLocation(items[i-1], items[i]) {
			return false
		}
	}
	return true
}

func mergeCappedLocations(a []Location, b []Location, limit int) []Location {
	// Fast paths: seal capacity so future appends on the result always reallocate
	// (prevents aliasing into the original backing array without copying).
	if len(b) == 0 {
		if len(a) == 0 {
			return nil
		}
		return a[:len(a):len(a)]
	}
	if len(a) == 0 {
		return b[:len(b):len(b)]
	}
	// Subset check: if b adds nothing new, return a as-is (sealed).
	// Very common in fixpoint passes once the analysis has stabilised.
	bSubsetOfA := true
	for _, item := range b {
		if !locationSliceContains(a, item) {
			bSubsetOfA = false
			break
		}
	}
	if bSubsetOfA && (limit <= 0 || len(a) <= limit) {
		return a[:len(a):len(a)]
	}
	// General case: linear dedup via O(N²) scan — no map allocation.
	// limit is always maxFlowContextLocations (16), both inputs are already ≤ limit.
	// Capacity matches original: len(a)+len(b).
	out := make([]Location, 0, len(a)+len(b))
	for _, items := range [][]Location{a, b} {
		for _, item := range items {
			if locationSliceContains(out, item) {
				continue
			}
			if limit > 0 && len(out) >= limit {
				return out
			}
			out = append(out, item)
		}
	}
	return out
}

// locationSliceContains reports whether item is present in locs using a linear scan.
// Callers guarantee len(locs) ≤ maxFlowContextLocations (16), so O(N²) is acceptable.
func locationSliceContains(locs []Location, item Location) bool {
	for _, l := range locs {
		if l == item {
			return true
		}
	}
	return false
}

func mergeUniqueLocations(a []Location, b []Location, limit int) []Location {
	// Linear dedup + sort. make([]Location, 0, ...) always returns a non-nil slice,
	// preserving the nil-vs-empty semantics callers depend on.
	out := make([]Location, 0, len(a)+len(b))
outer_loc:
	for _, items := range [][]Location{a, b} {
		for _, item := range items {
			if locationSliceContains(out, item) {
				continue
			}
			if limit > 0 && len(out) >= limit {
				break outer_loc
			}
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i int, j int) bool {
		return lessLocation(out[i], out[j])
	})
	return out
}

func hasMeaningfulFlowContext(ctx FlowContext) bool {
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

func mergeOptionalFlowContext(a FlowContext, b FlowContext) FlowContext {
	if !hasMeaningfulFlowContext(a) {
		if !hasMeaningfulFlowContext(b) {
			return FlowContext{}
		}
		return b
	}
	if !hasMeaningfulFlowContext(b) {
		return a
	}
	return mergeFlowContext(a, b)
}

func mergeReplayedFindingContext(template FlowContext, current FlowContext) FlowContext {
	merged := mergeOptionalFlowContext(template, current)
	if len(current.EntryPoints) == 0 || !hasMeaningfulFlowContext(merged) {
		return merged
	}
	// Replayed findings should keep the concrete caller surface while still inheriting
	// guard signals from the helper summary they were replayed through.
	merged.EntryPoints = uniqueEntryPoints(current.EntryPoints)
	merged.Access = deriveAccess(merged)
	return merged
}

func flowContextsEquivalent(a FlowContext, b FlowContext) bool {
	if !hasMeaningfulFlowContext(a) || !hasMeaningfulFlowContext(b) {
		return !hasMeaningfulFlowContext(a) && !hasMeaningfulFlowContext(b)
	}
	a = normalizeFlowContext(a)
	b = normalizeFlowContext(b)
	if a.Access != b.Access {
		return false
	}
	return entryPointsEqual(a.EntryPoints, b.EntryPoints) &&
		locationsEqual(a.CapabilityChecks, b.CapabilityChecks) &&
		locationsEqual(a.NonceChecks, b.NonceChecks) &&
		locationsEqual(a.ValidationChecks, b.ValidationChecks) &&
		locationsEqual(a.AuthChecks, b.AuthChecks) &&
		locationsEqual(a.UnauthChecks, b.UnauthChecks) &&
		locationsEqual(a.AdminChecks, b.AdminChecks) &&
		locationsEqual(a.AjaxChecks, b.AjaxChecks)
}

func flowEntryPointKey(item EntryPoint) string {
	return strings.Join([]string{
		item.Kind,
		item.Name,
		item.Route,
		item.Methods,
		item.Access,
		locationKey(item.Location),
	}, "|")
}

func lessEntryPoint(a EntryPoint, b EntryPoint) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Route != b.Route {
		return a.Route < b.Route
	}
	if a.Methods != b.Methods {
		return a.Methods < b.Methods
	}
	if a.Access != b.Access {
		return a.Access < b.Access
	}
	return lessLocation(a.Location, b.Location)
}

func entryPointsEqual(a []EntryPoint, b []EntryPoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func locationsEqual(a []Location, b []Location) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func deriveAccess(ctx FlowContext) string {
	if ctxHasPrivilegedCapabilityCheck(ctx) {
		return "capability_checked"
	}
	// A low-privilege capability check (e.g. current_user_can('read')) only
	// proves the request is authenticated; it does not authorize a privileged
	// action, so it must not be labelled capability_checked.
	lowPrivCapAuthenticated := len(ctx.CapabilityChecks) > 0
	if (len(ctx.AuthChecks) > 0 || lowPrivCapAuthenticated) && len(ctx.UnauthChecks) == 0 {
		return "authenticated"
	}
	if len(ctx.UnauthChecks) > 0 && len(ctx.AuthChecks) == 0 {
		return "unauthenticated"
	}
	hasUnauth := false
	hasAuth := false
	hasPermissionCallback := false
	for _, entry := range ctx.EntryPoints {
		switch entry.Access {
		case "unauthenticated":
			hasUnauth = true
		case "authenticated":
			hasAuth = true
		case "permission_callback":
			hasPermissionCallback = true
		}
	}
	if len(ctx.NonceChecks) > 0 && len(ctx.AuthChecks) == 0 {
		return "nonce_only"
	}
	if hasPermissionCallback {
		return "permission_callback"
	}
	if hasUnauth {
		return "unauthenticated"
	}
	if hasAuth {
		return "authenticated"
	}
	if len(ctx.NonceChecks) > 0 {
		return "nonce_only"
	}
	return "unknown"
}

func restPermissionContextAccess(current string, permissionCtx FlowContext) string {
	switch deriveAccess(permissionCtx) {
	case "capability_checked":
		return "capability_checked"
	case "authenticated":
		return "authenticated"
	case "nonce_only":
		return "nonce_only"
	case "unauthenticated":
		return "unauthenticated"
	default:
		return current
	}
}

func definitelyCapabilityGuarded(ctx FlowContext) bool {
	// Only a privileged capability check authorizes a sensitive action; a
	// subscriber-level cap ('read') leaves the handler exploitable by any
	// logged-in user, so it must not suppress the finding.
	if !ctxHasPrivilegedCapabilityCheck(ctx) {
		return false
	}
	if len(ctx.EntryPoints) == 0 {
		return true
	}
	for _, entry := range ctx.EntryPoints {
		switch entry.Access {
		case "unknown", "unauthenticated":
			return false
		}
	}
	return true
}

func definitelyCapabilityGuardedForAction(ctx FlowContext) bool {
	if !definitelyCapabilityGuarded(ctx) {
		return false
	}
	hasAdminPage := false
	hasAjax := false
	for _, entry := range ctx.EntryPoints {
		switch entry.Kind {
		case "admin_page":
			hasAdminPage = true
		case "ajax":
			hasAjax = true
		}
	}
	if hasAdminPage && hasAjax {
		return false
	}
	return true
}

func definitelyCapabilityGuardedForActionAtSink(ctx FlowContext, sink Location) bool {
	if !definitelyCapabilityGuarded(ctx) {
		return false
	}
	hasAdminPage := false
	hasAjax := false
	for _, entry := range ctx.EntryPoints {
		switch entry.Kind {
		case "admin_page":
			hasAdminPage = true
		case "ajax":
			hasAjax = true
		}
	}
	if !(hasAdminPage && hasAjax) {
		return true
	}
	return hasLocalGuardNearSink(ctx.CapabilityChecks, sink) &&
		(hasLocalGuardNearSink(ctx.NonceChecks, sink) || hasLocalGuardNearSink(ctx.ValidationChecks, sink))
}

func hasLocalGuardNearSink(checks []Location, sink Location) bool {
	if sink.Path == "" || sink.Line <= 0 {
		return false
	}
	for _, loc := range checks {
		if !pathsReferToSameFile(loc.Path, sink.Path) || loc.Line <= 0 || loc.Line > sink.Line {
			continue
		}
		if sink.Line-loc.Line <= 48 {
			return true
		}
	}
	return false
}

func pathsReferToSameFile(a string, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.HasSuffix(a, "/"+b) || strings.HasSuffix(b, "/"+a)
}
