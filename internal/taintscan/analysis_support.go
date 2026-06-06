package taintscan

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (s *analysisState) superglobalSource(name string, dim ast.Node, node ast.Node) (origin, bool) {
	kind := originSource
	if dim == nil {
		kind = originContainer
	}
	switch name {
	case "_GET", "_POST", "_REQUEST", "_COOKIE":
		return s.makeOrigin(node, kind), true
	case "_FILES":
		return s.makeOrigin(node, kind), true
	case "_SERVER":
		if dim == nil {
			return s.makeOrigin(node, kind), true
		}
		key := strings.ToUpper(literalString(dim))
		switch key {
		case "REQUEST_URI", "PATH_INFO", "REDIRECT_URL", "DOCUMENT_URI", "HTTP_HOST",
			"QUERY_STRING", "PHP_SELF", "PATH_TRANSLATED", "ORIG_PATH_INFO":
			return s.makeOrigin(node, originSource), true
		default:
			if strings.HasPrefix(key, "HTTP_") {
				return s.makeOrigin(node, originSource), true
			}
		}
	}
	return origin{}, false
}

func superglobalArrayRootName(node ast.Node) (string, bool) {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return "", false
		}
		return name, true
	case *ast.ExprArrayDimFetch:
		return superglobalArrayRootName(typed.Var)
	default:
		return "", false
	}
}

func (s *analysisState) makeOrigin(node ast.Node, kind string) origin {
	return origin{
		kind:   kind,
		source: s.locationForNode(node),
	}
}

func (s *analysisState) makeSourceOrigin(node ast.Node) origin {
	return s.makeOrigin(node, originSource)
}

func (s *analysisState) currentDirectRequestOrigins(limit int) originSet {
	if limit <= 0 {
		limit = 4
	}
	out := originSet{}
	walkCallableExecutableNodes(s.current, func(node ast.Node) {
		if len(out) >= limit || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprVariable:
			if name, ok := typed.Name.(string); ok {
				if origin, ok := s.superglobalSource(strings.ToUpper(strings.TrimSpace(name)), nil, typed); ok {
					out = unionInto(out, makeOriginSet(origin))
				}
			}
		case *ast.ExprArrayDimFetch:
			if name, ok := superglobalArrayRootName(typed.Var); ok {
				if origin, ok := s.superglobalSource(strings.ToUpper(strings.TrimSpace(name)), typed.Dim, typed); ok {
					out = unionInto(out, makeOriginSet(origin))
				}
			}
		case *ast.ExprFuncCall:
			if isDirectRequestSourceFunc(identifierText(typed.Name)) {
				out = unionInto(out, makeOriginSet(s.makeSourceOrigin(typed)))
				return
			}
			if len(typed.Args) > 0 && isPHPInputLiteral(argValue(typed.Args[0])) {
				out = unionInto(out, makeOriginSet(s.makeSourceOrigin(typed)))
			}
		case *ast.ExprMethodCall:
			if isRequestGetterMethodCall(typed) {
				out = unionInto(out, makeOriginSet(s.makeSourceOrigin(typed)))
			}
		case *ast.ExprStaticCall:
			className := s.engine.resolveClassNameForCallable(typed.Class, s.current)
			if isRequestGetterStaticCall(className, identifierText(typed.Name)) || isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
				out = unionInto(out, makeOriginSet(s.makeSourceOrigin(typed)))
			}
		}
	})
	return out
}

func (s *analysisState) currentActionRequestOrigins() originSet {
	if origins := s.currentDirectRequestOrigins(4); len(origins) != 0 {
		return origins
	}
	return originSet{}
}

func (e *engine) entrypointParamOrigin(c callable, idx int) (origin, bool) {
	kind, ok := entrypointParamSourceKind(e.contexts[c.Key], e.directEntryPointsByCallable[c.Key], idx)
	if !ok {
		return origin{}, false
	}
	loc := Location{
		Path: c.SourcePath,
		Line: c.StartLine,
	}
	if file, ok := e.fileIndex[c.SourcePath]; ok {
		if loc.Line >= 1 && loc.Line <= len(file.Lines) {
			loc.Snippet = strings.TrimSpace(file.Lines[loc.Line-1])
		}
	}
	return origin{kind: kind, source: loc}, true
}

func entrypointParamSourceKind(ctx FlowContext, directEntries []EntryPoint, idx int) (string, bool) {
	if kind, ok := directEntrypointParamSourceKind(directEntries, idx); ok {
		return kind, true
	}
	for _, entry := range ctx.EntryPoints {
		switch entry.Kind {
		case "shortcode", "block":
			if idx == 0 {
				return originContainer, true
			}
		}
	}
	return "", false
}

func directEntrypointParamSourceKind(directEntries []EntryPoint, idx int) (string, bool) {
	for _, entry := range directEntries {
		switch entry.Kind {
		case "filter":
			if model, ok := sqlClauseFilterModelForHook(entry.Name); ok && model.TaintCallbackArg0 && idx == model.ArgIndex {
				return originSource, true
			}
			if model, ok := uploadValidationFilterModelForHook(entry.Name); ok && idx == model.FilenameArgIndex {
				return originSource, true
			}
		case "shortcode", "block":
			if idx == 0 {
				return originContainer, true
			}
		}
	}
	return "", false
}

func (e *engine) sqlClauseFilterReturnSinkForCallable(key string) (string, string, bool) {
	for _, entry := range e.directEntryPointsByCallable[key] {
		if entry.Kind != "filter" {
			continue
		}
		if model, ok := sqlClauseFilterModelForHook(entry.Name); ok {
			return model.RuleID, model.Message, true
		}
	}
	return "", "", false
}

func (s *analysisState) currentContext() FlowContext {
	ctx := mergeOptionalFlowContext(s.engine.contexts[s.current.Key], s.contextOverride)
	if direct := s.engine.directEntryPointsByCallable[s.current.Key]; len(direct) != 0 {
		// For the callable currently under analysis, prefer its concrete direct
		// surfaces over propagated caller surfaces. This keeps shared bootstrap
		// hooks from polluting direct admin/ajax/rest handlers.
		ctx.EntryPoints = uniqueEntryPoints(direct)
		ctx.Access = deriveAccess(ctx)
	}
	if !hasMeaningfulFlowContext(ctx) || ctx.Access == "unknown" {
		ctx = mergeOptionalFlowContext(ctx, s.engine.reverseCallerContext(s.current.Key))
		ctx = mergeOptionalFlowContext(ctx, s.contextOverride)
	}
	// Resolve capability to minimum WordPress role for bounty triage.
	resolveCapabilityAndRole(&ctx)
	return ctx
}

func (s *analysisState) annotateStoredWriteOrigins(origins originSet) originSet {
	ctx := s.currentContext()
	if len(origins) == 0 || !hasMeaningfulFlowContext(ctx) {
		return origins
	}
	return applyStoredWriteContext(origins, ctx)
}

func applyStoredWriteContext(origins originSet, ctx FlowContext) originSet {
	if len(origins) == 0 || !hasMeaningfulFlowContext(ctx) {
		return origins
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		item.storedWriteContext = mergeOptionalFlowContext(item.storedWriteContext, ctx)
		out[originKey(item)] = item
	}
	return out
}

func (e *engine) reverseCallerContext(key string) FlowContext {
	out := FlowContext{}
	for callerKey := range e.reverseCallEdges[key] {
		callerCtx := e.contexts[callerKey]
		if !hasMeaningfulFlowContext(callerCtx) {
			continue
		}
		out = mergeOptionalFlowContext(out, callerCtx)
	}
	return out
}

func (e *engine) callableKeyForDisplay(display string) string {
	display = strings.TrimSpace(display)
	if display == "" {
		return ""
	}
	if strings.Contains(display, "::") {
		parts := strings.SplitN(display, "::", 2)
		if len(parts) == 2 {
			return e.lookupMethodKey(parts[0], parts[1])
		}
	}
	if key, ok := e.functions[normalizeName(display)]; ok {
		return key
	}
	if !strings.HasPrefix(display, `\`) {
		if key, ok := e.functions[normalizeName(`\`+display)]; ok {
			return key
		}
	}
	return ""
}

func replayedTemplateGuardContext(ctx FlowContext) FlowContext {
	ctx.EntryPoints = nil
	ctx.Access = ""
	return normalizeFlowContext(ctx)
}

func (e *engine) callableDirectContext(display string, fallback FlowContext) (FlowContext, bool) {
	if key := e.callableKeyForDisplay(display); key != "" {
		if c, ok := e.callables[key]; ok {
			if direct := e.directEntryPointsByCallable[key]; len(direct) != 0 {
				ctx := e.inspectCallableContext(c)
				ctx.EntryPoints = uniqueEntryPoints(direct)
				ctx.Access = deriveAccess(ctx)
				return normalizeFlowContext(ctx), true
			}
		}
	}
	if len(fallback.EntryPoints) != 0 {
		return normalizeFlowContext(fallback), true
	}
	return FlowContext{}, false
}

func (e *engine) callableLocalGuardContext(display string, fallback FlowContext) FlowContext {
	if key := e.callableKeyForDisplay(display); key != "" {
		if c, ok := e.callables[key]; ok {
			return replayedTemplateGuardContext(e.inspectCallableContext(c))
		}
	}
	return replayedTemplateGuardContext(fallback)
}

func (e *engine) callableHasRecordRead(key string) bool {
	_, ok := e.recordReadCallables[key]
	return ok
}

func (s *analysisState) addSinkFindings(ruleID string, message string, origins originSet, sink Location, context FlowContext) {
	for _, item := range origins.sorted() {
		switch item.kind {
		case originSource, originContainer:
			record := findingRecord{
				RuleID:   ruleID,
				Message:  message,
				Source:   item.source,
				Sink:     sink,
				Callable: s.current.Display,
				Context:  context,
			}
			if hasMeaningfulFlowContext(item.storedWriteContext) && !flowContextsEquivalent(item.storedWriteContext, context) {
				record.StoredWriteContext = item.storedWriteContext
			}
			if existing, ok := s.sourceHits[findingRecordKey(record)]; ok {
				record.Context = mergeFlowContext(existing.Context, record.Context)
				record.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, record.StoredWriteContext)
			}
			s.sourceHits[findingRecordKey(record)] = record
		case originParam:
			templates := s.paramSinks[item.paramIdx]
			if templates == nil {
				templates = map[string]sinkTemplate{}
				s.paramSinks[item.paramIdx] = templates
			}
			template := sinkTemplate{
				RuleID:             ruleID,
				Message:            message,
				Sink:               sink,
				Callable:           s.current.Display,
				Context:            context,
				StoredWriteContext: item.storedWriteContext,
				ParamPath:          item.paramPath,
			}
			key := sinkTemplateKey(template) + "|" + item.paramPath
			if existing, ok := templates[key]; ok {
				template.Context = mergeFlowContext(existing.Context, template.Context)
				template.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, template.StoredWriteContext)
			}
			templates[key] = template
		case originReceiver:
			template := sinkTemplate{
				RuleID:             ruleID,
				Message:            message,
				Sink:               sink,
				Callable:           s.current.Display,
				Context:            context,
				StoredWriteContext: item.storedWriteContext,
				ReceiverPath:       item.receiverPath,
			}
			key := sinkTemplateKey(template)
			if existing, ok := s.receiverSinks[key]; ok {
				template.Context = mergeFlowContext(existing.Context, template.Context)
				template.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, template.StoredWriteContext)
			}
			s.receiverSinks[key] = template
		}
	}
}

func (s *analysisState) addRecordDisclosureFinding(origins originSet, sink Location) {
	if !s.engine.allowsSinkOp("output") {
		return
	}
	if !s.hasRecordRead {
		return
	}
	context := s.currentContext()
	if definitelyCapabilityGuarded(context) {
		return
	}
	s.addSinkFindings("wp-request-record-read-to-output-without-cap-check", requestRecordOutputMessage, origins, sink, context)
}

func (s *analysisState) addPersistentOutputFinding(origins originSet, sink Location) {
	if !s.engine.allowsSinkOp("output") {
		return
	}
	unsafeOrigins := unsafePersistentReadOrigins(origins)
	if len(unsafeOrigins) != 0 {
		s.addSinkFindings("wp-stored-xss-persistent-read-to-output", storedXSSOutputMessage, unsafeOrigins, sink, s.currentContext())
		return
	}
	if placeholders := replayablePersistentOutputOrigins(origins); len(placeholders) != 0 {
		s.addSinkFindings("wp-stored-xss-persistent-read-to-output", storedXSSOutputMessage, placeholders, sink, s.currentContext())
	}
}

// reflectedOutputOrigins keeps only origins eligible for a reflected-XSS
// finding: direct request taint that has NOT been routed through an
// output-safe escaper (esc_html/esc_attr/wp_kses/numeric cast) and is NOT a
// persistent-store read (those belong to the stored-XSS path).
func reflectedOutputOrigins(origins originSet) originSet {
	out := originSet{}
	for key, item := range origins {
		if item.persistentRead || item.outputSafeHTML {
			continue
		}
		// Numeric-coerced values (intval/absint/(int)...) cannot carry HTML/JS
		// metacharacters, so they are not reflected XSS even though they remain
		// attacker-controlled for IDOR/stored sinks.
		if item.numericSafe {
			continue
		}
		// Origins routed through a persistent store are stored XSS, emitted by
		// addPersistentOutputFinding; keep the reflected path to truly direct
		// (non-persisted) request->output flows.
		if hasMeaningfulFlowContext(item.storedWriteContext) {
			continue
		}
		out[key] = item
	}
	return out
}

// addReflectedRequestOutputFinding emits wp-reflected-xss-direct-request-output
// when request-controlled data reaches an HTML output sink (echo/print/printf)
// without an output-safe boundary. Capability gating is intentionally NOT
// applied here (mirroring the stored-XSS output path); exploitability is
// expressed through the finding's access context for triage ranking.
func (s *analysisState) addReflectedRequestOutputFinding(origins originSet, sink Location) {
	if !s.engine.allowsSinkOp("output") {
		return
	}
	// Record-read callables route request-derived output through the more
	// specific disclosure rule (wp-request-record-read-to-output-without-cap-check),
	// which already covers this sink; avoid emitting a duplicate reflected
	// finding for the same flow.
	if s.hasRecordRead {
		return
	}
	reflected := reflectedOutputOrigins(origins)
	if len(reflected) == 0 {
		return
	}
	s.addSinkFindings("wp-reflected-xss-direct-request-output", reflectedXSSOutputMessage, reflected, sink, s.currentContext())
}

func (s *analysisState) addUnauthorizedFileUploadFinding(origins originSet, sink Location) {
	context := s.currentContext()
	if definitelyCapabilityGuarded(context) {
		return
	}
	s.addSinkFindings("wp-request-file-upload-without-cap-check", requestFileUploadMessage, origins, sink, context)
}

func (s *analysisState) addUnauthorizedFileDeleteFinding(origins originSet, sink Location) bool {
	context := s.currentContext()
	if definitelyCapabilityGuarded(context) || context.Access == "unknown" {
		return false
	}
	s.addSinkFindings("wp-request-file-delete-without-cap-check", requestFileDeleteMessage, origins, sink, context)
	return true
}

func (s *analysisState) addUnauthorizedActionFinding(ruleID, message string, origins originSet, sink Location) bool {
	context := s.currentContext()
	if definitelyCapabilityGuardedForAction(context) {
		return false
	}
	s.addSinkFindings(ruleID, message, origins, sink, context)
	return true
}

func (s *analysisState) addUnauthorizedSensitiveActionFinding(origins originSet, sink Location) bool {
	return s.addUnauthorizedActionFinding("wp-request-sensitive-action-without-cap-check", requestSensitiveActionMessage, origins, sink)
}

func (s *analysisState) locationForNode(node ast.Node) Location {
	loc := Location{
		Path: s.current.SourcePath,
	}
	if node == nil {
		loc.Line = s.current.StartLine
		return loc
	}
	loc.Line = node.StartLine()
	file := s.engine.fileIndex[s.current.SourcePath]
	if loc.Line >= 1 && loc.Line <= len(file.Lines) {
		loc.Snippet = strings.TrimSpace(file.Lines[loc.Line-1])
	}
	return loc
}

func originsHaveUnsafePersistentRead(origins originSet) bool {
	return len(unsafePersistentReadOrigins(origins)) != 0
}

func unsafePersistentReadOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := originSet{}
	for _, item := range origins {
		if !(item.persistentRead || hasMeaningfulFlowContext(item.storedWriteContext)) {
			continue
		}
		if item.outputUnsafeHTML || !item.outputSafeHTML {
			out[originKey(item)] = item
		}
	}
	return out
}

func replayablePersistentOutputOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := originSet{}
	for _, item := range origins {
		if item.outputSafeHTML && !item.outputUnsafeHTML {
			continue
		}
		switch item.kind {
		case originParam, originReceiver:
			out[originKey(item)] = item
		}
	}
	return out
}

func flowContextReturnsPublicMarkup(ctx FlowContext) bool {
	for _, entry := range ctx.EntryPoints {
		switch entry.Kind {
		case "shortcode", "block":
			return true
		}
	}
	return false
}

func engineCallableReturnsPublicMarkup(e *engine, key string) bool {
	if _, ok := e.directPublicCallables[key]; ok {
		return true
	}
	for _, entry := range e.directEntryPointsByCallable[key] {
		switch entry.Kind {
		case "shortcode", "block":
			return true
		}
	}
	return false
}

func (s *analysisState) currentCallableReturnsPublicMarkup() bool {
	if _, ok := s.engine.directPublicCallables[s.current.Key]; ok {
		return true
	}
	for _, entry := range s.engine.directEntryPointsByCallable[s.current.Key] {
		switch entry.Kind {
		case "shortcode", "block":
			return true
		}
	}
	return false
}

func (s *analysisState) resolveFunctionKey(node ast.Node) string {
	name := identifierText(node)
	if strings.TrimSpace(name) == "" {
		return ""
	}
	return s.engine.lookupFunctionKey(s.current.Namespace, name)
}

func (s *analysisState) resolveFunctionKeyWithArgs(node ast.Node, args []ast.Node) string {
	key := s.resolveFunctionKey(node)
	if key == "" {
		return ""
	}
	return s.engine.maybeSpecializeCallableForLiteralArgsAndPaths(
		key,
		literalArgHintsForArgsWithEnv(args, s.current, s.engine, s.stringEnv),
		literalArgPathHintsForArgsWithEnv(args, s.current, s.engine, s.stringEnv, 0, nil),
	)
}

func (s *analysisState) resolveMethodKey(className string, methodName string) string {
	if className == "" || methodName == "" {
		return ""
	}
	seen := map[string]struct{}{}
	current := className
	for current != "" {
		if _, ok := seen[current]; ok {
			break
		}
		seen[current] = struct{}{}
		if methods := s.engine.methods[current]; methods != nil {
			if key, ok := methods[strings.ToLower(methodName)]; ok {
				return key
			}
		}
		current = s.engine.classParents[current]
	}
	return ""
}

func (s *analysisState) resolveMethodKeyWithArgs(className string, methodName string, args []ast.Node) string {
	key := s.resolveMethodKey(className, methodName)
	if key == "" {
		return ""
	}
	return s.engine.maybeSpecializeCallableForLiteralArgsAndPaths(
		key,
		literalArgHintsForArgsWithEnv(args, s.current, s.engine, s.stringEnv),
		literalArgPathHintsForArgsWithEnv(args, s.current, s.engine, s.stringEnv, 0, nil),
	)
}

func (e *engine) lookupMethodKeysByPattern(className string, prefix string, suffix string) []string {
	if className == "" {
		return nil
	}
	seenClasses := map[string]struct{}{}
	seenKeys := map[string]struct{}{}
	out := make([]string, 0, 4)
	current := className
	for current != "" {
		if _, ok := seenClasses[current]; ok {
			break
		}
		seenClasses[current] = struct{}{}
		if methods := e.methods[current]; methods != nil {
			for methodName, key := range methods {
				if prefix != "" && !strings.HasPrefix(methodName, prefix) {
					continue
				}
				if suffix != "" && !strings.HasSuffix(methodName, suffix) {
					continue
				}
				if _, ok := seenKeys[key]; ok {
					continue
				}
				seenKeys[key] = struct{}{}
				out = append(out, key)
			}
		}
		current = e.classParents[current]
	}
	sort.Strings(out)
	return out
}

func (e *engine) lookupClassesByPattern(prefix string, suffix string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	for className := range e.methods {
		if className == "" {
			continue
		}
		if prefix != "" && !strings.HasPrefix(className, prefix) {
			continue
		}
		if suffix != "" && !strings.HasSuffix(className, suffix) {
			continue
		}
		if _, ok := seen[className]; ok {
			continue
		}
		seen[className] = struct{}{}
		out = append(out, className)
	}
	sort.Strings(out)
	return out
}

func (s *analysisState) clone() analysisState {
	return s.cloneWith(cloneVarMap(s.varTaint), cloneVarMap(s.propTaint), cloneVarMap(s.staticPropTaint), cloneStringMap(s.classEnv), cloneStringMap(s.stringEnv))
}

func (s *analysisState) cloneWith(vars map[string]originSet, props map[string]originSet, staticProps map[string]originSet, classes map[string]string, stringsEnv map[string]string) analysisState {
	return analysisState{
		engine:                  s.engine,
		current:                 s.current,
		contextOverride:         s.contextOverride,
		varTaint:                vars,
		propTaint:               props,
		staticPropTaint:         staticProps,
		classEnv:                classes,
		stringEnv:               stringsEnv,
		weakIdentifierEnv:       cloneWeakIdentifierMap(s.weakIdentifierEnv),
		safePathVars:            cloneStringSet(s.safePathVars),
		safePathExprSigs:        cloneStringSet(s.safePathExprSigs),
		varPathExprSig:          cloneStringMap(s.varPathExprSig),
		extractContainers:       append([]ast.Node(nil), s.extractContainers...),
		activeExtractResolves:   cloneStringSet(s.activeExtractResolves),
		sourceHits:              map[string]findingRecord{},
		paramSinks:              map[int]map[string]sinkTemplate{},
		receiverSinks:           map[string]sinkTemplate{},
		returnValue:             originSet{},
		returnPathWrites:        cloneVarMap(s.returnPathWrites),
		returnClasses:           cloneStringSet(s.returnClasses),
		receiverWrites:          cloneVarMap(s.receiverWrites),
		receiverStorageLinks:    cloneStringMap(s.receiverStorageLinks),
		structuralStorageLinks:  cloneStringMap(s.structuralStorageLinks),
		storageWrites:           cloneVarMap(s.storageWrites),
		storagePathWrites:       cloneVarMap(s.storagePathWrites),
		hasRecordRead:           s.hasRecordRead,
		includeStack:            cloneStringSet(s.includeStack),
		summaryWarmCache:        s.summaryWarmCache,
		summaryWarmStack:        cloneStringSet(s.summaryWarmStack),
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}
}

func cloneWeakIdentifierMap(src map[string]weakIdentifierHint) map[string]weakIdentifierHint {
	if len(src) == 0 {
		return map[string]weakIdentifierHint{}
	}
	out := make(map[string]weakIdentifierHint, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func mergeNodeSlices(dst []ast.Node, src []ast.Node) []ast.Node {
	if len(src) == 0 {
		return dst
	}
	if len(dst) == 0 {
		return append([]ast.Node(nil), src...)
	}
	out := append([]ast.Node(nil), dst...)
	out = append(out, src...)
	return out
}

func mergeWeakIdentifierMaps(dst map[string]weakIdentifierHint, src map[string]weakIdentifierHint) map[string]weakIdentifierHint {
	if len(dst) == 0 {
		return cloneWeakIdentifierMap(src)
	}
	if len(src) == 0 {
		return dst
	}
	out := cloneWeakIdentifierMap(dst)
	for key, value := range src {
		if existing, ok := out[key]; ok {
			out[key] = mergeWeakIdentifierHint(existing, value)
			continue
		}
		out[key] = value
	}
	return out
}

func (s *analysisState) mergeFindingsFrom(other analysisState) {
	for key, record := range other.sourceHits {
		if existing, ok := s.sourceHits[key]; ok {
			record.Context = mergeFlowContext(existing.Context, record.Context)
			record.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, record.StoredWriteContext)
		}
		s.sourceHits[key] = record
	}
	for idx, items := range other.paramSinks {
		target := s.paramSinks[idx]
		if target == nil {
			target = map[string]sinkTemplate{}
			s.paramSinks[idx] = target
		}
		for key, item := range items {
			if existing, ok := target[key]; ok {
				item.Context = mergeFlowContext(existing.Context, item.Context)
			}
			target[key] = item
		}
	}
	for key, item := range other.receiverSinks {
		if existing, ok := s.receiverSinks[key]; ok {
			item.Context = mergeFlowContext(existing.Context, item.Context)
			item.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, item.StoredWriteContext)
		}
		s.receiverSinks[key] = item
	}
}

func buildBaseEngineForSinkOps(target string, files []sourceFile, allowedSinkOps map[string]struct{}) (*engine, error) {
	timingsEnabled := taintscanTimingsEnabled()
	phaseStart := time.Now()
	logPhase := func(label string) {
		logTiming(timingsEnabled, "build-base:"+label, time.Since(phaseStart))
		phaseStart = time.Now()
	}
	e := &engine{
		target:                          target,
		files:                           files,
		localArrayResolvers:             &sync.Map{},
		heapGauge:                       new(atomic.Uint64),
		fileIndex:                       map[string]sourceFile{},
		callables:                       map[string]callable{},
		functions:                       map[string]string{},
		methods:                         map[string]map[string]string{},
		classParents:                    map[string]string{},
		staticPropOwners:                map[string]map[string]string{},
		literalClassIndex:               map[string][]string{},
		literalClassProperties:          map[string]string{},
		specializedLiteralCallables:     map[string]map[string]string{},
		literalGlobalConsts:             map[string]string{},
		literalClassConsts:              map[string]string{},
		directReturnHints:               map[string]string{},
		directReturnPropertyHints:       map[string]string{},
		literalArgHints:                 map[string]map[int]string{},
		literalArgPathHints:             map[string]map[int]map[string]string{},
		receiverPropertyClassHints:      map[string][]string{},
		receiverPropertyFallbackHints:   map[string]classHintCandidatesCacheEntry{},
		statementGuardWeakAuthCache:     map[string]locationCacheEntry{},
		callableReceiverPropertyClasses: map[string]map[string][]string{},
		receiverPropertyEntryClassHints: map[string][]string{},
		callableArrayEntryClassHints:    map[string][]string{},
		receiverMutatingCallables:       map[string]struct{}{},
		summaries:                       map[string]summary{},
		contexts:                        map[string]FlowContext{},
		staticProps:                     map[string]originSet{},
		storage:                         map[string]originSet{},
		storagePaths:                    map[string]originSet{},
		callEdges:                       map[string]map[string]struct{}{},
		dataCallEdges:                   map[string]map[string]struct{}{},
		callSiteEdges:                   map[string][]callSiteEdge{},
		reverseCallEdges:                map[string]map[string]struct{}{},
		storageReadFamiliesByCallable:   map[string]map[string]struct{}{},
		storageReadBucketsByCallable:    map[string]map[string]struct{}{},
		directStorageWriterCallables:    map[string]struct{}{},
		storageBaseReadersByFamily:      map[string]map[string]struct{}{},
		storagePathReadersByExact:       map[string]map[string]struct{}{},
		storagePathReadersByBucket:      map[string]map[string]struct{}{},
		storageBaseWritersByFamily:      map[string]map[string]struct{}{},
		storageBaseWritersByFamilyClass: map[string]map[string]struct{}{},
		storagePathWritersByBucket:      map[string]map[string]struct{}{},
		storagePathWritersByBucketClass: map[string]map[string]struct{}{},
		staticReadRootsByCallable:       map[string]map[string]struct{}{},
		staticReadPathsByCallable:       map[string]map[string]struct{}{},
		staticBaseReadersByRoot:         map[string]map[string]struct{}{},
		staticPathReadersByExact:        map[string]map[string]struct{}{},
		staticPathReadersByBucket:       map[string]map[string]struct{}{},
		directPublicCallables:           map[string]struct{}{},
		directEntryPointsByCallable:     map[string][]EntryPoint{},
		requestReachableCallables:       map[string]struct{}{},
		requestOriginReachableCallables: map[string]struct{}{},
		relevantCallables:               map[string]struct{}{},
		recordReadCallables:             map[string]struct{}{},
		callSinkRelevantUseOrders:       map[string]map[string]int{},
		callSinkRelevantUsePaths:        map[string]map[string]map[string]int{},
		callInputConsumingCallables:     map[string]bool{},
		outputSinkRelevantUseOrders:     map[string]map[string]int{},
		outputSinkRelevantUsePaths:      map[string]map[string]map[string]int{},
		sqlSinkRelevantUseOrders:        map[string]map[string]int{},
		actionSinkRelevantUseOrders:     map[string]map[string]int{},
		actionSinkRelevantUsePaths:      map[string]map[string]map[string]int{},
		fileSinkRelevantUseOrders:       map[string]map[string]int{},
		fileSinkRelevantUsePaths:        map[string]map[string]map[string]int{},
		includeSinkRelevantUseOrders:    map[string]map[string]int{},
		includeSinkRelevantUsePaths:     map[string]map[string]map[string]int{},
		actionCallbacks:                 map[string][]string{},
		filterCallbacks:                 map[string][]string{},
		summaryFingerprints:             map[string]string{},
		summaryInputFingerprints:        map[string]string{},
		storageStateFingerprints:        map[string]string{},
		storagePathStateFingerprints:    map[string]string{},
		staticStateFingerprints:         map[string]string{},
		allowedSinkOps:                  cloneStringSet(allowedSinkOps),
		timingsEnabled:                  timingsEnabled,
	}
	for _, file := range files {
		e.fileIndex[file.Relative] = file
		for _, root := range topLevelCallable(file) {
			e.addCallable(root)
		}
		for _, fn := range collectFunctionCallables(file.AST, "", file.Relative, nil) {
			e.addCallable(fn)
		}
		for _, method := range collectMethodCallables(file.AST, "", file.Relative, nil) {
			e.addCallable(method)
		}
		for _, parent := range collectClassParents(file.AST, "", file.Relative, nil) {
			e.classParents[parent.class] = parent.parent
		}
		for _, decl := range collectStaticPropertyDecls(file.AST, "", file.Relative) {
			props := e.staticPropOwners[decl.class]
			if props == nil {
				props = map[string]string{}
				e.staticPropOwners[decl.class] = props
			}
			props[decl.property] = decl.class
		}
		for _, prop := range collectClassLiteralProperties(file.AST, "", file.Relative) {
			e.indexLiteralClass(prop.class, prop.property, prop.value)
		}
	}
	logPhase("index-callables-and-literals")
	for pass := 0; pass < 8; pass++ {
		changed := false
		for _, file := range files {
			if e.indexLiteralGlobalConsts(file.AST, "", file.Relative) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	logPhase("index-literal-global-consts")
	for pass := 0; pass < 8; pass++ {
		changed := false
		for _, file := range files {
			if e.indexLiteralClassConsts(file.AST, "", file.Relative) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	logPhase("index-literal-class-consts")
	for pass := 0; pass < 8; pass++ {
		changed := false
		for _, file := range files {
			if e.indexLiteralStaticPropertyAssignments(file.AST, "", "", file.Relative) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	logPhase("index-literal-static-props")
	sort.Strings(e.callOrder)
	logPhase("sort-call-order")
	e.indexReceiverMutatingCallables()
	logPhase("index-receiver-mutating-callables")
	e.buildDirectReturnHints()
	logPhase("build-direct-return-hints")
	e.indexDirectReturnPropertyHints()
	logPhase("index-direct-return-property-hints")
	e.indexReceiverPropertyReturnClassHints()
	logPhase("index-receiver-property-class-hints")
	e.indexCallableReceiverPropertyClassHints()
	logPhase("index-callable-receiver-property-class-hints")
	e.indexLiteralArgHints()
	logPhase("index-literal-arg-hints")
	e.indexAllCallbackRegistrations()
	logPhase("index-all-callback-registrations")
	e.buildCallGraph()
	logPhase("build-call-graph")
	e.topologicalSortCallOrder()
	logPhase("topological-sort-call-order")
	e.indexGlobalStateReaders()
	logPhase("index-global-state-readers")
	e.indexRecordReadCallables()
	logPhase("index-record-read-callables")
	if needsCallRelevanceIndexForSinkOps(allowedSinkOps) {
		e.indexCallSinkRelevantUseOrders()
		logPhase("index-call-sink-relevant-use-orders")
		e.indexCallInputConsumingCallables()
		logPhase("index-call-input-consuming-callables")
	}
	if needsSQLRelevanceIndexForSinkOps(allowedSinkOps) {
		e.indexSQLSinkRelevantUseOrders()
		logPhase("index-sql-sink-relevant-use-orders")
	}
	if needsActionRelevanceIndexForSinkOps(allowedSinkOps) {
		e.indexActionSinkRelevantUseOrders()
		logPhase("index-action-sink-relevant-use-orders")
	}
	if needsFileRelevanceIndexForSinkOps(allowedSinkOps) {
		e.indexFileSinkRelevantUseOrders()
		logPhase("index-file-sink-relevant-use-orders")
		e.indexIncludeSinkRelevantUseOrders()
		logPhase("index-include-sink-relevant-use-orders")
	}
	return e, nil
}

func buildBaseEngine(target string, files []sourceFile) (*engine, error) {
	return buildBaseEngineForSinkOps(target, files, nil)
}

func cloneEngineForOptions(base *engine, options Options) *engine {
	e := *base
	e.summaries = map[string]summary{}
	e.staticProps = map[string]originSet{}
	e.storage = map[string]originSet{}
	e.storagePaths = map[string]originSet{}
	e.contexts = map[string]FlowContext{}
	e.directPublicCallables = map[string]struct{}{}
	e.directEntryPointsByCallable = map[string][]EntryPoint{}
	e.requestReachableCallables = map[string]struct{}{}
	e.requestOriginReachableCallables = map[string]struct{}{}
	e.relevantCallables = map[string]struct{}{}
	if needsSQLRelevanceIndexForSinkOps(e.allowedSinkOps) {
		e.sqlSinkRelevantUseOrders = map[string]map[string]int{}
	} else {
		e.sqlSinkRelevantUseOrders = nil
	}
	if needsFileRelevanceIndexForSinkOps(e.allowedSinkOps) {
		e.fileSinkRelevantUseOrders = map[string]map[string]int{}
		e.fileSinkRelevantUsePaths = map[string]map[string]map[string]int{}
		e.includeSinkRelevantUseOrders = map[string]map[string]int{}
		e.includeSinkRelevantUsePaths = map[string]map[string]map[string]int{}
	} else {
		e.fileSinkRelevantUseOrders = nil
		e.fileSinkRelevantUsePaths = nil
		e.includeSinkRelevantUseOrders = nil
		e.includeSinkRelevantUsePaths = nil
	}
	e.summaryFingerprints = map[string]string{}
	e.summaryInputFingerprints = map[string]string{}
	e.storageStateFingerprints = map[string]string{}
	e.storagePathStateFingerprints = map[string]string{}
	e.staticStateFingerprints = map[string]string{}
	e.directStorageWriterCallables = cloneStringSet(base.directStorageWriterCallables)
	e.allowedSinkOps = cloneStringSet(options.AllowedSinkOps)
	e.maxPasses = options.MaxPasses
	e.timingsEnabled = false
	e.instrumentationEnabled = options.Instrumentation
	e.currentBatchName = batchNameForAllowedOps(e.allowedSinkOps)
	if needsStorageWriterIndexForSinkOps(e.allowedSinkOps) {
		e.storageBaseWritersByFamily = map[string]map[string]struct{}{}
		e.storageBaseWritersByFamilyClass = map[string]map[string]struct{}{}
		e.storagePathWritersByBucket = map[string]map[string]struct{}{}
		e.storagePathWritersByBucketClass = map[string]map[string]struct{}{}
		e.indexGlobalStateWriters()
	} else if len(e.allowedSinkOps) == 1 {
		switch {
		case e.allowsSinkOp("action"), e.allowsSinkOp("call"):
			// Pure action/call batches can start with direct writer markers and
			// lazily build the heavier cross-request writer index only if a later
			// relevance step actually demands it.
			e.storageBaseWritersByFamily = nil
			e.storageBaseWritersByFamilyClass = nil
			e.storagePathWritersByBucket = nil
			e.storagePathWritersByBucketClass = nil
			if len(e.directStorageWriterCallables) == 0 {
				e.indexDirectStorageWriterCallables()
			}
		default:
			e.storageBaseWritersByFamily = map[string]map[string]struct{}{}
			e.storageBaseWritersByFamilyClass = map[string]map[string]struct{}{}
			e.storagePathWritersByBucket = map[string]map[string]struct{}{}
			e.storagePathWritersByBucketClass = map[string]map[string]struct{}{}
		}
	} else {
		e.storageBaseWritersByFamily = map[string]map[string]struct{}{}
		e.storageBaseWritersByFamilyClass = map[string]map[string]struct{}{}
		e.storagePathWritersByBucket = map[string]map[string]struct{}{}
		e.storagePathWritersByBucketClass = map[string]map[string]struct{}{}
	}
	e.collectWordPressFlowContext()
	if needsOutputRelevanceIndexForSinkOps(e.allowedSinkOps) {
		e.indexOutputSinkRelevantUseOrders()
	}
	if needsSQLRelevanceIndexForSinkOps(e.allowedSinkOps) {
		e.indexSQLSinkRelevantUseOrders()
	}
	if needsFileRelevanceIndexForSinkOps(e.allowedSinkOps) {
		e.indexFileSinkRelevantUseOrders()
		e.indexIncludeSinkRelevantUseOrders()
	}
	e.indexRequestReachableCallables()
	e.indexRequestOriginReachableCallables()
	e.markRelevantCallables()
	return &e
}

func needsStorageWriterIndexForSinkOps(allowedSinkOps map[string]struct{}) bool {
	if len(allowedSinkOps) == 1 {
		_, writeOnly := allowedSinkOps["write"]
		_, surfaceOnly := allowedSinkOps["surface"]
		_, actionOnly := allowedSinkOps["action"]
		_, callOnly := allowedSinkOps["call"]
		return !writeOnly && !surfaceOnly && !actionOnly && !callOnly
	}
	return true
}

func needsCallRelevanceIndexForSinkOps(allowedSinkOps map[string]struct{}) bool {
	if len(allowedSinkOps) == 0 {
		return true
	}
	_, ok := allowedSinkOps["call"]
	return ok
}

func needsSQLRelevanceIndexForSinkOps(allowedSinkOps map[string]struct{}) bool {
	if len(allowedSinkOps) == 0 {
		return true
	}
	_, ok := allowedSinkOps["sql"]
	return ok
}

func needsOutputRelevanceIndexForSinkOps(allowedSinkOps map[string]struct{}) bool {
	if len(allowedSinkOps) == 0 {
		return true
	}
	_, ok := allowedSinkOps["output"]
	return ok
}

func needsActionRelevanceIndexForSinkOps(allowedSinkOps map[string]struct{}) bool {
	if len(allowedSinkOps) == 0 {
		return true
	}
	_, ok := allowedSinkOps["action"]
	return ok
}

func needsFileRelevanceIndexForSinkOps(allowedSinkOps map[string]struct{}) bool {
	if len(allowedSinkOps) == 0 {
		return true
	}
	for op := range allowedSinkOps {
		switch op {
		case "delete", "read", "open", "include", "write":
			return true
		}
	}
	return false
}

func buildEngine(target string, files []sourceFile, options Options) (*engine, error) {
	base, err := buildBaseEngineForSinkOps(target, files, options.AllowedSinkOps)
	if err != nil {
		return nil, err
	}
	return cloneEngineForOptions(base, options), nil
}
