package taintscan

import (
	"strconv"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

const broadDynamicCallbackReplayCap = 32
const broadStaticCallbackReplayCap = 64

func shouldSkipBroadCallbackReplay(batchName, hook string, keys []string) bool {
	if batchName != "call" {
		return false
	}
	if len(keys) == 0 {
		return false
	}
	if !strings.Contains(hook, "{") {
		return len(keys) > broadStaticCallbackReplayCap
	}
	if len(keys) <= broadDynamicCallbackReplayCap {
		return false
	}
	start := strings.Index(hook, "{")
	if start <= 0 || strings.TrimSpace(hook[:start]) == "" {
		return false
	}
	end := strings.LastIndex(hook, "}")
	if end == -1 || end < start {
		return false
	}
	return strings.TrimSpace(hook[end+1:]) == ""
}

// isDynamicCallNameExpr reports whether a call/method/class name is a runtime
// value expression (variable, array element, property) rather than a literal
// identifier — i.e. dynamic dispatch.
func isDynamicCallNameExpr(node ast.Node) bool {
	switch node.(type) {
	case *ast.ExprVariable, *ast.ExprArrayDimFetch, *ast.ExprPropertyFetch, *ast.ExprStaticPropertyFetch:
		return true
	default:
		return false
	}
}

// emitDynamicCallNameFinding flags request-controlled dynamic dispatch (a
// tainted callable/method/class name reaching native `$x(...)` / `$o->$m(...)` /
// `new $c(...)`) as an unsafe-use code-execution sink, gated on the call sink op
// and the absence of a capability check (mirroring the call_user_func model).
func (s *analysisState) emitDynamicCallNameFinding(nameExpr ast.Node, sink Location) {
	if !s.engine.allowsSinkOp("call") || !isDynamicCallNameExpr(nameExpr) {
		return
	}
	nameOrigins := s.evalExpr(nameExpr)
	if len(nameOrigins) == 0 {
		return
	}
	context := s.currentContext()
	if len(context.CapabilityChecks) != 0 {
		return
	}
	s.addSinkFindings("unsafe-use", unsafeUseMessage, nameOrigins, sink, context)
}

func (s *analysisState) evalFuncCall(call *ast.ExprFuncCall) originSet {
	if closure, ok := call.Name.(*ast.ExprClosure); ok {
		return s.evalInlineClosureCall(closure, call.Args)
	}
	name := normalizeName(identifierText(call.Name))
	args := s.evalArgs(call.Args)
	if name == "" {
		// Native dynamic dispatch: $func(...), $arr['cb'](...), $this->cb(...).
		// An attacker-controlled callable name is a code-execution / arbitrary-
		// method primitive (the classic AJAX-router / webshell pattern).
		s.emitDynamicCallNameFinding(call.Name, s.locationForNode(call))
	}
	if origins, ok := surfaceSecretConfigReadOriginsForFuncCall(name, call, s); ok {
		return origins
	}
	s.addIssuedAuthLinkSurfaceFindingForFuncCall(call, name)
	recordReadOrigins := originSet{}
	if s.engine.allowsSinkOp("output") {
		recordReadOrigins = recordReadSelectorOrigins(name, args)
	}
	if name == "register_rest_route" && s.engine.allowsSinkOp("surface") && len(call.Args) > 2 && restRouteShowsInIndex(argValue(call.Args[2])) {
		if origins := args[0].union(args[1]); len(origins) != 0 {
			s.addSinkFindings("wp-rest-public-data-disclosure-surface", restPublicDataDisclosureMessage, origins, s.locationForNode(call), s.currentContext())
		}
	}
	if (name == "do_action" || name == "do_action_ref_array") && len(call.Args) > 0 {
		hook := hookDispatchKeyForCallable(argValue(call.Args[0]), s.current, s.engine)
		payloadArgs := args[1:]
		payloadNodes := sliceArgValues(call.Args[1:])
		if name == "do_action_ref_array" {
			payloadArgs, payloadNodes, _ = s.evalRefArrayArgs(call.Args, 1)
		}
		keys := s.engine.dispatchRelevantCallbackKeys(name, hook)
		if shouldSkipBroadCallbackReplay(s.engine.currentBatchName, hook, keys) {
			return originSet{}
		}
		for _, key := range keys {
			if key == s.current.Key {
				continue
			}
			summary := s.summaryForKey(key)
			s.instantiateSummaryReturnWithOptions(
				key,
				payloadArgs,
				payloadNodes,
				"",
				true,
				s.allowCurrentBatchStateSideEffectsForCallbackReplay(key, summary, payloadArgs),
				call.StartLine(),
			)
		}
		return originSet{}
	}
	if (name == "apply_filters" || name == "apply_filters_ref_array") && len(call.Args) > 1 {
		hook := hookDispatchKeyForCallable(argValue(call.Args[0]), s.current, s.engine)
		current := args[1]
		extraArgs := args[2:]
		valueNode := argValue(call.Args[1])
		extraNodes := sliceArgValues(call.Args[2:])
		if name == "apply_filters_ref_array" {
			refArgs, refNodes, ok := s.evalRefArrayArgs(call.Args, 1)
			if ok && len(refArgs) > 0 {
				current = refArgs[0]
				valueNode = refNodes[0]
				if len(refArgs) > 1 {
					extraArgs = refArgs[1:]
					extraNodes = refNodes[1:]
				} else {
					extraArgs = nil
					extraNodes = nil
				}
			}
		}
		if hook == "" {
			return unionAll(args[1:]).union(recordReadOrigins)
		}
		keys := s.engine.dispatchRelevantCallbackKeys(name, hook)
		if shouldSkipBroadCallbackReplay(s.engine.currentBatchName, hook, keys) {
			return current.union(recordReadOrigins)
		}
		for _, key := range keys {
			if key == s.current.Key {
				continue
			}
			callbackArgs := make([]originSet, 0, 1+len(extraArgs))
			callbackArgs = append(callbackArgs, current)
			callbackArgs = append(callbackArgs, extraArgs...)
			callbackNodes := make([]ast.Node, 0, 1+len(extraNodes))
			callbackNodes = append(callbackNodes, valueNode)
			callbackNodes = append(callbackNodes, extraNodes...)
			summary := s.summaryForCurrentCall(key, call.StartLine())
			allowStateSideEffects := true
			if s.engine.currentBatchName == "output" || s.engine.currentBatchName == "delete" {
				allowStateSideEffects = s.allowCurrentBatchStateSideEffectsForCallbackReplay(key, summary, callbackArgs)
			}
			if returned := s.instantiateSummaryReturnWithOptions(key, callbackArgs, callbackNodes, "", true, allowStateSideEffects, call.StartLine()); len(returned) != 0 {
				current = returned
			}
		}
		return current.union(recordReadOrigins)
	}
	if isDynamicCallbackHelper(name) && len(args) > 0 && s.engine.allowsSinkOp("call") {
		if callbackExpr := argValue(call.Args[0]); len(args[0]) != 0 {
			context := s.currentContext()
			if len(context.CapabilityChecks) == 0 {
				switch {
				case isDynamicCallbackExpr(callbackExpr):
					s.addSinkFindings("render-callback-execution", renderCallbackMessage, args[0], s.locationForNode(call), context)
				case isDynamicCallbackArrayExpr(callbackExpr):
					s.addSinkFindings("unsafe-use", unsafeUseMessage, args[0], s.locationForNode(call), context)
				}
			}
		}
	}
	if callbackKeys, callbackArgs, callbackNodes, ok := s.dispatchHelperCallTargets(name, call.Args); ok {
		var returned originSet
		for _, key := range callbackKeys {
			returned = unionInto(returned, s.instantiateSummaryReturn(key, callbackArgs, callbackNodes, "", true))
		}
		return returned.union(recordReadOrigins)
	}
	if isSQLSanitizingFunc(name, call.Args) {
		if len(s.engine.allowedSinkOps) == 1 && s.engine.allowsSinkOp("sql") {
			return originSet{}
		}
		// intval/absint/floatval/boolval coerce to a number: safe for reflected
		// HTML output (mark numericSafe) but still attacker-controlled for
		// resource-selection/stored sinks, so the taint is propagated, not dropped.
		return markNumericSafeOrigins(unionAll(args).union(recordReadOrigins))
	}
	if isPathTraversalSanitizingFunc(name) {
		// basename/wp_basename/sanitize_file_name strip directory components,
		// making the result safe for path traversal sinks (include, file ops).
		return markPathSafeOrigins(unionAll(args).union(recordReadOrigins))
	}
	if name == "extract" && len(call.Args) > 0 {
		s.applyExtractToCurrentLocals(argValue(call.Args[0]), extractOverwritesLocals(call.Args))
		return originSet{}
	}
	if sinkIndexes, ruleID, message, ok := unsafeUseFuncArgIndexes(name); ok && s.engine.allowsSinkOp("call") {
		for _, sinkIndex := range sinkIndexes {
			if sinkIndex >= 0 && sinkIndex < len(call.Args) {
				s.addSinkFindings(ruleID, message, args[sinkIndex], s.locationForNode(argValue(call.Args[sinkIndex])), s.currentContext())
			}
		}
		return originSet{}
	}
	if sinkIndex, ruleID, message, ok := unsafeDeserializationFuncArgIndex(call); ok && s.engine.allowsSinkOp("call") {
		if sinkIndex >= 0 && sinkIndex < len(call.Args) {
			s.addSinkFindings(ruleID, message, args[sinkIndex], s.locationForNode(argValue(call.Args[sinkIndex])), s.currentContext())
		}
		return originSet{}
	}
	if sinkIndexes, ruleID, message, ok := unsafeDeserializationCallbackArgIndexes(call); ok && s.engine.allowsSinkOp("call") {
		for _, sinkIndex := range sinkIndexes {
			if sinkIndex >= 0 && sinkIndex < len(call.Args) {
				s.addSinkFindings(ruleID, message, args[sinkIndex], s.locationForNode(argValue(call.Args[sinkIndex])), s.currentContext())
			}
		}
		return originSet{}
	}
	if sinkIndex, ruleID, message, ok := sqlExecutionFuncArgIndex(name, len(call.Args)); ok && s.engine.allowsSinkOp("sql") {
		if sinkIndex >= 0 && sinkIndex < len(call.Args) {
			s.addSinkFindings(ruleID, message, s.sqlExecutionOrigins(argValue(call.Args[sinkIndex])), s.locationForNode(argValue(call.Args[sinkIndex])), s.currentContext())
		}
		return originSet{}
	}

	// Raw request-body readers on php://input are direct request sources on
	// EVERY sink-op batch. file_get_contents/file/readfile return the body
	// directly; fopen returns a tainted stream handle whose reads (fread/fgets/
	// stream_get_contents, modeled as propagating funcs) carry the taint. This
	// is the dominant modern REST/AJAX JSON-body input vector.
	if len(call.Args) > 0 && isPHPInputLiteral(argValue(call.Args[0])) {
		switch normalizeName(name) {
		case "file_get_contents", "file", "readfile", "fopen", "fgets", "fgetss", "stream_get_contents":
			return makeOriginSet(s.makeSourceOrigin(call))
		}
	}
	if name == "file_get_contents" && len(call.Args) > 0 {
		if s.engine.allowsSinkOp("call") && !isDefinitelyStaticIncludePath(argValue(call.Args[0])) {
			return makeOriginSet(s.makeSourceOrigin(call))
		}
	}
	if isDirectRequestSourceFunc(name) {
		return makeOriginSet(s.makeSourceOrigin(call))
	}
	if isRemoteResponseSourceFunc(name) && s.engine.allowsSinkOp("call") {
		return makeOriginSet(s.makeSourceOrigin(call))
	}
	if name == "define" && len(call.Args) > 1 {
		if path := globalConstPath(literalStringForCallable(argValue(call.Args[0]), s.current, s.engine)); path != "" {
			root := structuralRoot{key: path, isStatic: true}
			s.clearStructuralSubtree(root)
			s.copyStructuralFromExpr(root, argValue(call.Args[1]))
			if len(args[1]) != 0 {
				unionMapEntry(s.staticPropTaint, path, args[1])
			}
		}
		return originSet{}
	}
	if sinkIndex, sinkPath, ruleID, message, ok := privilegeMutationFuncArgPath(name); ok && s.engine.allowsSinkOp("call") {
		if sinkIndex >= 0 && sinkIndex < len(call.Args) {
			sinkExpr := argValue(call.Args[sinkIndex])
			sinkOrigins := s.resolveArgumentPathOrigins(sinkExpr, sinkPath)
			selectedNodes := resolveArgumentPathNodesForCallable(s.current, sinkExpr, sinkPath, call.StartLine())
			if privilegeMutationNodesAllLowPrivilegeRoles(s.current, selectedNodes, call.StartLine()) {
				return originSet{}
			}
			if len(sinkOrigins) == 0 && len(selectedNodes) != 0 {
				sinkOrigins = s.currentActionRequestOrigins()
			}
			if len(sinkOrigins) != 0 {
				s.addSinkFindings(ruleID, message, sinkOrigins, s.locationForNode(call), s.currentContext())
			}
		}
		return originSet{}
	}
	if idx, ok := capabilityMetaPrivilegeValueArgIndex(call); ok && s.engine.allowsSinkOp("call") {
		if idx >= 0 && idx < len(call.Args) {
			origins := args[idx]
			if len(origins) == 0 {
				origins = s.currentActionRequestOrigins()
			}
			if len(origins) != 0 {
				s.addSinkFindings("wp-request-tainted-privilege-mutation", privilegeMutationMessage, origins, s.locationForNode(call), s.currentContext())
			}
		}
		return originSet{}
	}
	hasActionSink := false
	if model, ok := actionSinkModelByFunc(name); ok {
		hasActionSink = true
		if s.engine.allowsSinkOp("action") {
			for _, idx := range actionSinkArgIndexes(model, len(args)) {
				s.addUnauthorizedActionFinding(model.RuleID, model.Message, args[idx], s.locationForNode(argValue(call.Args[idx])))
			}
		}
	}
	if isDisclosureOutputFunc(name) && len(args) > 0 {
		s.addRecordDisclosureFinding(args[0], s.locationForNode(argValue(call.Args[0])))
		return originSet{}
	}
	if s.engine.allowsSinkOp("output") {
		if indexes, ok := directOutputFuncArgIndexes(call); ok {
			for _, idx := range indexes {
				if idx >= 0 && idx < len(args) {
					loc := s.locationForNode(argValue(call.Args[idx]))
					s.addReflectedRequestOutputFinding(args[idx], loc)
					s.addPersistentOutputFinding(args[idx], loc)
				}
			}
		}
	}
	if isDownloadOutputFunc(name) &&
		s.engine.allowsSinkOp("action") &&
		(s.engine.callableHasRecordRead(s.current.Key) || callableHasDownloadDataSource(s.current)) &&
		callableHasAttachmentDispositionHeaderBefore(s.engine, s.current, call.StartLine()) {
		actionOrigins := s.currentActionRequestOrigins()
		if len(actionOrigins) != 0 {
			s.addUnauthorizedActionFinding("wp-request-sensitive-action-without-cap-check", requestSensitiveActionMessage, actionOrigins, s.locationForNode(call))
		}
	}
	if writes := storageWritesForFuncCall(call, s); len(writes) != 0 {
		for family, origins := range writes {
			origins = s.annotateStoredWriteOrigins(origins)
			unionMapEntry(s.storageWrites, family, origins)
		}
	}
	if pathWrites := storagePathWritesForFuncCall(call, s); len(pathWrites) != 0 {
		for path, origins := range pathWrites {
			origins = s.annotateStoredWriteOrigins(origins)
			unionMapEntry(s.storagePathWrites, path, origins)
		}
	}
	if origins, ok := storageReadOriginsForFuncCall(call, s); ok {
		return origins
	}
	if hasActionSink {
		return originSet{}
	}
	if isHTMLUnsafeTransformFunc(name) && len(args) > 0 {
		return markHTMLOutputUnsafeOrigins(args[0]).union(recordReadOrigins)
	}
	if isHTMLOutputSafeFunc(name) && len(args) > 0 {
		return markHTMLOutputSafeOrigins(args[0]).union(recordReadOrigins)
	}
	if isPropagatingFunc(name) {
		return unionAll(args)
	}
	if sinkIndexes, ok := fileUploadSinkArgIndexesByFunc(name); ok {
		result := originSet{}
		if resultIndex, ok := fileUploadReturnArgIndexByFunc(name); ok && resultIndex >= 0 && resultIndex < len(args) {
			result = args[resultIndex]
		}
		if !s.engine.allowsSinkOp("write") {
			return result
		}
		for _, sinkIndex := range sinkIndexes {
			if sinkIndex >= 0 && sinkIndex < len(args) {
				s.addUnauthorizedFileUploadFinding(args[sinkIndex], s.locationForNode(argValue(call.Args[sinkIndex])))
			}
		}
		return result
	}
	if sinkIndex, ruleID, message, ok := builtinRedirectHeaderSinkByFunc(name); ok && s.engine.allowsSinkOp("action") {
		if sinkIndex >= 0 && sinkIndex < len(call.Args) {
			s.addSinkFindings(ruleID, message, args[sinkIndex], s.locationForNode(argValue(call.Args[sinkIndex])), s.currentContext())
		}
		return originSet{}
	}
	if sinkIndex, op, ruleID, message, ok := builtinSinkByFunc(name); ok {
		if !s.engine.allowsSinkOp(op) {
			if op == "read" && builtinReadReturnsContent(name) && sinkIndex >= 0 && sinkIndex < len(args) {
				sinkExpr := argValue(call.Args[sinkIndex])
				return s.filterPathSinkOrigins(sinkExpr, args[sinkIndex])
			}
			return originSet{}
		}
		if sinkIndex >= 0 && sinkIndex < len(args) {
			sinkExpr := argValue(call.Args[sinkIndex])
			sinkOrigins := s.filterPathSinkOrigins(sinkExpr, args[sinkIndex])
			if op == "delete" {
				if !s.addUnauthorizedFileDeleteFinding(sinkOrigins, s.locationForNode(sinkExpr)) {
					s.addSinkFindings(ruleID, message, sinkOrigins, s.locationForNode(sinkExpr), s.currentContext())
				}
			} else if ruleID == "wp-request-file-upload-without-cap-check" {
				s.addUnauthorizedFileUploadFinding(sinkOrigins, s.locationForNode(sinkExpr))
			} else {
				s.addSinkFindings(ruleID, message, sinkOrigins, s.locationForNode(sinkExpr), s.currentContext())
			}
		}
		return originSet{}
	}
	if name == "load_template" {
		if len(call.Args) > 0 {
			if returned := s.evalStaticIncludedFile(argValue(call.Args[0])); len(returned) != 0 {
				if !s.engine.allowsSinkOp("include") {
					return returned.union(recordReadOrigins)
				}
			}
		}
		if s.engine.allowsSinkOp("include") && len(args) > 0 {
			sinkExpr := argValue(call.Args[0])
			s.addSinkFindings("path-transversal", pathTransversalMessage, s.filterPathSinkOrigins(sinkExpr, args[0]), s.locationForNode(sinkExpr), s.currentContext())
		}
		return originSet{}
	}

	if key := s.resolveFunctionKeyWithArgs(call.Name, call.Args); key != "" {
		summary := s.summaryForCurrentCall(key, call.StartLine())
		result := s.instantiateSummaryReturnWithOptions(key, args, call.Args, "", true, s.allowCurrentBatchStateSideEffectsForCall(key, summary, args, ""), call.StartLine())
		if len(result) == 0 {
			result = result.union(s.indexedStorageReadOriginsForCallable(key))
		}
		if len(result) == 0 && summaryHasNoEffects(summary) && isPropagatingFunc(name) {
			result = unionAll(args)
		}
		if len(result) == 0 && summaryHasOnlyReturnEffects(summary) && isPropagatingFunc(name) {
			result = unionAll(args)
		}
		if len(result) == 0 && summaryHasOnlyReturnEffects(summary) && isTemplatePathHelper(name) {
			result = unionAll(args)
		}
		return result.union(recordReadOrigins)
	}
	return unionAll(args).union(recordReadOrigins)
}

func (s *analysisState) evalInlineClosureCall(closure *ast.ExprClosure, argNodes []ast.Node) originSet {
	args := s.evalArgs(argNodes)
	branch := s.clone()
	branch.bindInlineClosureUses(closure.Uses)
	branch.bindInlineClosureParams(closure.Params, argNodes, args)
	branch.walkStatements(closure.Stmts)
	s.mergeInlineClosureEffects(branch, closure.Uses)
	return branch.returnValue
}

func (s *analysisState) bindInlineClosureUses(uses []ast.Node) {
	for _, rawUse := range uses {
		useItem, ok := rawUse.(*ast.ClosureUse)
		if !ok {
			continue
		}
		name := variableNodeName(useItem.Var)
		if name == "" {
			continue
		}
		s.varTaint[name] = s.evalExpr(useItem.Var)
		if className := s.resolveClassExpr(useItem.Var); className != "" {
			s.classEnv[name] = className
		}
		if hinted := dynamicDispatchStringForCallable(useItem.Var, s.current, s.engine, s.stringEnv); hinted != "" {
			s.stringEnv[name] = hinted
		}
	}
}

func (s *analysisState) bindInlineClosureParams(params []ast.Node, argNodes []ast.Node, args []originSet) {
	for idx, rawParam := range params {
		param, ok := rawParam.(*ast.Param)
		if !ok {
			continue
		}
		name := variableNodeName(param.Var)
		if name == "" {
			continue
		}
		valueNode := param.Default
		origins := originSet{}
		if param.Variadic {
			if idx < len(argNodes) {
				valueNode = argValue(argNodes[idx])
				origins = unionAll(args[idx:])
			}
		} else if idx < len(argNodes) {
			valueNode = argValue(argNodes[idx])
			origins = args[idx]
		} else if valueNode != nil {
			origins = s.evalExpr(valueNode)
		}
		s.varTaint[name] = origins
		if className := s.resolveClassExpr(valueNode); className != "" {
			s.classEnv[name] = className
		} else {
			delete(s.classEnv, name)
		}
		if hinted := dynamicDispatchStringForCallable(valueNode, s.current, s.engine, s.stringEnv); hinted != "" {
			s.stringEnv[name] = hinted
		} else {
			delete(s.stringEnv, name)
		}
	}
}

func (s *analysisState) mergeInlineClosureEffects(branch analysisState, uses []ast.Node) {
	s.mergeFindingsFrom(branch)
	s.propTaint = mergeVarMaps(s.propTaint, branch.propTaint)
	s.staticPropTaint = mergeVarMaps(s.staticPropTaint, branch.staticPropTaint)
	s.receiverWrites = mergeVarMaps(s.receiverWrites, branch.receiverWrites)
	s.receiverStorageLinks = mergeStringMaps(s.receiverStorageLinks, branch.receiverStorageLinks)
	s.structuralStorageLinks = mergeStringMaps(s.structuralStorageLinks, branch.structuralStorageLinks)
	s.storageWrites = mergeVarMaps(s.storageWrites, branch.storageWrites)
	s.storagePathWrites = mergeVarMaps(s.storagePathWrites, branch.storagePathWrites)
	s.returnPathWrites = mergeVarMaps(s.returnPathWrites, branch.returnPathWrites)
	s.returnClasses = mergeStringSets(s.returnClasses, branch.returnClasses)
	s.hasRecordRead = s.hasRecordRead || branch.hasRecordRead
	for _, rawUse := range uses {
		useItem, ok := rawUse.(*ast.ClosureUse)
		if !ok || !useItem.ByRef {
			continue
		}
		name := variableNodeName(useItem.Var)
		if name == "" {
			continue
		}
		if origins, ok := branch.varTaint[name]; ok {
			s.varTaint[name] = origins
		}
		if className := strings.TrimSpace(branch.classEnv[name]); className != "" {
			s.classEnv[name] = className
		} else {
			delete(s.classEnv, name)
		}
		if hinted := strings.TrimSpace(branch.stringEnv[name]); hinted != "" {
			s.stringEnv[name] = hinted
		} else {
			delete(s.stringEnv, name)
		}
	}
}

func (s *analysisState) evalStaticIncludedFile(expr ast.Node) originSet {
	if !s.engine.allowsSinkOp("output") {
		return originSet{}
	}
	keys := s.engine.staticIncludedFileCallableKeys(expr, s.current)
	if len(keys) == 0 {
		return originSet{}
	}
	var returned originSet
	for _, key := range keys {
		if _, ok := s.includeStack[key]; ok {
			continue
		}
		callable, ok := s.engine.callables[key]
		if !ok {
			continue
		}
		branch := s.clone()
		branch.current = callable
		branch.contextOverride = mergeOptionalFlowContext(s.currentContext(), s.contextOverride)
		branch.hasRecordRead = s.hasRecordRead || branch.hasRecordRead
		if branch.includeStack == nil {
			branch.includeStack = map[string]struct{}{}
		}
		branch.includeStack[key] = struct{}{}
		branch.walkStatements(callable.Stmts)
		s.mergeIncludedFileEffects(branch)
		returned = unionInto(returned, branch.returnValue)
	}
	return returned
}

func (s *analysisState) mergeIncludedFileEffects(branch analysisState) {
	s.mergeFindingsFrom(branch)
	s.varTaint = mergeVarMaps(s.varTaint, branch.varTaint)
	s.propTaint = mergeVarMaps(s.propTaint, branch.propTaint)
	s.staticPropTaint = mergeVarMaps(s.staticPropTaint, branch.staticPropTaint)
	s.receiverWrites = mergeVarMaps(s.receiverWrites, branch.receiverWrites)
	s.receiverStorageLinks = mergeStringMaps(s.receiverStorageLinks, branch.receiverStorageLinks)
	s.structuralStorageLinks = mergeStringMaps(s.structuralStorageLinks, branch.structuralStorageLinks)
	s.storageWrites = mergeVarMaps(s.storageWrites, branch.storageWrites)
	s.storagePathWrites = mergeVarMaps(s.storagePathWrites, branch.storagePathWrites)
	s.classEnv = mergeStringMaps(s.classEnv, branch.classEnv)
	s.stringEnv = mergeStringMaps(s.stringEnv, branch.stringEnv)
	s.weakIdentifierEnv = mergeWeakIdentifierMaps(s.weakIdentifierEnv, branch.weakIdentifierEnv)
	s.safePathVars = mergeStringSets(s.safePathVars, branch.safePathVars)
	s.safePathExprSigs = mergeStringSets(s.safePathExprSigs, branch.safePathExprSigs)
	s.varPathExprSig = mergeStringMaps(s.varPathExprSig, branch.varPathExprSig)
	s.returnPathWrites = mergeVarMaps(s.returnPathWrites, branch.returnPathWrites)
	s.returnClasses = mergeStringSets(s.returnClasses, branch.returnClasses)
	s.hasRecordRead = s.hasRecordRead || branch.hasRecordRead
}

func (s *analysisState) applyExtractToCurrentLocals(container ast.Node, overwrite bool) {
	if container == nil {
		return
	}
	s.extractContainers = append(s.extractContainers, container)
	containerName := variableNodeName(container)
	existingNames := map[string]struct{}{}
	for name := range s.varTaint {
		existingNames[name] = struct{}{}
	}
	for name := range s.classEnv {
		existingNames[name] = struct{}{}
	}
	for name := range s.stringEnv {
		existingNames[name] = struct{}{}
	}
	names := map[string]struct{}{}
	for name := range existingNames {
		names[name] = struct{}{}
	}
	for relPath := range s.resolveArgumentStructuralPaths(container, "") {
		segment, _, ok := nextPathSegment(relPath)
		if !ok || segment == "" || segment == "[]" || segment == "*" || strings.HasPrefix(segment, ".") {
			continue
		}
		name := strings.TrimSpace(segment)
		if name == "" {
			continue
		}
		names[name] = struct{}{}
	}
	for name := range names {
		name = strings.TrimSpace(name)
		if name == "" || strings.EqualFold(name, "this") {
			continue
		}
		if containerName != "" && strings.EqualFold(name, containerName) {
			continue
		}
		if !overwrite {
			if _, ok := existingNames[name]; ok {
				continue
			}
		}
		origins := s.resolveArgumentPathOrigins(container, "["+strings.ToLower(name)+"]")
		if len(origins) == 0 {
			continue
		}
		s.varTaint[name] = origins
		selectedNodes := s.resolveArgumentPathNodes(container, "["+strings.ToLower(name)+"]")
		className := ""
		hinted := ""
		for _, selected := range selectedNodes {
			if className == "" {
				className = s.resolveClassExpr(selected)
			}
			if hinted == "" {
				hinted = dynamicDispatchStringForCallable(selected, s.current, s.engine, s.stringEnv)
			}
		}
		if className != "" {
			s.classEnv[name] = className
		} else {
			delete(s.classEnv, name)
		}
		if hinted != "" {
			s.stringEnv[name] = hinted
		} else {
			delete(s.stringEnv, name)
		}
	}
}

func extractOverwritesLocals(args []ast.Node) bool {
	if len(args) < 2 {
		return true
	}
	switch typed := argValue(args[1]).(type) {
	case *ast.ExprConstFetch:
		return !strings.EqualFold(identifierText(typed.Name), "EXTR_SKIP")
	case *ast.ScalarInt:
		return typed.Value != 1
	default:
		return true
	}
}

func variableNodeName(node ast.Node) string {
	variable, ok := node.(*ast.ExprVariable)
	if !ok {
		return ""
	}
	name, ok := variable.Name.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(name)
}

func isDynamicCallbackHelper(name string) bool {
	switch normalizeName(name) {
	case "call_user_func", "call_user_func_array", "forward_static_call", "forward_static_call_array":
		return true
	default:
		return false
	}
}

func isDynamicCallbackExpr(node ast.Node) bool {
	switch node.(type) {
	case *ast.ExprVariable, *ast.ExprArrayDimFetch, *ast.ExprPropertyFetch, *ast.ExprStaticPropertyFetch:
		return true
	default:
		return false
	}
}

func isDynamicCallbackArrayExpr(node ast.Node) bool {
	arrayNode, ok := node.(*ast.ExprArray)
	if !ok {
		return false
	}
	items := arrayItems(arrayNode)
	if len(items) < 2 {
		return false
	}
	return isDynamicCallbackExpr(items[0]) || isDynamicCallbackExpr(items[1])
}

func isDirectCallSinkSeedExpr(node ast.Node) bool {
	switch node := node.(type) {
	case *ast.ExprArrayDimFetch, *ast.ExprPropertyFetch, *ast.ExprStaticPropertyFetch:
		return true
	case *ast.ExprVariable:
		if name, ok := node.Name.(string); ok {
			switch strings.ToUpper(strings.TrimSpace(name)) {
			case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES":
				return true
			}
		}
		return false
	default:
		return false
	}
}

func sliceArgValues(items []ast.Node) []ast.Node {
	out := make([]ast.Node, 0, len(items))
	for _, item := range items {
		out = append(out, argValue(item))
	}
	return out
}

func (s *analysisState) evalRefArrayArgs(args []ast.Node, index int) ([]originSet, []ast.Node, bool) {
	if index < 0 || index >= len(args) {
		return nil, nil, false
	}
	arrayNode, ok := argValue(args[index]).(*ast.ExprArray)
	if ok {
		items := arrayItems(arrayNode)
		callbackArgs := make([]originSet, 0, len(items))
		callbackNodes := make([]ast.Node, 0, len(items))
		for _, item := range items {
			callbackArgs = append(callbackArgs, s.evalExpr(item))
			callbackNodes = append(callbackNodes, item)
		}
		return callbackArgs, callbackNodes, true
	}
	valueNode := argValue(args[index])
	return []originSet{s.evalExpr(valueNode)}, []ast.Node{valueNode}, true
}

func (s *analysisState) dispatchHelperCallTargets(name string, args []ast.Node) ([]string, []originSet, []ast.Node, bool) {
	switch name {
	case "call_user_func", "forward_static_call":
		if len(args) == 0 {
			return nil, nil, nil, false
		}
		keys := s.engine.batchRelevantCallbackKeys(s.engine.resolveCallbackKeysWithEnv(argValue(args[0]), s.current, s.stringEnv))
		if len(keys) == 0 {
			return nil, nil, nil, false
		}
		callbackArgs := s.evalArgs(args[1:])
		callbackNodes := sliceArgValues(args[1:])
		return keys, callbackArgs, callbackNodes, true
	case "call_user_func_array", "forward_static_call_array":
		if len(args) < 2 {
			return nil, nil, nil, false
		}
		keys := s.engine.batchRelevantCallbackKeys(s.engine.resolveCallbackKeysWithEnv(argValue(args[0]), s.current, s.stringEnv))
		if len(keys) == 0 {
			return nil, nil, nil, false
		}
		arrayNode, ok := argValue(args[1]).(*ast.ExprArray)
		if !ok {
			return nil, nil, nil, false
		}
		items := arrayItems(arrayNode)
		callbackArgs := make([]originSet, 0, len(items))
		callbackNodes := make([]ast.Node, 0, len(items))
		for _, item := range items {
			callbackArgs = append(callbackArgs, s.evalExpr(item))
			callbackNodes = append(callbackNodes, item)
		}
		return keys, callbackArgs, callbackNodes, true
	default:
		return nil, nil, nil, false
	}
}

func (s *analysisState) instantiateSummaryStructuralWrites(dst map[string]originSet, basePath string, effect taintSummary, argNodes []ast.Node) {
	if dst == nil || basePath == "" || len(argNodes) == 0 {
		return
	}
	for _, idx := range effect.Params {
		if idx < 0 || idx >= len(argNodes) {
			continue
		}
		for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[idx]), "") {
			unionMapEntry(dst, basePath+suffix, origins)
		}
	}
	for _, ref := range effect.ParamPaths {
		if ref.Index < 0 || ref.Index >= len(argNodes) {
			continue
		}
		for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[ref.Index]), ref.Path) {
			unionMapEntry(dst, basePath+suffix, origins)
		}
	}
	for concretePath, origins := range s.instantiateConcreteSummaryPathWrites(basePath, effect, argNodes) {
		unionMapEntry(dst, concretePath, origins)
	}
}

func (s *analysisState) evalMethodCall(call *ast.ExprMethodCall) originSet {
	name := strings.ToLower(identifierText(call.Name))
	args := s.evalArgs(call.Args)
	if name == "" {
		// $obj->{$_GET['m']}(...) — attacker-chosen method name (arbitrary-method
		// invocation / router-bypass).
		s.emitDynamicCallNameFinding(call.Name, s.locationForNode(call))
	}
	if origins, ok := surfaceSecretConfigReadOriginsForMethodCall(name, call, s); ok {
		return origins
	}
	s.addPublicOAuthCallbackAuthSurfaceFindingForMethodCall(call)
	recordReadOrigins := originSet{}
	if s.engine.allowsSinkOp("output") {
		recordReadOrigins = recordReadSelectorOrigins(name, args)
	}
	if sinkIndex, ruleID, message, ok := sqlExecutionMethodArgIndex(name); ok && s.engine.allowsSinkOp("sql") && s.isLikelyDatabaseMethodCall(call) {
		if sinkIndex >= 0 && sinkIndex < len(call.Args) {
			s.addSinkFindings(ruleID, message, s.sqlExecutionOrigins(argValue(call.Args[sinkIndex])), s.locationForNode(argValue(call.Args[sinkIndex])), s.currentContext())
		}
		return originSet{}
	}
	if sinkIndex, ruleID, message, ok := sqlTemplateMethodArgIndex(name); ok && s.engine.allowsSinkOp("sql") && s.isLikelySQLTemplateMethodCall(call) {
		if sinkIndex >= 0 && sinkIndex < len(call.Args) {
			templateNode := argValue(call.Args[sinkIndex])
			if !isSafePreparedSQLTemplate(templateNode) {
				s.addSinkFindings(ruleID, message, s.sqlExecutionOrigins(templateNode), s.locationForNode(templateNode), s.currentContext())
			}
		}
		return originSet{}
	}
	if sinkIndexes, ruleID, message, ok := sqlIdentifierWriteMethodArgIndexes(name); ok && s.engine.allowsSinkOp("sql") && s.isLikelyDatabaseWriteMethodCall(call) {
		for _, sinkIndex := range sinkIndexes {
			if sinkIndex < 0 || sinkIndex >= len(call.Args) {
				continue
			}
			if origins := s.sqlWriteIdentifierOrigins(argValue(call.Args[sinkIndex]), call.StartLine()); len(origins) != 0 {
				s.addSinkFindings(ruleID, message, origins, s.locationForNode(argValue(call.Args[sinkIndex])), s.currentContext())
			}
		}
	}
	if isRequestGetterMethodCall(call) {
		return makeOriginSet(s.makeSourceOrigin(call))
	}
	hasActionSink := false
	if model, ok := actionSinkModelByMethod(name); ok && actionSinkModelMatchesMethodCall(model, call, s) {
		hasActionSink = true
		if s.engine.allowsSinkOp("action") {
			for _, idx := range actionSinkArgIndexes(model, len(args)) {
				s.addUnauthorizedActionFinding(model.RuleID, model.Message, args[idx], s.locationForNode(argValue(call.Args[idx])))
			}
		}
	}
	if writes := storageWritesForMethodCall(call, s); len(writes) != 0 {
		for family, origins := range writes {
			origins = s.annotateStoredWriteOrigins(origins)
			s.storageWrites[family] = s.storageWrites[family].union(origins)
		}
	}
	if pathWrites := storagePathWritesForMethodCall(call, s); len(pathWrites) != 0 {
		for path, origins := range pathWrites {
			if len(s.storagePathWrites) >= 512 {
				break // Cap storage path writes to prevent memory explosion
			}
			origins = s.annotateStoredWriteOrigins(origins)
			s.storagePathWrites[path] = s.storagePathWrites[path].union(origins)
		}
	}
	if sinkIndex, op, ruleID, message, ok := builtinMethodSink(name); ok {
		if op == "delete" && !s.engine.deleteMethodSinkMatches(s.current, call) {
			return originSet{}
		}
		if !s.engine.allowsSinkOp(op) {
			return originSet{}
		}
		if sinkIndex >= 0 && sinkIndex < len(args) {
			sinkExpr := argValue(call.Args[sinkIndex])
			sinkOrigins := args[sinkIndex]
			if ruleID == "wp-request-tainted-privilege-mutation" && len(sinkOrigins) == 0 {
				sinkOrigins = s.currentActionRequestOrigins()
				if len(sinkOrigins) != 0 {
					s.addUnauthorizedActionFinding(ruleID, message, sinkOrigins, s.locationForNode(call))
					return originSet{}
				}
			}
			switch op {
			case "read", "open", "delete", "include":
				sinkOrigins = s.filterPathSinkOrigins(sinkExpr, args[sinkIndex])
			}
			if op == "delete" {
				if !s.addUnauthorizedFileDeleteFinding(sinkOrigins, s.locationForNode(sinkExpr)) {
					s.addSinkFindings(ruleID, message, sinkOrigins, s.locationForNode(sinkExpr), s.currentContext())
				}
			} else {
				s.addSinkFindings(ruleID, message, sinkOrigins, s.locationForNode(sinkExpr), s.currentContext())
			}
		}
		return originSet{}
	}
	if sinkIndexes, ok := fileUploadSinkArgIndexesByMethod(name); ok {
		if !s.engine.allowsSinkOp("write") {
			return originSet{}
		}
		if !fileUploadSinkMethodMatchesCall(name, call, s) {
			return originSet{}
		}
		for _, sinkIndex := range sinkIndexes {
			if sinkIndex >= 0 && sinkIndex < len(args) {
				s.addUnauthorizedFileUploadFinding(args[sinkIndex], s.locationForNode(argValue(call.Args[sinkIndex])))
			}
		}
		return originSet{}
	}
	if origins, ok := storageReadOriginsForMethodCall(call, s); ok {
		if len(origins) == 0 {
			origins = sourceLikeSQLReadOriginsForMethodCall(call, s)
		}
		return origins.union(recordReadOrigins)
	}
	if origins := sourceLikeSQLReadOriginsForMethodCall(call, s); len(origins) != 0 {
		return origins.union(recordReadOrigins)
	}
	if hasActionSink {
		return originSet{}
	}
	if isHTMLUnsafeTransformFunc(name) && len(args) > 0 {
		return markHTMLOutputUnsafeOrigins(args[0]).union(recordReadOrigins)
	}
	if isHTMLOutputSafeFunc(name) && len(args) > 0 {
		return markHTMLOutputSafeOrigins(args[0]).union(recordReadOrigins)
	}
	className := s.resolveClassExpr(call.Var)
	classCandidates := []string{}
	if className != "" {
		classCandidates = append(classCandidates, className)
	} else {
		classCandidates = s.engine.resolveCallbackClassRefs(call.Var, s.current)
	}
	var result originSet
	foundMethod := false
	receiverRoot := receiverRootKey(call.Var, s.current.Class)
	if receiverRoot == "" {
		receiverRoot = s.materializeInlineNewReceiverRoot(call.Var)
	}
	for _, candidate := range classCandidates {
		key := s.resolveMethodKeyWithArgs(candidate, name, call.Args)
		if key == "" {
			continue
		}
		foundMethod = true
		summary := s.summaryForCurrentCall(key, call.StartLine())
		allowReceiverSideEffects := s.allowLocalReceiverSideEffectsAfterMethodCall(call, receiverRoot)
		instantiated := s.instantiateSummaryReturnWithOptions(key, args, call.Args, receiverRoot, allowReceiverSideEffects, s.allowCurrentBatchStateSideEffectsForCall(key, summary, args, receiverRoot), call.StartLine())
		if len(instantiated) == 0 {
			instantiated = instantiated.union(s.indexedStorageReadOriginsForCallable(key))
		}
		if len(instantiated) == 0 && summaryHasNoEffects(summary) && isPropagatingMethod(name) {
			instantiated = unionAll(args)
		}
		if len(instantiated) == 0 && summaryHasOnlyReturnEffects(summary) && isTemplatePathHelper(name) {
			instantiated = unionAll(args)
		}
		result = unionInto(result, instantiated)
	}
	if foundMethod {
		return result.union(recordReadOrigins)
	}
	origins := s.evalExpr(call.Var)
	return origins.union(unionAll(args)).union(recordReadOrigins)
}

func (s *analysisState) materializeInlineNewReceiverRoot(node ast.Node) string {
	newExpr, ok := node.(*ast.ExprNew)
	if !ok || s == nil || s.engine == nil {
		return ""
	}
	className := resolveClassName(newExpr.Class, s.current.Class, s.engine.classParents)
	if className == "" {
		return ""
	}
	key := s.resolveMethodKey(className, "__construct")
	if key == "" {
		return ""
	}
	s.inlineReceiverSeq++
	root := "__inline_new_receiver_" + strconv.Itoa(s.inlineReceiverSeq)
	args := s.evalArgs(newExpr.Args)
	summary := s.summaryForKey(key)
	for name, effect := range summary.ReceiverWrites {
		unionMapEntry(s.propTaint, root+"."+name, s.instantiateTaintSummary(effect, args, newExpr.Args))
	}
	for path, effect := range summary.ReceiverPathWrites {
		unionMapEntry(s.propTaint, root+"."+path, s.instantiateTaintSummary(effect, args, newExpr.Args))
	}
	for path, family := range summary.ReceiverStorageLinks {
		dstRoot := root + "." + path
		copyPersistentStructuralPathMap(s.propTaint, s.engine.storagePaths, dstRoot, family)
		copyStructuralPathMap(s.propTaint, s.storagePathWrites, dstRoot, family)
		s.recordStructuralStorageLink(dstRoot, family)
	}
	return root
}

func (s *analysisState) evalStaticCall(call *ast.ExprStaticCall) originSet {
	name := strings.ToLower(identifierText(call.Name))
	args := s.evalArgs(call.Args)
	if name == "" {
		// Class::{$_GET['m']}(...) — attacker-chosen static method name.
		s.emitDynamicCallNameFinding(call.Name, s.locationForNode(call))
	}
	if origins, ok := surfaceSecretConfigReadOriginsForStaticCall(name, call, s); ok {
		return origins
	}
	recordReadOrigins := originSet{}
	if s.engine.allowsSinkOp("output") {
		recordReadOrigins = recordReadSelectorOrigins(name, args)
	}
	className := resolveClassName(call.Class, s.current.Class, s.engine.classParents)
	if sinkIndex, ruleID, message, ok := sqlTemplateMethodArgIndex(name); ok && s.engine.allowsSinkOp("sql") && s.isLikelySQLTemplateStaticCall(call) {
		if sinkIndex >= 0 && sinkIndex < len(call.Args) {
			templateNode := argValue(call.Args[sinkIndex])
			if !isSafePreparedSQLTemplate(templateNode) {
				s.addSinkFindings(ruleID, message, s.sqlExecutionOrigins(templateNode), s.locationForNode(templateNode), s.currentContext())
			}
		}
		return originSet{}
	}
	if model, ok := actionSinkModelByMethod(name); ok && actionSinkModelMatchesStaticCall(model, className) {
		if s.engine.allowsSinkOp("action") {
			for _, idx := range actionSinkArgIndexes(model, len(args)) {
				s.addUnauthorizedActionFinding(model.RuleID, model.Message, args[idx], s.locationForNode(argValue(call.Args[idx])))
			}
		}
		return originSet{}
	}
	if isRequestGetterStaticCall(className, name) || isRequestGetterStaticCall(identifierText(call.Class), name) {
		return makeOriginSet(s.makeSourceOrigin(call))
	}
	if origins, ok := storageReadOriginsForStaticCall(call, s); ok {
		if len(origins) == 0 {
			origins = sourceLikeSQLReadOriginsForStaticCall(call, s)
		}
		return origins.union(recordReadOrigins)
	}
	if origins := sourceLikeSQLReadOriginsForStaticCall(call, s); len(origins) != 0 {
		return origins.union(recordReadOrigins)
	}
	if isHTMLUnsafeTransformFunc(name) && len(args) > 0 {
		return markHTMLOutputUnsafeOrigins(args[0]).union(recordReadOrigins)
	}
	if isHTMLOutputSafeFunc(name) && len(args) > 0 {
		return markHTMLOutputSafeOrigins(args[0]).union(recordReadOrigins)
	}
	if keys := dynamicStaticMethodKeysForCallable(s.engine, s.current, className, call.Name, s.stringEnv); len(keys) != 0 {
		result := originSet{}
		literalHints := literalArgHintsForArgsWithEnv(call.Args, s.current, s.engine, s.stringEnv)
		pathHints := literalArgPathHintsForArgsWithEnv(call.Args, s.current, s.engine, s.stringEnv, 0, nil)
		for _, key := range keys {
			key = s.engine.maybeSpecializeCallableForLiteralArgsAndPaths(key, literalHints, pathHints)
			summary := s.summaryForCurrentCall(key, call.StartLine())
			instantiated := s.instantiateSummaryReturnWithOptions(key, args, call.Args, "", true, s.allowCurrentBatchStateSideEffectsForCall(key, summary, args, ""), call.StartLine())
			if len(instantiated) == 0 && len(keys) == 1 && summaryHasNoEffects(summary) && isPropagatingMethod(name) {
				instantiated = unionAll(args)
			}
			if len(instantiated) == 0 && len(keys) == 1 && summaryHasOnlyReturnEffects(summary) && isTemplatePathHelper(name) {
				instantiated = unionAll(args)
			}
			result = result.union(instantiated)
		}
		return result.union(recordReadOrigins)
	}
	return unionAll(args).union(recordReadOrigins)
}

func actionSinkModelMatchesMethodCall(model actionSinkModel, call *ast.ExprMethodCall, s *analysisState) bool {
	if model.RequireConfigLike && !isConfigLikeMethodCall(call, s) {
		return false
	}
	if model.RequireInstallerLike && !isInstallerLikeMethodCall(call, s) {
		return false
	}
	if model.RequireUserLike && !isUserLikeMethodCall(call, s) {
		return false
	}
	return true
}

func actionSinkModelMatchesStaticCall(model actionSinkModel, className string) bool {
	if model.RequireConfigLike && !isConfigLikeReceiverClassName(className) {
		return false
	}
	if model.RequireInstallerLike && !isInstallerLikeReceiverClassName(className) {
		return false
	}
	if model.RequireUserLike && !isUserLikeReceiverClassName(className) {
		return false
	}
	return true
}

func isUserLikeMethodCall(call *ast.ExprMethodCall, s *analysisState) bool {
	className := s.resolveClassExpr(call.Var)
	if isUserLikeReceiverClassName(className) {
		return true
	}
	if variable, ok := call.Var.(*ast.ExprVariable); ok {
		if name, ok := variable.Name.(string); ok && isUserLikeReceiverVarName(name) {
			return true
		}
	}
	if property, ok := propertyPathKey(call.Var, s.current.Class); ok && isUserLikeReceiverVarName(property) {
		return true
	}
	return false
}

func surfaceSecretConfigReadOriginsForFuncCall(name string, call *ast.ExprFuncCall, s *analysisState) (originSet, bool) {
	if !s.engine.allowsSinkOp("surface") || !isSecretLikeConfigReadName(name) || len(call.Args) == 0 {
		return nil, false
	}
	if !isSecretLikeConfigKey(argValue(call.Args[0]), s.current, s.engine) {
		return nil, false
	}
	return makeOriginSet(s.makeSourceOrigin(call)), true
}

func surfaceSecretConfigReadOriginsForMethodCall(name string, call *ast.ExprMethodCall, s *analysisState) (originSet, bool) {
	if !s.engine.allowsSinkOp("surface") || !isSecretLikeConfigReadName(name) || len(call.Args) == 0 {
		return nil, false
	}
	if !isSecretLikeConfigKey(argValue(call.Args[0]), s.current, s.engine) {
		return nil, false
	}
	return makeOriginSet(s.makeSourceOrigin(call)), true
}

func surfaceSecretConfigReadOriginsForStaticCall(name string, call *ast.ExprStaticCall, s *analysisState) (originSet, bool) {
	if !s.engine.allowsSinkOp("surface") || !isSecretLikeConfigReadName(name) || len(call.Args) == 0 {
		return nil, false
	}
	if !isSecretLikeConfigKey(argValue(call.Args[0]), s.current, s.engine) {
		return nil, false
	}
	return makeOriginSet(s.makeSourceOrigin(call)), true
}

func summaryHasNoEffects(item summary) bool {
	return len(item.ReturnSources) == 0 &&
		len(item.ReturnSourceOrigins) == 0 &&
		len(item.ReturnReceiverPaths) == 0 &&
		len(item.ReturnParams) == 0 &&
		len(item.ReturnParamPaths) == 0 &&
		len(item.ReturnPathWrites) == 0 &&
		len(item.ReturnClasses) == 0 &&
		len(item.SourceFindings) == 0 &&
		len(item.ParamFindings) == 0 &&
		len(item.ReceiverFindings) == 0 &&
		len(item.StaticWrites) == 0 &&
		len(item.ReceiverWrites) == 0 &&
		len(item.ReceiverPathWrites) == 0 &&
		len(item.ReceiverStorageLinks) == 0 &&
		len(item.StorageWrites) == 0 &&
		len(item.StoragePathWrites) == 0
}

func summaryHasOnlyReturnEffects(item summary) bool {
	return len(item.SourceFindings) == 0 &&
		len(item.ParamFindings) == 0 &&
		len(item.ReceiverFindings) == 0 &&
		len(item.StaticWrites) == 0 &&
		len(item.ReceiverWrites) == 0 &&
		len(item.ReceiverPathWrites) == 0 &&
		len(item.ReceiverStorageLinks) == 0 &&
		len(item.StorageWrites) == 0 &&
		len(item.StoragePathWrites) == 0
}

func summaryHasReturnEffects(item summary) bool {
	return len(item.ReturnSources) != 0 ||
		len(item.ReturnSourceOrigins) != 0 ||
		len(item.ReturnReceiverPaths) != 0 ||
		len(item.ReturnParams) != 0 ||
		len(item.ReturnParamPaths) != 0 ||
		len(item.ReturnPathWrites) != 0 ||
		len(item.ReturnClasses) != 0
}

func summaryHasOnlyStorageEffects(item summary) bool {
	return !summaryHasReturnEffects(item) &&
		len(item.SourceFindings) == 0 &&
		len(item.ParamFindings) == 0 &&
		len(item.ReceiverFindings) == 0 &&
		len(item.StaticWrites) == 0 &&
		len(item.ReceiverWrites) == 0 &&
		len(item.ReceiverPathWrites) == 0 &&
		len(item.ReceiverStorageLinks) == 0 &&
		(len(item.StorageWrites) != 0 || len(item.StoragePathWrites) != 0)
}

func originsCarryCurrentBatchStateInterest(origins originSet) bool {
	for _, item := range origins {
		switch item.kind {
		case originParam, originReceiver, originContainer:
			return true
		case originSource:
			if !item.persistentRead {
				return true
			}
		}
	}
	return false
}

func summaryHasOnlyPersistentReadStorageSideEffects(item summary) bool {
	if len(item.StaticWrites) != 0 ||
		len(item.ReceiverWrites) != 0 ||
		len(item.ReceiverPathWrites) != 0 ||
		len(item.ReceiverStorageLinks) != 0 {
		return false
	}
	if len(item.StorageWrites) == 0 && len(item.StoragePathWrites) == 0 {
		return false
	}
	for _, effect := range item.StorageWrites {
		if !taintSummaryIsPersistentReadOnlyStructural(effect) {
			return false
		}
	}
	for _, effect := range item.StoragePathWrites {
		if !taintSummaryIsPersistentReadOnlyStructural(effect) {
			return false
		}
	}
	return true
}

func summaryHasOnlyReturnAndPersistentReadStorageEffects(item summary) bool {
	if !summaryHasReturnEffects(item) {
		return false
	}
	if len(item.SourceFindings) != 0 ||
		len(item.ParamFindings) != 0 ||
		len(item.ReceiverFindings) != 0 ||
		len(item.StaticWrites) != 0 ||
		len(item.ReceiverWrites) != 0 ||
		len(item.ReceiverPathWrites) != 0 ||
		len(item.ReceiverStorageLinks) != 0 {
		return false
	}
	if len(item.StorageWrites) == 0 && len(item.StoragePathWrites) == 0 {
		return false
	}
	return summaryHasOnlyPersistentReadStorageSideEffects(item)
}

func (s *analysisState) allowCurrentBatchStateSideEffectsForCallbackReplay(key string, item summary, args []originSet) bool {
	if s == nil || s.engine == nil {
		return true
	}
	deleteBatch := s.engine.currentBatchName == "delete"
	outputBatch := s.engine.currentBatchName == "output"
	callBatch := s.engine.currentBatchName == "call"
	if !outputBatch && !deleteBatch && !callBatch {
		return true
	}
	if summaryHasOnlyStorageEffects(item) &&
		s.engine.callableHasDirectOutputSyntax(s.current) &&
		!s.currentCallableReadsRelevantStorageForSummary(item) {
		_ = key
		_ = args
		return false
	}
	if !s.engine.callableHasPersistentReadOnlyStandaloneSourceSummary(key, item) {
		return true
	}
	if summaryHasOnlyPersistentReadStorageSideEffects(item) {
		return false
	}
	if callBatch && !summaryHasReturnEffects(item) {
		return false
	}
	for _, origins := range args {
		if originsCarryCurrentBatchStateInterest(origins) {
			return true
		}
	}
	return false
}

func (s *analysisState) allowCurrentBatchStateSideEffectsForCall(key string, item summary, args []originSet, receiverRoot string) bool {
	if s == nil || s.engine == nil {
		return true
	}
	deleteBatch := s.engine.currentBatchName == "delete"
	outputBatch := s.engine.currentBatchName == "output"
	callBatch := s.engine.currentBatchName == "call"
	if !outputBatch && !deleteBatch && !callBatch {
		return true
	}
	if summaryHasOnlyStorageEffects(item) &&
		s.engine.callableHasDirectOutputSyntax(s.current) &&
		!s.currentCallableReadsRelevantStorageForSummary(item) {
		_ = key
		_ = args
		_ = receiverRoot
		return false
	}
	if !s.engine.callableHasPersistentReadOnlyStandaloneSourceSummary(key, item) {
		return true
	}
	if summaryHasOnlyPersistentReadStorageSideEffects(item) {
		return false
	}
	if !summaryHasReturnEffects(item) {
		return true
	}
	for _, origins := range args {
		if originsCarryCurrentBatchStateInterest(origins) {
			return true
		}
	}
	_ = receiverRoot
	return false
}

func (s *analysisState) currentCallableReadsRelevantStorageForSummary(item summary) bool {
	if s == nil || s.engine == nil {
		return true
	}
	readFamilies := s.engine.storageReadFamiliesByCallable[s.current.Key]
	readBuckets := s.engine.storageReadBucketsByCallable[s.current.Key]
	if len(readFamilies) == 0 && len(readBuckets) == 0 {
		return false
	}
	for family := range item.StorageWrites {
		if _, ok := readFamilies[family]; ok {
			return true
		}
		for bucket := range readBuckets {
			if structuralPathRoot(bucket) == family {
				return true
			}
		}
	}
	for path := range item.StoragePathWrites {
		root := structuralPathRoot(path)
		if _, ok := readFamilies[root]; ok {
			return true
		}
		for bucket := range readBuckets {
			if structuralPathRoot(bucket) == root && structuralPathsOverlap(path, bucket) {
				return true
			}
		}
	}
	return false
}

func (s *analysisState) sqlExecutionOrigins(node ast.Node) originSet {
	switch typed := node.(type) {
	case nil:
		return originSet{}
	case *ast.ScalarString, *ast.ScalarInt, *ast.ScalarFloat:
		return originSet{}
	case *ast.ExprCastInt, *ast.ExprCastDouble, *ast.ExprCastBool:
		return originSet{}
	case *ast.ExprBinaryOpConcat:
		return s.sqlExecutionOrigins(typed.Left).union(s.sqlExecutionOrigins(typed.Right))
	case *ast.ExprArray:
		var out originSet
		for _, item := range typed.Items {
			out = unionInto(out, s.sqlExecutionOrigins(item))
		}
		return out
	case *ast.ArrayItem:
		return s.sqlExecutionOrigins(typed.Value).union(s.sqlExecutionOrigins(typed.Key))
	case *ast.ExprTernary:
		return s.sqlExecutionOrigins(typed.If).union(s.sqlExecutionOrigins(typed.Else))
	case *ast.ExprFuncCall:
		if isSQLSanitizingFunc(identifierText(typed.Name), typed.Args) {
			return originSet{}
		}
	case *ast.ExprMethodCall:
		if idx, _, _, ok := sqlTemplateMethodArgIndex(identifierText(typed.Name)); ok && s.isLikelySQLTemplateMethodCall(typed) {
			if idx >= 0 && idx < len(typed.Args) {
				templateNode := argValue(typed.Args[idx])
				if isSafePreparedSQLTemplate(templateNode) {
					return originSet{}
				}
				return s.sqlExecutionOrigins(templateNode)
			}
			return originSet{}
		}
	case *ast.ExprStaticCall:
		if idx, _, _, ok := sqlTemplateMethodArgIndex(identifierText(typed.Name)); ok && s.isLikelySQLTemplateStaticCall(typed) {
			if idx >= 0 && idx < len(typed.Args) {
				templateNode := argValue(typed.Args[idx])
				if isSafePreparedSQLTemplate(templateNode) {
					return originSet{}
				}
				return s.sqlExecutionOrigins(templateNode)
			}
			return originSet{}
		}
	case *ast.ExprNew:
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if idx, _, _, ok := sqlTemplateConstructorArgIndex(className); ok {
			if idx >= 0 && idx < len(typed.Args) {
				return s.sqlExecutionOrigins(argValue(typed.Args[idx]))
			}
			return originSet{}
		}
	}
	// Leaf resolution (bare variables / interpolated strings): drop
	// numeric-coerced origins. A value passed through (int)/(float)/(bool) or
	// intval/absint/floatval cannot break out of a SQL string in any context
	// (quoted or unquoted), so it cannot cause SQL injection even when the cast
	// happened at an earlier assignment and the value is later interpolated.
	// Numeric IDOR is a distinct rule and does not flow through this sink.
	return dropNumericSafeOrigins(s.evalExpr(node))
}

func dropNumericSafeOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return origins
	}
	var out originSet
	for key, item := range origins {
		if item.numericSafe {
			continue
		}
		if out == nil {
			out = make(originSet, len(origins))
		}
		out[key] = item
	}
	return out
}

func (s *analysisState) sqlWriteIdentifierOrigins(node ast.Node, beforeLine int) originSet {
	return s.sqlWriteIdentifierOriginsSeen(node, beforeLine, map[string]struct{}{})
}

func (s *analysisState) sqlWriteIdentifierOriginsSeen(node ast.Node, beforeLine int, seen map[string]struct{}) originSet {
	switch typed := node.(type) {
	case nil:
		return originSet{}
	case *ast.ExprArray:
		var out originSet
		for _, rawItem := range typed.Items {
			item, ok := rawItem.(*ast.ArrayItem)
			if !ok || item.Key == nil {
				continue
			}
			out = unionInto(out, s.sqlExecutionOrigins(item.Key))
		}
		return out
	case *ast.ExprVariable:
		name := variableNodeName(typed)
		if name == "" {
			return originSet{}
		}
		if source, ok := s.superglobalSource(name, nil, typed); ok {
			return makeOriginSet(source)
		}
		return s.sqlWriteIdentifierOriginsForLocalVariable(name, beforeLine, seen)
	case *ast.ExprAssign:
		return s.sqlWriteIdentifierOriginsSeen(typed.Expr, beforeLine, seen)
	case *ast.ExprAssignRef:
		return s.sqlWriteIdentifierOriginsSeen(typed.Expr, beforeLine, seen)
	case *ast.ExprFuncCall:
		if isPropagatingFunc(identifierText(typed.Name)) {
			return unionAllOriginsForNodes(typed.Args, func(child ast.Node) originSet {
				return s.sqlWriteIdentifierOriginsSeen(argValue(child), beforeLine, seen)
			})
		}
	case *ast.ExprMethodCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.sqlWriteIdentifierOriginsSeen(argValue(typed.Args[0]), beforeLine, seen)
		}
	case *ast.ExprStaticCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.sqlWriteIdentifierOriginsSeen(argValue(typed.Args[0]), beforeLine, seen)
		}
	}
	return originSet{}
}

func (s *analysisState) sqlWriteIdentifierOriginsForLocalVariable(name string, beforeLine int, seen map[string]struct{}) originSet {
	if _, ok := seen[name]; ok {
		return originSet{}
	}
	seen[name] = struct{}{}
	var out originSet
	walkNodes(s.current.Stmts, func(node ast.Node) {
		if node == nil {
			return
		}
		line := node.StartLine()
		if line <= 0 || line >= beforeLine {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprAssign:
			out = unionInto(out, s.sqlWriteIdentifierOriginsFromAssignment(name, typed.Var, typed.Expr, beforeLine, seen))
		case *ast.ExprAssignRef:
			out = unionInto(out, s.sqlWriteIdentifierOriginsFromAssignment(name, typed.Var, typed.Expr, beforeLine, seen))
		}
	})
	delete(seen, name)
	return out
}

func (s *analysisState) sqlWriteIdentifierOriginsFromAssignment(name string, target ast.Node, expr ast.Node, beforeLine int, seen map[string]struct{}) originSet {
	switch typed := target.(type) {
	case *ast.ExprVariable:
		if variableNodeName(typed) == name {
			return s.sqlWriteIdentifierOriginsSeen(expr, beforeLine, seen)
		}
	case *ast.ExprArrayDimFetch:
		if rootName, keyNode, ok := directLocalArrayKeyAssignment(typed); ok && rootName == name {
			return s.sqlExecutionOrigins(keyNode)
		}
	}
	return originSet{}
}

func directLocalArrayKeyAssignment(fetch *ast.ExprArrayDimFetch) (string, ast.Node, bool) {
	root, ok := fetch.Var.(*ast.ExprVariable)
	if !ok {
		return "", nil, false
	}
	name := variableNodeName(root)
	if name == "" {
		return "", nil, false
	}
	return name, fetch.Dim, true
}

func unionAllOriginsForNodes(nodes []ast.Node, eval func(ast.Node) originSet) originSet {
	var out originSet
	for _, node := range nodes {
		out = unionInto(out, eval(node))
	}
	return out
}

func (s *analysisState) isLikelySQLTemplateMethodCall(call *ast.ExprMethodCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "prepare" {
		return true
	}
	return s.isLikelyDatabaseMethodCall(call)
}

func (s *analysisState) isLikelySQLTemplateStaticCall(call *ast.ExprStaticCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "prepare" {
		return true
	}
	className := strings.ToLower(strings.TrimPrefix(resolveClassName(call.Class, s.current.Class, s.engine.classParents), `\`))
	leaf := className
	if idx := strings.LastIndex(leaf, `\`); idx != -1 {
		leaf = leaf[idx+1:]
	}
	return leaf == "db" ||
		strings.Contains(className, "wpdb") ||
		strings.Contains(className, "database") ||
		strings.Contains(className, "querybuilder") ||
		strings.Contains(className, "builder") ||
		strings.Contains(className, "conn")
}

func (s *analysisState) isLikelyDatabaseStaticCall(call *ast.ExprStaticCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	switch name {
	case "get_var", "get_row", "get_col", "get_results", "query", "queryrow", "queryall", "queryone", "querycol", "execute", "executequery":
		return true
	}
	className := strings.ToLower(strings.TrimPrefix(resolveClassName(call.Class, s.current.Class, s.engine.classParents), `\`))
	leaf := className
	if idx := strings.LastIndex(leaf, `\`); idx != -1 {
		leaf = leaf[idx+1:]
	}
	return leaf == "db" ||
		strings.Contains(className, "wpdb") ||
		strings.Contains(className, "database") ||
		strings.Contains(className, "querybuilder") ||
		strings.Contains(className, "builder") ||
		strings.Contains(className, "conn")
}

func (s *analysisState) isLikelyDatabaseMethodCall(call *ast.ExprMethodCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	switch name {
	case "get_var", "get_row", "get_col", "get_results", "query", "execute", "executequery",
		"multi_query", "real_query", "send_query":
		return true
	}
	if variable, ok := call.Var.(*ast.ExprVariable); ok {
		if varName, ok := variable.Name.(string); ok {
			lower := strings.ToLower(strings.TrimSpace(varName))
			if strings.Contains(lower, "wpdb") || strings.Contains(lower, "db") || strings.Contains(lower, "conn") || strings.Contains(lower, "pdo") || strings.Contains(lower, "mysqli") {
				return true
			}
		}
	}
	className := strings.ToLower(strings.TrimPrefix(s.resolveClassExpr(call.Var), `\`))
	return strings.Contains(className, "wpdb") || strings.Contains(className, "database") || strings.Contains(className, "db") || strings.Contains(className, "conn") || strings.Contains(className, "pdo") || strings.Contains(className, "mysqli")
}

func sourceLikeSQLReadOriginsForMethodCall(call *ast.ExprMethodCall, s *analysisState) originSet {
	if s == nil || call == nil {
		return originSet{}
	}
	if !s.engine.allowsSinkOp("call") && !s.engine.allowsSinkOp("output") {
		return originSet{}
	}
	if !s.isLikelyDatabaseMethodCall(call) || !isSQLSelectReadMethodCallWithContext(call, s.current, s.engine, call.StartLine()) || isSQLAggregateScalarReadMethodCallWithContext(call, s.current, s.engine, call.StartLine()) {
		return originSet{}
	}
	if s.engine.currentBatchName == "output" && isSQLNonContentScalarReadMethodCallWithContext(call, s.current, s.engine, call.StartLine()) {
		return originSet{}
	}
	return markPersistentReadOrigins(makeOriginSet(s.makeSourceOrigin(call)))
}

func isSQLNonContentScalarReadMethodCallWithContext(call *ast.ExprMethodCall, current callable, e *engine, beforeLine int) bool {
	if strings.ToLower(identifierText(call.Name)) != "get_var" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	query := sqlQueryStringWithContext(argValue(call.Args[0]), current, e, beforeLine, map[string]struct{}{})
	if query == "" && len(call.Args) > 1 {
		query = sqlQueryStringWithContext(argValue(call.Args[1]), current, e, beforeLine, map[string]struct{}{})
	}
	if query == "" {
		return false
	}
	return !isSQLContentLikeScalarQuery(query)
}

func isSQLContentLikeScalarQuery(query string) bool {
	query = strings.TrimSpace(strings.ToLower(query))
	if !strings.HasPrefix(query, "select ") {
		return false
	}
	fromIdx := strings.Index(query, " from ")
	if fromIdx == -1 {
		return false
	}
	selectList := strings.TrimSpace(query[len("select "):fromIdx])
	if selectList == "" || selectList == "*" {
		return false
	}
	if strings.HasPrefix(selectList, "distinct ") {
		selectList = strings.TrimSpace(selectList[len("distinct "):])
	}
	items := splitSQLSelectList(selectList)
	if len(items) != 1 {
		return false
	}
	item := strings.TrimSpace(items[0])
	if item == "" || strings.Contains(item, "(") {
		return false
	}
	if aliasIdx := strings.LastIndex(item, " as "); aliasIdx != -1 {
		item = strings.TrimSpace(item[:aliasIdx])
	}
	item = strings.Trim(item, "`\"' ")
	if dotIdx := strings.LastIndex(item, "."); dotIdx != -1 {
		item = strings.TrimSpace(item[dotIdx+1:])
	}
	item = strings.Trim(item, "`\"' ")
	if item == "" {
		return false
	}
	for _, token := range []string{"meta_value", "option_value", "content", "text", "message", "description", "excerpt", "body", "html", "comment", "review", "title"} {
		if strings.Contains(item, token) {
			return true
		}
	}
	return false
}

func sourceLikeSQLReadOriginsForStaticCall(call *ast.ExprStaticCall, s *analysisState) originSet {
	if s == nil || call == nil {
		return originSet{}
	}
	if !s.engine.allowsSinkOp("call") && !s.engine.allowsSinkOp("output") && !s.engine.allowsSinkOp("read") && !s.engine.allowsSinkOp("open") {
		return originSet{}
	}
	if !s.isLikelyDatabaseStaticCall(call) || !isSQLSelectReadStaticCall(call) || isSQLAggregateScalarReadStaticCall(call) {
		return originSet{}
	}
	return markPersistentReadOrigins(makeOriginSet(s.makeSourceOrigin(call)))
}

func (s *analysisState) isLikelyDatabaseWriteMethodCall(call *ast.ExprMethodCall) bool {
	if s.isLikelyDatabaseMethodCall(call) {
		return true
	}
	if len(call.Args) == 0 {
		return false
	}
	return isLikelySQLTableReference(argValue(call.Args[0]))
}

func isLikelySQLTableReference(node ast.Node) bool {
	switch typed := node.(type) {
	case *ast.ScalarString:
		return strings.TrimSpace(typed.Value) != ""
	case *ast.ExprBinaryOpConcat:
		return isLikelySQLTableReference(typed.Left) || isLikelySQLTableReference(typed.Right)
	case *ast.ExprVariable:
		name := strings.ToLower(variableNodeName(typed))
		return strings.Contains(name, "table") || strings.Contains(name, "wpdb") || strings.Contains(name, "db")
	case *ast.ExprPropertyFetch:
		name := strings.ToLower(identifierText(typed.Name))
		return strings.Contains(name, "table") || strings.Contains(name, "wpdb") || strings.Contains(name, "db")
	case *ast.ExprStaticPropertyFetch:
		name := strings.ToLower(identifierText(typed.Name))
		return strings.Contains(name, "table") || strings.Contains(name, "wpdb") || strings.Contains(name, "db")
	default:
		return false
	}
}

func isConfigLikeMethodCall(call *ast.ExprMethodCall, s *analysisState) bool {
	className := s.resolveClassExpr(call.Var)
	if isConfigLikeReceiverClassName(className) {
		return true
	}
	if variable, ok := call.Var.(*ast.ExprVariable); ok {
		if name, ok := variable.Name.(string); ok {
			return isConfigLikeReceiverVarName(name)
		}
	}
	if property, ok := propertyPathKey(call.Var, s.current.Class); ok {
		return isConfigLikeReceiverVarName(property)
	}
	return false
}

func isInstallerLikeMethodCall(call *ast.ExprMethodCall, s *analysisState) bool {
	return isInstallerLikeReceiverClassName(s.resolveClassExpr(call.Var))
}

func (s *analysisState) instantiateSummaryReturn(key string, args []originSet, argNodes []ast.Node, receiverRoot string, allowReceiverSideEffects bool) originSet {
	return s.instantiateSummaryReturnWithOptions(key, args, argNodes, receiverRoot, allowReceiverSideEffects, true, 0)
}

func (s *analysisState) instantiateSummaryReturnWithOptions(key string, args []originSet, argNodes []ast.Node, receiverRoot string, allowReceiverSideEffects bool, allowStateSideEffects bool, callLine int) originSet {
	// Memory circuit-breaker on the interprocedural instantiation path: a single
	// statement's deep cross-callable replay is the dominant transient-allocation
	// burst on mega-plugins. Bail (returning the args' taint as an
	// over-approximation) under heap pressure so the burst cannot OOM the process.
	if s.engine.heapHardLimit > 0 && s.engine.underMemoryPressure() {
		s.aborted = true
		return unionAll(args)
	}
	summary := s.summaryForCurrentCall(key, callLine)
	if key == s.current.Key && summaryHasOnlyReturnEffects(summary) {
		return unionAll(args)
	}
	currentContext := s.currentContext()
	for _, finding := range summary.SourceFindings {
		originalContext := s.engine.callableLocalGuardContext(finding.Callable, finding.Context)
		if directContext, ok := s.engine.callableDirectContext(finding.Callable, finding.Context); ok {
			finding.Context = directContext
		} else {
			finding.Context = mergeReplayedFindingContext(originalContext, currentContext)
		}
		if shouldSuppressFindingForContext(finding.RuleID, finding.Context, finding.Sink) {
			continue
		}
		if len(args) == 0 && receiverRoot == "" && flowContextsEquivalent(finding.Context, originalContext) {
			continue
		}
		recordKey := findingRecordKey(finding)
		if existing, ok := s.sourceHits[recordKey]; ok {
			finding.Context = mergeFlowContext(existing.Context, finding.Context)
			finding.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, finding.StoredWriteContext)
		}
		s.sourceHits[recordKey] = finding
	}
	for idx, templates := range summary.ParamFindings {
		if idx < 0 || idx >= len(args) {
			continue
		}
		for _, template := range templates {
			templateContext := mergeReplayedFindingContext(
				s.engine.callableLocalGuardContext(template.Callable, template.Context),
				currentContext,
			)
			origins := args[idx]
			if template.ParamPath != "" {
				origins = s.resolveArgumentPathOrigins(argValue(argNodes[idx]), template.ParamPath)
			}
			origins = applyStoredWriteContext(origins, template.StoredWriteContext)
			origins = s.filterReplayedSinkOrigins(template.RuleID, origins)
			if shouldSuppressFindingForContext(template.RuleID, templateContext, template.Sink) {
				continue
			}
			s.addSinkFindings(template.RuleID, template.Message, origins, template.Sink, templateContext)
		}
	}
	for _, template := range summary.ReceiverFindings {
		mergedContext := mergeReplayedFindingContext(
			s.engine.callableLocalGuardContext(template.Callable, template.Context),
			currentContext,
		)
		if receiverRoot == "this" {
			key := sinkTemplateKey(sinkTemplate{
				RuleID:             template.RuleID,
				Message:            template.Message,
				Sink:               template.Sink,
				Callable:           s.current.Display,
				Context:            mergedContext,
				StoredWriteContext: template.StoredWriteContext,
				ReceiverPath:       template.ReceiverPath,
			})
			next := sinkTemplate{
				RuleID:             template.RuleID,
				Message:            template.Message,
				Sink:               template.Sink,
				Callable:           s.current.Display,
				Context:            mergedContext,
				StoredWriteContext: template.StoredWriteContext,
				ReceiverPath:       template.ReceiverPath,
			}
			if existing, ok := s.receiverSinks[key]; ok {
				next.Context = mergeFlowContext(existing.Context, next.Context)
				next.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, next.StoredWriteContext)
			}
			s.receiverSinks[key] = next
		}
		if receiverRoot != "" {
			origins := applyStoredWriteContext(s.resolveReceiverPathOrigins(receiverRoot, template.ReceiverPath), template.StoredWriteContext)
			origins = s.filterReplayedSinkOrigins(template.RuleID, origins)
			if shouldSuppressFindingForContext(template.RuleID, mergedContext, template.Sink) {
				continue
			}
			s.addSinkFindings(template.RuleID, template.Message, origins, template.Sink, mergedContext)
		}
	}
	if receiverRoot != "" && allowReceiverSideEffects {
		for name, effect := range summary.ReceiverWrites {
			applied := s.resolveReceiverSummaryOrigins(s.instantiateTaintSummary(effect, args, argNodes), receiverRoot)
			unionMapEntry(s.propTaint, receiverRoot+"."+name, applied)
			s.instantiateSummaryStructuralWrites(s.propTaint, receiverRoot+"."+name, effect, argNodes)
			if receiverRoot == "this" {
				unionMapEntry(s.receiverWrites, name, applied)
			}
		}
		for path, effect := range summary.ReceiverPathWrites {
			applied := s.resolveReceiverSummaryOrigins(s.instantiateTaintSummary(effect, args, argNodes), receiverRoot)
			unionMapEntry(s.propTaint, receiverRoot+"."+path, applied)
			s.instantiateSummaryStructuralWrites(s.propTaint, receiverRoot+"."+path, effect, argNodes)
			if receiverRoot == "this" {
				unionMapEntry(s.receiverWrites, path, applied)
			}
		}
		for path, family := range summary.ReceiverStorageLinks {
			dstRoot := receiverRoot + "." + path
			copyPersistentStructuralPathMap(s.propTaint, s.engine.storagePaths, dstRoot, family)
			copyStructuralPathMap(s.propTaint, s.storagePathWrites, dstRoot, family)
			s.recordStructuralStorageLink(dstRoot, family)
			if receiverRoot == "this" {
				s.receiverStorageLinks[path] = family
			}
		}
	}
	if allowStateSideEffects {
		skipPurePersistentReadStateWrites := (s.engine.currentBatchName == "output" || s.engine.currentBatchName == "call") &&
			s.engine.callableHasPersistentReadOnlyStandaloneSourceSummary(key, summary)
		for path, effect := range summary.StaticWrites {
			applied := s.resolveReceiverSummaryOrigins(s.instantiateTaintSummary(effect, args, argNodes), receiverRoot)
			if shouldSkipTransitiveConcreteWrite(effect, applied) {
				continue
			}
			unionMapEntry(s.staticPropTaint, path, applied)
			s.instantiateSummaryStructuralWrites(s.staticPropTaint, path, effect, argNodes)
		}
		for family, effect := range summary.StorageWrites {
			applied := s.annotateStoredWriteOrigins(s.resolveReceiverSummaryOrigins(s.instantiateTaintSummary(effect, args, argNodes), receiverRoot))
			if shouldSkipTransitiveConcreteWrite(effect, applied) {
				continue
			}
			if skipPurePersistentReadStateWrites && originsArePersistentReadOnlyStructural(applied) {
				continue
			}
			unionMapEntry(s.storageWrites, family, applied)
			for _, idx := range effect.Params {
				if idx < 0 || idx >= len(argNodes) {
					continue
				}
				for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[idx]), "") {
					origins = s.annotateStoredWriteOrigins(origins)
					if skipPurePersistentReadStateWrites && originsArePersistentReadOnlyStructural(origins) {
						continue
					}
					unionMapEntry(s.storagePathWrites, family+suffix, origins)
				}
			}
			for _, ref := range effect.ParamPaths {
				if ref.Index < 0 || ref.Index >= len(argNodes) {
					continue
				}
				for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[ref.Index]), ref.Path) {
					origins = s.annotateStoredWriteOrigins(origins)
					if skipPurePersistentReadStateWrites && originsArePersistentReadOnlyStructural(origins) {
						continue
					}
					unionMapEntry(s.storagePathWrites, family+suffix, origins)
				}
			}
		}
		for path, effect := range summary.StoragePathWrites {
			applied := s.annotateStoredWriteOrigins(s.resolveReceiverSummaryOrigins(s.instantiateTaintSummary(effect, args, argNodes), receiverRoot))
			if shouldSkipTransitiveConcreteWrite(effect, applied) {
				continue
			}
			if skipPurePersistentReadStateWrites && originsArePersistentReadOnlyStructural(applied) {
				continue
			}
			for concretePath, origins := range s.instantiateConcreteSummaryPathWrites(path, effect, argNodes) {
				origins = s.annotateStoredWriteOrigins(origins)
				if skipPurePersistentReadStateWrites && originsArePersistentReadOnlyStructural(origins) {
					continue
				}
				unionMapEntry(s.storagePathWrites, concretePath, origins)
			}
			unionMapEntry(s.storagePathWrites, path, applied)
		}
	}

	out := s.instantiateTaintSummary(taintSummary{
		Sources:       summary.ReturnSources,
		SourceOrigins: summary.ReturnSourceOrigins,
		ReceiverPaths: summary.ReturnReceiverPaths,
		Params:        summary.ReturnParams,
		ParamPaths:    summary.ReturnParamPaths,
	}, args, argNodes)
	return s.resolveReceiverSummaryOrigins(out, receiverRoot)
}

func (s *analysisState) allowLocalReceiverSideEffectsAfterMethodCall(call *ast.ExprMethodCall, receiverRoot string) bool {
	if !isSimpleLocalReceiverRoot(receiverRoot) {
		return true
	}
	return localReceiverRootUsedAfter(call, s.current.Stmts, receiverRoot, s.current.Class)
}

func isSimpleLocalReceiverRoot(root string) bool {
	return root != "" && root != "this" && !strings.ContainsAny(root, ".[")
}

func localReceiverRootUsedAfter(target ast.Node, stmts []ast.Node, root string, currentClass string) bool {
	seenTarget := false
	var walk func(ast.Node) bool
	walk = func(node ast.Node) bool {
		if node == nil {
			return false
		}
		if node == target {
			seenTarget = true
			return false
		}
		if seenTarget && nodeReferencesSimpleLocalRoot(node, root, currentClass) {
			return true
		}
		for _, name := range node.SubNodeNames() {
			value := node.SubNode(name)
			switch typed := value.(type) {
			case ast.Node:
				if walk(typed) {
					return true
				}
			case []ast.Node:
				for _, child := range typed {
					if walk(child) {
						return true
					}
				}
			}
		}
		return false
	}
	for _, stmt := range stmts {
		if walk(stmt) {
			return true
		}
	}
	return false
}

func nodeReferencesSimpleLocalRoot(node ast.Node, root string, currentClass string) bool {
	if node == nil {
		return false
	}
	if receiverRootKey(node, currentClass) == root {
		return true
	}
	switch typed := node.(type) {
	case *ast.ExprArrayDimFetch:
		return nodeReferencesSimpleLocalRoot(typed.Var, root, currentClass)
	case *ast.ExprPropertyFetch:
		return nodeReferencesSimpleLocalRoot(typed.Var, root, currentClass)
	}
	return false
}

func (s *analysisState) indexedStorageReadOriginsForCallable(key string) originSet {
	if key == "" {
		return originSet{}
	}
	origins := originSet{}
	for bucket := range s.engine.storageReadBucketsByCallable[key] {
		origins = unionInto(origins, s.storageSelfOrigins(bucket))
		origins = unionInto(origins, s.storageChildOrigins(bucket))
	}
	for family := range s.engine.storageReadFamiliesByCallable[key] {
		origins = unionInto(origins, storageOriginsForFamily(family, s))
	}
	if len(origins) == 0 {
		return origins
	}
	return markPersistentReadOrigins(origins)
}

func shouldSkipTransitiveConcreteWrite(effect taintSummary, applied originSet) bool {
	if len(effect.Params) != 0 || len(effect.ParamPaths) != 0 {
		return false
	}
	return originSetsEquivalent(originsFromTaintSummary(effect), applied)
}

func originsArePersistentReadOnlyStructural(origins originSet) bool {
	if len(origins) == 0 {
		return false
	}
	for _, item := range origins {
		if item.kind != originSource {
			return false
		}
		if !item.persistentRead ||
			item.pathSafe ||
			item.outputSafeHTML ||
			item.outputUnsafeHTML ||
			hasMeaningfulFlowContext(item.storedWriteContext) {
			return false
		}
	}
	return true
}

func (s *analysisState) evalArgs(args []ast.Node) []originSet {
	out := make([]originSet, 0, len(args))
	for _, argNode := range args {
		out = append(out, s.evalExpr(argValue(argNode)))
	}
	return out
}

func (s *analysisState) evalChildren(node ast.Node) originSet {
	var origins originSet
	if node == nil {
		return origins
	}
	for _, name := range node.SubNodeNames() {
		value := node.SubNode(name)
		switch typed := value.(type) {
		case ast.Node:
			origins = unionInto(origins, s.evalExpr(typed))
		case []ast.Node:
			for _, child := range typed {
				origins = unionInto(origins, s.evalExpr(child))
			}
		}
	}
	return origins
}
