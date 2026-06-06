package taintscan

import (
	"runtime"
	"sort"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (e *engine) resetPassWarmSummaryCache() {
	e.passWarmSummaryMu.Lock()
	e.passWarmSummaryCache = map[string]summary{}
	e.passWarmSummaryInflight = map[string]chan struct{}{}
	e.passWarmSummaryMu.Unlock()
}

func (e *engine) clearPassWarmSummaryCache() {
	e.passWarmSummaryMu.Lock()
	e.passWarmSummaryCache = nil
	e.passWarmSummaryInflight = nil
	e.passWarmSummaryMu.Unlock()
}

func (e *engine) getPassWarmSummary(key string) (summary, bool) {
	e.passWarmSummaryMu.RLock()
	item, ok := e.passWarmSummaryCache[key]
	e.passWarmSummaryMu.RUnlock()
	return item, ok
}

func (e *engine) isPassWarmSummaryInflight(key string) bool {
	e.passWarmSummaryMu.RLock()
	_, ok := e.passWarmSummaryInflight[key]
	e.passWarmSummaryMu.RUnlock()
	return ok
}

func (e *engine) hasInflightPassWarmSummary(keys map[string]struct{}) bool {
	if len(keys) == 0 {
		return false
	}
	e.passWarmSummaryMu.RLock()
	defer e.passWarmSummaryMu.RUnlock()
	for key := range keys {
		if _, ok := e.passWarmSummaryInflight[key]; ok {
			return true
		}
	}
	return false
}

func (e *engine) setPassWarmSummary(key string, item summary) {
	e.passWarmSummaryMu.Lock()
	if e.passWarmSummaryCache == nil {
		e.passWarmSummaryCache = map[string]summary{}
	}
	e.passWarmSummaryCache[key] = item
	e.passWarmSummaryMu.Unlock()
}

func (e *engine) getOrComputePassWarmSummary(key string, compute func() summary) summary {
	for {
		e.passWarmSummaryMu.Lock()
		if item, ok := e.passWarmSummaryCache[key]; ok {
			e.passWarmSummaryMu.Unlock()
			return item
		}
		if e.passWarmSummaryInflight == nil {
			e.passWarmSummaryInflight = map[string]chan struct{}{}
		}
		if wait, ok := e.passWarmSummaryInflight[key]; ok {
			e.passWarmSummaryMu.Unlock()
			<-wait
			continue
		}
		wait := make(chan struct{})
		e.passWarmSummaryInflight[key] = wait
		e.passWarmSummaryMu.Unlock()

		item := compute()

		e.passWarmSummaryMu.Lock()
		if e.passWarmSummaryCache == nil {
			e.passWarmSummaryCache = map[string]summary{}
		}
		e.passWarmSummaryCache[key] = item
		delete(e.passWarmSummaryInflight, key)
		close(wait)
		e.passWarmSummaryMu.Unlock()
		return item
	}
}

func (e *engine) analyzeCallable(c callable) summary {
	return e.analyzeCallableWithWarmStack(c, nil)
}

func callableHasReturnExpr(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		if ret, ok := node.(*ast.StmtReturn); ok && ret.Expr != nil {
			found = true
		}
	})
	return found
}

func syntheticActionHelperSummary(c callable) summary {
	return syntheticPassthroughHelperSummary(c)
}

func syntheticOutputHelperSummary(c callable) summary {
	return syntheticPassthroughHelperSummary(c)
}

func syntheticFileHelperSummary(c callable) summary {
	return syntheticPassthroughHelperSummary(c)
}

func syntheticPassthroughHelperSummary(c callable) summary {
	item := summary{}
	if !callableHasReturnExpr(c) {
		return item
	}
	item.ReturnParams = make([]int, 0, len(c.Params))
	for idx := range c.Params {
		item.ReturnParams = append(item.ReturnParams, idx)
	}
	return item
}

func canUseSyntheticOutputWarmSummary(c callable) bool {
	hasReturn := false
	safe := true
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if !safe || node == nil {
			return
		}
		switch node.(type) {
		case *ast.StmtReturn:
			hasReturn = true
		case *ast.ExprFuncCall,
			*ast.ExprMethodCall,
			*ast.ExprStaticCall,
			*ast.ExprNew,
			*ast.ExprAssign,
			*ast.ExprAssignRef,
			*ast.ExprAssignOpPlus,
			*ast.ExprAssignOpMinus,
			*ast.ExprAssignOpMul,
			*ast.ExprAssignOpDiv,
			*ast.ExprAssignOpConcat,
			*ast.ExprAssignOpMod,
			*ast.ExprAssignOpBitwiseAnd,
			*ast.ExprAssignOpBitwiseOr,
			*ast.ExprAssignOpBitwiseXor,
			*ast.ExprAssignOpShiftLeft,
			*ast.ExprAssignOpShiftRight,
			*ast.StmtEcho,
			*ast.ExprPrint,
			*ast.ExprInclude,
			*ast.StmtForeach,
			*ast.StmtFor,
			*ast.StmtWhile,
			*ast.StmtDo,
			*ast.StmtSwitch,
			*ast.StmtTryCatch,
			*ast.ExprThrow,
			*ast.ExprYield,
			*ast.ExprYieldFrom:
			safe = false
		}
	})
	return safe && hasReturn
}

// maxCallableStatements limits per-callable analysis to prevent OOM on
// extremely large functions (e.g., 1000+ line auto-generated switch/case blocks).
// WordPress plugins centralize logic in giant admin-ajax dispatchers and
// settings handlers; a cap that is too low silently drops sinks in those
// handlers. But analyzing very large callables on mega-plugins (WooCommerce-
// scale) drives a transient-allocation OOM that the per-callable heap guard
// (checked only between callables) cannot catch, so the cap must stay
// conservative until per-callable allocation is bounded mid-analysis.
const maxCallableStatements = 2000

// maxStateMapEntries caps the per-callable propTaint, receiverWrites,
// returnPathWrites, and storageWrites maps. This bounds the memory growth
// when analyzing callables in plugins with deep property chains.
const maxStateMapEntries = 128

func countStatements(stmts []ast.Node) int {
	count := 0
	for range stmts {
		count++
		if count > maxCallableStatements {
			return count
		}
	}
	return count
}

func (e *engine) analyzeCallableWithWarmStack(c callable, warmStack map[string]struct{}) summary {
	// Skip excessively large callables to prevent memory explosion.
	if len(c.Stmts) > maxCallableStatements {
		return summary{}
	}
	// Memory-pressure guard. When a hard limit is configured, read the cheap
	// background-sampled gauge (no per-callable stop-the-world ReadMemStats); on
	// pressure, GC and skip this callable. Otherwise fall back to the legacy
	// per-callable 3 GiB check.
	if e.heapHardLimit > 0 {
		if e.underMemoryPressure() {
			runtime.GC()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			e.heapGauge.Store(ms.HeapAlloc)
			if ms.HeapAlloc > e.heapHardLimit {
				return summary{}
			}
		}
	} else {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		if ms.HeapAlloc > 3*1024*1024*1024 { // 3 GiB
			runtime.GC() // Force GC to reclaim memory
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > 2*1024*1024*1024 { // Still above 2 GiB after GC
				return summary{}
			}
		}
	}
	if warmStack != nil && len(e.allowedSinkOps) == 1 {
		if e.allowsSinkOp("action") && !e.callableNeedsActionWarmSummary(c.Key) {
			return syntheticActionHelperSummary(c)
		}
		if e.allowsSinkOp("output") && !e.callableNeedsOutputWarmSummary(c.Key) && canUseSyntheticOutputWarmSummary(c) {
			return syntheticOutputHelperSummary(c)
		}
		if e.usesFileWarmSummaries() && !e.callableNeedsFileWarmSummary(c.Key) {
			return syntheticFileHelperSummary(c)
		}
	}
	activeWarmStack := cloneStringSet(warmStack)
	if activeWarmStack == nil {
		activeWarmStack = map[string]struct{}{}
	}
	activeWarmStack[c.Key] = struct{}{}
	state := analysisState{
		engine:                  e,
		current:                 c,
		varTaint:                map[string]originSet{},
		propTaint:               map[string]originSet{},
		staticPropTaint:         map[string]originSet{},
		classEnv:                map[string]string{},
		stringEnv:               map[string]string{},
		weakIdentifierEnv:       map[string]weakIdentifierHint{},
		safePathVars:            map[string]struct{}{},
		safePathExprSigs:        map[string]struct{}{},
		varPathExprSig:          map[string]string{},
		activeExtractResolves:   map[string]struct{}{},
		sourceHits:              map[string]findingRecord{},
		paramSinks:              map[int]map[string]sinkTemplate{},
		receiverSinks:           map[string]sinkTemplate{},
		returnValue:             originSet{},
		returnPathWrites:        map[string]originSet{},
		returnClasses:           map[string]struct{}{},
		receiverWrites:          map[string]originSet{},
		receiverStorageLinks:    map[string]string{},
		structuralStorageLinks:  map[string]string{},
		storageWrites:           map[string]originSet{},
		storagePathWrites:       map[string]originSet{},
		hasRecordRead:           e.callableHasRecordRead(c.Key),
		includeStack:            map[string]struct{}{c.Key: {}},
		summaryWarmCache:        map[string]summary{},
		summaryWarmStack:        activeWarmStack,
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}
	for idx, param := range c.Params {
		origins := makeOriginSet(origin{kind: originParam, paramIdx: idx})
		if sourceOrigin, ok := e.entrypointParamOrigin(c, idx); ok {
			origins = origins.union(makeOriginSet(sourceOrigin))
		}
		state.varTaint[param] = origins
	}
	state.walkStatements(c.Stmts)
	state.returnValue = state.filterCurrentBatchReturnOrigins(state.returnValue)
	state.returnPathWrites = state.filterCurrentBatchReturnPathWrites(state.returnPathWrites)

	out := summary{
		ReturnSources:        make([]Location, 0),
		ReturnSourceOrigins:  make([]sourceOriginRef, 0),
		ReturnReceiverPaths:  make([]receiverPathRef, 0),
		ReturnParams:         make([]int, 0),
		ReturnParamPaths:     make([]paramPathRef, 0),
		ReturnPathWrites:     map[string]taintSummary{},
		ReturnClasses:        make([]string, 0),
		SourceFindings:       make([]findingRecord, 0, len(state.sourceHits)),
		ParamFindings:        map[int][]sinkTemplate{},
		ReceiverFindings:     make([]sinkTemplate, 0, len(state.receiverSinks)),
		StaticWrites:         map[string]taintSummary{},
		ReceiverWrites:       map[string]taintSummary{},
		ReceiverPathWrites:   map[string]taintSummary{},
		ReceiverStorageLinks: map[string]string{},
		StorageWrites:        map[string]taintSummary{},
		StoragePathWrites:    map[string]taintSummary{},
	}

	returnParams := map[int]struct{}{}
	returnParamPaths := map[string]paramPathRef{}
	returnSources := map[string]Location{}
	returnSourceOrigins := map[string]sourceOriginRef{}
	returnReceiverPaths := map[string]receiverPathRef{}
	for _, item := range state.returnValue.sorted() {
		switch item.kind {
		case originParam:
			if item.paramPath != "" || item.persistentRead || item.pathSafe || item.outputSafeHTML || item.outputUnsafeHTML || hasMeaningfulFlowContext(item.storedWriteContext) {
				key := paramPathSyntheticPrefix(item.paramIdx) + item.paramPath
				ref := returnParamPaths[key]
				ref.Index = item.paramIdx
				ref.Path = item.paramPath
				ref.PersistentRead = ref.PersistentRead || item.persistentRead
				ref.PathSafe = ref.PathSafe || item.pathSafe
				ref.OutputSafeHTML = ref.OutputSafeHTML || item.outputSafeHTML
				ref.OutputUnsafeHTML = ref.OutputUnsafeHTML || item.outputUnsafeHTML
				ref.StoredWriteContext = mergeOptionalFlowContext(ref.StoredWriteContext, item.storedWriteContext)
				returnParamPaths[key] = ref
				continue
			}
			returnParams[item.paramIdx] = struct{}{}
		case originSource:
			returnSources[locationKey(item.source)] = item.source
			if item.persistentRead || item.pathSafe || item.outputSafeHTML || item.outputUnsafeHTML || hasMeaningfulFlowContext(item.storedWriteContext) {
				ref := returnSourceOrigins[locationKey(item.source)]
				ref.Location = item.source
				ref.PersistentRead = ref.PersistentRead || item.persistentRead
				ref.PathSafe = ref.PathSafe || item.pathSafe
				ref.OutputSafeHTML = ref.OutputSafeHTML || item.outputSafeHTML
				ref.OutputUnsafeHTML = ref.OutputUnsafeHTML || item.outputUnsafeHTML
				ref.StoredWriteContext = mergeOptionalFlowContext(ref.StoredWriteContext, item.storedWriteContext)
				returnSourceOrigins[locationKey(item.source)] = ref
			}
		case originReceiver:
			key := item.receiverPath
			ref := returnReceiverPaths[key]
			ref.Path = item.receiverPath
			ref.PersistentRead = ref.PersistentRead || item.persistentRead
			ref.PathSafe = ref.PathSafe || item.pathSafe
			ref.OutputSafeHTML = ref.OutputSafeHTML || item.outputSafeHTML
			ref.OutputUnsafeHTML = ref.OutputUnsafeHTML || item.outputUnsafeHTML
			ref.StoredWriteContext = mergeOptionalFlowContext(ref.StoredWriteContext, item.storedWriteContext)
			returnReceiverPaths[key] = ref
		}
	}
	for param := range returnParams {
		out.ReturnParams = append(out.ReturnParams, param)
	}
	sort.Ints(out.ReturnParams)
	returnParamPaths = compactParamPathRefsByRoot(returnParamPaths)
	for _, key := range sortedKeys(returnParamPaths) {
		out.ReturnParamPaths = append(out.ReturnParamPaths, returnParamPaths[key])
	}
	for _, loc := range sortedLocations(returnSources) {
		out.ReturnSources = append(out.ReturnSources, loc)
	}
	for _, key := range sortedKeys(returnSourceOrigins) {
		out.ReturnSourceOrigins = append(out.ReturnSourceOrigins, returnSourceOrigins[key])
	}
	returnReceiverPaths = compactReceiverPathRefsByRoot(returnReceiverPaths)
	for _, key := range sortedKeys(returnReceiverPaths) {
		out.ReturnReceiverPaths = append(out.ReturnReceiverPaths, returnReceiverPaths[key])
	}
	for path, origins := range compactStoragePathsByRoot(state.returnPathWrites) {
		out.ReturnPathWrites[path] = summarizeOriginsCompacted(origins)
	}
	for _, className := range sortedStringSet(state.returnClasses) {
		out.ReturnClasses = append(out.ReturnClasses, className)
	}
	for _, key := range sortedKeys(state.sourceHits) {
		out.SourceFindings = append(out.SourceFindings, state.sourceHits[key])
	}
	for param, items := range state.paramSinks {
		keys := sortedKeysTemplate(items)
		list := make([]sinkTemplate, 0, len(keys))
		for _, key := range keys {
			list = append(list, items[key])
		}
		out.ParamFindings[param] = list
	}
	for _, key := range sortedKeysTemplate(state.receiverSinks) {
		out.ReceiverFindings = append(out.ReceiverFindings, state.receiverSinks[key])
	}
	for path, origins := range compactStaticPropsByRoot(state.staticPropTaint) {
		out.StaticWrites[path] = summarizeOriginsCompacted(origins)
	}
	for name, origins := range state.receiverWrites {
		out.ReceiverWrites[name] = summarizeOriginsCompacted(origins)
	}
	receiverPathWrites := map[string]originSet{}
	for path, origins := range state.propTaint {
		if !strings.HasPrefix(path, "this.") {
			continue
		}
		receiverPathWrites[strings.TrimPrefix(path, "this.")] = origins
	}
	for path, origins := range compactStoragePathsByRoot(receiverPathWrites) {
		out.ReceiverPathWrites[path] = summarizeOriginsCompacted(origins)
	}
	for path, family := range state.receiverStorageLinks {
		out.ReceiverStorageLinks[path] = family
	}
	if state.engine != nil && state.engine.currentBatchName == "output" {
		out = filterSummaryReceiverEffectsCoveredByStorageLinks(out)
	}
	storageWriteOrigins := state.storageWrites
	storagePathOrigins := state.storagePathWrites
	if state.engine != nil && state.engine.currentBatchName == "output" {
		storageWriteOrigins = state.filterCurrentBatchPersistentReadStorageOrigins(storageWriteOrigins)
		storagePathOrigins = state.filterCurrentBatchPersistentReadStorageOrigins(storagePathOrigins)
	}
	if state.engine != nil && state.engine.currentBatchName == "delete" {
		storagePathOrigins = filterDeleteStoragePathWrites(storagePathOrigins)
	}
	storageWrites, storagePathWrites := summarizeStorageEffects(storageWriteOrigins, storagePathOrigins)
	storageWrites, storagePathWrites = state.filterCurrentBatchStorageEffects(storageWrites, storagePathWrites)
	for family, effect := range storageWrites {
		out.StorageWrites[family] = effect
	}
	for path, effect := range storagePathWrites {
		out.StoragePathWrites[path] = effect
	}
	if !callableCanReplayReceiverEffects(state.current) {
		out.ReceiverFindings = nil
	}
	if state.shouldCompactCurrentOutputSummaryToStorageContextOnly(out) {
		out = filterSummaryForOutputWriterContextOnly(out)
	}
	if allowedReturnPaths, ok := state.currentAssignedReturnPathInterest(out); ok {
		out = filterSummaryForAssignedReturnReplayWithRootDrop(out, allowedReturnPaths, state.shouldDropAssignedReturnRoots(out))
	}
	if state.shouldCompactCurrentOutputSummaryToBooleanContextOnly(out) {
		out = summary{}
	}
	if state.shouldCompactCurrentDeleteSummaryToRendererContextOnly(out) {
		out = filterSummaryForDeleteRendererContextOnly(out)
	}
	if state.shouldCompactCurrentActionSummaryToSinkContextOnly(out) {
		out = filterSummaryForActionSinkContextOnly(out)
	}
	if state.shouldCompactCurrentIncludeSummaryToRendererContextOnly(out) {
		out = filterSummaryForDeleteRendererContextOnly(out)
	}
	if state.engine != nil && state.engine.currentBatchUsesPathLikeStorageInterest() {
		out = filterSummaryForFilePathLikeCallInterest(out)
	}
	return out
}

func callableCanReplayReceiverEffects(c callable) bool {
	return c.Class != "" && !c.Static
}

func (e *engine) callableHasDirectOutputSyntax(c callable) bool {
	if e == nil {
		return false
	}
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.StmtReturn:
			found = engineCallableReturnsPublicMarkup(e, c.Key)
		case *ast.StmtEcho, *ast.ExprPrint:
			found = true
		case *ast.ExprFuncCall:
			found = isDisclosureOutputFunc(normalizeName(identifierText(typed.Name))) && len(typed.Args) > 0
		}
	})
	return found
}

func filterSummaryForOutputWriterContextOnly(item summary) summary {
	item.ReturnSources = nil
	item.ReturnSourceOrigins = nil
	item.ReturnReceiverPaths = nil
	item.ReturnParams = nil
	item.ReturnParamPaths = nil
	item.ReturnPathWrites = nil
	item.ReturnClasses = nil
	item.SourceFindings = nil
	item.ParamFindings = nil
	item.ReceiverFindings = nil
	item.StaticWrites = nil
	item.ReceiverWrites = nil
	item.ReceiverPathWrites = nil
	item.ReceiverStorageLinks = nil
	return item
}

func filterSummaryForDeleteRendererContextOnly(item summary) summary {
	item.SourceFindings = nil
	item.ReturnSources = nil
	item.ReturnSourceOrigins = nil
	item.ReturnReceiverPaths = nil
	item.ReturnParams = nil
	item.ReturnParamPaths = nil
	item.ReturnPathWrites = nil
	item.ReturnClasses = nil
	item.StaticWrites = nil
	item.ReceiverWrites = nil
	item.ReceiverPathWrites = nil
	item.ReceiverStorageLinks = nil
	item.StorageWrites = nil
	item.StoragePathWrites = nil
	return item
}

func filterSummaryForActionSinkContextOnly(item summary) summary {
	item.ReturnSources = nil
	item.ReturnSourceOrigins = nil
	item.ReturnReceiverPaths = nil
	item.ReturnParams = nil
	item.ReturnParamPaths = nil
	item.ReturnPathWrites = nil
	item.ReturnClasses = nil
	item.StaticWrites = nil
	item.ReceiverWrites = nil
	item.ReceiverPathWrites = nil
	item.ReceiverStorageLinks = nil
	item.StorageWrites = nil
	item.StoragePathWrites = nil
	return item
}

func (s *analysisState) shouldCompactCurrentOutputSummaryToStorageContextOnly(item summary) bool {
	if s == nil || s.engine == nil {
		return false
	}
	if s.engine.currentBatchName != "output" {
		return false
	}
	if !s.engine.callableIsStorageWriter(s.current.Key) {
		return false
	}
	if s.engine.callableHasDirectSink(s.current) {
		return false
	}
	if len(s.engine.outputSinkRelevantUseOrders[s.current.Key]) != 0 {
		return false
	}
	if summaryHasReturnEffects(item) {
		return false
	}
	return true
}

func (s *analysisState) shouldCompactCurrentOutputSummaryToBooleanContextOnly(item summary) bool {
	if s == nil || s.engine == nil {
		return false
	}
	if s.engine.currentBatchName != "output" {
		return false
	}
	if s.engine.callableHasDirectSink(s.current) ||
		s.engine.callableIsStorageWriter(s.current.Key) ||
		s.engine.callableHasSupportedCrossRequestWriter(s.current.Key) {
		return false
	}
	if !summaryHasOnlyReturnEffects(item) {
		return false
	}
	return s.engine.callableHasOnlyBooleanRelevantOutputUses(s.current.Key)
}

func (s *analysisState) shouldCompactCurrentDeleteSummaryToRendererContextOnly(item summary) bool {
	if s == nil || s.engine == nil {
		return false
	}
	if s.engine.currentBatchName != "delete" || len(s.engine.allowedSinkOps) != 1 || !s.engine.allowsSinkOp("delete") {
		return false
	}
	if !s.engine.callableHasDirectOutputSyntax(s.current) {
		return false
	}
	if s.engine.callableHasDirectSink(s.current) ||
		s.engine.callableIsStorageWriter(s.current.Key) ||
		s.engine.callableHasSupportedCrossRequestWriter(s.current.Key) {
		return false
	}
	if len(s.engine.fileSinkRelevantUseOrders[s.current.Key]) != 0 {
		return false
	}
	if len(item.SourceFindings) != 0 &&
		(s.engine.callableHasDirectRequestInput(s.current) ||
			s.engine.callableHasEntrypointSourceParam(s.current) ||
			s.engine.callableHasDirectCallSource(s.current) ||
			s.engine.callableHasDirectSQLReadSource(s.current)) {
		return false
	}
	return len(item.SourceFindings) != 0 ||
		len(item.ReturnSources) != 0 ||
		len(item.ReturnSourceOrigins) != 0 ||
		len(item.ReturnReceiverPaths) != 0 ||
		len(item.ReturnParams) != 0 ||
		len(item.ReturnParamPaths) != 0 ||
		len(item.ReturnPathWrites) != 0 ||
		len(item.ReturnClasses) != 0 ||
		len(item.StaticWrites) != 0 ||
		len(item.ReceiverWrites) != 0 ||
		len(item.ReceiverPathWrites) != 0 ||
		len(item.ReceiverStorageLinks) != 0 ||
		len(item.StorageWrites) != 0 ||
		len(item.StoragePathWrites) != 0
}

func (s *analysisState) shouldCompactCurrentActionSummaryToSinkContextOnly(item summary) bool {
	if s == nil || s.engine == nil {
		return false
	}
	if s.engine.currentBatchName != "action" || !s.engine.allowsSinkOp("action") {
		return false
	}
	if !s.engine.callableHasDirectSink(s.current) {
		return false
	}
	if summaryHasReturnEffects(item) {
		return false
	}
	return len(item.SourceFindings) != 0 ||
		len(item.ParamFindings) != 0 ||
		len(item.ReceiverFindings) != 0 ||
		len(item.StaticWrites) != 0 ||
		len(item.ReceiverWrites) != 0 ||
		len(item.ReceiverPathWrites) != 0 ||
		len(item.ReceiverStorageLinks) != 0 ||
		len(item.StorageWrites) != 0 ||
		len(item.StoragePathWrites) != 0
}

func (s *analysisState) shouldCompactCurrentIncludeSummaryToRendererContextOnly(item summary) bool {
	if s == nil || s.engine == nil {
		return false
	}
	if s.engine.currentBatchName != "include" || len(s.engine.allowedSinkOps) != 1 || !s.engine.allowsSinkOp("include") {
		return false
	}
	if !s.engine.callableHasDirectOutputSyntax(s.current) {
		return false
	}
	if s.engine.callableHasDirectRequestInput(s.current) ||
		s.engine.callableHasEntrypointSourceParam(s.current) ||
		s.engine.callableHasDirectCallSource(s.current) ||
		s.engine.callableHasDirectSQLReadSource(s.current) {
		return false
	}
	if s.engine.callableHasDirectSink(s.current) ||
		s.engine.callableIsStorageWriter(s.current.Key) ||
		s.engine.callableHasSupportedCrossRequestWriter(s.current.Key) {
		return false
	}
	if len(s.engine.fileSinkRelevantUseOrders[s.current.Key]) != 0 {
		return false
	}
	return len(item.SourceFindings) != 0 ||
		len(item.ReturnSources) != 0 ||
		len(item.ReturnSourceOrigins) != 0 ||
		len(item.ReturnReceiverPaths) != 0 ||
		len(item.ReturnParams) != 0 ||
		len(item.ReturnParamPaths) != 0 ||
		len(item.ReturnPathWrites) != 0 ||
		len(item.ReturnClasses) != 0 ||
		len(item.StaticWrites) != 0 ||
		len(item.ReceiverWrites) != 0 ||
		len(item.ReceiverPathWrites) != 0 ||
		len(item.ReceiverStorageLinks) != 0 ||
		len(item.StorageWrites) != 0 ||
		len(item.StoragePathWrites) != 0
}

func (s *analysisState) currentAssignedReturnPathInterest(item summary) (map[string]struct{}, bool) {
	if s == nil || s.engine == nil {
		return nil, false
	}
	if !s.engine.currentBatchUsesAssignedReturnPathInterest() {
		return nil, false
	}
	if s.engine.callableHasDirectSink(s.current) ||
		s.engine.callableIsStorageWriter(s.current.Key) ||
		s.engine.callableHasSupportedCrossRequestWriter(s.current.Key) {
		return nil, false
	}
	if !summaryHasReturnEffects(item) {
		return nil, false
	}
	if s.engine.currentBatchName == "output" {
		if !summaryHasOnlyReturnEffects(item) && !summaryHasOnlyReturnAndPersistentReadStorageEffects(item) {
			return nil, false
		}
		return s.engine.outputAssignedReturnPathInterestForCallable(s.current.Key)
	}
	if s.engine.currentBatchName == "call" {
		if !summaryHasOnlyReturnEffects(item) && !summaryHasOnlyReturnAndPersistentReadStorageEffects(item) {
			return nil, false
		}
		return s.engine.callAssignedReturnPathInterestForCallable(s.current.Key)
	}
	if s.engine.currentBatchName == "action" {
		if !summaryHasOnlyReturnEffects(item) {
			return nil, false
		}
		return s.engine.actionAssignedReturnPathInterestForCallable(s.current.Key)
	}
	if s.engine.currentBatchUsesPathLikeStorageInterest() {
		if !summaryHasOnlyReturnEffects(item) && !summaryHasReplayableAssignedReturnEffects(item) {
			return nil, false
		}
		return s.engine.fileAssignedReturnPathInterestForCallable(s.current.Key)
	}
	return nil, false
}

func summaryHasReplayableAssignedReturnEffects(item summary) bool {
	if len(item.ReturnParamPaths) == 0 && len(item.ReturnPathWrites) == 0 && len(item.ReturnReceiverPaths) == 0 {
		return false
	}
	return len(item.ParamFindings) == 0 &&
		len(item.ReceiverFindings) == 0 &&
		len(item.StaticWrites) == 0 &&
		len(item.ReceiverWrites) == 0 &&
		len(item.ReceiverPathWrites) == 0 &&
		len(item.ReceiverStorageLinks) == 0 &&
		len(item.StorageWrites) == 0 &&
		len(item.StoragePathWrites) == 0
}

func (s *analysisState) filterCurrentBatchStorageEffects(storageWrites, storagePathWrites map[string]taintSummary) (map[string]taintSummary, map[string]taintSummary) {
	if s == nil || s.engine == nil {
		return storageWrites, storagePathWrites
	}
	if (s.engine.currentBatchName == "output" || s.engine.currentBatchName == "call") &&
		s.currentCallableHasPersistentReadOnlyStandaloneSource() {
		return nil, nil
	}
	if s.engine.currentBatchName == "include" {
		return filterFileBatchStorageWritesForCallInterest(storageWrites), filterFileBatchStorageWritesForCallInterest(storagePathWrites)
	}
	return storageWrites, storagePathWrites
}

func (s *analysisState) filterCurrentBatchPersistentReadStorageOrigins(writes map[string]originSet) map[string]originSet {
	if s == nil || s.engine == nil || len(writes) == 0 {
		return writes
	}
	if s.engine.currentBatchName != "output" && s.engine.currentBatchName != "call" {
		return writes
	}
	if !s.engine.callableHasDirectOutputSyntax(s.current) ||
		s.engine.callableIsStorageWriter(s.current.Key) ||
		s.engine.callableHasSupportedCrossRequestWriter(s.current.Key) {
		return writes
	}
	filtered := map[string]originSet{}
	for key, origins := range writes {
		next := originSet{}
		for originKey, item := range origins {
			if item.persistentRead {
				continue
			}
			next[originKey] = item
		}
		if len(next) == 0 {
			continue
		}
		filtered[key] = next
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func (s *analysisState) filterCurrentBatchReturnOrigins(origins originSet) originSet {
	if s == nil || s.engine == nil || len(origins) == 0 {
		return origins
	}
	if s.engine.currentBatchName != "output" || !s.currentCallableHasPersistentReadOnlyStandaloneSource() {
		return origins
	}
	filtered := originSet{}
	for key, item := range origins {
		if item.outputSafeHTML && !item.outputUnsafeHTML {
			continue
		}
		filtered[key] = item
	}
	return filtered
}

func (s *analysisState) filterCurrentBatchReturnPathWrites(writes map[string]originSet) map[string]originSet {
	if s == nil || s.engine == nil || len(writes) == 0 {
		return writes
	}
	if s.engine.currentBatchName != "output" || !s.currentCallableHasPersistentReadOnlyStandaloneSource() {
		return writes
	}
	filtered := map[string]originSet{}
	for path, origins := range writes {
		next := s.filterCurrentBatchReturnOrigins(origins)
		if len(next) == 0 {
			continue
		}
		filtered[path] = next
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryForAssignedReturnReplay(item summary, allowedReturnPaths map[string]struct{}) summary {
	return filterSummaryForAssignedReturnReplayWithRootDrop(item, allowedReturnPaths, false)
}

func filterSummaryForAssignedReturnReplayWithRootDrop(item summary, allowedReturnPaths map[string]struct{}, dropRootForExplicitPaths bool) summary {
	if len(allowedReturnPaths) == 0 {
		return item
	}
	hadExplicitReturnPathEffects := len(item.ReturnParamPaths) != 0 || len(item.ReturnPathWrites) != 0 || len(item.ReturnReceiverPaths) != 0
	item.ReturnParamPaths = filterSummaryReturnParamPathsForAssignedInterest(item.ReturnParamPaths, allowedReturnPaths)
	item.ReturnPathWrites = filterSummaryWritesForAssignedInterest(item.ReturnPathWrites, allowedReturnPaths)
	item.ReturnReceiverPaths = filterSummaryReturnReceiverPathsForAssignedInterest(item.ReturnReceiverPaths, allowedReturnPaths)
	if (dropRootForExplicitPaths && hadExplicitReturnPathEffects) || summaryAssignedReturnPathsCovered(item, allowedReturnPaths) {
		item.ReturnSources = nil
		item.ReturnSourceOrigins = nil
		item.ReturnParams = nil
		item.ReturnClasses = nil
	}
	if dropRootForExplicitPaths && summaryHasOnlyPersistentReadStorageSideEffects(item) {
		item.StorageWrites = nil
		item.StoragePathWrites = nil
	}
	return item
}

func collapseSummaryAssignedReturnToRoot(item summary) summary {
	if !summaryHasReturnEffects(item) {
		return item
	}
	returnSources := map[string]Location{}
	returnSourceOrigins := map[string]sourceOriginRef{}
	returnParams := map[int]struct{}{}
	returnParamPaths := map[string]paramPathRef{}
	returnReceiverPaths := map[string]receiverPathRef{}

	mergeSourceOrigin := func(ref sourceOriginRef) {
		key := locationKey(ref.Location)
		returnSources[key] = ref.Location
		existing := returnSourceOrigins[key]
		existing.Location = ref.Location
		existing.PersistentRead = existing.PersistentRead || ref.PersistentRead
		existing.PathSafe = existing.PathSafe || ref.PathSafe
		existing.OutputSafeHTML = existing.OutputSafeHTML || ref.OutputSafeHTML
		existing.OutputUnsafeHTML = existing.OutputUnsafeHTML || ref.OutputUnsafeHTML
		existing.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, ref.StoredWriteContext)
		returnSourceOrigins[key] = existing
	}
	mergeParamRoot := func(idx int) {
		if _, ok := returnParamPaths[paramPathSyntheticPrefix(idx)]; ok {
			return
		}
		returnParams[idx] = struct{}{}
	}
	mergeParamRootRef := func(ref paramPathRef) {
		ref.Path = ""
		if !ref.PersistentRead &&
			!ref.PathSafe &&
			!ref.OutputSafeHTML &&
			!ref.OutputUnsafeHTML &&
			!hasMeaningfulFlowContext(ref.StoredWriteContext) {
			mergeParamRoot(ref.Index)
			return
		}
		delete(returnParams, ref.Index)
		unionParamPathRefEntry(returnParamPaths, paramPathSyntheticPrefix(ref.Index), ref)
	}
	mergeReceiverRootRef := func(ref receiverPathRef) {
		ref.Path = ""
		unionReceiverPathRefEntry(returnReceiverPaths, "", ref)
	}
	mergeRootEffect := func(effect taintSummary) {
		for _, loc := range effect.Sources {
			returnSources[locationKey(loc)] = loc
		}
		for _, ref := range effect.SourceOrigins {
			mergeSourceOrigin(ref)
		}
		for _, idx := range effect.Params {
			mergeParamRoot(idx)
		}
		for _, ref := range effect.ParamPaths {
			mergeParamRootRef(ref)
		}
		for _, ref := range effect.ReceiverPaths {
			mergeReceiverRootRef(ref)
		}
	}

	for _, loc := range item.ReturnSources {
		returnSources[locationKey(loc)] = loc
	}
	for _, ref := range item.ReturnSourceOrigins {
		mergeSourceOrigin(ref)
	}
	for _, idx := range item.ReturnParams {
		mergeParamRoot(idx)
	}
	for _, ref := range item.ReturnParamPaths {
		mergeParamRootRef(ref)
	}
	for _, ref := range item.ReturnReceiverPaths {
		mergeReceiverRootRef(ref)
	}
	for _, effect := range item.ReturnPathWrites {
		mergeRootEffect(effect)
	}

	item.ReturnSources = sortedLocations(returnSources)
	item.ReturnSourceOrigins = item.ReturnSourceOrigins[:0]
	for _, key := range sortedKeys(returnSourceOrigins) {
		item.ReturnSourceOrigins = append(item.ReturnSourceOrigins, returnSourceOrigins[key])
	}
	item.ReturnParams = item.ReturnParams[:0]
	paramIndexes := make([]int, 0, len(returnParams))
	for idx := range returnParams {
		paramIndexes = append(paramIndexes, idx)
	}
	sort.Ints(paramIndexes)
	item.ReturnParams = append(item.ReturnParams, paramIndexes...)
	item.ReturnParamPaths = item.ReturnParamPaths[:0]
	for _, key := range sortedKeys(returnParamPaths) {
		item.ReturnParamPaths = append(item.ReturnParamPaths, returnParamPaths[key])
	}
	item.ReturnReceiverPaths = item.ReturnReceiverPaths[:0]
	for _, key := range sortedKeys(returnReceiverPaths) {
		item.ReturnReceiverPaths = append(item.ReturnReceiverPaths, returnReceiverPaths[key])
	}
	item.ReturnPathWrites = nil
	if summaryHasOnlyPersistentReadStorageSideEffects(item) {
		item.StorageWrites = nil
		item.StoragePathWrites = nil
	}
	return item
}

func summaryAssignedReturnPathsCovered(item summary, allowedReturnPaths map[string]struct{}) bool {
	if len(allowedReturnPaths) == 0 {
		return false
	}
	for allowed := range allowedReturnPaths {
		covered := false
		for _, ref := range item.ReturnParamPaths {
			if structuralPathsOverlap(ref.Path, allowed) {
				covered = true
				break
			}
		}
		if !covered {
			for path := range item.ReturnPathWrites {
				if structuralPathsOverlap(path, allowed) {
					covered = true
					break
				}
			}
		}
		if !covered {
			for _, ref := range item.ReturnReceiverPaths {
				if structuralPathsOverlap(ref.Path, allowed) {
					covered = true
					break
				}
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func (s *analysisState) currentBatchAssignedReturnPathsForCall(key string, callLine int) (map[string]struct{}, bool) {
	if s == nil || s.engine == nil || key == "" || callLine <= 0 {
		return nil, false
	}
	if !s.engine.currentBatchUsesAssignedReturnPathInterest() {
		return nil, false
	}
	callerKey := s.current.Key
	if callerKey == "" {
		return nil, false
	}
	relevantOrders := s.engine.currentBatchRelevantUseOrders(callerKey)
	if len(relevantOrders) == 0 {
		return nil, false
	}
	var allowed map[string]struct{}
	matched := false
	for _, site := range s.engine.callSiteEdges[callerKey] {
		if site.callee != key || site.line != callLine || site.assignedRoot == "" {
			continue
		}
		if !callRelevantUseAfter(relevantOrders, site.assignedRoot, site.order) {
			continue
		}
		matched = true
		paths := s.engine.currentBatchAssignedPathsAfter(callerKey, site.assignedRoot, site.order)
		if len(paths) == 0 {
			return nil, false
		}
		if allowed == nil {
			allowed = map[string]struct{}{}
		}
		for path := range paths {
			allowed[path] = struct{}{}
		}
	}
	if !matched || len(allowed) == 0 {
		return nil, false
	}
	return allowed, true
}

func (s *analysisState) currentBatchAssignedReturnRootOnlyForCall(key string, callLine int, item summary) bool {
	if s == nil || s.engine == nil || key == "" || callLine <= 0 {
		return false
	}
	if s.engine.currentBatchName != "output" {
		return false
	}
	if !summaryHasOnlyReturnEffects(item) && !summaryHasOnlyReturnAndPersistentReadStorageEffects(item) {
		return false
	}
	callerKey := s.current.Key
	if callerKey == "" {
		return false
	}
	relevantOrders := s.engine.currentBatchRelevantUseOrders(callerKey)
	if len(relevantOrders) == 0 {
		return false
	}
	matched := false
	for _, site := range s.engine.callSiteEdges[callerKey] {
		if site.callee != key || site.line != callLine {
			continue
		}
		includeAssignedReturn, includeReturns := s.engine.includeAssignedReturnsForCurrentBatch(site, false, relevantOrders)
		if !includeReturns || !includeAssignedReturn {
			continue
		}
		matched = true
		if paths := s.engine.currentBatchAssignedPathsAfter(callerKey, site.assignedRoot, site.order); len(paths) != 0 {
			return false
		}
	}
	return matched
}

func (s *analysisState) summaryForCurrentCall(key string, callLine int) summary {
	item := s.summaryForKey(key)
	if allowedReturnPaths, ok := s.currentBatchAssignedReturnPathsForCall(key, callLine); ok {
		item = filterSummaryForAssignedReturnReplayWithRootDrop(item, allowedReturnPaths, s.shouldDropAssignedReturnRoots(item))
	} else if s.currentBatchAssignedReturnRootOnlyForCall(key, callLine, item) {
		item = collapseSummaryAssignedReturnToRoot(item)
	}
	return item
}

func (s *analysisState) shouldDropAssignedReturnRoots(item summary) bool {
	if s == nil || s.engine == nil {
		return false
	}
	if s.engine.currentBatchUsesPathLikeStorageInterest() {
		return true
	}
	if (s.engine.currentBatchName == "call" || s.engine.currentBatchName == "action") && summaryHasOnlyReturnEffects(item) {
		return true
	}
	if s.engine.currentBatchName == "output" || s.engine.currentBatchName == "call" {
		return summaryHasOnlyReturnAndPersistentReadStorageEffects(item)
	}
	return false
}

func (s *analysisState) currentCallableHasPersistentReadOnlyStandaloneSource() bool {
	if s == nil || s.engine == nil {
		return false
	}
	if s.engine.callableHasRecordReadOnlyStandaloneSource(s.current.Key) {
		return true
	}
	if s.engine.callableHasDirectRequestInput(s.current) ||
		s.engine.callableHasEntrypointSourceParam(s.current) ||
		s.engine.callableHasDirectCallSource(s.current) ||
		s.engine.callableHasDirectSQLReadSource(s.current) {
		return false
	}
	for _, item := range s.returnValue {
		if item.persistentRead {
			return true
		}
	}
	return false
}

func summarizeStorageEffects(rootWrites, pathWrites map[string]originSet) (map[string]taintSummary, map[string]taintSummary) {
	compactedPaths := compactStoragePathsByRoot(pathWrites)
	prunedRoots := pruneStructuralRootOriginsCoveredByChildren(rootWrites, compactedPaths)

	outRoots := map[string]taintSummary{}
	for family, origins := range prunedRoots {
		outRoots[family] = summarizeOrigins(origins)
	}
	outPaths := map[string]taintSummary{}
	for path, origins := range compactedPaths {
		outPaths[path] = summarizeOrigins(origins)
	}
	return outRoots, outPaths
}

func filterDeleteStoragePathWrites(pathWrites map[string]originSet) map[string]originSet {
	if len(pathWrites) == 0 {
		return nil
	}
	filtered := map[string]originSet{}
	for path, origins := range pathWrites {
		if !deleteBatchStorageWriteRelevantToCallInterest(path) {
			continue
		}
		filtered[path] = origins
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

type analysisState struct {
	engine                  *engine
	current                 callable
	// aborted is set when the heap-pressure guard fires mid-analysis; the walk
	// stops, discarding this callable's growing transient state. stmtCounter
	// bounds how often the (cheap) gauge is polled.
	aborted                 bool
	stmtCounter             int
	contextOverride         FlowContext
	varTaint                map[string]originSet
	propTaint               map[string]originSet
	staticPropTaint         map[string]originSet
	classEnv                map[string]string
	stringEnv               map[string]string
	weakIdentifierEnv       map[string]weakIdentifierHint
	safePathVars            map[string]struct{}
	safePathExprSigs        map[string]struct{}
	varPathExprSig          map[string]string
	extractContainers       []ast.Node
	activeExtractResolves   map[string]struct{}
	sourceHits              map[string]findingRecord
	paramSinks              map[int]map[string]sinkTemplate
	receiverSinks           map[string]sinkTemplate
	returnValue             originSet
	returnPathWrites        map[string]originSet
	returnClasses           map[string]struct{}
	receiverWrites          map[string]originSet
	receiverStorageLinks    map[string]string
	structuralStorageLinks  map[string]string
	storageWrites           map[string]originSet
	storagePathWrites       map[string]originSet
	hasRecordRead           bool
	includeStack            map[string]struct{}
	summaryWarmCache        map[string]summary
	summaryWarmStack        map[string]struct{}
	summaryReturnPathCache  map[string]map[string]originSet
	summaryReturnPathActive map[string]struct{}
	inlineReceiverSeq       int
}

func filterSummaryReceiverEffectsCoveredByStorageLinks(item summary) summary {
	if len(item.ReceiverStorageLinks) == 0 {
		return item
	}
	filteredWrites := map[string]taintSummary{}
	for path, effect := range item.ReceiverWrites {
		if receiverEffectCoveredByStorageLinks(path, effect, item.ReceiverStorageLinks) {
			continue
		}
		filteredWrites[path] = effect
	}
	filteredPathWrites := map[string]taintSummary{}
	for path, effect := range item.ReceiverPathWrites {
		if receiverEffectCoveredByStorageLinks(path, effect, item.ReceiverStorageLinks) {
			continue
		}
		filteredPathWrites[path] = effect
	}
	item.ReceiverWrites = filteredWrites
	item.ReceiverPathWrites = filteredPathWrites
	return item
}

func receiverEffectCoveredByStorageLinks(path string, effect taintSummary, links map[string]string) bool {
	if !taintSummaryIsPersistentReadOnlyStructural(effect) {
		return false
	}
	for linkPath := range links {
		if path == linkPath {
			return true
		}
		if _, ok := trimStructuralPrefix(path, linkPath); ok {
			return true
		}
	}
	return false
}

func taintSummaryIsPersistentReadOnlyStructural(effect taintSummary) bool {
	if len(effect.Params) != 0 || len(effect.ParamPaths) != 0 {
		return false
	}
	origins := originsFromTaintSummary(effect)
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

func (s *analysisState) summaryForKey(key string) summary {
	if key == "" {
		return summary{}
	}
	if warmed, ok := s.engine.getPassWarmSummary(key); ok {
		return warmed
	}
	if s.summaryWarmCache != nil {
		if warmed, ok := s.summaryWarmCache[key]; ok {
			return warmed
		}
	}
	item := s.engine.summaries[key]
	if _, analyzed := s.engine.summaryInputFingerprints[key]; analyzed || !summaryHasNoEffects(item) {
		return item
	}
	if len(s.engine.allowedSinkOps) == 1 && key != s.current.Key && (s.engine.allowsSinkOp("call") || s.engine.allowsSinkOp("action")) {
		if strings.HasSuffix(strings.ToLower(key), "::__construct") {
			goto allowWarm
		}
		if _, ok := s.engine.relevantCallables[key]; !ok {
			baseKey := baseCallableKeyForLiteralSpecialization(key)
			if baseKey == "" {
				return item
			}
			if _, ok := s.engine.relevantCallables[baseKey]; !ok {
				return item
			}
		}
		if s.engine.allowsSinkOp("action") && !s.engine.callableNeedsActionWarmSummary(key) {
			return item
		}
	}
allowWarm:
	if _, active := s.summaryWarmStack[key]; active {
		return item
	}
	callable, ok := s.engine.callables[key]
	if !ok {
		return item
	}
	// Avoid cross-goroutine deadlocks where two inflight warm summaries try to
	// wait on each other. If we're already inside another inflight warm chain,
	// compute the requested helper locally with the current warm stack instead of
	// blocking on the global singleflight entry.
	if s.engine.isPassWarmSummaryInflight(key) && s.engine.hasInflightPassWarmSummary(s.summaryWarmStack) {
		warmed := s.engine.analyzeCallableWithWarmStack(callable, s.summaryWarmStack)
		if s.summaryWarmCache == nil {
			s.summaryWarmCache = map[string]summary{}
		}
		s.summaryWarmCache[key] = warmed
		return warmed
	}
	warmed := s.engine.getOrComputePassWarmSummary(key, func() summary {
		return s.engine.analyzeCallableWithWarmStack(callable, s.summaryWarmStack)
	})
	if s.summaryWarmCache == nil {
		s.summaryWarmCache = map[string]summary{}
	}
	// Evict oldest entries when cache exceeds budget to prevent OOM.
	if len(s.summaryWarmCache) >= 128 {
		// Simple eviction: clear the cache. The entries will be re-fetched
		// from the global singleflight cache if needed.
		s.summaryWarmCache = map[string]summary{}
	}
	s.summaryWarmCache[key] = warmed
	return warmed
}
