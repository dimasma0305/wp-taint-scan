package taintscan

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dimasma0305/php-parser-go/ast"
)

type localArrayLiteralAssignment struct {
	line  int
	array *ast.ExprArray
}

type localExprAssignment struct {
	line int
	expr ast.Node
}

type localArrayLiteralResolver struct {
	byName     map[string][]localArrayLiteralAssignment
	exprByName map[string][]localExprAssignment
}

func newLocalArrayLiteralResolver(c callable) *localArrayLiteralResolver {
	resolver := &localArrayLiteralResolver{
		byName:     map[string][]localArrayLiteralAssignment{},
		exprByName: map[string][]localExprAssignment{},
	}
	if len(c.Stmts) == 0 {
		return resolver
	}
	walkNodes(c.Stmts, func(node ast.Node) {
		targetName, expr, line, ok := localExprAssignmentParts(node)
		if !ok {
			return
		}
		resolver.exprByName[targetName] = append(resolver.exprByName[targetName], localExprAssignment{
			line: line,
			expr: expr,
		})
		arrayNode, ok := expr.(*ast.ExprArray)
		if !ok {
			return
		}
		resolver.byName[targetName] = append(resolver.byName[targetName], localArrayLiteralAssignment{
			line:  line,
			array: arrayNode,
		})
	})
	for name := range resolver.byName {
		assignments := resolver.byName[name]
		sort.Slice(assignments, func(i, j int) bool {
			return assignments[i].line < assignments[j].line
		})
		resolver.byName[name] = assignments
	}
	for name := range resolver.exprByName {
		assignments := resolver.exprByName[name]
		sort.Slice(assignments, func(i, j int) bool {
			return assignments[i].line < assignments[j].line
		})
		resolver.exprByName[name] = assignments
	}
	return resolver
}

// localArrayLiteralResolver returns the cached resolver for a callable, building
// it once per callable for the whole scan. The resolver is read-only and purely
// AST-derived, so it is safe to share across passes, batches, and worker
// goroutines.
func (e *engine) localArrayLiteralResolver(c callable) *localArrayLiteralResolver {
	if e == nil || e.localArrayResolvers == nil || c.Key == "" {
		return newLocalArrayLiteralResolver(c)
	}
	if v, ok := e.localArrayResolvers.Load(c.Key); ok {
		return v.(*localArrayLiteralResolver)
	}
	r := newLocalArrayLiteralResolver(c)
	actual, _ := e.localArrayResolvers.LoadOrStore(c.Key, r)
	return actual.(*localArrayLiteralResolver)
}

func localExprAssignmentParts(node ast.Node) (string, ast.Node, int, bool) {
	var target ast.Node
	var expr ast.Node
	var line int
	switch typed := node.(type) {
	case *ast.ExprAssign:
		target = typed.Var
		expr = typed.Expr
		line = typed.StartLine()
	case *ast.ExprAssignOpConcat:
		target = typed.Var
		expr = typed.Expr
		line = typed.StartLine()
	default:
		return "", nil, 0, false
	}
	targetVar, ok := target.(*ast.ExprVariable)
	if !ok {
		return "", nil, 0, false
	}
	targetName, ok := targetVar.Name.(string)
	if !ok || targetName == "" || line <= 0 || expr == nil {
		return "", nil, 0, false
	}
	return targetName, expr, line, true
}

func (r *localArrayLiteralResolver) latest(name string, beforeLine int) (*ast.ExprArray, int) {
	if r == nil || name == "" {
		return nil, -1
	}
	assignments := r.byName[name]
	if len(assignments) == 0 {
		return nil, -1
	}
	if beforeLine <= 0 {
		best := assignments[len(assignments)-1]
		return best.array, best.line
	}
	idx := sort.Search(len(assignments), func(i int) bool {
		return assignments[i].line >= beforeLine
	})
	if idx == 0 {
		return nil, -1
	}
	best := assignments[idx-1]
	return best.array, best.line
}

func (r *localArrayLiteralResolver) latestExpr(name string, beforeLine int) (ast.Node, int) {
	if r == nil || name == "" {
		return nil, -1
	}
	assignments := r.exprByName[name]
	if len(assignments) == 0 {
		return nil, -1
	}
	if beforeLine <= 0 {
		best := assignments[len(assignments)-1]
		return best.expr, best.line
	}
	idx := sort.Search(len(assignments), func(i int) bool {
		return assignments[i].line >= beforeLine
	})
	if idx == 0 {
		return nil, -1
	}
	best := assignments[idx-1]
	return best.expr, best.line
}

func (e *engine) relevantCallOrder() []string {
	if len(e.relevantCallables) == 0 {
		if len(e.allowedSinkOps) != 0 {
			return nil
		}
		return e.callOrder
	}
	sqlOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("sql")
	outputOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("output")
	actionOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("action")
	fileOnlyMode := len(e.allowedSinkOps) == 1 && (e.allowsSinkOp("delete") || e.allowsSinkOp("read") || e.allowsSinkOp("open") || e.allowsSinkOp("include"))
	combinedFileWarmMode := e.usesFileWarmSummaries() && len(e.allowedSinkOps) > 1
	out := make([]string, 0, len(e.callOrder))
	for _, key := range e.callOrder {
		if _, ok := e.relevantCallables[key]; ok {
			if combinedFileWarmMode && e.callableIsInertNonReturningHelperForFileBatch(key) {
				continue
			}
			if sqlOnlyMode && e.callableIsInertFileWrapperForSQLBatch(key) {
				continue
			}
			if sqlOnlyMode && e.callableIsLowValueSQLHelper(key) {
				continue
			}
			if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call") && e.callableIsInertFileWrapperForCallBatch(key) {
				continue
			}
			if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call") && e.callableIsOrphanFileDirectSinkForCallBatch(key) {
				continue
			}
			if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call") && e.callableIsLowValueCallWrapper(key) {
				continue
			}
			if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call") && e.callableIsOrphanNonSinkCallHelper(key) {
				continue
			}
			if outputOnlyMode && e.callableIsLowValueOutputWrapper(key) {
				continue
			}
			if actionOnlyMode && e.callableIsLowValueActionHelper(key) {
				continue
			}
			if fileOnlyMode && e.callableIsLowValueFileWrapperForFileBatch(key) {
				continue
			}
			out = append(out, key)
		}
	}
	if len(out) == 0 {
		return e.callOrder
	}
	return out
}

func (e *engine) callableIsInertFileWrapperForSQLBatch(key string) bool {
	c, ok := e.callables[key]
	if !ok || !callableIsFileWrapper(c) {
		return false
	}
	if e.callableHasDirectSink(c) {
		return false
	}
	if e.callableHasDirectRequestInput(c) {
		return false
	}
	if e.callableHasEntrypointSourceParam(c) {
		return false
	}
	return true
}

func (e *engine) callableIsLowValueSQLHelper(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	ctx := e.contexts[key]
	if len(e.sqlSinkRelevantUseOrders[key]) != 0 {
		return false
	}
	entryParam := e.callableHasEntrypointSourceParam(c)
	if entryParam {
		return false
	}
	incomingData := e.callableHasIncomingDataCarrier(key)
	if incomingData {
		return false
	}
	if len(e.directEntryPointsByCallable[key]) == 0 {
		switch ctx.Access {
		case "nonce_only", "authenticated", "capability_checked":
			return true
		}
	}
	directRequest := e.callableHasDirectRequestInput(c)
	if directRequest {
		return false
	}
	if !e.callableHasDirectSink(c) {
		return true
	}
	return !e.callableHasPublicLikeEntrypoint(key)
}

func (e *engine) callableHasIncomingDataCarrier(key string) bool {
	if key == "" {
		return false
	}
	for caller := range e.reverseCallEdges[key] {
		for _, site := range e.callSiteEdges[caller] {
			if site.callee == key && site.dataCarrier {
				return true
			}
		}
	}
	return false
}

func (e *engine) callableIsInertFileWrapperForCallBatch(key string) bool {
	c, ok := e.callables[key]
	if !ok || !callableIsFileWrapper(c) {
		return false
	}
	if e.callableHasDirectSink(c) || e.callableHasDirectRequestInput(c) {
		return false
	}
	return true
}

func (e *engine) callableIsLowValueFileWrapperForFileBatch(key string) bool {
	c, ok := e.callables[key]
	if !ok || !callableIsFileWrapper(c) {
		return false
	}
	if e.callableHasDirectSink(c) {
		return false
	}
	if len(e.fileSinkRelevantUseOrders[key]) != 0 {
		return false
	}
	if e.callableHasEntrypointSourceParam(c) {
		return false
	}
	if e.callableHasIncomingDataCarrier(key) {
		return false
	}
	if len(e.directEntryPointsByCallable[key]) != 0 && e.callableHasPublicLikeEntrypoint(key) {
		return false
	}
	return true
}

func (e *engine) callableIsInertNonReturningHelperForFileBatch(key string) bool {
	c, ok := e.callables[key]
	if !ok || callableHasReturnExpr(c) {
		return false
	}
	return !e.callableNeedsFileWarmSummary(key)
}

func (e *engine) callableIsLowValueCallWrapper(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	if e.callableHasDirectSink(c) || e.callInputConsumingCallables[key] || e.callableHasDirectRequestInput(c) {
		return false
	}
	return len(e.directEntryPointsByCallable[key]) == 0
}

func (e *engine) callableIsLowValueOutputWrapper(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	if e.callableHasDirectSink(c) || e.callableHasDirectRequestInput(c) || e.callableHasEntrypointSourceParam(c) {
		return false
	}
	if e.callableHasRecordRead(key) || e.callableIsStorageWriter(key) || e.callableHasSupportedCrossRequestWriter(key) {
		return false
	}
	if len(e.outputSinkRelevantUseOrders[key]) != 0 {
		return false
	}
	if len(e.storageReadFamiliesByCallable[key]) != 0 || len(e.storageReadBucketsByCallable[key]) != 0 {
		return false
	}
	if len(e.directEntryPointsByCallable[key]) != 0 {
		return false
	}
	hasReturn := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if hasReturn || node == nil {
			return
		}
		if ret, ok := node.(*ast.StmtReturn); ok && ret.Expr != nil {
			hasReturn = true
		}
	})
	return !hasReturn
}

func (e *engine) callableHasOnlyBooleanRelevantOutputUses(key string) bool {
	if e == nil || key == "" {
		return false
	}
	if len(e.allowedSinkOps) != 1 || !e.allowsSinkOp("output") {
		return false
	}
	if len(e.relevantCallables) != 0 {
		if _, ok := e.relevantCallables[key]; !ok {
			return false
		}
	}
	hasUse := false
	for caller := range e.reverseCallEdges[key] {
		if len(e.relevantCallables) != 0 {
			if _, ok := e.relevantCallables[caller]; !ok {
				continue
			}
		}
		for _, site := range e.callSiteEdges[caller] {
			if site.callee != key {
				continue
			}
			hasUse = true
			if !site.booleanUse ||
				site.assignedRoot != "" ||
				site.dataCarrier ||
				site.receiverCarrier ||
				site.receiverStateRelevant {
				return false
			}
		}
	}
	return hasUse
}

func (e *engine) outputAssignedReturnPathInterestForCallable(key string) (map[string]struct{}, bool) {
	if e == nil || key == "" {
		return nil, false
	}
	if len(e.allowedSinkOps) != 1 || !e.allowsSinkOp("output") {
		return nil, false
	}
	if len(e.relevantCallables) != 0 {
		if _, ok := e.relevantCallables[key]; !ok {
			return nil, false
		}
	}
	allowed := map[string]struct{}{}
	hasInterest := false
	for caller := range e.reverseCallEdges[key] {
		if len(e.relevantCallables) != 0 {
			if _, ok := e.relevantCallables[caller]; !ok {
				continue
			}
		}
		relevantOrders := e.outputSinkRelevantUseOrders[caller]
		for _, site := range e.callSiteEdges[caller] {
			if site.callee != key {
				continue
			}
			includeAssignedReturn, includeReturns := e.includeAssignedReturnsForCurrentBatch(site, false, relevantOrders)
			if includeReturns || site.booleanUse || site.receiverCarrier || site.receiverStateRelevant {
				return nil, false
			}
			if !includeAssignedReturn {
				continue
			}
			paths := e.outputRelevantAssignedPathsAfter(caller, site.assignedRoot, site.order)
			if len(paths) == 0 {
				return nil, false
			}
			hasInterest = true
			for path := range paths {
				allowed[path] = struct{}{}
			}
		}
	}
	if !hasInterest || len(allowed) == 0 {
		return nil, false
	}
	return allowed, true
}

func (e *engine) callAssignedReturnPathInterestForCallable(key string) (map[string]struct{}, bool) {
	if e == nil || key == "" {
		return nil, false
	}
	if e.currentBatchName != "call" {
		return nil, false
	}
	if len(e.relevantCallables) != 0 {
		if _, ok := e.relevantCallables[key]; !ok {
			return nil, false
		}
	}
	allowed := map[string]struct{}{}
	hasInterest := false
	for caller := range e.reverseCallEdges[key] {
		if len(e.relevantCallables) != 0 {
			if _, ok := e.relevantCallables[caller]; !ok {
				continue
			}
		}
		relevantOrders := e.callSinkRelevantUseOrders[caller]
		for _, site := range e.callSiteEdges[caller] {
			if site.callee != key {
				continue
			}
			includeAssignedReturn, includeReturns := e.includeAssignedReturnsForCurrentBatch(site, false, relevantOrders)
			if site.booleanUse || site.receiverCarrier || site.receiverStateRelevant {
				return nil, false
			}
			if !includeAssignedReturn {
				if includeReturns {
					return nil, false
				}
				continue
			}
			paths := e.callRelevantAssignedPathsAfter(caller, site.assignedRoot, site.order)
			if len(paths) == 0 {
				return nil, false
			}
			hasInterest = true
			for path := range paths {
				allowed[path] = struct{}{}
			}
		}
	}
	if !hasInterest || len(allowed) == 0 {
		return nil, false
	}
	return allowed, true
}

func (e *engine) actionAssignedReturnPathInterestForCallable(key string) (map[string]struct{}, bool) {
	if e == nil || key == "" {
		return nil, false
	}
	if e.currentBatchName != "action" {
		return nil, false
	}
	if len(e.relevantCallables) != 0 {
		if _, ok := e.relevantCallables[key]; !ok {
			return nil, false
		}
	}
	allowed := map[string]struct{}{}
	hasInterest := false
	for caller := range e.reverseCallEdges[key] {
		if len(e.relevantCallables) != 0 {
			if _, ok := e.relevantCallables[caller]; !ok {
				continue
			}
		}
		relevantOrders := e.actionSinkRelevantUseOrders[caller]
		for _, site := range e.callSiteEdges[caller] {
			if site.callee != key {
				continue
			}
			includeAssignedReturn, includeReturns := e.includeAssignedReturnsForCurrentBatch(site, false, relevantOrders)
			if site.booleanUse || site.receiverCarrier || site.receiverStateRelevant {
				return nil, false
			}
			if !includeAssignedReturn {
				if includeReturns {
					return nil, false
				}
				continue
			}
			paths := e.actionRelevantAssignedPathsAfter(caller, site.assignedRoot, site.order)
			if len(paths) == 0 {
				return nil, false
			}
			hasInterest = true
			for path := range paths {
				allowed[path] = struct{}{}
			}
		}
	}
	if !hasInterest || len(allowed) == 0 {
		return nil, false
	}
	return allowed, true
}

func (e *engine) fileAssignedReturnPathInterestForCallable(key string) (map[string]struct{}, bool) {
	if e == nil || key == "" || !e.currentBatchUsesPathLikeStorageInterest() {
		return nil, false
	}
	if len(e.relevantCallables) != 0 {
		if _, ok := e.relevantCallables[key]; !ok {
			return nil, false
		}
	}
	allowed := map[string]struct{}{}
	hasInterest := false
	for caller := range e.reverseCallEdges[key] {
		if len(e.relevantCallables) != 0 {
			if _, ok := e.relevantCallables[caller]; !ok {
				continue
			}
		}
		relevantOrders := e.currentBatchRelevantUseOrders(caller)
		for _, site := range e.callSiteEdges[caller] {
			if site.callee != key {
				continue
			}
			includeAssignedReturn, includeReturns := e.includeAssignedReturnsForCurrentBatch(site, false, relevantOrders)
			if site.booleanUse || site.receiverCarrier || site.receiverStateRelevant {
				return nil, false
			}
			if !includeAssignedReturn {
				if includeReturns {
					return nil, false
				}
				continue
			}
			paths := e.fileRelevantAssignedPathsAfter(caller, site.assignedRoot, site.order)
			if len(paths) == 0 {
				return nil, false
			}
			hasInterest = true
			for path := range paths {
				allowed[path] = struct{}{}
			}
		}
	}
	if !hasInterest || len(allowed) == 0 {
		return nil, false
	}
	return allowed, true
}

func (e *engine) callableIsLowValueActionHelper(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	ctx := e.contexts[key]
	if len(e.actionSinkRelevantUseOrders[key]) != 0 {
		return false
	}
	if e.callableHasDirectSink(c) ||
		e.callableHasDirectRequestInput(c) ||
		e.callableHasEntrypointSourceParam(c) ||
		e.callableHasIncomingDataCarrier(key) ||
		e.callableHasRecordRead(key) ||
		e.callableHasDirectCallSource(c) ||
		e.callableHasDirectSQLReadSource(c) ||
		len(e.storageReadFamiliesByCallable[key]) != 0 ||
		len(e.storageReadBucketsByCallable[key]) != 0 ||
		e.callableIsStorageWriter(key) ||
		e.callableHasSupportedCrossRequestWriter(key) {
		return false
	}
	if len(e.directEntryPointsByCallable[key]) == 0 {
		switch ctx.Access {
		case "nonce_only", "authenticated", "capability_checked":
			return true
		}
	}
	if len(e.directEntryPointsByCallable[key]) != 0 && e.callableHasPublicLikeEntrypoint(key) {
		return false
	}
	return true
}

func (e *engine) callableNeedsActionWarmSummary(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	return e.callableHasDirectSink(c) ||
		len(e.actionSinkRelevantUseOrders[key]) != 0 ||
		e.callableHasDirectRequestInput(c) ||
		e.callableHasEntrypointSourceParam(c) ||
		e.callableHasRecordRead(key) ||
		e.callableHasDirectCallSource(c) ||
		e.callableHasDirectSQLReadSource(c) ||
		len(e.storageReadFamiliesByCallable[key]) != 0 ||
		len(e.storageReadBucketsByCallable[key]) != 0 ||
		e.callableIsStorageWriter(key) ||
		e.callableHasSupportedCrossRequestWriter(key)
}

func (e *engine) callableNeedsOutputWarmSummary(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	return e.callableHasDirectSink(c) ||
		len(e.outputSinkRelevantUseOrders[key]) != 0 ||
		e.callableHasDirectRequestInput(c) ||
		e.callableHasEntrypointSourceParam(c) ||
		e.callableHasRecordRead(key) ||
		e.callableHasDirectCallSource(c) ||
		e.callableHasDirectSQLReadSource(c) ||
		len(e.storageReadFamiliesByCallable[key]) != 0 ||
		len(e.storageReadBucketsByCallable[key]) != 0 ||
		e.callableIsStorageWriter(key) ||
		e.callableHasSupportedCrossRequestWriter(key) ||
		engineCallableReturnsPublicMarkup(e, key)
}

func (e *engine) usesFileWarmSummaries() bool {
	if len(e.allowedSinkOps) == 0 {
		return false
	}
	for op := range e.allowedSinkOps {
		switch op {
		case "delete", "read", "open", "include", "write":
		default:
			return false
		}
	}
	return true
}

func (e *engine) callableNeedsFileWarmSummary(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	if callableHasReturnExpr(c) {
		return true
	}
	if e.callableHasDynamicDirectFileSink(c) ||
		len(e.fileSinkRelevantUseOrders[key]) != 0 ||
		e.callableHasEntrypointSourceParam(c) ||
		e.callableHasIncomingDataCarrier(key) ||
		e.callableHasFileRelevantRecordRead(key) ||
		e.callableHasDirectCallSource(c) ||
		e.callableHasDirectSQLReadSource(c) ||
		e.callableHasFileRelevantStorageWriter(key) ||
		e.callableCallsFileRelevantCallee(key) ||
		e.callableHasFileRelevantStateAccess(key) ||
		callableMayNeedDirectReturnHint(c) {
		return true
	}
	return false
}

func (e *engine) callableCallsFileRelevantCallee(key string) bool {
	for _, site := range e.callSiteEdges[key] {
		for _, calleeKey := range fileRelevantCallableKeys(site.callee) {
			callee, ok := e.callables[calleeKey]
			if !ok {
				continue
			}
			if e.callableHasDynamicDirectFileSink(callee) ||
				e.callableHasFileRelevantRecordRead(calleeKey) ||
				e.callableHasFileRelevantStorageWriter(calleeKey) {
				return true
			}
		}
	}
	return false
}

func fileRelevantCallableKeys(key string) []string {
	if key == "" {
		return nil
	}
	baseKey := baseCallableKeyForLiteralSpecialization(key)
	if baseKey == "" || baseKey == key {
		return []string{key}
	}
	return []string{key, baseKey}
}

func (e *engine) callableHasFileRelevantStateAccess(key string) bool {
	if _, ok := e.receiverMutatingCallables[key]; ok {
		return true
	}
	for path := range e.staticReadPathsByCallable[key] {
		if fileStaticStateKeyRelevant(path) {
			return true
		}
	}
	for root := range e.staticReadRootsByCallable[key] {
		if fileStaticStateKeyRelevant(root) {
			return true
		}
	}
	return false
}

func (e *engine) callableHasFileRelevantStorageWriter(key string) bool {
	for family, writers := range e.storageBaseWritersByFamily {
		if !fileStorageFamilyRelevantToStandaloneReturn(family) {
			continue
		}
		if _, ok := writers[key]; ok {
			return true
		}
	}
	for family, writers := range e.storageBaseWritersByFamilyClass {
		if !fileStorageFamilyRelevantToStandaloneReturn(family) {
			continue
		}
		if _, ok := writers[key]; ok {
			return true
		}
	}
	for bucket, writers := range e.storagePathWritersByBucket {
		if !fileStorageBucketRelevantToStandaloneReturn(bucket) {
			continue
		}
		if _, ok := writers[key]; ok {
			return true
		}
	}
	return false
}

func (e *engine) callableHasFileRelevantRecordRead(key string) bool {
	if !e.callableHasRecordRead(key) {
		return false
	}
	readBuckets := filterFileBatchStorageReadBucketsForCallInterest(e.storageReadBucketsByCallable[key])
	if len(readBuckets) != 0 {
		return true
	}
	specificBuckets := map[string]bool{}
	for bucket := range readBuckets {
		family := structuralPathRoot(bucket)
		if bucket != "" && family != "" && bucket != family {
			specificBuckets[family] = true
		}
	}
	readFamilies := filterFileBatchStorageReadFamiliesForCallInterest(e.storageReadFamiliesByCallable[key], specificBuckets)
	return len(readFamilies) != 0
}

func (e *engine) callableIsOrphanFileDirectSinkForCallBatch(key string) bool {
	c, ok := e.callables[key]
	if !ok || !callableIsFileWrapper(c) {
		return false
	}
	if !e.callableHasDirectSink(c) {
		return false
	}
	if len(e.directEntryPointsByCallable[key]) != 0 {
		return false
	}
	if len(e.reverseCallEdges[key]) != 0 {
		return false
	}
	return true
}

func (e *engine) callableIsOrphanNonSinkCallHelper(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	if e.callableHasDirectSink(c) {
		return false
	}
	if len(e.directEntryPointsByCallable[key]) != 0 {
		return false
	}
	if len(e.reverseCallEdges[key]) != 0 {
		return false
	}
	return true
}

func (e *engine) callableIsInternalDispatchCallback(key string) bool {
	if key == "" || len(e.directEntryPointsByCallable[key]) != 0 {
		return false
	}
	for _, callbackKeys := range e.actionCallbacks {
		for _, callbackKey := range callbackKeys {
			if callbackKey == key {
				return true
			}
		}
	}
	for _, callbackKeys := range e.filterCallbacks {
		for _, callbackKey := range callbackKeys {
			if callbackKey == key {
				return true
			}
		}
	}
	return false
}

func (e *engine) literalArgHintForParam(current callable, paramName string) string {
	if current.Key == "" || paramName == "" {
		return ""
	}
	hints := e.literalArgHints[current.Key]
	if hints == nil {
		return ""
	}
	for idx, name := range current.Params {
		if name != paramName {
			continue
		}
		hint := hints[idx]
		if hint == "" || hint == conflictingLiteralArgHint {
			return ""
		}
		return hint
	}
	return ""
}

func literalArgPathHintKey(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			return ""
		}
		builder.WriteString("[")
		builder.WriteString(part)
		builder.WriteString("]")
	}
	return builder.String()
}

func (e *engine) literalArgPathHintForFetch(current callable, fetch *ast.ExprArrayDimFetch) string {
	if current.Key == "" || fetch == nil {
		return ""
	}
	rootName, dims, ok := localArrayFetchPath(fetch)
	if !ok || len(dims) == 0 {
		return ""
	}
	hints := e.literalArgPathHints[current.Key]
	if len(hints) == 0 {
		return ""
	}
	pathKey := literalArgPathHintKey(dims)
	if pathKey == "" {
		return ""
	}
	for idx, name := range current.Params {
		if name != rootName {
			continue
		}
		if values := decodeLiteralArgHintValues(hints[idx][pathKey]); len(values) == 1 {
			return values[0]
		}
		return ""
	}
	return ""
}

const literalArgHintValueSeparator = "\x1f"

func encodeLiteralArgHintValues(values []string) string {
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		return strings.TrimSpace(values[0])
	}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == conflictingLiteralArgHint {
			continue
		}
		duplicate := false
		for _, existing := range cleaned {
			if existing == value {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		cleaned = append(cleaned, value)
	}
	if len(cleaned) == 0 {
		return ""
	}
	if len(cleaned) == 1 {
		return cleaned[0]
	}
	sort.Strings(cleaned)
	return strings.Join(cleaned, literalArgHintValueSeparator)
}

func decodeLiteralArgHintValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == conflictingLiteralArgHint {
		return nil
	}
	if !strings.Contains(raw, literalArgHintValueSeparator) {
		return []string{raw}
	}
	parts := strings.Split(raw, literalArgHintValueSeparator)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == conflictingLiteralArgHint {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func literalArgRootListHintIndex(path string) (int, bool) {
	path = strings.TrimSpace(path)
	if len(path) < 3 || !strings.HasPrefix(path, "[") || !strings.HasSuffix(path, "]") {
		return 0, false
	}
	inner := strings.TrimSpace(path[1 : len(path)-1])
	if inner == "" || strings.Contains(inner, "][") {
		return 0, false
	}
	idx, err := strconv.Atoi(inner)
	if err != nil || idx < 0 {
		return 0, false
	}
	return idx, true
}

func literalArgRootListValues(hints map[string]string) []string {
	if len(hints) == 0 {
		return nil
	}
	valuesByIndex := map[int][]string{}
	for path, value := range hints {
		idx, ok := literalArgRootListHintIndex(path)
		if !ok {
			continue
		}
		values := decodeLiteralArgHintValues(value)
		if len(values) == 0 {
			continue
		}
		valuesByIndex[idx] = appendExactDynamicDispatchValues(valuesByIndex[idx], values)
		if valuesByIndex[idx] == nil {
			delete(valuesByIndex, idx)
		}
	}
	if len(valuesByIndex) == 0 {
		return nil
	}
	indexes := make([]int, 0, len(valuesByIndex))
	for idx := range valuesByIndex {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	out := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		out = appendExactDynamicDispatchValues(out, valuesByIndex[idx])
		if out == nil {
			return nil
		}
	}
	return out
}

func (e *engine) literalArgIterableValuesForParam(current callable, paramName string) []string {
	if e == nil || current.Key == "" || paramName == "" {
		return nil
	}
	if !e.callableUsesParamLiteralIncludeDispatch(current) {
		return nil
	}
	hints := e.literalArgPathHints[current.Key]
	if len(hints) == 0 {
		return nil
	}
	for idx, name := range current.Params {
		if name != paramName {
			continue
		}
		return literalArgRootListValues(hints[idx])
	}
	return nil
}

func (e *engine) callableHasLiteralArgSpecialization(key string) bool {
	return len(e.literalArgHints[key]) != 0 || len(e.literalArgPathHints[key]) != 0
}

func (e *engine) recordLiteralArgHints(callee string, hints map[int]string) {
	if callee == "" || len(hints) == 0 {
		return
	}
	c, ok := e.callables[callee]
	if !ok || len(c.Params) == 0 {
		return
	}
	entry := e.literalArgHints[callee]
	if entry == nil {
		entry = map[int]string{}
		e.literalArgHints[callee] = entry
	}
	for idx, value := range hints {
		if idx < 0 || idx >= len(c.Params) || value == "" {
			continue
		}
		switch existing := entry[idx]; {
		case existing == "":
			entry[idx] = value
		case existing == value || existing == conflictingLiteralArgHint:
			if existing == conflictingLiteralArgHint {
				continue
			}
		default:
			entry[idx] = conflictingLiteralArgHint
		}
	}
}

func (e *engine) indexLiteralArgHints() {
	for idx := 0; idx < len(e.callOrder); idx++ {
		key := e.callOrder[idx]
		_, _, callSites := e.collectDirectCallEdges(e.callables[key])
		for _, site := range callSites {
			e.recordLiteralArgHints(site.callee, site.literalArgs)
		}
	}
}

// topologicalSortCallOrder re-sorts callOrder into callee-before-caller order using
// a DFS post-order traversal over e.callEdges. This ensures that when indexing
// relevance orders (e.g., indexCallSinkRelevantUseOrders), every callee's result is
// already in the global cache when the caller is processed, eliminating the O(N²)
// re-computation that occurs with alphabetical ordering. Cycles are broken at back
// edges: nodes in a cycle are placed in an arbitrary but stable order relative to
// each other.
func (e *engine) topologicalSortCallOrder() {
	n := len(e.callOrder)
	if n == 0 {
		return
	}
	// Index existing positions for membership check.
	inOrder := make(map[string]bool, n)
	for _, key := range e.callOrder {
		inOrder[key] = true
	}
	result := make([]string, 0, n)
	visited := make(map[string]bool, n)
	visiting := make(map[string]bool, n)
	var visit func(key string)
	visit = func(key string) {
		if visited[key] || visiting[key] {
			return
		}
		visiting[key] = true
		for callee := range e.callEdges[key] {
			if inOrder[callee] {
				visit(callee)
			}
		}
		delete(visiting, key)
		visited[key] = true
		result = append(result, key)
	}
	// Visit in the existing (alphabetical) order to get a stable sort within SCCs.
	for _, key := range e.callOrder {
		visit(key)
	}
	e.callOrder = result
}

func (e *engine) buildCallGraph() {
	for idx := 0; idx < len(e.callOrder); idx++ {
		key := e.callOrder[idx]
		c := e.callables[key]
		allCallees, dataCallees, callSites := e.collectDirectCallEdges(c)
		for _, callee := range allCallees {
			if callee == "" {
				continue
			}
			targets := e.callEdges[key]
			if targets == nil {
				targets = map[string]struct{}{}
				e.callEdges[key] = targets
			}
			targets[callee] = struct{}{}
			callers := e.reverseCallEdges[callee]
			if callers == nil {
				callers = map[string]struct{}{}
				e.reverseCallEdges[callee] = callers
			}
			callers[key] = struct{}{}
		}
		for _, callee := range dataCallees {
			if callee == "" {
				continue
			}
			targets := e.dataCallEdges[key]
			if targets == nil {
				targets = map[string]struct{}{}
				e.dataCallEdges[key] = targets
			}
			targets[callee] = struct{}{}
		}
		e.callSiteEdges[key] = append([]callSiteEdge(nil), callSites...)
	}
}

func (e *engine) indexGlobalStateReaders() {
	for _, key := range e.callOrder {
		c := e.callables[key]
		literalSpecialized := e.callableHasLiteralArgSpecialization(key)
		var walk func(ast.Node, ast.Node)
		walk = func(node ast.Node, parent ast.Node) {
			if node == nil {
				return
			}
			switch typed := node.(type) {
			case *ast.StmtIf:
				walk(typed.Cond, node)
				if literalSpecialized {
					if truth, ok := e.literalConditionTruthForCallable(typed.Cond, c, map[string]struct{}{}); ok {
						if truth {
							for _, stmt := range typed.Stmts {
								walk(stmt, nil)
							}
							return
						}
						allElseifsKnown := true
						for _, elseifNode := range typed.Elseifs {
							elseifStmt, ok := elseifNode.(*ast.StmtElseIf)
							if !ok {
								continue
							}
							walk(elseifStmt.Cond, node)
							elseifTruth, elseifKnown := e.literalConditionTruthForCallable(elseifStmt.Cond, c, map[string]struct{}{})
							if !elseifKnown {
								allElseifsKnown = false
								break
							}
							if elseifTruth {
								for _, stmt := range elseifStmt.Stmts {
									walk(stmt, nil)
								}
								return
							}
						}
						if allElseifsKnown {
							if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
								for _, stmt := range elseStmt.Stmts {
									walk(stmt, nil)
								}
							}
							return
						}
					}
				}
				for _, stmt := range typed.Stmts {
					walk(stmt, nil)
				}
				for _, elseifNode := range typed.Elseifs {
					elseifStmt, ok := elseifNode.(*ast.StmtElseIf)
					if !ok {
						continue
					}
					walk(elseifStmt.Cond, node)
					for _, stmt := range elseifStmt.Stmts {
						walk(stmt, nil)
					}
				}
				if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
					for _, stmt := range elseStmt.Stmts {
						walk(stmt, nil)
					}
				}
				return
			case *ast.StmtSwitch:
				walk(typed.Cond, node)
				if literalSpecialized {
					if cases, ok := literalSwitchCasesForCallable(typed, c, e); ok {
						for _, caseStmt := range cases {
							if caseStmt.Cond != nil {
								walk(caseStmt.Cond, node)
							}
							for _, stmt := range caseStmt.Stmts {
								walk(stmt, nil)
							}
							if branchDefinitelyAborts(caseStmt.Stmts) {
								break
							}
						}
						return
					}
				}
				for _, rawCase := range typed.Cases {
					caseStmt, ok := rawCase.(*ast.StmtCase)
					if !ok {
						continue
					}
					if caseStmt.Cond != nil {
						walk(caseStmt.Cond, node)
					}
					for _, stmt := range caseStmt.Stmts {
						walk(stmt, nil)
					}
				}
				return
			}
			switch typed := node.(type) {
			case *ast.ExprFuncCall:
				if spec, ok := storageReadSpecForFunc(normalizeName(identifierText(typed.Name))); ok {
					if root, ok := storageRootForArgs(spec, typed.Args); ok {
						e.recordStorageReadFamily(key, structuralPathRoot(root))
						e.recordStorageReadBucket(key, root)
						e.indexStoragePathReader(root, key)
						break
					}
					if family := storageFamilyForSpec(spec, typed.Args); family != "" {
						e.recordStorageReadFamily(key, family)
						readers := e.storageBaseReadersByFamily[family]
						if readers == nil {
							readers = map[string]struct{}{}
							e.storageBaseReadersByFamily[family] = readers
						}
						readers[key] = struct{}{}
					}
				}
			case *ast.ExprMethodCall:
				if columns, _, ok := sqlSelectColumnsForMethodCallWithContext(typed, c, e, typed.StartLine()); ok {
					for _, column := range columns {
						if column.Family == "" {
							continue
						}
						e.recordStorageReadFamily(key, column.Family)
						readers := e.storageBaseReadersByFamily[column.Family]
						if readers == nil {
							readers = map[string]struct{}{}
							e.storageBaseReadersByFamily[column.Family] = readers
						}
						readers[key] = struct{}{}
					}
				} else if strings.EqualFold(identifierText(typed.Name), "get_results") && len(typed.Args) != 0 {
					if tableKey := sqlSelectTableKeyForNodeWithContext(argValue(typed.Args[0]), c, e, typed.StartLine()); tableKey != "" {
						root := "db_table_value[" + tableKey + "]"
						e.recordStorageReadFamily(key, root)
						e.recordStorageReadBucket(key, root)
						e.indexStoragePathReader(root, key)
						readers := e.storageBaseReadersByFamily[root]
						if readers == nil {
							readers = map[string]struct{}{}
							e.storageBaseReadersByFamily[root] = readers
						}
						readers[key] = struct{}{}
					}
				}
			case *ast.ExprStaticPropertyFetch:
				if path, ok := staticPropertyPathKey(typed, c.Class, e); ok {
					if isCompoundAssignTarget(parent, node) {
						break
					}
					root := structuralPathRoot(path)
					if root != "" {
						e.recordStaticReadRoot(key, root)
						if parentArray, ok := parent.(*ast.ExprArrayDimFetch); ok && parentArray.Var == node {
							e.recordStaticReadPath(key, path)
							e.indexStaticPathReader(path, key)
							break
						}
						readers := e.staticBaseReadersByRoot[root]
						if readers == nil {
							readers = map[string]struct{}{}
							e.staticBaseReadersByRoot[root] = readers
						}
						readers[key] = struct{}{}
					}
				}
			case *ast.ExprConstFetch:
				if path, ok := staticPropertyPathKey(typed, c.Class, e); ok {
					root := structuralPathRoot(path)
					if root != "" {
						e.recordStaticReadRoot(key, root)
						readers := e.staticBaseReadersByRoot[root]
						if readers == nil {
							readers = map[string]struct{}{}
							e.staticBaseReadersByRoot[root] = readers
						}
						readers[key] = struct{}{}
					}
				}
			case *ast.ExprArrayDimFetch:
				if path, ok := storagePathKey(typed); ok {
					e.recordStorageReadFamily(key, structuralPathRoot(path))
					e.recordStorageReadBucket(key, path)
					e.indexStoragePathReader(path, key)
				}
				if path, ok := staticPropertyPathKey(typed, c.Class, e); ok {
					if isCompoundAssignTarget(parent, node) {
						break
					}
					e.recordStaticReadRoot(key, structuralPathRoot(path))
					e.recordStaticReadPath(key, path)
					e.indexStaticPathReader(path, key)
				}
			case *ast.ExprPropertyFetch:
				if family, ok := storageFamilyExpr(typed); ok {
					if parentArray, ok := parent.(*ast.ExprArrayDimFetch); !ok || parentArray.Var != node {
						e.recordStorageReadFamily(key, family)
						readers := e.storageBaseReadersByFamily[family]
						if readers == nil {
							readers = map[string]struct{}{}
							e.storageBaseReadersByFamily[family] = readers
						}
						readers[key] = struct{}{}
					}
				}
			}
			for _, name := range node.SubNodeNames() {
				value := node.SubNode(name)
				switch typed := value.(type) {
				case ast.Node:
					walk(typed, node)
				case []ast.Node:
					for _, child := range typed {
						walk(child, node)
					}
				}
			}
		}
		for _, stmt := range c.Stmts {
			walk(stmt, nil)
		}
	}
}

func (e *engine) recordStorageReadFamily(key string, family string) {
	if key == "" || family == "" {
		return
	}
	families := e.storageReadFamiliesByCallable[key]
	if families == nil {
		families = map[string]struct{}{}
		e.storageReadFamiliesByCallable[key] = families
	}
	families[family] = struct{}{}
}

func (e *engine) recordStorageReadBucket(key string, path string) {
	if key == "" || path == "" {
		return
	}
	bucket := storagePathRelevanceBucket(path)
	if bucket == "" {
		return
	}
	buckets := e.storageReadBucketsByCallable[key]
	if buckets == nil {
		buckets = map[string]struct{}{}
		e.storageReadBucketsByCallable[key] = buckets
	}
	buckets[bucket] = struct{}{}
}

func (e *engine) indexStoragePathReader(path string, key string) {
	if path == "" {
		return
	}
	readers := e.storagePathReadersByExact[path]
	if readers == nil {
		readers = map[string]struct{}{}
		e.storagePathReadersByExact[path] = readers
	}
	readers[key] = struct{}{}
	if !strings.Contains(path, "[*]") {
		return
	}
	bucket := storageStablePathBucket(path)
	if bucket == "" {
		return
	}
	bucketReaders := e.storagePathReadersByBucket[bucket]
	if bucketReaders == nil {
		bucketReaders = map[string]struct{}{}
		e.storagePathReadersByBucket[bucket] = bucketReaders
	}
	bucketReaders[key] = struct{}{}
}

func (e *engine) indexGlobalStateWriters() {
	for _, key := range e.callOrder {
		c := e.callables[key]
		resolver := e.localArrayLiteralResolver(c)
		walkNodes(c.Stmts, func(node ast.Node) {
			if node == nil {
				return
			}
			switch typed := node.(type) {
			case *ast.ExprFuncCall:
				for _, family := range storageWriteFamiliesForFuncCallSyntax(typed) {
					e.indexStorageWriterFamily(key, family, c.Class)
				}
				for _, bucket := range storageWriteBucketsForFuncCallSyntax(typed, c, resolver) {
					e.indexStorageWriterBucket(key, bucket, c.Class)
				}
			case *ast.ExprMethodCall:
				for _, family := range storageWriteFamiliesForMethodCallSyntax(typed, c, resolver) {
					e.indexStorageWriterFamily(key, family, c.Class)
				}
				for _, bucket := range storageWriteBucketsForMethodCallSyntax(typed, c, resolver) {
					e.indexStorageWriterBucket(key, bucket, c.Class)
				}
			case *ast.ExprStaticCall:
				for _, family := range storageWriteFamiliesForStaticCallSyntax(typed, c, resolver) {
					e.indexStorageWriterFamily(key, family, c.Class)
				}
				for _, bucket := range storageWriteBucketsForStaticCallSyntax(typed, c, resolver) {
					e.indexStorageWriterBucket(key, bucket, c.Class)
				}
			}
		})
	}
}

func (e *engine) ensureGlobalStateWritersIndexed() {
	if e.storageBaseWritersByFamily != nil &&
		e.storageBaseWritersByFamilyClass != nil &&
		e.storagePathWritersByBucket != nil &&
		e.storagePathWritersByBucketClass != nil {
		return
	}
	e.storageBaseWritersByFamily = map[string]map[string]struct{}{}
	e.storageBaseWritersByFamilyClass = map[string]map[string]struct{}{}
	e.storagePathWritersByBucket = map[string]map[string]struct{}{}
	e.storagePathWritersByBucketClass = map[string]map[string]struct{}{}
	e.indexGlobalStateWriters()
}

func (e *engine) indexStorageWriterFamily(key string, family string, className string) {
	if key == "" || family == "" {
		return
	}
	writers := e.storageBaseWritersByFamily[family]
	if writers == nil {
		writers = map[string]struct{}{}
		e.storageBaseWritersByFamily[family] = writers
	}
	writers[key] = struct{}{}
	if className == "" {
		return
	}
	composite := storageWriterFamilyClassKey(family, className)
	classWriters := e.storageBaseWritersByFamilyClass[composite]
	if classWriters == nil {
		classWriters = map[string]struct{}{}
		e.storageBaseWritersByFamilyClass[composite] = classWriters
	}
	classWriters[key] = struct{}{}
}

func storageWriterFamilyClassKey(family string, className string) string {
	return family + "|" + normalizeName(className)
}

func storageWriterBucketClassKey(bucket string, className string) string {
	return bucket + "|" + normalizeName(className)
}

func (e *engine) indexStorageWriterBucket(key string, path string, className string) {
	if key == "" || path == "" {
		return
	}
	bucket := storagePathRelevanceBucket(path)
	if bucket == "" {
		return
	}
	writers := e.storagePathWritersByBucket[bucket]
	if writers == nil {
		writers = map[string]struct{}{}
		e.storagePathWritersByBucket[bucket] = writers
	}
	writers[key] = struct{}{}
	if className == "" {
		return
	}
	composite := storageWriterBucketClassKey(bucket, className)
	classWriters := e.storagePathWritersByBucketClass[composite]
	if classWriters == nil {
		classWriters = map[string]struct{}{}
		e.storagePathWritersByBucketClass[composite] = classWriters
	}
	classWriters[key] = struct{}{}
}

func storageWriteFamiliesForFuncCallSyntax(call *ast.ExprFuncCall) []string {
	families := map[string]struct{}{}
	for family := range postRecordWriteFamiliesForFuncCallSyntax(call) {
		families[family] = struct{}{}
	}
	spec, ok := storageWriteSpecForFunc(normalizeName(identifierText(call.Name)))
	if ok {
		if family := storageFamilyForSpec(spec, call.Args); family != "" {
			families[family] = struct{}{}
		}
	}
	if len(families) == 0 {
		return nil
	}
	out := make([]string, 0, len(families))
	for family := range families {
		out = append(out, family)
	}
	return out
}

func storageWriteBucketsForFuncCallSyntax(call *ast.ExprFuncCall, c callable, resolver *localArrayLiteralResolver) []string {
	buckets := map[string]struct{}{}
	for bucket := range postRecordWriteBucketsForFuncCallSyntax(call, c, resolver) {
		buckets[bucket] = struct{}{}
	}
	spec, ok := storageWriteSpecForFunc(normalizeName(identifierText(call.Name)))
	if ok && spec.valueArg >= 0 && spec.valueArg < len(call.Args) {
		if root, ok := storageRootForArgs(spec, call.Args); ok {
			for bucket := range storageWriteBucketsFromValueSyntax(root, argValue(call.Args[spec.valueArg]), c, call.StartLine(), resolver) {
				buckets[bucket] = struct{}{}
			}
		}
	}
	if len(buckets) == 0 {
		return nil
	}
	out := make([]string, 0, len(buckets))
	for bucket := range buckets {
		out = append(out, bucket)
	}
	return out
}

func storageWriteFamiliesForMethodCallSyntax(call *ast.ExprMethodCall, c callable, resolver *localArrayLiteralResolver) []string {
	name := strings.ToLower(identifierText(call.Name))
	families := map[string]struct{}{}
	switch name {
	case "query":
		if len(call.Args) > 0 {
			for _, family := range parseSQLWriteFamilies(sqlQueryString(argValue(call.Args[0]))) {
				families[family] = struct{}{}
			}
		}
	case "insert", "update", "replace":
		if len(call.Args) >= 2 {
			for family := range storageWriteFamiliesFromPayloadSyntax(argValue(call.Args[1]), c, call.StartLine(), resolver) {
				families[family] = struct{}{}
			}
		}
	case "use_insert", "use_update":
		if len(call.Args) >= 1 {
			for family := range storageWriteFamiliesFromPayloadSyntax(argValue(call.Args[0]), c, call.StartLine(), resolver) {
				families[family] = struct{}{}
			}
		}
	}
	if len(families) == 0 {
		return nil
	}
	out := make([]string, 0, len(families))
	for family := range families {
		out = append(out, family)
	}
	return out
}

func storageWriteBucketsForMethodCallSyntax(call *ast.ExprMethodCall, c callable, resolver *localArrayLiteralResolver) []string {
	name := strings.ToLower(identifierText(call.Name))
	buckets := map[string]struct{}{}
	switch name {
	case "insert", "update", "replace":
		if len(call.Args) >= 2 {
			for bucket := range storageWriteBucketsFromPayloadSyntax(argValue(call.Args[1]), c, call.StartLine(), resolver) {
				buckets[bucket] = struct{}{}
			}
		}
	case "use_insert", "use_update":
		if len(call.Args) >= 1 {
			for bucket := range storageWriteBucketsFromPayloadSyntax(argValue(call.Args[0]), c, call.StartLine(), resolver) {
				buckets[bucket] = struct{}{}
			}
		}
	}
	if len(buckets) == 0 {
		return nil
	}
	out := make([]string, 0, len(buckets))
	for bucket := range buckets {
		out = append(out, bucket)
	}
	return out
}

func storageWriteFamiliesForStaticCallSyntax(call *ast.ExprStaticCall, c callable, resolver *localArrayLiteralResolver) []string {
	name := strings.ToLower(identifierText(call.Name))
	if !looksLikeWrapperWriteMethod(name) || len(call.Args) == 0 {
		return nil
	}
	families := storageWriteFamiliesFromPayloadSyntax(argValue(call.Args[0]), c, call.StartLine(), resolver)
	if len(families) == 0 {
		return nil
	}
	out := make([]string, 0, len(families))
	for family := range families {
		out = append(out, family)
	}
	return out
}

func storageWriteBucketsForStaticCallSyntax(call *ast.ExprStaticCall, c callable, resolver *localArrayLiteralResolver) []string {
	name := strings.ToLower(identifierText(call.Name))
	if !looksLikeWrapperWriteMethod(name) || len(call.Args) == 0 {
		return nil
	}
	buckets := storageWriteBucketsFromPayloadSyntax(argValue(call.Args[0]), c, call.StartLine(), resolver)
	if len(buckets) == 0 {
		return nil
	}
	out := make([]string, 0, len(buckets))
	for bucket := range buckets {
		out = append(out, bucket)
	}
	return out
}

func looksLikeWrapperWriteMethod(name string) bool {
	switch name {
	case "add", "create", "insert", "replace", "save", "set", "update", "use_insert", "use_update":
		return true
	default:
		return false
	}
}

func storageWriteFamiliesFromPayloadSyntax(node ast.Node, c callable, beforeLine int, resolver *localArrayLiteralResolver) map[string]struct{} {
	if arrayNode, ok := node.(*ast.ExprArray); ok {
		return storageWriteFamiliesFromArrayLiteral(arrayNode)
	}
	if fetch, ok := node.(*ast.ExprArrayDimFetch); ok {
		return storageWriteFamiliesFromLocalArrayFetch(fetch, c, beforeLine, resolver)
	}
	varNode, ok := node.(*ast.ExprVariable)
	if !ok {
		return nil
	}
	name, ok := varNode.Name.(string)
	if !ok || name == "" {
		return nil
	}
	return storageWriteFamiliesFromLocalArrayLiteral(name, c, beforeLine, resolver)
}

func storageWriteBucketsFromPayloadSyntax(node ast.Node, c callable, beforeLine int, resolver *localArrayLiteralResolver) map[string]struct{} {
	if arrayNode, ok := node.(*ast.ExprArray); ok {
		return storageWriteBucketsFromArrayLiteral(arrayNode)
	}
	if fetch, ok := node.(*ast.ExprArrayDimFetch); ok {
		return storageWriteBucketsFromLocalArrayFetch(fetch, c, beforeLine, resolver)
	}
	varNode, ok := node.(*ast.ExprVariable)
	if !ok {
		return nil
	}
	name, ok := varNode.Name.(string)
	if !ok || name == "" {
		return nil
	}
	return storageWriteBucketsFromLocalArrayLiteral(name, c, beforeLine, resolver)
}

func storageWriteFamiliesFromArrayLiteral(arrayNode *ast.ExprArray) map[string]struct{} {
	if arrayNode == nil {
		return nil
	}
	families := map[string]struct{}{}
	for _, itemNode := range arrayNode.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok {
			continue
		}
		key := strings.ToLower(literalString(item.Key))
		if _, ok := storageFamilies[key]; ok {
			families[key] = struct{}{}
		}
	}
	if len(families) == 0 {
		return nil
	}
	return families
}

func storageWriteBucketsFromArrayLiteral(arrayNode *ast.ExprArray) map[string]struct{} {
	if arrayNode == nil {
		return nil
	}
	buckets := map[string]struct{}{}
	for _, itemNode := range arrayNode.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok {
			continue
		}
		key := strings.ToLower(literalString(item.Key))
		if _, ok := storageFamilies[key]; !ok {
			continue
		}
		root := key
		for bucket := range storageWriteBucketsFromValueSyntax(root, item.Value, callable{}, 0, nil) {
			buckets[bucket] = struct{}{}
		}
	}
	if len(buckets) == 0 {
		return nil
	}
	return buckets
}

func storageWriteFamiliesFromLocalArrayLiteral(name string, c callable, beforeLine int, resolver *localArrayLiteralResolver) map[string]struct{} {
	best, _ := latestLocalArrayLiteralAssignment(name, c, beforeLine, resolver)
	if best == nil {
		return nil
	}
	return storageWriteFamiliesFromArrayLiteral(best)
}

func storageWriteBucketsFromLocalArrayLiteral(name string, c callable, beforeLine int, resolver *localArrayLiteralResolver) map[string]struct{} {
	best, _ := latestLocalArrayLiteralAssignment(name, c, beforeLine, resolver)
	if best == nil {
		return nil
	}
	return storageWriteBucketsFromArrayLiteral(best)
}

func storageWriteFamiliesFromLocalArrayFetch(fetch *ast.ExprArrayDimFetch, c callable, beforeLine int, resolver *localArrayLiteralResolver) map[string]struct{} {
	rootName, dims, ok := localArrayFetchPath(fetch)
	if !ok {
		return nil
	}
	best, _ := latestLocalArrayLiteralAssignment(rootName, c, beforeLine, resolver)
	if best == nil {
		return nil
	}
	var current ast.Node = best
	for _, dim := range dims {
		arrayNode, ok := current.(*ast.ExprArray)
		if !ok {
			return nil
		}
		current = arrayValueForStringKey(arrayNode, dim)
		if current == nil {
			return nil
		}
	}
	arrayNode, ok := current.(*ast.ExprArray)
	if !ok {
		return nil
	}
	return storageWriteFamiliesFromArrayLiteral(arrayNode)
}

func storageWriteBucketsFromLocalArrayFetch(fetch *ast.ExprArrayDimFetch, c callable, beforeLine int, resolver *localArrayLiteralResolver) map[string]struct{} {
	rootName, dims, ok := localArrayFetchPath(fetch)
	if !ok {
		return nil
	}
	best, _ := latestLocalArrayLiteralAssignment(rootName, c, beforeLine, resolver)
	if best == nil {
		return nil
	}
	var current ast.Node = best
	for _, dim := range dims {
		arrayNode, ok := current.(*ast.ExprArray)
		if !ok {
			return nil
		}
		current = arrayValueForStringKey(arrayNode, dim)
		if current == nil {
			return nil
		}
	}
	arrayNode, ok := current.(*ast.ExprArray)
	if !ok {
		return nil
	}
	return storageWriteBucketsFromArrayLiteral(arrayNode)
}

func storageWriteBucketsFromValueSyntax(root string, node ast.Node, c callable, beforeLine int, resolver *localArrayLiteralResolver) map[string]struct{} {
	return storageWriteBucketsFromValueSyntaxSeen(root, node, c, beforeLine, resolver, map[string]struct{}{})
}

func storageWriteBucketsFromValueSyntaxSeen(root string, node ast.Node, c callable, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) map[string]struct{} {
	if root == "" || node == nil {
		return nil
	}
	buckets := map[string]struct{}{root: {}}
	key := storageWriteBucketsVisitKey(root, node, c, beforeLine)
	if _, ok := seen[key]; ok {
		return buckets
	}
	seen[key] = struct{}{}
	defer delete(seen, key)
	switch typed := node.(type) {
	case *ast.ExprArray:
		for _, itemNode := range typed.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			childRoot := appendArrayPath(root, item.Key)
			for bucket := range storageWriteBucketsFromValueSyntaxSeen(childRoot, item.Value, c, beforeLine, resolver, seen) {
				buckets[bucket] = struct{}{}
			}
		}
	case *ast.ExprFuncCall:
		for _, idx := range structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args)) {
			for bucket := range storageWriteBucketsFromValueSyntaxSeen(root, argValue(typed.Args[idx]), c, typed.StartLine(), resolver, seen) {
				buckets[bucket] = struct{}{}
			}
		}
	case *ast.ExprMethodCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			for bucket := range storageWriteBucketsFromValueSyntaxSeen(root, argValue(typed.Args[0]), c, typed.StartLine(), resolver, seen) {
				buckets[bucket] = struct{}{}
			}
		}
	case *ast.ExprStaticCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			for bucket := range storageWriteBucketsFromValueSyntaxSeen(root, argValue(typed.Args[0]), c, typed.StartLine(), resolver, seen) {
				buckets[bucket] = struct{}{}
			}
		}
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok && name != "" && c.Key != "" {
			for bucket := range storageWriteBucketsFromLocalValueSeen(name, root, c, beforeLine, resolver, seen) {
				buckets[bucket] = struct{}{}
			}
		}
	case *ast.ExprArrayDimFetch:
		if nested := storageWriteBucketsFromLocalValueFetchSeen(typed, root, c, beforeLine, resolver, seen); len(nested) != 0 {
			for bucket := range nested {
				buckets[bucket] = struct{}{}
			}
		}
	}
	return buckets
}

func storageWriteBucketsVisitKey(root string, node ast.Node, c callable, beforeLine int) string {
	return fmt.Sprintf("%s|%s|%d|%T:%p", c.Key, root, beforeLine, node, node)
}

func storagePathRelevanceBucket(path string) string {
	if path == "" {
		return ""
	}
	if bucket := structuralStablePathBucket(path); bucket != "" {
		return bucket
	}
	return path
}

func storageWriteBucketsFromLocalValue(name string, root string, c callable, beforeLine int) map[string]struct{} {
	return storageWriteBucketsFromLocalValueSeen(name, root, c, beforeLine, nil, map[string]struct{}{})
}

func storageWriteBucketsFromLocalValueSeen(name string, root string, c callable, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) map[string]struct{} {
	best, _ := latestLocalArrayLiteralAssignment(name, c, beforeLine, resolver)
	if best == nil {
		return nil
	}
	return storageWriteBucketsFromValueSyntaxSeen(root, best, c, beforeLine, resolver, seen)
}

func storageWriteBucketsFromLocalValueFetch(fetch *ast.ExprArrayDimFetch, root string, c callable, beforeLine int) map[string]struct{} {
	return storageWriteBucketsFromLocalValueFetchSeen(fetch, root, c, beforeLine, nil, map[string]struct{}{})
}

func storageWriteBucketsFromLocalValueFetchSeen(fetch *ast.ExprArrayDimFetch, root string, c callable, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) map[string]struct{} {
	rootName, dims, ok := localArrayFetchPath(fetch)
	if !ok {
		return nil
	}
	best, _ := latestLocalArrayLiteralAssignment(rootName, c, beforeLine, resolver)
	if best == nil {
		return nil
	}
	var current ast.Node = best
	for _, dim := range dims {
		arrayNode, ok := current.(*ast.ExprArray)
		if !ok {
			return nil
		}
		current = arrayValueForStringKey(arrayNode, dim)
		if current == nil {
			return nil
		}
	}
	return storageWriteBucketsFromValueSyntaxSeen(root, current, c, beforeLine, resolver, seen)
}

func latestLocalArrayLiteralAssignment(name string, c callable, beforeLine int, resolver *localArrayLiteralResolver) (*ast.ExprArray, int) {
	if resolver != nil {
		return resolver.latest(name, beforeLine)
	}
	return newLocalArrayLiteralResolver(c).latest(name, beforeLine)
}

func localArrayFetchPath(fetch *ast.ExprArrayDimFetch) (string, []string, bool) {
	dims := []string{}
	current := fetch
	for {
		key, ok := stableArrayDimKey(current.Dim)
		if !ok {
			return "", nil, false
		}
		dims = append([]string{key}, dims...)
		switch typed := current.Var.(type) {
		case *ast.ExprVariable:
			name, ok := typed.Name.(string)
			if !ok || name == "" {
				return "", nil, false
			}
			return name, dims, true
		case *ast.ExprArrayDimFetch:
			current = typed
		default:
			return "", nil, false
		}
	}
}

func (e *engine) callableIsStorageWriter(key string) bool {
	if _, ok := e.directStorageWriterCallables[key]; ok {
		return true
	}
	for _, writers := range e.storageBaseWritersByFamily {
		if _, ok := writers[key]; ok {
			return true
		}
	}
	for _, writers := range e.storageBaseWritersByFamilyClass {
		if _, ok := writers[key]; ok {
			return true
		}
	}
	return false
}

func (e *engine) indexDirectStorageWriterCallables() {
	if e.directStorageWriterCallables == nil {
		e.directStorageWriterCallables = map[string]struct{}{}
	}
	for _, key := range e.callOrder {
		c := e.callables[key]
		if callableHasDirectStorageWriteSyntax(c) {
			e.directStorageWriterCallables[key] = struct{}{}
		}
	}
}

func callableHasDirectStorageWriteSyntax(c callable) bool {
	resolver := newLocalArrayLiteralResolver(c)
	found := false
	walkNodes(c.Stmts, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			found = len(storageWriteFamiliesForFuncCallSyntax(typed)) != 0
		case *ast.ExprMethodCall:
			found = len(storageWriteFamiliesForMethodCallSyntax(typed, c, resolver)) != 0
		case *ast.ExprStaticCall:
			found = len(storageWriteFamiliesForStaticCallSyntax(typed, c, resolver)) != 0
		}
	})
	return found
}

func postRecordWriteFamiliesForFuncCallSyntax(call *ast.ExprFuncCall) map[string]struct{} {
	fields, _ := postRecordFieldValues(call)
	if len(fields) == 0 {
		return nil
	}
	out := map[string]struct{}{"post_record": {}}
	for field := range fields {
		out[field] = struct{}{}
	}
	return out
}

func postRecordWriteBucketsForFuncCallSyntax(call *ast.ExprFuncCall, c callable, resolver *localArrayLiteralResolver) map[string]struct{} {
	fields, root := postRecordFieldValues(call)
	if len(fields) == 0 || root == "" {
		return nil
	}
	buckets := map[string]struct{}{}
	for field, valueNode := range fields {
		path := root + "." + field
		for bucket := range storageWriteBucketsFromValueSyntax(path, valueNode, c, call.StartLine(), resolver) {
			buckets[bucket] = struct{}{}
		}
	}
	if len(buckets) == 0 {
		return nil
	}
	return buckets
}

func (e *engine) indexStaticPathReader(path string, key string) {
	if path == "" {
		return
	}
	readers := e.staticPathReadersByExact[path]
	if readers == nil {
		readers = map[string]struct{}{}
		e.staticPathReadersByExact[path] = readers
	}
	readers[key] = struct{}{}
	if !strings.Contains(path, "[*]") {
		return
	}
	bucket := staticPathInvalidationBucket(path)
	if bucket == "" {
		return
	}
	bucketReaders := e.staticPathReadersByBucket[bucket]
	if bucketReaders == nil {
		bucketReaders = map[string]struct{}{}
		e.staticPathReadersByBucket[bucket] = bucketReaders
	}
	bucketReaders[key] = struct{}{}
}

func (e *engine) recordStaticReadRoot(key string, root string) {
	if key == "" || root == "" {
		return
	}
	roots := e.staticReadRootsByCallable[key]
	if roots == nil {
		roots = map[string]struct{}{}
		e.staticReadRootsByCallable[key] = roots
	}
	roots[root] = struct{}{}
}

func (e *engine) recordStaticReadPath(key string, path string) {
	if key == "" || path == "" {
		return
	}
	paths := e.staticReadPathsByCallable[key]
	if paths == nil {
		paths = map[string]struct{}{}
		e.staticReadPathsByCallable[key] = paths
	}
	paths[path] = struct{}{}
}

func (e *engine) indexRecordReadCallables() {
	for _, key := range e.callOrder {
		c := e.callables[key]
		found := false
		walkNodes(c.Stmts, func(node ast.Node) {
			if found || node == nil {
				return
			}
			switch typed := node.(type) {
			case *ast.ExprFuncCall:
				if isRecordReadName(identifierText(typed.Name)) && len(typed.Args) > 0 {
					found = true
				}
			case *ast.ExprMethodCall:
				if isRecordReadName(identifierText(typed.Name)) && len(typed.Args) > 0 {
					found = true
				}
			case *ast.ExprStaticCall:
				if isRecordReadName(identifierText(typed.Name)) && len(typed.Args) > 0 {
					found = true
				}
			}
		})
		if found {
			e.recordReadCallables[key] = struct{}{}
		}
	}
}

func (e *engine) indexRequestReachableCallables() {
	reverseQueue := make([]string, 0)
	for _, key := range e.callOrder {
		if e.callableHasDirectRequestInput(e.callables[key]) && e.callableCanSeedStandaloneRequestInput(e.callables[key]) {
			if _, ok := e.requestReachableCallables[key]; !ok {
				e.requestReachableCallables[key] = struct{}{}
				reverseQueue = append(reverseQueue, key)
			}
		}
		if _, ok := e.directPublicCallables[key]; ok {
			e.requestReachableCallables[key] = struct{}{}
		}
	}
	for len(reverseQueue) > 0 {
		key := reverseQueue[0]
		reverseQueue = reverseQueue[1:]
		for caller := range e.reverseCallEdges[key] {
			if _, ok := e.requestReachableCallables[caller]; ok {
				continue
			}
			e.requestReachableCallables[caller] = struct{}{}
			reverseQueue = append(reverseQueue, caller)
		}
	}
	forwardQueue := make([]string, 0, len(e.requestReachableCallables))
	for key := range e.requestReachableCallables {
		forwardQueue = append(forwardQueue, key)
	}
	for len(forwardQueue) > 0 {
		key := forwardQueue[0]
		forwardQueue = forwardQueue[1:]
		for callee := range e.callEdges[key] {
			if _, ok := e.requestReachableCallables[callee]; ok {
				continue
			}
			e.requestReachableCallables[callee] = struct{}{}
			forwardQueue = append(forwardQueue, callee)
		}
	}
}

func (e *engine) indexRequestOriginReachableCallables() {
	reverseQueue := make([]string, 0)
	for _, key := range e.callOrder {
		c := e.callables[key]
		if !e.callableHasEntrypointSourceParam(c) && !(e.callableHasDirectRequestInput(c) && e.callableCanSeedStandaloneRequestInput(c)) {
			continue
		}
		if _, ok := e.requestOriginReachableCallables[key]; ok {
			continue
		}
		e.requestOriginReachableCallables[key] = struct{}{}
		reverseQueue = append(reverseQueue, key)
	}
	for len(reverseQueue) > 0 {
		key := reverseQueue[0]
		reverseQueue = reverseQueue[1:]
		for caller := range e.reverseCallEdges[key] {
			if _, ok := e.requestOriginReachableCallables[caller]; ok {
				continue
			}
			e.requestOriginReachableCallables[caller] = struct{}{}
			reverseQueue = append(reverseQueue, caller)
		}
	}
	forwardQueue := make([]string, 0, len(e.requestOriginReachableCallables))
	for key := range e.requestOriginReachableCallables {
		forwardQueue = append(forwardQueue, key)
	}
	for len(forwardQueue) > 0 {
		key := forwardQueue[0]
		forwardQueue = forwardQueue[1:]
		for callee := range e.callEdges[key] {
			if _, ok := e.requestOriginReachableCallables[callee]; ok {
				continue
			}
			e.requestOriginReachableCallables[callee] = struct{}{}
			forwardQueue = append(forwardQueue, callee)
		}
	}
}

func (e *engine) callableCanSeedStandaloneRequestInput(c callable) bool {
	if !strings.HasPrefix(c.Key, "file::") {
		return true
	}
	if !e.fileHasWordPressBootstrapGuard(c) {
		return true
	}
	return len(e.reverseCallEdges[c.Key]) != 0
}

func (e *engine) indexCallSinkRelevantUseOrders() {
	e.callSinkRelevantUseOrders = map[string]map[string]int{}
	e.callSinkRelevantUsePaths = map[string]map[string]map[string]int{}
	for _, key := range e.callOrder {
		t0 := time.Now()
		orders, paths := e.callSinkRelevantUseOrdersForCallable(e.callables[key])
		if d := time.Since(t0); d >= 500*time.Millisecond && e.timingsEnabled {
			fmt.Fprintf(os.Stderr, "[taintscan] build-base:slow-call-relevance callable=%s duration=%s\n", key, d.Round(time.Millisecond))
		}
		if len(orders) != 0 {
			e.callSinkRelevantUseOrders[key] = orders
		}
		if len(paths) != 0 {
			e.callSinkRelevantUsePaths[key] = paths
		}
	}
}

func (e *engine) indexCallInputConsumingCallables() {
	memo := map[string]bool{}
	visiting := map[string]bool{}
	for _, key := range e.callOrder {
		e.callInputConsumingCallables[key] = e.callableConsumesCallInput(key, memo, visiting)
	}
}

func (e *engine) callableConsumesCallInput(key string, memo map[string]bool, visiting map[string]bool) bool {
	if done, ok := memo[key]; ok {
		return done
	}
	if visiting[key] {
		return false
	}
	visiting[key] = true
	defer delete(visiting, key)
	c, ok := e.callables[key]
	if !ok {
		memo[key] = false
		return false
	}
	if e.callableHasDirectSink(c) && e.callableConsumesCallArgs(c) {
		memo[key] = true
		return true
	}
	if e.callableHasDirectSink(c) && e.callableHasCallRelevantReceiverUse(key) {
		memo[key] = true
		return true
	}
	for _, site := range e.callSiteEdges[key] {
		if site.callee == "" {
			continue
		}
		callee, ok := e.callables[site.callee]
		if !ok {
			continue
		}
		if e.callableConsumesCallInput(site.callee, memo, visiting) {
			if e.callSiteSuppliesConsumedInput(callee, site) {
				memo[key] = true
				return true
			}
		}
	}
	memo[key] = false
	return false
}

func (e *engine) callableConsumesCallArgs(c callable) bool {
	if len(c.Params) == 0 {
		return false
	}
	return len(e.callRelevantParamIndexes(c)) != 0
}

func (e *engine) callableConsumesCallReceiver(c callable) bool {
	return e.callableHasCallRelevantReceiverUse(c.Key)
}

func (e *engine) callSiteSuppliesConsumedInput(callee callable, site callSiteEdge) bool {
	paramIndexes := e.callRelevantParamIndexes(callee)
	if e.callableHasDynamicCallbackDirectSink(callee) {
		return callSiteSuppliesRuntimeArgAtAnyConsumedParam(site, paramIndexes)
	}
	if callSiteSuppliesRuntimeArgAtAnyConsumedParam(site, paramIndexes) {
		return true
	}
	if len(paramIndexes) == 0 && len(callee.Params) != 0 && site.argCarrier {
		return true
	}
	if e.callableConsumesCallReceiver(callee) && site.receiverCarrier {
		return true
	}
	return false
}

func (e *engine) callRelevantParamIndexes(c callable) []int {
	if len(c.Params) == 0 {
		return nil
	}
	orders := e.callSinkRelevantUseOrders[c.Key]
	if len(orders) == 0 {
		return nil
	}
	out := make([]int, 0, len(c.Params))
	for idx, param := range c.Params {
		if param == "" {
			continue
		}
		if callRelevantRootPresent(orders, param) {
			out = append(out, idx)
		}
	}
	return out
}

func (e *engine) sqlRelevantParamIndexes(c callable) []int {
	if len(c.Params) == 0 {
		return nil
	}
	orders := e.sqlSinkRelevantUseOrders[c.Key]
	if len(orders) == 0 {
		return nil
	}
	out := make([]int, 0, len(c.Params))
	for idx, param := range c.Params {
		if param == "" {
			continue
		}
		if callRelevantRootPresent(orders, param) {
			out = append(out, idx)
		}
	}
	return out
}

func (e *engine) fileRelevantParamIndexes(c callable) []int {
	if len(c.Params) == 0 {
		return nil
	}
	orders := e.fileSinkRelevantUseOrders[c.Key]
	if len(orders) == 0 {
		return nil
	}
	out := make([]int, 0, len(c.Params))
	for idx, param := range c.Params {
		if param == "" {
			continue
		}
		if callRelevantRootPresent(orders, param) {
			out = append(out, idx)
		}
	}
	return out
}

func callSiteSuppliesRuntimeArgAtAnyConsumedParam(site callSiteEdge, paramIndexes []int) bool {
	if len(paramIndexes) == 0 {
		return false
	}
	if site.argCount == 0 {
		return site.argCarrier
	}
	if len(site.runtimeArgIdxs) == 0 {
		return site.argCarrier
	}
	for _, idx := range paramIndexes {
		if idx < 0 || idx >= site.argCount {
			continue
		}
		if _, ok := site.runtimeArgIdxs[idx]; ok {
			return true
		}
	}
	return false
}

func (e *engine) callableHasCallRelevantReceiverUse(key string) bool {
	for root := range e.callSinkRelevantUseOrders[key] {
		if root == "this" || strings.HasPrefix(root, "this.") || strings.HasPrefix(root, "this[") {
			return true
		}
	}
	return false
}

func (e *engine) callableHasDirectSQLRelevantReceiverUse(key string) bool {
	for root := range e.sqlSinkRelevantUseOrders[key] {
		if root == "this" || strings.HasPrefix(root, "this.") || strings.HasPrefix(root, "this[") {
			return true
		}
	}
	return false
}

func (e *engine) callableHasSQLRelevantReceiverUse(key string) bool {
	return e.callableHasSQLRelevantReceiverUseWithMemo(key, map[string]bool{}, map[string]struct{}{})
}

func (e *engine) callableHasSQLRelevantReceiverUseWithMemo(key string, memo map[string]bool, visiting map[string]struct{}) bool {
	if e == nil || key == "" {
		return false
	}
	if value, ok := memo[key]; ok {
		return value
	}
	if _, ok := visiting[key]; ok {
		return false
	}
	if e.callableHasDirectSQLRelevantReceiverUse(key) {
		memo[key] = true
		return true
	}
	visiting[key] = struct{}{}
	defer delete(visiting, key)
	for _, site := range e.callSiteEdges[key] {
		if site.callee == "" || !site.receiverCarrier {
			continue
		}
		if e.callableHasSQLRelevantReceiverUseWithMemo(site.callee, memo, visiting) {
			memo[key] = true
			return true
		}
	}
	memo[key] = false
	return false
}

func (e *engine) callableHasFileRelevantReceiverUse(key string) bool {
	for root := range e.fileSinkRelevantUseOrders[key] {
		if root == "this" || strings.HasPrefix(root, "this.") || strings.HasPrefix(root, "this[") {
			return true
		}
	}
	return false
}

func (e *engine) indexReceiverMutatingCallables() {
	for _, key := range e.callOrder {
		c := e.callables[key]
		if c.Class == "" {
			continue
		}
		if callableMutatesReceiverState(c) {
			e.receiverMutatingCallables[key] = struct{}{}
		}
	}
}

func callableMutatesReceiverState(c callable) bool {
	mutates := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if mutates || node == nil {
			return
		}
		exprStmt, ok := node.(*ast.StmtExpression)
		if !ok {
			return
		}
		var target ast.Node
		switch typed := exprStmt.Expr.(type) {
		case *ast.ExprAssign:
			target = typed.Var
		case *ast.ExprAssignRef:
			target = typed.Var
		case *ast.ExprAssignOpConcat:
			target = typed.Var
		case *ast.ExprAssignOpPlus:
			target = typed.Var
		case *ast.ExprAssignOpMinus:
			target = typed.Var
		case *ast.ExprAssignOpMul:
			target = typed.Var
		case *ast.ExprAssignOpDiv:
			target = typed.Var
		case *ast.ExprAssignOpMod:
			target = typed.Var
		case *ast.ExprAssignOpPow:
			target = typed.Var
		case *ast.ExprAssignOpBitwiseAnd:
			target = typed.Var
		case *ast.ExprAssignOpBitwiseOr:
			target = typed.Var
		case *ast.ExprAssignOpBitwiseXor:
			target = typed.Var
		case *ast.ExprAssignOpShiftLeft:
			target = typed.Var
		case *ast.ExprAssignOpShiftRight:
			target = typed.Var
		case *ast.ExprAssignOpCoalesce:
			target = typed.Var
		}
		if target == nil {
			return
		}
		path, ok := propertyPathKey(target, c.Class)
		if !ok {
			return
		}
		if path == "this" || strings.HasPrefix(path, "this.") || strings.HasPrefix(path, "this[") {
			mutates = true
		}
	})
	return mutates
}

func (e *engine) indexActionSinkRelevantUseOrders() {
	e.actionSinkRelevantUseOrders = map[string]map[string]int{}
	e.actionSinkRelevantUsePaths = map[string]map[string]map[string]int{}
	for _, key := range e.callOrder {
		orders, paths := e.actionSinkRelevantUseOrdersForCallable(e.callables[key])
		if len(orders) != 0 {
			e.actionSinkRelevantUseOrders[key] = orders
		}
		if len(paths) != 0 {
			e.actionSinkRelevantUsePaths[key] = paths
		}
	}
}

func (e *engine) indexOutputSinkRelevantUseOrders() {
	e.outputSinkRelevantUseOrders = map[string]map[string]int{}
	e.outputSinkRelevantUsePaths = map[string]map[string]map[string]int{}
	for _, key := range e.callOrder {
		orders, paths := e.outputSinkRelevantUseOrdersForCallable(e.callables[key])
		if len(orders) != 0 {
			e.outputSinkRelevantUseOrders[key] = orders
		}
		if len(paths) != 0 {
			e.outputSinkRelevantUsePaths[key] = paths
		}
	}
}

func (e *engine) indexSQLSinkRelevantUseOrders() {
	for _, key := range e.callOrder {
		orders := e.sqlSinkRelevantUseOrdersForCallable(e.callables[key])
		if len(orders) != 0 {
			e.sqlSinkRelevantUseOrders[key] = orders
		}
	}
}

func (e *engine) indexFileSinkRelevantUseOrders() {
	e.fileSinkRelevantUseOrders = map[string]map[string]int{}
	e.fileSinkRelevantUsePaths = map[string]map[string]map[string]int{}
	for _, key := range e.callOrder {
		orders, paths := e.fileSinkRelevantUseOrdersForCallable(e.callables[key], false)
		if len(orders) != 0 {
			e.fileSinkRelevantUseOrders[key] = orders
		}
		if len(paths) != 0 {
			e.fileSinkRelevantUsePaths[key] = paths
		}
	}
}

func (e *engine) callSinkRelevantUseOrdersForCallable(c callable) (map[string]int, map[string]map[string]int) {
	relevantConsumeMemo := map[string]bool{}
	relevantConsumeVisiting := map[string]bool{}
	orderMemo := map[string]map[string]int{}
	pathMemo := map[string]map[string]map[string]int{}
	orderVisiting := map[string]bool{}
	var computeOrders func(string) (map[string]int, map[string]map[string]int)
	var callableConsumesRelevantInput func(string) bool
	computeOrders = func(key string) (map[string]int, map[string]map[string]int) {
		if key != c.Key {
			if cached, ok := e.callSinkRelevantUseOrders[key]; ok {
				return cached, e.callSinkRelevantUsePaths[key]
			}
		}
		if cached, ok := orderMemo[key]; ok {
			return cached, pathMemo[key]
		}
		if orderVisiting[key] {
			return nil, nil
		}
		callee, ok := e.callables[key]
		if !ok {
			orderMemo[key] = nil
			pathMemo[key] = nil
			return nil, nil
		}
		orderVisiting[key] = true
		orders, paths := e.callSinkRelevantUseOrdersForCallableResolved(callee, callableConsumesRelevantInput)
		delete(orderVisiting, key)
		orderMemo[key] = orders
		pathMemo[key] = paths
		return orders, paths
	}
	callableConsumesRelevantInput = func(key string) bool {
		if done, ok := relevantConsumeMemo[key]; ok {
			return done
		}
		if relevantConsumeVisiting[key] {
			return false
		}
		relevantConsumeVisiting[key] = true
		defer delete(relevantConsumeVisiting, key)
		callee, ok := e.callables[key]
		if !ok {
			relevantConsumeMemo[key] = false
			return false
		}
		relevantOrders, _ := computeOrders(key)
		for _, param := range callee.Params {
			if param == "" {
				continue
			}
			if callRelevantRootPresent(relevantOrders, param) {
				relevantConsumeMemo[key] = true
				return true
			}
		}
		for root := range relevantOrders {
			if root == "this" || strings.HasPrefix(root, "this.") || strings.HasPrefix(root, "this[") {
				relevantConsumeMemo[key] = true
				return true
			}
		}
		relevantConsumeMemo[key] = false
		return false
	}
	return computeOrders(c.Key)
}

func (e *engine) callSinkRelevantUseOrdersForCallableResolved(c callable, callableConsumesRelevantInput func(string) bool) (map[string]int, map[string]map[string]int) {
	orders := map[string]int{}
	paths := map[string]map[string]int{}
	recordUse := func(node ast.Node, order int) {
		if node == nil {
			return
		}
		var walk func(ast.Node, ast.Node)
		walk = func(current ast.Node, parent ast.Node) {
			if current == nil {
				return
			}
			recordStructuralRelevantUse(current, parent, c, order, orders, paths)
			for _, name := range current.SubNodeNames() {
				value := current.SubNode(name)
				switch typed := value.(type) {
				case ast.Node:
					walk(typed, current)
				case []ast.Node:
					for _, child := range typed {
						walk(child, current)
					}
				}
			}
		}
		walk(node, nil)
	}
	recordCallSinkUses := func(node ast.Node, order int) {
		switch call := node.(type) {
		case *ast.ExprEval:
			recordUse(call.Expr, order)
		case *ast.ExprShellExec:
			for _, rawPart := range call.Parts {
				part, ok := rawPart.(ast.Node)
				if !ok {
					continue
				}
				recordUse(part, order)
			}
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(call.Name))
			switch {
			case func() bool {
				idx, _, _, _, ok := privilegeMutationFuncArgPath(name)
				if !ok || !e.allowsSinkOp("call") || idx < 0 || idx >= len(call.Args) {
					return false
				}
				recordUse(argValue(call.Args[idx]), order)
				return true
			}():
			case func() bool {
				if !isDynamicCallbackHelper(name) || !e.allowsSinkOp("call") || len(call.Args) == 0 {
					return false
				}
				callbackExpr := argValue(call.Args[0])
				if !isDirectCallSinkSeedExpr(callbackExpr) && !isDynamicCallbackArrayExpr(callbackExpr) {
					return false
				}
				recordUse(callbackExpr, order)
				return true
			}():
			case func() bool {
				indexes, _, _, ok := unsafeUseFuncArgIndexes(name)
				if !ok {
					return false
				}
				for _, idx := range indexes {
					if idx >= 0 && idx < len(call.Args) {
						recordUse(argValue(call.Args[idx]), order)
					}
				}
				return true
			}():
			case func() bool {
				_, _, _, ok := unsafeDeserializationFuncArgIndex(call)
				return ok
			}():
				if len(call.Args) > 0 {
					recordUse(argValue(call.Args[0]), order)
				}
			case func() bool {
				indexes, _, _, ok := unsafeDeserializationCallbackArgIndexes(call)
				if !ok {
					return false
				}
				for _, idx := range indexes {
					if idx >= 0 && idx < len(call.Args) {
						recordUse(argValue(call.Args[idx]), order)
					}
				}
				return true
			}():
			case isDynamicCallbackHelper(name):
				if len(call.Args) > 0 && isDynamicCallbackExpr(argValue(call.Args[0])) {
					recordUse(argValue(call.Args[0]), order)
				}
			case name == "is_callable":
				if len(call.Args) > 0 && isDynamicCallbackExpr(argValue(call.Args[0])) {
					recordUse(argValue(call.Args[0]), order)
				}
			case name == "apply_filters" || name == "apply_filters_ref_array" || name == "do_action" || name == "do_action_ref_array":
				hook := hookDispatchKeyForCallable(argValue(call.Args[0]), c, e)
				if hook != "" && len(e.dispatchCallbackKeys(name, hook)) == 0 {
					return
				}
				for _, arg := range call.Args[1:] {
					recordUse(argValue(arg), order)
				}
			case func() bool {
				key := e.lookupFunctionKey(c.Namespace, identifierText(call.Name))
				if key == "" || !callableConsumesRelevantInput(key) {
					return false
				}
				for _, arg := range call.Args {
					recordUse(argValue(arg), order)
				}
				return true
			}():
			}
		case *ast.ExprMethodCall:
			name := strings.ToLower(identifierText(call.Name))
			if idx, op, _, _, ok := builtinMethodSink(name); ok && op == "call" && e.allowsSinkOp("call") {
				if idx >= 0 && idx < len(call.Args) {
					recordUse(argValue(call.Args[idx]), order)
				}
				return
			}
			hints := literalArgHintsForArgs(call.Args, c, e)
			pathHints := literalArgPathHintsForArgs(call.Args, c, e, call.StartLine(), nil)
			for _, className := range resolveCallGraphClassExprCandidates(e, c, call.Var, nil) {
				key := e.maybeSpecializeRuntimeMethodKeyForLiteralArgsAndPaths(className, name, hints, pathHints)
				if key == "" || !callableConsumesRelevantInput(key) {
					continue
				}
				for _, arg := range call.Args {
					recordUse(argValue(arg), order)
				}
				if e.callableConsumesCallReceiver(e.callables[key]) {
					recordUse(call.Var, order)
				}
				break
			}
		case *ast.ExprStaticCall:
			name := strings.ToLower(identifierText(call.Name))
			if idx, op, _, _, ok := builtinMethodSink(name); ok && op == "call" && e.allowsSinkOp("call") {
				if idx >= 0 && idx < len(call.Args) {
					recordUse(argValue(call.Args[idx]), order)
				}
				return
			}
			hints := literalArgHintsForArgs(call.Args, c, e)
			pathHints := literalArgPathHintsForArgs(call.Args, c, e, call.StartLine(), nil)
			className := e.resolveClassNameForCallable(call.Class, c)
			for _, key := range dynamicStaticMethodKeysForCallable(e, c, className, call.Name, nil) {
				key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
				if key == "" || !callableConsumesRelevantInput(key) {
					continue
				}
				for _, arg := range call.Args {
					recordUse(argValue(arg), order)
				}
				break
			}
		}
	}
	recordReturnUse := func(node ast.Node, order int) {
		if node == nil {
			return
		}
		root := valueRootKey(node, c.Class)
		if root == "" {
			return
		}
		if order > orders[root] {
			orders[root] = order
		}
	}
	stmtOrder := 0
	var walkStmtList func([]ast.Node)
	walkStmtList = func(stmts []ast.Node) {
		for _, stmt := range stmts {
			if skipNestedDeclarationBodies(c, stmt) {
				continue
			}
			stmtOrder++
			switch typed := stmt.(type) {
			case *ast.StmtExpression:
				walkNode(typed.Expr, func(node ast.Node) {
					recordCallSinkUses(node, stmtOrder)
				})
			case *ast.StmtReturn:
				walkNode(typed.Expr, func(node ast.Node) {
					recordCallSinkUses(node, stmtOrder)
				})
				recordReturnUse(typed.Expr, stmtOrder)
			}
			for _, block := range childStatementBlocks(stmt) {
				walkStmtList(block)
			}
		}
	}
	walkStmtList(c.Stmts)
	if len(orders) == 0 {
		return nil, nil
	}
	if len(paths) == 0 {
		return orders, nil
	}
	return orders, paths
}

func (e *engine) actionSinkRelevantUseOrdersForCallable(c callable) (map[string]int, map[string]map[string]int) {
	orders := map[string]int{}
	paths := map[string]map[string]int{}
	recordUse := func(node ast.Node, order int) {
		if node == nil {
			return
		}
		var walk func(ast.Node, ast.Node)
		walk = func(current ast.Node, parent ast.Node) {
			if current == nil {
				return
			}
			recordStructuralRelevantUse(current, parent, c, order, orders, paths)
			for _, name := range current.SubNodeNames() {
				value := current.SubNode(name)
				switch typed := value.(type) {
				case ast.Node:
					walk(typed, current)
				case []ast.Node:
					for _, child := range typed {
						walk(child, current)
					}
				}
			}
		}
		walk(node, nil)
	}
	stmtOrder := 0
	var walkStmtList func([]ast.Node)
	walkStmtList = func(stmts []ast.Node) {
		for _, stmt := range stmts {
			if skipNestedDeclarationBodies(c, stmt) {
				continue
			}
			stmtOrder++
			switch typed := stmt.(type) {
			case *ast.StmtExpression:
				walkNode(typed.Expr, func(node ast.Node) {
					switch call := node.(type) {
					case *ast.ExprFuncCall:
						if model, ok := actionSinkModelByFunc(normalizeName(identifierText(call.Name))); ok {
							for _, idx := range actionSinkArgIndexes(model, len(call.Args)) {
								recordUse(argValue(call.Args[idx]), stmtOrder)
							}
							return
						}
						if key := e.lookupFunctionKey(c.Namespace, identifierText(call.Name)); key != "" && e.callableConsumesActionInput(key) {
							for _, arg := range call.Args {
								recordUse(argValue(arg), stmtOrder)
							}
						}
					case *ast.ExprMethodCall:
						if model, ok := actionSinkModelByMethod(strings.ToLower(identifierText(call.Name))); ok {
							if !model.RequireConfigLike || callableHasActionSinkMethod(e, c, call, model) {
								for _, idx := range actionSinkArgIndexes(model, len(call.Args)) {
									recordUse(argValue(call.Args[idx]), stmtOrder)
								}
							}
							return
						}
						className := resolveCallGraphClassExpr(e, c, call.Var, nil)
						if key := e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name))); key != "" && e.callableConsumesActionInput(key) {
							for _, arg := range call.Args {
								recordUse(argValue(arg), stmtOrder)
							}
						}
					case *ast.ExprStaticCall:
						if model, ok := actionSinkModelByMethod(strings.ToLower(identifierText(call.Name))); ok {
							if !model.RequireConfigLike || callableHasActionSinkStaticCall(e, c, call, model) {
								for _, idx := range actionSinkArgIndexes(model, len(call.Args)) {
									recordUse(argValue(call.Args[idx]), stmtOrder)
								}
							}
							return
						}
						className := e.resolveClassNameForCallable(call.Class, c)
						for _, key := range dynamicStaticMethodKeysForCallable(e, c, className, call.Name, nil) {
							if !e.callableConsumesActionInput(key) {
								continue
							}
							for _, arg := range call.Args {
								recordUse(argValue(arg), stmtOrder)
							}
							break
						}
					}
				})
			case *ast.StmtReturn:
				recordUse(typed.Expr, stmtOrder)
			}
			for _, block := range childStatementBlocks(stmt) {
				walkStmtList(block)
			}
		}
	}
	walkStmtList(c.Stmts)
	if len(orders) == 0 {
		return nil, nil
	}
	if len(paths) == 0 {
		return orders, nil
	}
	return orders, paths
}

func outputRelevantPathUseOrder(paths map[string]map[string]int, root, rel string) int {
	if len(paths) == 0 || root == "" {
		return 0
	}
	rootPaths := paths[root]
	if len(rootPaths) == 0 {
		return 0
	}
	return rootPaths[rel]
}

func recordOutputRelevantUse(node ast.Node, parent ast.Node, c callable, order int, orders map[string]int, paths map[string]map[string]int) {
	if node == nil {
		return
	}
	path, ok := propertyPathKey(node, c.Class)
	if !ok || path == "" {
		return
	}
	switch typed := parent.(type) {
	case *ast.ExprArrayDimFetch:
		if typed.Var == node {
			return
		}
	case *ast.ExprPropertyFetch:
		if typed.Var == node {
			return
		}
	}
	root := valueRootKey(node, c.Class)
	if root == "" {
		return
	}
	if order > orders[root] {
		orders[root] = order
	}
	rel, ok := trimStructuralPrefix(path, root)
	if !ok {
		return
	}
	if paths[root] == nil {
		paths[root] = map[string]int{}
	}
	if order > paths[root][rel] {
		paths[root][rel] = order
	}
}

func recordStructuralRelevantUse(node ast.Node, parent ast.Node, c callable, order int, orders map[string]int, paths map[string]map[string]int) {
	switch node.(type) {
	case *ast.ExprVariable, *ast.ExprArrayDimFetch, *ast.ExprPropertyFetch:
		recordOutputRelevantUse(node, parent, c, order, orders, paths)
	}
}

func (e *engine) outputSinkRelevantUseOrdersForCallable(c callable) (map[string]int, map[string]map[string]int) {
	orders := map[string]int{}
	paths := map[string]map[string]int{}
	recordUse := func(node ast.Node, order int) {
		if node == nil {
			return
		}
		var walk func(ast.Node, ast.Node)
		walk = func(current ast.Node, parent ast.Node) {
			if current == nil {
				return
			}
			recordOutputRelevantUse(current, parent, c, order, orders, paths)
			for _, name := range current.SubNodeNames() {
				value := current.SubNode(name)
				switch typed := value.(type) {
				case ast.Node:
					walk(typed, current)
				case []ast.Node:
					for _, child := range typed {
						walk(child, current)
					}
				}
			}
		}
		walk(node, nil)
	}
	stmtOrder := 0
	hasRecordRead := e.callableHasRecordRead(c.Key)
	hasDirectRequestInput := e.callableHasDirectRequestInput(c)
	returnsPublicMarkup := engineCallableReturnsPublicMarkup(e, c.Key)
	var walkStmtList func([]ast.Node)
	walkStmtList = func(stmts []ast.Node) {
		for _, stmt := range stmts {
			if skipNestedDeclarationBodies(c, stmt) {
				continue
			}
			stmtOrder++
			switch typed := stmt.(type) {
			case *ast.StmtExpression:
				walkNode(typed.Expr, func(node ast.Node) {
					switch call := node.(type) {
					case *ast.ExprFuncCall:
						if hasRecordRead && isDisclosureOutputFunc(normalizeName(identifierText(call.Name))) && len(call.Args) > 0 {
							recordUse(argValue(call.Args[0]), stmtOrder)
							return
						}
						if key := e.lookupFunctionKey(c.Namespace, identifierText(call.Name)); key != "" && e.callableConsumesOutputInput(key) {
							for _, arg := range call.Args {
								recordUse(argValue(arg), stmtOrder)
							}
						}
					case *ast.ExprMethodCall:
						className := resolveCallGraphClassExpr(e, c, call.Var, nil)
						if key := e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name))); key != "" && e.callableConsumesOutputInput(key) {
							for _, arg := range call.Args {
								recordUse(argValue(arg), stmtOrder)
							}
						}
					case *ast.ExprStaticCall:
						className := e.resolveClassNameForCallable(call.Class, c)
						for _, key := range dynamicStaticMethodKeysForCallable(e, c, className, call.Name, nil) {
							if !e.callableConsumesOutputInput(key) {
								continue
							}
							for _, arg := range call.Args {
								recordUse(argValue(arg), stmtOrder)
							}
							break
						}
					}
				})
			case *ast.StmtEcho:
				if !hasRecordRead && !hasDirectRequestInput {
					break
				}
				for _, expr := range typed.Exprs {
					recordUse(expr, stmtOrder)
				}
			case *ast.ExprPrint:
				if !hasRecordRead && !hasDirectRequestInput {
					break
				}
				recordUse(typed.Expr, stmtOrder)
			case *ast.StmtReturn:
				if returnsPublicMarkup {
					recordUse(typed.Expr, stmtOrder)
				}
			}
			for _, block := range childStatementBlocks(stmt) {
				walkStmtList(block)
			}
		}
	}
	walkStmtList(c.Stmts)
	if len(orders) == 0 {
		return nil, nil
	}
	if len(paths) == 0 {
		return orders, nil
	}
	return orders, paths
}

func (e *engine) callableConsumesOutputInput(key string) bool {
	if key == "" {
		return false
	}
	if e.callableHasDirectSink(e.callables[key]) {
		return true
	}
	return len(e.outputSinkRelevantUseOrders[key]) != 0
}

func (e *engine) callableHasOutputRelevantBoundary(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	return e.callableHasDirectSink(c) ||
		e.callableHasDirectRequestInput(c) ||
		e.callableHasEntrypointSourceParam(c) ||
		e.callableHasRecordRead(key) ||
		e.callableHasDirectCallSource(c) ||
		e.callableHasDirectSQLReadSource(c) ||
		len(e.storageReadFamiliesByCallable[key]) != 0 ||
		len(e.storageReadBucketsByCallable[key]) != 0 ||
		e.callableIsStorageWriter(key) ||
		e.callableHasSupportedCrossRequestWriter(key) ||
		engineCallableReturnsPublicMarkup(e, key)
}

func (e *engine) sqlSinkRelevantUseOrdersForCallable(c callable) map[string]int {
	orders := map[string]int{}
	resolver := e.localArrayLiteralResolver(c)
	recordUse := func(node ast.Node, order int, beforeLine int) {
		recordSQLRelevantUseWithLocalExpansion(orders, node, order, beforeLine, c, resolver, map[string]struct{}{})
	}
	stmtOrder := 0
	var walkStmtList func([]ast.Node)
	walkStmtList = func(stmts []ast.Node) {
		for _, stmt := range stmts {
			if skipNestedDeclarationBodies(c, stmt) {
				continue
			}
			stmtOrder++
			// Scan a value expression's full subtree for raw-SQL execution sinks
			// and record the tainted argument as SQL-relevant. Applied to every
			// statement's value expressions (expression statements, returns,
			// foreach iterables, if/while/switch conditions, echo args) so that
			// the common data-access shapes — `return $wpdb->get_results(...)`,
			// `foreach ($wpdb->query(...) as $r)` — seed SQL relevance across call
			// boundaries, not just bare expression statements.
			scanSQL := func(node ast.Node) {
				if node == nil {
					return
				}
				walkNode(node, func(n ast.Node) {
					switch call := n.(type) {
					case *ast.ExprFuncCall:
						name := normalizeName(identifierText(call.Name))
						if idx, op, _, _, ok := builtinSinkByFunc(name); ok && op == "sql" && idx >= 0 && idx < len(call.Args) {
							recordUse(argValue(call.Args[idx]), stmtOrder, call.StartLine())
						}
						if idx, _, _, ok := sqlExecutionFuncArgIndex(name, len(call.Args)); ok && idx >= 0 && idx < len(call.Args) {
							recordUse(argValue(call.Args[idx]), stmtOrder, call.StartLine())
						}
					case *ast.ExprMethodCall:
						if idx, _, _, ok := sqlExecutionMethodArgIndex(strings.ToLower(identifierText(call.Name))); ok && idx >= 0 && idx < len(call.Args) {
							recordUse(argValue(call.Args[idx]), stmtOrder, call.StartLine())
						}
						if sinkIndexes, _, _, ok := sqlIdentifierWriteMethodArgIndexes(strings.ToLower(identifierText(call.Name))); ok && callableHasSQLIdentifierWriteMethodSink(e, c, call) {
							for _, idx := range sinkIndexes {
								if idx >= 0 && idx < len(call.Args) {
									recordUse(argValue(call.Args[idx]), stmtOrder, call.StartLine())
								}
							}
						}
					case *ast.ExprStaticCall:
						if idx, _, _, ok := sqlExecutionMethodArgIndex(strings.ToLower(identifierText(call.Name))); ok && idx >= 0 && idx < len(call.Args) {
							recordUse(argValue(call.Args[idx]), stmtOrder, call.StartLine())
						}
					}
				})
			}
			switch typed := stmt.(type) {
			case *ast.StmtExpression:
				scanSQL(typed.Expr)
			case *ast.StmtReturn:
				scanSQL(typed.Expr)
				if callableHasSQLClauseFilterReturnSink(e, c) {
					// SQL clause-filter callbacks (posts_where, ...) return a raw
					// clause string; seed the whole return expression, not just
					// nested execution sinks.
					recordUse(typed.Expr, stmtOrder, typed.StartLine())
				}
			case *ast.StmtForeach:
				scanSQL(typed.Expr)
			case *ast.StmtIf:
				scanSQL(typed.Cond)
			case *ast.StmtElseIf:
				scanSQL(typed.Cond)
			case *ast.StmtWhile:
				scanSQL(typed.Cond)
			case *ast.StmtDo:
				scanSQL(typed.Cond)
			case *ast.StmtSwitch:
				scanSQL(typed.Cond)
			case *ast.StmtEcho:
				for _, expr := range typed.Exprs {
					scanSQL(expr)
				}
			}
			for _, block := range childStatementBlocks(stmt) {
				walkStmtList(block)
			}
		}
	}
	walkStmtList(c.Stmts)
	if len(orders) == 0 {
		return nil
	}
	return orders
}

func recordSQLRelevantUseWithLocalExpansion(orders map[string]int, node ast.Node, order int, beforeLine int, c callable, resolver *localArrayLiteralResolver, seen map[string]struct{}) {
	if node == nil {
		return
	}
	var walk func(ast.Node, int)
	walk = func(current ast.Node, currentBeforeLine int) {
		if current == nil {
			return
		}
		root := valueRootKey(current, c.Class)
		if root != "" && order > orders[root] {
			orders[root] = order
		}
		if resolver != nil && currentBeforeLine > 0 {
			name := localExpandedRelevantName(current)
			if name != "" && !localExpandedRelevantNameIsSuperglobal(name) {
				seenKey := fmt.Sprintf("%s@%d", name, currentBeforeLine)
				if _, ok := seen[seenKey]; !ok {
					seen[seenKey] = struct{}{}
					expr, line := resolver.latestExpr(name, currentBeforeLine)
					if expr != nil && line > 0 && line < currentBeforeLine {
						walk(expr, line)
					}
				}
			}
		}
		for _, name := range current.SubNodeNames() {
			value := current.SubNode(name)
			switch typed := value.(type) {
			case ast.Node:
				walk(typed, currentBeforeLine)
			case []ast.Node:
				for _, child := range typed {
					walk(child, currentBeforeLine)
				}
			case []any:
				for _, raw := range typed {
					child, ok := raw.(ast.Node)
					if !ok {
						continue
					}
					walk(child, currentBeforeLine)
				}
			}
		}
	}
	walk(node, beforeLine)
}

func (e *engine) callableConsumesActionInput(key string) bool {
	if key == "" {
		return false
	}
	if e.callInputConsumingCallables[key] {
		return true
	}
	return e.callableHasDirectSink(e.callables[key])
}

func recordFileRelevantUse(e *engine, node ast.Node, parent ast.Node, c callable, order int, orders map[string]int, paths map[string]map[string]int) {
	if node == nil {
		return
	}
	path, ok := propertyPathKey(node, c.Class)
	orderRoot := valueRootKey(node, c.Class)
	pathRoot := orderRoot
	if ok && path != "" {
		pathRoot = structuralPathRoot(path)
	}
	switch typed := parent.(type) {
	case *ast.ExprArrayDimFetch:
		if typed.Var == node {
			return
		}
	case *ast.ExprPropertyFetch:
		if typed.Var == node {
			return
		}
	}
	if orderRoot == "" {
		return
	}
	if order > orders[orderRoot] {
		orders[orderRoot] = order
	}
	if !ok || path == "" || pathRoot == "" {
		return
	}
	rel, ok := trimStructuralPrefix(path, pathRoot)
	if !ok {
		return
	}
	if paths[pathRoot] == nil {
		paths[pathRoot] = map[string]int{}
	}
	if order > paths[pathRoot][rel] {
		paths[pathRoot][rel] = order
	}
}

func (e *engine) indexIncludeSinkRelevantUseOrders() {
	e.includeSinkRelevantUseOrders = map[string]map[string]int{}
	e.includeSinkRelevantUsePaths = map[string]map[string]map[string]int{}
	for _, key := range e.callOrder {
		orders, paths := e.fileSinkRelevantUseOrdersForCallable(e.callables[key], true)
		if len(orders) != 0 {
			e.includeSinkRelevantUseOrders[key] = orders
		}
		if len(paths) != 0 {
			e.includeSinkRelevantUsePaths[key] = paths
		}
	}
}

func (e *engine) fileSinkRelevantUseOrdersForCallable(c callable, includeOnly bool) (map[string]int, map[string]map[string]int) {
	orders := map[string]int{}
	paths := map[string]map[string]int{}
	resolver := e.localArrayLiteralResolver(c)
	recordUse := func(node ast.Node, order int, beforeLine int) {
		recordFileRelevantUseWithLocalExpansion(e, orders, paths, node, order, beforeLine, c, resolver, map[string]struct{}{})
	}
	recordFileSinkUses := func(node ast.Node, order int) {
		if node == nil {
			return
		}
		walkNode(node, func(child ast.Node) {
			switch call := child.(type) {
			case *ast.ExprInclude:
				recordUse(call.Expr, order, call.StartLine())
				return
			case *ast.ExprFuncCall:
				name := normalizeName(identifierText(call.Name))
				if name == "load_template" && len(call.Args) > 0 {
					recordUse(argValue(call.Args[0]), order, call.StartLine())
					return
				}
				if includeOnly {
					return
				}
				if indexes, ok := fileUploadSinkArgIndexesByFunc(name); ok {
					for _, idx := range indexes {
						if idx >= 0 && idx < len(call.Args) {
							recordUse(argValue(call.Args[idx]), order, call.StartLine())
						}
					}
					return
				}
				if idx, op, _, _, ok := builtinSinkByFunc(name); ok {
					switch op {
					case "delete", "read", "open", "include", "write":
						if idx >= 0 && idx < len(call.Args) {
							recordUse(argValue(call.Args[idx]), order, call.StartLine())
						}
					}
				}
			}
		})
	}
	stmtOrder := 0
	var walkStmtList func([]ast.Node)
	walkStmtList = func(stmts []ast.Node) {
		for _, stmt := range stmts {
			if skipNestedDeclarationBodies(c, stmt) {
				continue
			}
			stmtOrder++
			switch typed := stmt.(type) {
			case *ast.StmtExpression:
				recordFileSinkUses(typed.Expr, stmtOrder)
			case *ast.StmtReturn:
				recordFileSinkUses(typed.Expr, stmtOrder)
			}
			for _, block := range childStatementBlocks(stmt) {
				walkStmtList(block)
			}
		}
	}
	walkStmtList(c.Stmts)
	if len(orders) == 0 {
		return nil, nil
	}
	if len(paths) == 0 {
		return orders, nil
	}
	return orders, paths
}

func recordFileRelevantUseWithLocalExpansion(e *engine, orders map[string]int, paths map[string]map[string]int, node ast.Node, order int, beforeLine int, c callable, resolver *localArrayLiteralResolver, seen map[string]struct{}) {
	if node == nil {
		return
	}
	var walk func(ast.Node, ast.Node)
	walk = func(current ast.Node, parent ast.Node) {
		if current == nil {
			return
		}
		recordFileRelevantUse(e, current, parent, c, order, orders, paths)
		for _, name := range current.SubNodeNames() {
			value := current.SubNode(name)
			switch typed := value.(type) {
			case ast.Node:
				walk(typed, current)
			case []ast.Node:
				for _, child := range typed {
					walk(child, current)
				}
			}
		}
	}
	walk(node, nil)
	if resolver == nil || beforeLine <= 0 {
		return
	}
	name := localExpandedRelevantName(node)
	if name == "" || localExpandedRelevantNameIsSuperglobal(name) {
		return
	}
	seenKey := fmt.Sprintf("%s@%d", name, beforeLine)
	if _, ok := seen[seenKey]; ok {
		return
	}
	seen[seenKey] = struct{}{}
	expr, line := resolver.latestExpr(name, beforeLine)
	if expr == nil || line <= 0 || line >= beforeLine {
		return
	}
	recordFileRelevantUseWithLocalExpansion(e, orders, paths, expr, order, line, c, resolver, seen)
}

func localExpandedRelevantName(node ast.Node) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			return strings.TrimSpace(name)
		}
	case *ast.ExprArrayDimFetch:
		if variable, ok := typed.Var.(*ast.ExprVariable); ok {
			if name, ok := variable.Name.(string); ok {
				return strings.TrimSpace(name)
			}
		}
	}
	return ""
}

func localExpandedRelevantNameIsSuperglobal(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER", "_ENV", "_SESSION", "GLOBALS":
		return true
	default:
		return false
	}
}

func (e *engine) expandPendingWithCallers(pendingSet map[string]struct{}, key string) {
	if key == "" {
		return
	}
	if _, ok := pendingSet[key]; ok {
		return
	}
	pendingSet[key] = struct{}{}
	for caller := range e.reverseCallEdges[key] {
		pendingSet[caller] = struct{}{}
	}
}

func changedMapKeys(before map[string]originSet, after map[string]originSet) map[string]struct{} {
	changed := map[string]struct{}{}
	for key, beforeValue := range before {
		if !reflect.DeepEqual(beforeValue, after[key]) {
			changed[key] = struct{}{}
		}
	}
	for key, afterValue := range after {
		if _, ok := before[key]; ok {
			continue
		}
		if !reflect.DeepEqual(afterValue, originSet(nil)) {
			changed[key] = struct{}{}
		}
	}
	return changed
}

func (e *engine) buildDirectReturnHints() {
	eligible := make([]string, 0, len(e.callOrder))
	for _, key := range e.callOrder {
		if callableMayNeedDirectReturnHint(e.callables[key]) {
			eligible = append(eligible, key)
		}
	}
	if e.timingsEnabled {
		fmt.Fprintf(os.Stderr, "[taintscan] build-direct-return-hints eligible=%d callables=%d\n", len(eligible), len(e.callOrder))
	}
	for pass := 0; pass < 8; pass++ {
		changed := false
		for _, key := range eligible {
			started := time.Time{}
			if e.timingsEnabled {
				started = time.Now()
			}
			className := e.inferDirectReturnClass(e.callables[key])
			if e.timingsEnabled {
				if elapsed := time.Since(started); elapsed > 2*time.Second {
					fmt.Fprintf(os.Stderr, "[taintscan] build-direct-return-hints slow-callable pass=%d callable=%s duration=%s\n", pass+1, key, elapsed.Round(time.Millisecond))
				}
			}
			if className == "" || e.directReturnHints[key] == className {
				continue
			}
			e.directReturnHints[key] = className
			changed = true
		}
		if !changed {
			return
		}
	}
}

func callableMayNeedDirectReturnHint(c callable) bool {
	return c.HasDirectReturnHintCandidate
}

func directReturnHintCandidateCallable(c callable) bool {
	if len(c.Stmts) == 0 {
		return false
	}
	hasClassProducer := false
	hasDeferredReturn := false
	hasImmediateReturn := false
	walkNodes(c.Stmts, func(node ast.Node) {
		if hasImmediateReturn {
			return
		}
		switch typed := node.(type) {
		case *ast.StmtExpression:
			switch expr := typed.Expr.(type) {
			case *ast.ExprAssign:
				if directReturnHintProducerExpr(expr.Expr, c.ParamTypes) {
					hasClassProducer = true
				}
			case *ast.ExprAssignRef:
				if directReturnHintProducerExpr(expr.Expr, c.ParamTypes) {
					hasClassProducer = true
				}
			}
		case *ast.StmtReturn:
			switch directReturnHintReturnKind(typed.Expr, c.ParamTypes) {
			case 2:
				hasImmediateReturn = true
			case 1:
				hasDeferredReturn = true
			}
		}
	})
	return hasImmediateReturn || (hasDeferredReturn && hasClassProducer)
}

func directReturnHintReturnKind(node ast.Node, paramTypes map[string]string) int {
	switch typed := node.(type) {
	case nil:
		return 0
	case *ast.ExprAssign:
		return directReturnHintReturnKind(typed.Expr, paramTypes)
	case *ast.ExprAssignRef:
		return directReturnHintReturnKind(typed.Expr, paramTypes)
	case *ast.ExprNew, *ast.ExprFuncCall, *ast.ExprStaticCall, *ast.ExprMethodCall:
		return 2
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if ok && paramTypes != nil && strings.TrimSpace(paramTypes[strings.TrimSpace(name)]) != "" {
			return 2
		}
		return 1
	case *ast.ExprArrayDimFetch:
		return 1
	default:
		return 0
	}
}

func directReturnHintProducerExpr(node ast.Node, paramTypes map[string]string) bool {
	switch typed := node.(type) {
	case nil:
		return false
	case *ast.ExprAssign:
		return directReturnHintProducerExpr(typed.Expr, paramTypes)
	case *ast.ExprAssignRef:
		return directReturnHintProducerExpr(typed.Expr, paramTypes)
	case *ast.ExprNew, *ast.ExprFuncCall, *ast.ExprStaticCall, *ast.ExprMethodCall,
		*ast.ExprArrayDimFetch, *ast.ExprPropertyFetch:
		return true
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		return ok && paramTypes != nil && strings.TrimSpace(paramTypes[strings.TrimSpace(name)]) != ""
	default:
		return false
	}
}

func (e *engine) inferDirectReturnClass(c callable) string {
	candidates := e.inferDirectReturnClasses(c)
	if len(candidates) != 1 {
		return ""
	}
	return candidates[0]
}

func (e *engine) inferDirectReturnClasses(c callable) []string {
	if len(c.Stmts) == 0 {
		return nil
	}
	classEnv := map[string]string{}
	stringEnv := map[string]string{}
	pathClasses := map[string]map[string]struct{}{}
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	addPathClass := func(path string, className string) {
		if path == "" || className == "" {
			return
		}
		items := pathClasses[path]
		if items == nil {
			items = map[string]struct{}{}
			pathClasses[path] = items
		}
		items[className] = struct{}{}
	}
	walkNodes(c.Stmts, func(node ast.Node) {
		switch typed := node.(type) {
		case *ast.StmtExpression:
			assign, ok := typed.Expr.(*ast.ExprAssign)
			if !ok {
				updateDirectReturnHintLocalEnvs(e, c, typed.Expr, classEnv, stringEnv)
				return
			}
			if className := e.resolveHintClassExpr(c, assign.Expr, classEnv, stringEnv); className != "" {
				if variable, ok := assign.Var.(*ast.ExprVariable); ok {
					if name, ok := variable.Name.(string); ok {
						classEnv[name] = className
					}
				}
				if path, ok := localClassPathKey(assign.Var); ok {
					classEnv[path] = className
					addPathClass(path, className)
				}
				if path, ok := propertyPathKey(assign.Var, c.Class); ok {
					addPathClass(path, className)
				}
				if path, ok := staticPropertyPathKey(assign.Var, c.Class, e); ok {
					addPathClass(path, className)
				}
			}
			updateDirectReturnHintLocalEnvs(e, c, typed.Expr, classEnv, stringEnv)
		case *ast.StmtReturn:
			if className := e.resolveHintClassExpr(c, typed.Expr, classEnv, stringEnv); className != "" {
				add(className)
				return
			}
			if path, ok := localClassPathKey(typed.Expr); ok {
				for className := range pathClasses[path] {
					add(className)
				}
			}
			if path, ok := propertyPathKey(typed.Expr, c.Class); ok {
				for className := range pathClasses[path] {
					add(className)
				}
			}
			if path, ok := staticPropertyPathKey(typed.Expr, c.Class, e); ok {
				for className := range pathClasses[path] {
					add(className)
				}
			}
		}
	})
	return out
}

func (e *engine) resolveHintClassExpr(c callable, node ast.Node, classEnv map[string]string, stringEnv map[string]string) string {
	return e.resolveHintClassExprWithState(c, node, classEnv, stringEnv, newDispatchResolutionState())
}

func (e *engine) resolveHintClassExprWithState(c callable, node ast.Node, classEnv map[string]string, stringEnv map[string]string, state *dispatchResolutionState) string {
	if state == nil {
		state = newDispatchResolutionState()
	}
	key := dispatchResolutionKey("class", c.Key, node)
	if !dispatchResolutionEnter(state.class, key) {
		return ""
	}
	defer dispatchResolutionLeave(state.class, key)

	switch typed := node.(type) {
	case nil:
		return ""
	case *ast.ExprAssign:
		return e.resolveHintClassExprWithState(c, typed.Expr, classEnv, stringEnv, state)
	case *ast.ExprAssignRef:
		return e.resolveHintClassExprWithState(c, typed.Expr, classEnv, stringEnv, state)
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		if name == "this" {
			return c.Class
		}
		if c.ParamTypes != nil {
			if className := strings.TrimSpace(c.ParamTypes[strings.TrimSpace(name)]); className != "" {
				return className
			}
		}
		return classEnv[name]
	case *ast.ExprArrayDimFetch:
		if path, ok := localClassPathKey(typed); ok {
			return classEnv[path]
		}
		return ""
	case *ast.ExprNew:
		return e.resolveClassNameForCallable(typed.Class, c)
	case *ast.ExprFuncCall:
		if className := e.directDispatchReturnClassHint(c, identifierText(typed.Name), typed.Args, stringEnv); className != "" {
			return className
		}
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		key := e.lookupFunctionKey(c.Namespace, identifierText(typed.Name))
		return e.callableReturnClassHint(key)
	case *ast.ExprStaticCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		className := e.resolveClassNameForCallable(typed.Class, c)
		if singletonClass := singletonFactoryReturnClass(identifierText(typed.Name), className); singletonClass != "" {
			return singletonClass
		}
		key := e.existingRuntimeMethodCallable(className, strings.ToLower(identifierText(typed.Name)))
		if className := e.callableReturnClassHint(key); className != "" {
			return className
		}
		return e.callableReturnedReceiverPropertyClassHintWithState(key, className, "", state)
	case *ast.ExprMethodCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		receiverClass := e.resolveHintClassExprWithState(c, typed.Var, classEnv, stringEnv, state)
		key := e.existingRuntimeMethodCallable(receiverClass, strings.ToLower(identifierText(typed.Name)))
		if className := e.callableReturnClassHint(key); className != "" {
			return className
		}
		previousMethodKey := ""
		if previousCall, ok := typed.Var.(*ast.ExprMethodCall); ok {
			previousReceiverClass := e.resolveHintClassExprWithState(c, previousCall.Var, classEnv, stringEnv, state)
			previousMethodKey = e.existingRuntimeMethodCallable(previousReceiverClass, strings.ToLower(identifierText(previousCall.Name)))
		}
		return e.callableReturnedReceiverPropertyClassHintWithState(key, receiverClass, previousMethodKey, state)
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, c.Class); ok {
			return e.receiverPropertyReturnClassHintWithState(c.Class, path, state)
		}
		return ""
	default:
		return ""
	}
}

func (e *engine) directDispatchReturnClassHint(current callable, name string, args []ast.Node, stringEnv map[string]string) string {
	candidates := e.directDispatchReturnClassCandidates(current, name, args, stringEnv)
	if len(candidates) != 1 {
		return ""
	}
	return candidates[0]
}

func (e *engine) directDispatchReturnClassCandidates(current callable, name string, args []ast.Node, stringEnv map[string]string) []string {
	dispatchName := normalizeName(name)
	var callback ast.Node
	switch dispatchName {
	case "call_user_func", "forward_static_call":
		if len(args) == 0 {
			return nil
		}
		callback = argValue(args[0])
	case "call_user_func_array", "forward_static_call_array":
		if len(args) < 2 {
			return nil
		}
		callback = argValue(args[0])
	default:
		return nil
	}
	keys := e.resolveCallbackKeysWithEnv(callback, current, stringEnv)
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	for _, key := range keys {
		if key == current.Key {
			continue
		}
		if className := summaryReturnClass(e.summaries[key]); className != "" {
			add(className)
			continue
		}
		if className := e.directReturnHints[key]; className != "" {
			add(className)
		}
	}
	return out
}

func updateDirectReturnHintLocalEnvs(e *engine, c callable, expr ast.Node, classEnv map[string]string, stringEnv map[string]string) {
	updateDirectReturnHintLocalEnvsWithState(e, c, expr, classEnv, stringEnv, newDispatchResolutionState())
}

func updateDirectReturnHintLocalEnvsWithState(e *engine, c callable, expr ast.Node, classEnv map[string]string, stringEnv map[string]string, state *dispatchResolutionState) {
	switch typed := expr.(type) {
	case *ast.ExprAssign:
		variable, ok := typed.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok || name == "" {
			return
		}
		if value := dynamicDispatchStringForCallableWithState(typed.Expr, c, e, stringEnv, state); value != "" {
			stringEnv[name] = value
		}
	case *ast.ExprAssignRef:
		variable, ok := typed.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok || name == "" {
			return
		}
		if value := dynamicDispatchStringForCallableWithState(typed.Expr, c, e, stringEnv, state); value != "" {
			stringEnv[name] = value
		}
	case *ast.ExprAssignOpConcat:
		variable, ok := typed.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok || name == "" {
			return
		}
		current := dynamicDispatchStringForCallableWithState(typed.Var, c, e, stringEnv, state)
		next := dynamicDispatchStringForCallableWithState(typed.Expr, c, e, stringEnv, state)
		if current != "" && next != "" {
			stringEnv[name] = current + next
		}
	}
}

func (e *engine) receiverPropertyReturnClassHint(className string, propertyPath string) string {
	return e.receiverPropertyReturnClassHintWithState(className, propertyPath, newDispatchResolutionState())
}

func (e *engine) receiverPropertyReturnClassHintWithState(className string, propertyPath string, state *dispatchResolutionState) string {
	candidates := e.receiverPropertyReturnClassCandidatesWithState(className, propertyPath, state)
	if len(candidates) != 1 {
		return ""
	}
	return candidates[0]
}

func (e *engine) receiverPropertyReturnClassCandidates(className string, propertyPath string) []string {
	return e.receiverPropertyReturnClassCandidatesWithState(className, propertyPath, newDispatchResolutionState())
}

func receiverPropertyClassHintKey(className string, propertyPath string) string {
	return strings.TrimSpace(className) + "|" + strings.TrimSpace(propertyPath)
}

func appendUniqueClassHint(hints []string, candidate string) []string {
	if candidate == "" {
		return hints
	}
	for _, existing := range hints {
		if existing == candidate {
			return hints
		}
	}
	return append(hints, candidate)
}

func directReturnReceiverPropertyPath(c callable, node ast.Node, varPaths map[string]string) string {
	switch typed := node.(type) {
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, c.Class); ok && strings.HasPrefix(path, "this.") {
			return path
		}
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		return varPaths[name]
	case *ast.ExprAssign:
		return directReturnReceiverPropertyPath(c, typed.Expr, varPaths)
	case *ast.ExprAssignRef:
		return directReturnReceiverPropertyPath(c, typed.Expr, varPaths)
	}
	return ""
}

func (e *engine) inferDirectReturnPropertyHint(c callable) string {
	if len(c.Stmts) == 0 || c.Class == "" {
		return ""
	}
	varPaths := map[string]string{}
	out := ""
	conflicting := false
	setPath := func(path string) {
		if path == "" {
			return
		}
		if out == "" {
			out = path
			return
		}
		if out != path {
			conflicting = true
		}
	}
	walkNodes(c.Stmts, func(node ast.Node) {
		switch typed := node.(type) {
		case *ast.StmtExpression:
			switch expr := typed.Expr.(type) {
			case *ast.ExprAssign:
				variable, ok := expr.Var.(*ast.ExprVariable)
				if !ok {
					return
				}
				name, ok := variable.Name.(string)
				if !ok || name == "" {
					return
				}
				if path := directReturnReceiverPropertyPath(c, expr.Expr, varPaths); path != "" {
					varPaths[name] = path
				} else {
					delete(varPaths, name)
				}
			case *ast.ExprAssignRef:
				variable, ok := expr.Var.(*ast.ExprVariable)
				if !ok {
					return
				}
				name, ok := variable.Name.(string)
				if !ok || name == "" {
					return
				}
				if path := directReturnReceiverPropertyPath(c, expr.Expr, varPaths); path != "" {
					varPaths[name] = path
				} else {
					delete(varPaths, name)
				}
			}
		case *ast.StmtReturn:
			setPath(directReturnReceiverPropertyPath(c, typed.Expr, varPaths))
		}
	})
	if conflicting {
		return ""
	}
	return out
}

func (e *engine) indexDirectReturnPropertyHints() {
	for _, key := range e.callOrder {
		if path := e.inferDirectReturnPropertyHint(e.callables[key]); path != "" {
			e.directReturnPropertyHints[key] = path
		}
	}
}

func (e *engine) indexReceiverPropertyReturnClassHints() {
	for _, key := range e.callOrder {
		candidateCallable := e.callables[key]
		if candidateCallable.Class == "" {
			continue
		}
		classEnv := map[string]string{}
		stringEnv := map[string]string{}
		state := newDispatchResolutionState()
		walkNodes(candidateCallable.Stmts, func(node ast.Node) {
			exprStmt, ok := node.(*ast.StmtExpression)
			if !ok {
				return
			}
			assign, ok := exprStmt.Expr.(*ast.ExprAssign)
			if !ok {
				updateDirectReturnHintLocalEnvsWithState(e, candidateCallable, exprStmt.Expr, classEnv, stringEnv, state)
				return
			}
			if path, ok := propertyPathKey(assign.Var, candidateCallable.Class); ok && strings.HasPrefix(path, "this.") {
				if resolved := e.resolveHintClassExprWithState(candidateCallable, assign.Expr, classEnv, stringEnv, state); resolved != "" {
					cacheKey := receiverPropertyClassHintKey(candidateCallable.Class, path)
					e.callbackClassHintMu.Lock()
					e.receiverPropertyClassHints[cacheKey] = appendUniqueClassHint(e.receiverPropertyClassHints[cacheKey], resolved)
					e.callbackClassHintMu.Unlock()
				}
			}
			updateDirectReturnHintLocalEnvsWithState(e, candidateCallable, exprStmt.Expr, classEnv, stringEnv, state)
		})
	}
}

func (e *engine) indexCallableReceiverPropertyClassHints() {
	for _, key := range e.callOrder {
		candidateCallable := e.callables[key]
		if candidateCallable.Class == "" {
			continue
		}
		classEnv := map[string]string{}
		stringEnv := map[string]string{}
		state := newDispatchResolutionState()
		walkNodes(candidateCallable.Stmts, func(node ast.Node) {
			exprStmt, ok := node.(*ast.StmtExpression)
			if !ok {
				return
			}
			var (
				assign *ast.ExprAssign
				ref    *ast.ExprAssignRef
				target ast.Node
				value  ast.Node
			)
			assign, _ = exprStmt.Expr.(*ast.ExprAssign)
			if assign != nil {
				target = assign.Var
				value = assign.Expr
			} else {
				ref, _ = exprStmt.Expr.(*ast.ExprAssignRef)
				if ref == nil {
					updateDirectReturnHintLocalEnvsWithState(e, candidateCallable, exprStmt.Expr, classEnv, stringEnv, state)
					return
				}
				target = ref.Var
				value = ref.Expr
			}
			if path, ok := propertyPathKey(target, candidateCallable.Class); ok && strings.HasPrefix(path, "this.") {
				if resolved := e.resolveHintClassExprWithState(candidateCallable, value, classEnv, stringEnv, state); resolved != "" {
					hints := e.callableReceiverPropertyClasses[key]
					if hints == nil {
						hints = map[string][]string{}
						e.callableReceiverPropertyClasses[key] = hints
					}
					hints[path] = appendUniqueClassHint(hints[path], resolved)
				}
			}
			updateDirectReturnHintLocalEnvsWithState(e, candidateCallable, exprStmt.Expr, classEnv, stringEnv, state)
		})
	}
}

func (e *engine) callableReceiverPropertyClassHint(key string, propertyPath string) string {
	if key == "" || propertyPath == "" {
		return ""
	}
	hints := e.callableReceiverPropertyClasses[key]
	if len(hints) == 0 {
		return ""
	}
	candidates := hints[propertyPath]
	if len(candidates) != 1 {
		return ""
	}
	return candidates[0]
}

func (e *engine) callableReturnedReceiverPropertyClassHint(key string, receiverClass string, previousMethodKey string) string {
	return e.callableReturnedReceiverPropertyClassHintWithState(key, receiverClass, previousMethodKey, newDispatchResolutionState())
}

func (e *engine) callableReturnedReceiverPropertyClassHintWithState(key string, receiverClass string, previousMethodKey string, state *dispatchResolutionState) string {
	if key == "" {
		return ""
	}
	path := e.directReturnPropertyHints[key]
	if path == "" {
		return ""
	}
	if className := e.callableReceiverPropertyClassHint(previousMethodKey, path); className != "" {
		return className
	}
	if receiverClass == "" {
		return ""
	}
	return e.receiverPropertyReturnClassHintWithState(receiverClass, path, state)
}

func (e *engine) receiverPropertyReturnClassCandidatesWithState(className string, propertyPath string, state *dispatchResolutionState) []string {
	if className == "" || propertyPath == "" {
		return nil
	}
	if state == nil {
		state = newDispatchResolutionState()
	}
	resolutionKey := receiverPropertyClassHintKey(className, propertyPath)
	if !dispatchResolutionEnter(state.property, resolutionKey) {
		return nil
	}
	defer dispatchResolutionLeave(state.property, resolutionKey)
	owners := classHierarchyForPropertyHints(className, e.classParents)
	cachedOut := make([]string, 0, 2)
	e.callbackClassHintMu.RLock()
	for _, owner := range owners {
		if cached := e.receiverPropertyClassHints[receiverPropertyClassHintKey(owner, propertyPath)]; len(cached) != 0 {
			for _, candidate := range cached {
				cachedOut = appendUniqueClassHint(cachedOut, candidate)
			}
		}
	}
	e.callbackClassHintMu.RUnlock()
	if len(cachedOut) != 0 {
		return cachedOut
	}
	cacheKey := resolutionKey
	e.callbackClassHintMu.RLock()
	if cached, ok := e.receiverPropertyFallbackHints[cacheKey]; ok && cached.Computed {
		e.callbackClassHintMu.RUnlock()
		return append([]string(nil), cached.Candidates...)
	}
	e.callbackClassHintMu.RUnlock()
	resolutionState := newDispatchResolutionStateForPropertyFallback(state)
	out := make([]string, 0, 2)
	add := func(candidate string) {
		out = appendUniqueClassHint(out, candidate)
	}
	ownerSet := map[string]struct{}{}
	for _, owner := range owners {
		ownerSet[owner] = struct{}{}
	}
	for _, key := range e.callOrder {
		candidateCallable := e.callables[key]
		if _, ok := ownerSet[candidateCallable.Class]; !ok {
			continue
		}
		classEnv := map[string]string{}
		stringEnv := map[string]string{}
		walkNodes(candidateCallable.Stmts, func(node ast.Node) {
			exprStmt, ok := node.(*ast.StmtExpression)
			if !ok {
				return
			}
			assign, ok := exprStmt.Expr.(*ast.ExprAssign)
			if !ok {
				updateDirectReturnHintLocalEnvsWithState(e, candidateCallable, exprStmt.Expr, classEnv, stringEnv, resolutionState)
				return
			}
			if path, ok := propertyPathKey(assign.Var, candidateCallable.Class); ok && path == propertyPath {
				if resolved := e.resolveHintClassExprWithState(candidateCallable, assign.Expr, classEnv, stringEnv, resolutionState); resolved != "" {
					add(resolved)
				}
			}
			updateDirectReturnHintLocalEnvsWithState(e, candidateCallable, exprStmt.Expr, classEnv, stringEnv, resolutionState)
		})
	}
	e.callbackClassHintMu.Lock()
	e.receiverPropertyFallbackHints[cacheKey] = classHintCandidatesCacheEntry{
		Candidates: append([]string(nil), out...),
		Computed:   true,
	}
	e.callbackClassHintMu.Unlock()
	return out
}

func classHierarchyForPropertyHints(className string, classParents map[string]string) []string {
	if className == "" {
		return nil
	}
	out := []string{className}
	seen := map[string]struct{}{className: {}}
	for current := className; current != ""; {
		parent := classParents[current]
		if parent == "" {
			break
		}
		if _, ok := seen[parent]; ok {
			break
		}
		seen[parent] = struct{}{}
		out = append(out, parent)
		current = parent
	}
	return out
}

func (e *engine) callableReturnClassHint(key string) string {
	if key == "" {
		return ""
	}
	if className := summaryReturnClass(e.summaries[key]); className != "" {
		return className
	}
	return e.directReturnHints[key]
}

func (e *engine) callableReturnClassCandidates(key string) []string {
	if key == "" {
		return nil
	}
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	for _, className := range e.summaries[key].ReturnClasses {
		add(className)
	}
	if len(out) == 0 {
		for _, className := range e.inferDirectReturnClasses(e.callables[key]) {
			add(className)
		}
	}
	if len(out) == 0 {
		add(e.directReturnHints[key])
	}
	return out
}

func (e *engine) markRelevantCallables() {
	type queueItem struct {
		key         string
		dataReached bool
	}
	callOnlyMode := e.allowsSinkOp("call") && len(e.allowedSinkOps) == 1
	actionOnlyMode := e.allowsSinkOp("action") && len(e.allowedSinkOps) == 1
	sqlOnlyMode := e.allowsSinkOp("sql") && len(e.allowedSinkOps) == 1
	requestGatedDirectSeeds := e.requestReachableDirectSinkSeedMode()
	reverseRelevant := map[string]struct{}{}
	queue := make([]queueItem, 0)
	for _, key := range e.callOrder {
		if !e.directSinkSeedAllowed(key, requestGatedDirectSeeds) {
			continue
		}
		reverseRelevant[key] = struct{}{}
		queue = append(queue, queueItem{key: key})
	}
	for len(queue) > 0 {
		key := queue[0].key
		queue = queue[1:]
		for next := range e.reverseCallEdges[key] {
			if requestGatedDirectSeeds {
				if _, ok := e.requestReachableCallables[next]; !ok {
					continue
				}
			}
			if callOnlyMode && !e.isCallRelevantReverseCaller(next, key) {
				continue
			}
			if actionOnlyMode && !e.isActionRelevantReverseCaller(next, key) {
				continue
			}
			if sqlOnlyMode && !e.isSQLRelevantReverseCaller(next, key) {
				continue
			}
			if _, ok := reverseRelevant[next]; ok {
				continue
			}
			reverseRelevant[next] = struct{}{}
			queue = append(queue, queueItem{key: next})
		}
	}
	anchorRelevant := cloneStringSet(reverseRelevant)
	for {
		previewRelevant := cloneStringSet(reverseRelevant)
		previewDataReached := map[string]bool{}
		previewQueue := make([]queueItem, 0, len(reverseRelevant))
		for key := range reverseRelevant {
			previewQueue = append(previewQueue, queueItem{key: key})
		}
		for len(previewQueue) > 0 {
			item := previewQueue[0]
			previewQueue = previewQueue[1:]
			for _, edge := range e.forwardRelevantCallees(item.key, reverseRelevant, anchorRelevant, item.dataReached) {
				if _, ok := previewRelevant[edge.callee]; ok {
					if edge.dataCarrier && !previewDataReached[edge.callee] {
						previewDataReached[edge.callee] = true
						previewQueue = append(previewQueue, queueItem{key: edge.callee, dataReached: true})
					}
					continue
				}
				previewRelevant[edge.callee] = struct{}{}
				previewDataReached[edge.callee] = edge.dataCarrier
				previewQueue = append(previewQueue, queueItem{key: edge.callee, dataReached: edge.dataCarrier})
			}
		}
		if !e.crossRequestWriterRelevanceEnabled() {
			break
		}
		readFamilies := map[string]struct{}{}
		for key := range previewRelevant {
			for family := range e.storageReadFamiliesByCallable[key] {
				if !supportsCrossRequestWriterSeeding(family) {
					continue
				}
				readFamilies[family] = struct{}{}
			}
		}
		if len(readFamilies) == 0 {
			break
		}
		e.ensureGlobalStateWritersIndexed()
		storageQueue := make([]queueItem, 0)
		added := false
		for key := range previewRelevant {
			className := e.callables[key].Class
			pathSeededFamilies := map[string]struct{}{}
			hasSpecificReadBucket := map[string]bool{}
			for bucket := range e.storageReadBucketsByCallable[key] {
				family := structuralPathRoot(bucket)
				if bucket != "" && family != "" && bucket != family {
					hasSpecificReadBucket[family] = true
				}
			}
			for bucket := range e.storageReadBucketsByCallable[key] {
				family := structuralPathRoot(bucket)
				if _, ok := readFamilies[family]; !ok {
					continue
				}
				if bucket == family && hasSpecificReadBucket[family] {
					continue
				}
				var writerSet map[string]struct{}
				if className != "" {
					writerSet = e.boundCrossRequestWriters(e.storagePathWritersByBucketClass[storageWriterBucketClassKey(bucket, className)])
				}
				if len(writerSet) == 0 {
					bucketWriters := e.boundCrossRequestWriters(e.storagePathWritersByBucket[bucket])
					if len(bucketWriters) == 0 {
						continue
					}
					writerSet = bucketWriters
				}
				pathSeededFamilies[family] = struct{}{}
				for writer := range writerSet {
					if !e.deleteFamilyWideWriterAllowed(writer, family) {
						continue
					}
					if _, ok := reverseRelevant[writer]; ok {
						continue
					}
					reverseRelevant[writer] = struct{}{}
					storageQueue = append(storageQueue, queueItem{key: writer})
					added = true
				}
			}
			for family := range e.storageReadFamiliesByCallable[key] {
				if _, ok := readFamilies[family]; !ok {
					continue
				}
				if _, ok := pathSeededFamilies[family]; ok {
					continue
				}
				sameClassWriters := map[string]struct{}{}
				if className != "" {
					sameClassWriters = e.boundCrossRequestWriters(e.storageBaseWritersByFamilyClass[storageWriterFamilyClassKey(family, className)])
				}
				writerSet := sameClassWriters
				if len(writerSet) == 0 {
					familyWriters := e.boundCrossRequestWriters(e.storageBaseWritersByFamily[family])
					if len(familyWriters) == 0 {
						continue
					}
					writerSet = familyWriters
				}
				for writer := range writerSet {
					if _, ok := reverseRelevant[writer]; ok {
						continue
					}
					reverseRelevant[writer] = struct{}{}
					storageQueue = append(storageQueue, queueItem{key: writer})
					added = true
				}
			}
		}
		for len(storageQueue) > 0 {
			key := storageQueue[0].key
			storageQueue = storageQueue[1:]
			for next := range e.reverseCallEdges[key] {
				if _, ok := e.requestReachableCallables[next]; !ok {
					continue
				}
				if _, ok := reverseRelevant[next]; ok {
					continue
				}
				reverseRelevant[next] = struct{}{}
				storageQueue = append(storageQueue, queueItem{key: next})
				added = true
			}
		}
		if !added {
			break
		}
	}
	e.relevantCallables = cloneStringSet(reverseRelevant)
	dataReachedCallables := map[string]bool{}
	queue = make([]queueItem, 0, len(reverseRelevant))
	for _, key := range e.callOrder {
		if _, ok := reverseRelevant[key]; ok {
			queue = append(queue, queueItem{key: key})
		}
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		for _, edge := range e.forwardRelevantCallees(item.key, reverseRelevant, anchorRelevant, item.dataReached) {
			if _, ok := e.relevantCallables[edge.callee]; ok {
				if edge.dataCarrier && !dataReachedCallables[edge.callee] {
					dataReachedCallables[edge.callee] = true
					queue = append(queue, queueItem{key: edge.callee, dataReached: true})
				}
				continue
			}
			e.relevantCallables[edge.callee] = struct{}{}
			dataReachedCallables[edge.callee] = edge.dataCarrier
			queue = append(queue, queueItem{key: edge.callee, dataReached: edge.dataCarrier})
		}
	}
	e.propagateForwardRelevantFromSeeds(e.retainDirectPublicRelevantOutputWrappers())
	e.pruneDetachedDeleteRelevantCallables(requestGatedDirectSeeds)
}

func (e *engine) retainDirectPublicRelevantOutputWrappers() []string {
	if len(e.allowedSinkOps) != 1 || !e.allowsSinkOp("output") {
		return nil
	}
	changed := true
	added := map[string]struct{}{}
	for changed {
		changed = false
		for key := range e.directPublicCallables {
			if _, ok := e.relevantCallables[key]; ok {
				continue
			}
			if _, ok := e.requestReachableCallables[key]; !ok {
				continue
			}
			for _, site := range e.callSiteEdges[key] {
				if _, ok := e.relevantCallables[site.callee]; !ok {
					continue
				}
				e.relevantCallables[key] = struct{}{}
				added[key] = struct{}{}
				changed = true
				break
			}
		}
	}
	if len(added) == 0 {
		return nil
	}
	out := make([]string, 0, len(added))
	for key := range added {
		out = append(out, key)
	}
	return out
}

func (e *engine) propagateForwardRelevantFromSeeds(seeds []string) {
	if len(seeds) == 0 {
		return
	}
	type queueItem struct {
		key         string
		dataReached bool
	}
	anchorRelevant := cloneStringSet(e.relevantCallables)
	dataReachedCallables := map[string]bool{}
	queue := make([]queueItem, 0, len(seeds))
	for _, key := range seeds {
		if key == "" {
			continue
		}
		queue = append(queue, queueItem{key: key})
	}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		for _, edge := range e.forwardRelevantCallees(item.key, e.relevantCallables, anchorRelevant, item.dataReached) {
			if _, ok := e.relevantCallables[edge.callee]; ok {
				if edge.dataCarrier && !dataReachedCallables[edge.callee] {
					dataReachedCallables[edge.callee] = true
					queue = append(queue, queueItem{key: edge.callee, dataReached: true})
				}
				continue
			}
			e.relevantCallables[edge.callee] = struct{}{}
			anchorRelevant[edge.callee] = struct{}{}
			dataReachedCallables[edge.callee] = edge.dataCarrier
			queue = append(queue, queueItem{key: edge.callee, dataReached: edge.dataCarrier})
		}
	}
}

func (e *engine) crossRequestWriterRelevanceEnabled() bool {
	if len(e.allowedSinkOps) != 1 {
		return true
	}
	if e.allowsSinkOp("sql") {
		return false
	}
	return true
}

func (e *engine) requestReachableDirectSinkSeedMode() bool {
	if len(e.directPublicCallables) == 0 {
		return false
	}
	if len(e.allowedSinkOps) != 1 {
		if len(e.allowedSinkOps) > 1 && e.allowedSinkOpsAreOnlyFileBatch() {
			return true
		}
		return false
	}
	for op := range e.allowedSinkOps {
		switch op {
		case "call", "action", "sql", "output", "read", "write", "include", "delete", "surface":
			return true
		}
	}
	return false
}

func (e *engine) allowedSinkOpsAreOnlyFileBatch() bool {
	if len(e.allowedSinkOps) == 0 {
		return false
	}
	for op := range e.allowedSinkOps {
		switch op {
		case "delete", "read", "open", "include":
		default:
			return false
		}
	}
	return true
}

func (e *engine) directSinkSeedAllowed(key string, requestGated bool) bool {
	c, ok := e.callables[key]
	if !ok || !e.callableHasDirectSink(c) {
		return false
	}
	if !requestGated {
		return true
	}
	if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call") {
		if _, ok := e.requestReachableCallables[key]; !ok {
			return false
		}
		if e.callableHasDirectRequestInput(c) {
			return true
		}
		if e.callableHasEntrypointSourceParam(c) {
			return true
		}
		if e.callableHasRecordRead(key) {
			return true
		}
		if e.callableHasDirectCallSource(c) || e.callableHasDirectSQLReadSource(c) {
			return true
		}
		if e.callableHasDynamicCallbackDirectSink(c) {
			if e.callableConsumesCallArgs(c) {
				return e.callableHasRequestReachableArgCaller(key)
			}
			if e.callableHasCallRelevantReceiverUse(key) {
				return e.callableHasRequestReachableReceiverCaller(key)
			}
			return false
		}
		if e.callableIsInternalDispatchCallback(key) {
			if e.callableConsumesCallArgs(c) {
				return e.callableHasRequestReachableDataCaller(key)
			}
			if e.callableHasCallRelevantReceiverUse(key) {
				return e.callableHasRequestReachableReceiverCaller(key)
			}
			return false
		}
		if e.callableHasCallRelevantReceiverUse(key) {
			return e.callableHasRequestReachableReceiverCaller(key)
		}
		if e.callableConsumesCallArgs(c) {
			return e.callableHasRequestReachableDataCaller(key)
		}
		return false
	}
	if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("delete") {
		if e.callableHasDirectRequestInput(c) {
			return true
		}
		if e.callableHasEntrypointSourceParam(c) {
			return true
		}
		if _, ok := e.requestOriginReachableCallables[key]; ok && e.callableHasReceiverBackedDirectDeleteSink(c) {
			return true
		}
		return e.callableHasRequestOriginDataCaller(key)
	}
	if _, ok := e.requestReachableCallables[key]; !ok {
		return false
	}
	sqlOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("sql")
	readLikeOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("read")
	writeLikeOnlyMode := len(e.allowedSinkOps) == 1 && (e.allowsSinkOp("open") || e.allowsSinkOp("write"))
	fileOnlyMode := readLikeOnlyMode || writeLikeOnlyMode
	if (sqlOnlyMode || writeLikeOnlyMode) && e.contexts[key].Access == "capability_checked" && !e.callableHasPublicLikeEntrypoint(key) {
		if sqlOnlyMode {
			if !e.callableHasWeakAuthenticatedCapabilityCheck(key) &&
				!e.callableHasRequestReachableSQLCaller(key) {
				return false
			}
		} else {
			return false
		}
	}
	directPublic := false
	if _, ok := e.directPublicCallables[key]; ok {
		directPublic = true
	}
	// Delete-only scans are too broad if every public hook callback with a local
	// cleanup sink seeds relevance. SQL-only and write-only scans have the same
	// problem: public registration alone keeps too many local sinks alive even
	// when no request or filter data reaches the sink-bearing callable.
	if directPublic && !(len(e.allowedSinkOps) == 1 && e.allowsSinkOp("delete")) && !sqlOnlyMode && !fileOnlyMode {
		return true
	}
	if sqlOnlyMode {
		if e.callableHasRelevantDirectRequestInput(c, e.sqlSinkRelevantUseOrders[key]) {
			return true
		}
		if len(e.directEntryPointsByCallable[key]) != 0 && e.callableHasDirectRequestInput(c) && e.callableHasDynamicDirectSQLSink(c) {
			return true
		}
		if e.callableHasEntrypointSourceParam(c) {
			return true
		}
		return e.callableHasRequestReachableSQLCaller(key)
	}
	if fileOnlyMode {
		if e.callableHasRelevantDirectRequestInput(c, e.fileSinkRelevantUseOrders[key]) {
			return true
		}
		if e.callableHasDirectRequestInput(c) && e.callableHasDynamicDirectFileSink(c) {
			return true
		}
		if e.callableHasEntrypointSourceParam(c) {
			return true
		}
		if readLikeOnlyMode && e.callableHasDirectSink(c) {
			if e.callableHasFileEntrypoint(key) {
				return true
			}
			return e.callableHasRequestReachableDataCaller(key) || e.callableHasRequestReachableFileCaller(key)
		}
		return e.callableHasRequestReachableFileCaller(key)
	}
	if e.callableHasDirectRequestInput(c) {
		return true
	}
	if e.callableHasEntrypointSourceParam(c) {
		return true
	}
	return e.callableHasRequestReachableDataCaller(key)
}

func (e *engine) callableHasPublicLikeEntrypoint(key string) bool {
	ctx, ok := e.contexts[key]
	if !ok {
		return false
	}
	for _, entry := range ctx.EntryPoints {
		switch entry.Kind {
		case "ajax":
			if strings.HasPrefix(entry.Name, "wp_ajax_nopriv_") {
				return true
			}
		case "admin_post":
			if strings.HasPrefix(entry.Name, "admin_post_nopriv_") {
				return true
			}
		case "rest":
			switch entry.Access {
			case "", "public", "unknown", "nonce_only":
				return true
			}
		case "front_hook", "hook", "rest_init", "shortcode", "block_render", "file":
			return true
		}
	}
	return false
}

func (e *engine) callableHasWeakAuthenticatedCapabilityCheck(key string) bool {
	ctx, ok := e.contexts[key]
	if !ok {
		return false
	}
	for _, loc := range ctx.CapabilityChecks {
		if capabilityCheckSnippetIsWeakAuthenticated(loc.Snippet) {
			return true
		}
	}
	return false
}

func capabilityCheckSnippetIsWeakAuthenticated(snippet string) bool {
	if snippet == "" {
		return false
	}
	lower := strings.ToLower(snippet)
	if strings.Contains(lower, "current_user_can") || strings.Contains(lower, "user_can") {
		return strings.Contains(lower, "'read'") || strings.Contains(lower, `"read"`)
	}
	return false
}

func (e *engine) callableHasFileEntrypoint(key string) bool {
	ctx, ok := e.contexts[key]
	if !ok {
		return false
	}
	for _, entry := range ctx.EntryPoints {
		if entry.Kind == "file" {
			return true
		}
	}
	return false
}

func (e *engine) callableHasRelevantDirectRequestInput(c callable, orders map[string]int) bool {
	if len(orders) == 0 {
		return false
	}
	found := false
	walkNodes(c.Stmts, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprAssign:
			if !exprContainsDirectRequestSource(e, c, typed.Expr) {
				return
			}
			if root := valueRootKey(typed.Var, c.Class); callRelevantRootPresent(orders, root) {
				found = true
			}
		default:
			if !isDirectRequestSourceExpr(e, c, node) {
				return
			}
			if root := valueRootKey(node, c.Class); callRelevantRootPresent(orders, root) {
				found = true
			}
		}
	})
	return found
}

func exprContainsDirectRequestSource(e *engine, c callable, node ast.Node) bool {
	found := false
	walkNode(node, func(child ast.Node) {
		if found || child == nil {
			return
		}
		if isDirectRequestSourceExpr(e, c, child) {
			found = true
		}
	})
	return found
}

func isDirectRequestSourceExpr(e *engine, c callable, node ast.Node) bool {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			switch strings.ToUpper(strings.TrimSpace(name)) {
			case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER":
				return true
			}
		}
	case *ast.ExprArrayDimFetch:
		if name, ok := superglobalArrayRootName(typed.Var); ok {
			switch strings.ToUpper(strings.TrimSpace(name)) {
			case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER":
				return true
			}
		}
	case *ast.ExprFuncCall:
		if isDirectRequestSourceFunc(identifierText(typed.Name)) {
			return true
		}
		if len(typed.Args) > 0 && isPHPInputLiteral(argValue(typed.Args[0])) {
			return true
		}
	case *ast.ExprMethodCall:
		if isRequestGetterMethodCall(typed) {
			return true
		}
	case *ast.ExprStaticCall:
		className := e.resolveClassNameForCallable(typed.Class, c)
		if isRequestGetterStaticCall(className, identifierText(typed.Name)) || isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
			return true
		}
	}
	return false
}

func (e *engine) callableHasReceiverBackedDirectDeleteSink(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(typed.Name))
			if idx, op, _, _, ok := builtinSinkByFunc(name); ok && op == "delete" && idx >= 0 && idx < len(typed.Args) {
				found = exprContainsReceiverBackedPath(argValue(typed.Args[idx]), c.Class)
			}
		case *ast.ExprMethodCall:
			if idx, op, _, _, ok := builtinMethodSink(strings.ToLower(identifierText(typed.Name))); ok && op == "delete" && idx >= 0 && idx < len(typed.Args) && e.deleteMethodSinkMatches(c, typed) {
				found = exprContainsReceiverBackedPath(argValue(typed.Args[idx]), c.Class)
			}
		}
	})
	return found
}

func (e *engine) callableHasDynamicCallbackDirectSink(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		call, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		name := normalizeName(identifierText(call.Name))
		if !isDynamicCallbackHelper(name) || len(call.Args) == 0 {
			return
		}
		callbackExpr := argValue(call.Args[0])
		found = isDynamicCallbackExpr(callbackExpr) || isDynamicCallbackArrayExpr(callbackExpr)
	})
	return found
}

func exprContainsReceiverBackedPath(node ast.Node, currentClass string) bool {
	found := false
	walkNode(node, func(child ast.Node) {
		if found || child == nil {
			return
		}
		switch typed := child.(type) {
		case *ast.ExprPropertyFetch:
			if path, ok := propertyPathKey(typed, currentClass); ok && strings.HasPrefix(path, "this.") {
				found = true
			}
		case *ast.ExprArrayDimFetch:
			if path, ok := propertyPathKey(typed, currentClass); ok && strings.HasPrefix(path, "this.") {
				found = true
			}
		}
	})
	return found
}

func (e *engine) callableHasEntrypointSourceParam(c callable) bool {
	for idx := range c.Params {
		if _, ok := directEntrypointParamSourceKind(e.directEntryPointsByCallable[c.Key], idx); ok {
			return true
		}
	}
	return false
}

func (e *engine) callableHasDirectCallSource(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		call, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		name := normalizeName(identifierText(call.Name))
		if name == "file_get_contents" && len(call.Args) > 0 && !isDefinitelyStaticIncludePath(argValue(call.Args[0])) {
			found = true
			return
		}
		if isRemoteResponseSourceFunc(name) {
			found = true
		}
	})
	return found
}

func (e *engine) callableHasDirectSQLReadSource(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprMethodCall:
			switch strings.ToLower(identifierText(typed.Name)) {
			case "get_var", "get_row", "get_col", "get_results":
				found = true
				return
			}
			if _, _, ok := sqlSelectColumnsForMethodCallWithContext(typed, c, e, typed.StartLine()); ok {
				found = true
			}
		case *ast.ExprStaticCall:
			switch strings.ToLower(identifierText(typed.Name)) {
			case "get_var", "get_row", "get_col", "get_results":
				found = true
				return
			}
			if _, _, ok := sqlSelectColumnsForStaticCall(typed); ok {
				found = true
			}
		}
	})
	return found
}

func (e *engine) callableHasDynamicDirectSQLSink(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.StmtReturn:
			if callableHasSQLClauseFilterReturnSink(e, c) && typed.Expr != nil && !isDefinitelyStaticIncludePath(typed.Expr) {
				found = true
			}
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(typed.Name))
			if idx, op, _, _, ok := builtinSinkByFunc(name); ok && op == "sql" && idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) {
				found = true
			}
		case *ast.ExprMethodCall:
			if idx, _, _, ok := sqlExecutionMethodArgIndex(strings.ToLower(identifierText(typed.Name))); ok && idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) {
				found = true
			}
			if sinkIndexes, _, _, ok := sqlIdentifierWriteMethodArgIndexes(strings.ToLower(identifierText(typed.Name))); ok && callableHasSQLIdentifierWriteMethodSink(e, c, typed) {
				for _, idx := range sinkIndexes {
					if idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) {
						found = true
						return
					}
				}
			}
		case *ast.ExprStaticCall:
			if idx, _, _, ok := sqlExecutionMethodArgIndex(strings.ToLower(identifierText(typed.Name))); ok && idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) {
				found = true
			}
		}
	})
	return found
}

func (e *engine) callableHasDynamicDirectFileSink(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprInclude:
			found = e.allowsSinkOp("include") && !isDefinitelyStaticIncludePath(typed.Expr) && exprMayProducePathLikeValue(typed.Expr)
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(typed.Name))
			if indexes, ok := fileUploadSinkArgIndexesByFunc(name); ok {
				if !e.allowsSinkOp("write") {
					return
				}
				for _, idx := range indexes {
					if idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
						found = true
						return
					}
				}
				return
			}
			if idx, op, _, _, ok := builtinSinkByFunc(name); ok {
				switch op {
				case "delete", "read", "open", "include", "write":
					if e.allowsSinkOp(op) && idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
						found = true
					}
				}
			}
		case *ast.ExprMethodCall:
			if indexes, ok := fileUploadSinkArgIndexesByMethod(strings.ToLower(identifierText(typed.Name))); ok {
				if !e.allowsSinkOp("write") {
					return
				}
				if !fileUploadSinkMethodMatchesMethodCall(strings.ToLower(identifierText(typed.Name)), typed, c, e) {
					return
				}
				for _, idx := range indexes {
					if idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
						found = true
						return
					}
				}
			}
			if idx, op, _, _, ok := builtinMethodSink(strings.ToLower(identifierText(typed.Name))); ok {
				switch op {
				case "delete", "read", "open", "include", "write":
					if e.allowsSinkOp(op) && idx >= 0 && idx < len(typed.Args) && e.deleteMethodSinkMatches(c, typed) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
						found = true
					}
				}
			}
		case *ast.ExprStaticCall:
			if indexes, ok := fileUploadSinkArgIndexesByMethod(strings.ToLower(identifierText(typed.Name))); ok {
				if !e.allowsSinkOp("write") {
					return
				}
				for _, idx := range indexes {
					if idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
						found = true
						return
					}
				}
			}
			if idx, op, _, _, ok := builtinMethodSink(strings.ToLower(identifierText(typed.Name))); ok {
				switch op {
				case "delete", "read", "open", "include", "write":
					if e.allowsSinkOp(op) && idx >= 0 && idx < len(typed.Args) && e.deleteStaticSinkMatches(c, typed) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
						found = true
					}
				}
			}
		}
	})
	return found
}

func (e *engine) callableHasDynamicDirectDeleteSink(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(typed.Name))
			if idx, op, _, _, ok := builtinSinkByFunc(name); ok && op == "delete" && idx >= 0 && idx < len(typed.Args) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
				found = true
			}
		case *ast.ExprMethodCall:
			if idx, op, _, _, ok := builtinMethodSink(strings.ToLower(identifierText(typed.Name))); ok && op == "delete" && idx >= 0 && idx < len(typed.Args) && e.deleteMethodSinkMatches(c, typed) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
				found = true
			}
		case *ast.ExprStaticCall:
			if idx, op, _, _, ok := builtinMethodSink(strings.ToLower(identifierText(typed.Name))); ok && op == "delete" && idx >= 0 && idx < len(typed.Args) && e.deleteStaticSinkMatches(c, typed) && !isDefinitelyStaticIncludePath(argValue(typed.Args[idx])) && exprMayProducePathLikeValue(argValue(typed.Args[idx])) {
				found = true
			}
		}
	})
	return found
}

func (e *engine) callableHasRequestReachableDataCaller(callee string) bool {
	if callee == "" {
		return false
	}
	for callerKey, sites := range e.callSiteEdges {
		if _, ok := e.requestReachableCallables[callerKey]; !ok {
			continue
		}
		for _, site := range sites {
			if site.callee != callee {
				continue
			}
			if site.dataCarrier || site.argCarrier {
				return true
			}
		}
	}
	return false
}

func (e *engine) callableHasRequestReachableSQLCaller(callee string) bool {
	if callee == "" {
		return false
	}
	calleeCallable := e.callables[callee]
	paramIndexes := e.sqlRelevantParamIndexes(calleeCallable)
	receiverRelevant := e.callableHasSQLRelevantReceiverUse(callee)
	if len(paramIndexes) == 0 && !receiverRelevant {
		return false
	}
	for callerKey, sites := range e.callSiteEdges {
		if _, ok := e.requestReachableCallables[callerKey]; !ok {
			continue
		}
		for _, site := range sites {
			if site.callee != callee {
				continue
			}
			if callSiteSuppliesRuntimeArgAtAnyConsumedParam(site, paramIndexes) {
				return true
			}
			if receiverRelevant && site.receiverCarrier {
				return true
			}
		}
	}
	return false
}

func (e *engine) callableHasRequestReachableFileCaller(callee string) bool {
	if callee == "" {
		return false
	}
	calleeCallable := e.callables[callee]
	paramIndexes := e.fileRelevantParamIndexes(calleeCallable)
	receiverRelevant := e.callableHasFileRelevantReceiverUse(callee)
	for callerKey, sites := range e.callSiteEdges {
		if _, ok := e.requestReachableCallables[callerKey]; !ok {
			continue
		}
		callerOrders := e.fileSinkRelevantUseOrders[callerKey]
		for _, site := range sites {
			if site.callee != callee {
				continue
			}
			if site.assignedRoot != "" && callRelevantUseAfter(callerOrders, site.assignedRoot, site.order) {
				return true
			}
			if callSiteSuppliesRuntimeArgAtAnyConsumedParam(site, paramIndexes) {
				return true
			}
			if receiverRelevant && site.receiverCarrier {
				return true
			}
		}
	}
	return false
}

func (e *engine) callableHasRequestReachableArgCaller(callee string) bool {
	if callee == "" {
		return false
	}
	calleeCallable := e.callables[callee]
	for callerKey, sites := range e.callSiteEdges {
		if _, ok := e.requestReachableCallables[callerKey]; !ok {
			continue
		}
		for _, site := range sites {
			if site.callee == callee && callSiteSuppliesRuntimeArgAtAnyConsumedParam(site, e.callRelevantParamIndexes(calleeCallable)) {
				return true
			}
		}
	}
	return false
}

func (e *engine) callableHasRequestReachableReceiverCaller(callee string) bool {
	if callee == "" {
		return false
	}
	for callerKey, sites := range e.callSiteEdges {
		if _, ok := e.requestReachableCallables[callerKey]; !ok {
			continue
		}
		for _, site := range sites {
			if site.callee == callee && site.receiverCarrier {
				return true
			}
		}
	}
	return false
}

func (e *engine) callableHasRequestOriginDataCaller(callee string) bool {
	if callee == "" {
		return false
	}
	for callerKey, sites := range e.callSiteEdges {
		if _, ok := e.requestOriginReachableCallables[callerKey]; !ok {
			continue
		}
		for _, site := range sites {
			if site.callee != callee {
				continue
			}
			if site.dataCarrier || site.argCarrier {
				return true
			}
		}
	}
	return false
}

func (e *engine) boundCrossRequestWriters(writerSet map[string]struct{}) map[string]struct{} {
	if len(writerSet) == 0 {
		return nil
	}
	reachable := map[string]struct{}{}
	for writer := range writerSet {
		if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("delete") {
			c := e.callables[writer]
			if !e.callableHasDirectRequestInput(c) && !e.callableHasEntrypointSourceParam(c) && !e.callableHasRequestOriginDataCaller(writer) {
				continue
			}
		}
		if _, ok := e.requestReachableCallables[writer]; ok {
			reachable[writer] = struct{}{}
		}
	}
	if len(reachable) != 0 {
		if len(reachable) > maxCrossRequestFamilyWideWriterFallback {
			return nil
		}
		return reachable
	}
	if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("delete") {
		return nil
	}
	if len(writerSet) > maxCrossRequestFamilyWideWriterFallback {
		return nil
	}
	return writerSet
}

func (e *engine) deleteFamilyWideWriterAllowed(writer string, family string) bool {
	if writer == "" || family == "" {
		return false
	}
	if len(e.allowedSinkOps) != 1 || !e.allowsSinkOp("delete") {
		return true
	}
	switch family {
	case "meta_value", "post_meta_value", "user_meta_value", "term_meta_value", "comment_meta_value":
	default:
		return true
	}
	if e.callableHasPreciseWriterBucketForFamily(writer, family) {
		return true
	}
	return e.callableLooksLikeSerializedMetaWriter(writer)
}

func (e *engine) callableHasPreciseWriterBucketForFamily(writer string, family string) bool {
	for bucket, writers := range e.storagePathWritersByBucket {
		if structuralPathRoot(bucket) != family || bucket == family {
			continue
		}
		if _, ok := writers[writer]; ok {
			return true
		}
	}
	return false
}

func (e *engine) callableLooksLikeSerializedMetaWriter(key string) bool {
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		call, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		switch normalizeName(identifierText(call.Name)) {
		case "maybe_serialize", "serialize", "json_encode", "wp_json_encode":
			found = true
		}
	})
	return found
}

func (e *engine) callableHasSupportedCrossRequestWriter(key string) bool {
	for family, writers := range e.storageBaseWritersByFamily {
		if !supportsCrossRequestWriterSeeding(family) {
			continue
		}
		if _, ok := writers[key]; ok {
			if !e.deleteFamilyWideWriterAllowed(key, family) {
				continue
			}
			return true
		}
	}
	for bucket, writers := range e.storagePathWritersByBucket {
		if !supportsCrossRequestWriterSeeding(structuralPathRoot(bucket)) {
			continue
		}
		if _, ok := writers[key]; ok {
			return true
		}
	}
	return false
}

func (e *engine) callableLooksLikeDeleteReturnChurnHelper(key string) bool {
	c, ok := e.callables[key]
	if !ok || c.Class == "" {
		return false
	}
	if strings.HasSuffix(strings.ToLower(key), "::__construct") {
		return false
	}
	if e.callableHasDirectSink(c) || e.callableIsStorageWriter(key) {
		return false
	}
	for _, site := range e.callSiteEdges[key] {
		if site.callee == key && site.dataCarrier {
			return true
		}
	}
	return false
}

func (e *engine) pruneDetachedDeleteRelevantCallables(requestGated bool) {
	if len(e.allowedSinkOps) != 1 || !e.allowsSinkOp("delete") || !requestGated {
		return
	}
	roots := map[string]struct{}{}
	for key := range e.relevantCallables {
		if e.directSinkSeedAllowed(key, requestGated) || e.callableHasSupportedCrossRequestWriter(key) {
			roots[key] = struct{}{}
		}
	}
	if len(roots) == 0 {
		return
	}
	reverseKeep := cloneStringSet(roots)
	queue := make([]string, 0, len(roots))
	for key := range roots {
		queue = append(queue, key)
	}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		for prev := range e.reverseCallEdges[key] {
			if _, ok := e.relevantCallables[prev]; !ok {
				continue
			}
			if _, ok := reverseKeep[prev]; ok {
				continue
			}
			reverseKeep[prev] = struct{}{}
			queue = append(queue, prev)
		}
	}
	keep := cloneStringSet(reverseKeep)
	type queueItem struct {
		key         string
		dataReached bool
	}
	dataReachedCallables := map[string]bool{}
	forwardQueue := make([]queueItem, 0, len(reverseKeep))
	for _, key := range e.callOrder {
		if _, ok := reverseKeep[key]; ok {
			forwardQueue = append(forwardQueue, queueItem{key: key})
		}
	}
	for len(forwardQueue) > 0 {
		item := forwardQueue[0]
		forwardQueue = forwardQueue[1:]
		for _, edge := range e.forwardRelevantCallees(item.key, reverseKeep, reverseKeep, item.dataReached) {
			if _, ok := e.relevantCallables[edge.callee]; !ok {
				continue
			}
			if _, ok := keep[edge.callee]; ok {
				if edge.dataCarrier && !dataReachedCallables[edge.callee] {
					dataReachedCallables[edge.callee] = true
					forwardQueue = append(forwardQueue, queueItem{key: edge.callee, dataReached: true})
				}
				continue
			}
			keep[edge.callee] = struct{}{}
			dataReachedCallables[edge.callee] = edge.dataCarrier
			forwardQueue = append(forwardQueue, queueItem{key: edge.callee, dataReached: edge.dataCarrier})
		}
	}
	e.relevantCallables = keep
}

func (e *engine) isCallRelevantReverseCaller(caller string, callee string) bool {
	c, ok := e.callables[caller]
	if !ok {
		return false
	}
	calleeCallable, ok := e.callables[callee]
	if !ok {
		return false
	}
	if e.callableHasDirectSink(c) {
		return true
	}
	callRelevantOrders := e.callSinkRelevantUseOrders[caller]
	relevantOrderAfter := func(order int) bool {
		for _, useOrder := range callRelevantOrders {
			if useOrder > order {
				return true
			}
		}
		return false
	}
	for _, site := range e.callSiteEdges[caller] {
		if site.callee != callee {
			continue
		}
		if e.callInputConsumingCallables[callee] && e.callSiteSuppliesConsumedInput(e.callables[callee], site) {
			return true
		}
		if e.callableHasDirectRequestInput(calleeCallable) || e.callableHasEntrypointSourceParam(calleeCallable) || e.callableHasRecordRead(callee) || e.callableHasDirectCallSource(calleeCallable) || e.callableHasDirectSQLReadSource(calleeCallable) {
			return true
		}
		if !site.dataCarrier {
			if relevantOrderAfter(site.order) {
				return true
			}
			continue
		}
		if site.assignedRoot == "" {
			return true
		}
		if callRelevantUseAfter(callRelevantOrders, site.assignedRoot, site.order) {
			return true
		}
	}
	return false
}

func (e *engine) isActionRelevantReverseCaller(caller string, callee string) bool {
	callerCallable, ok := e.callables[caller]
	if !ok {
		return false
	}
	calleeCallable, ok := e.callables[callee]
	if !ok {
		return false
	}
	if e.callableHasDirectSink(callerCallable) {
		return true
	}
	actionRelevantOrders := e.actionSinkRelevantUseOrders[caller]
	relevantOrderAfter := func(order int) bool {
		for _, useOrder := range actionRelevantOrders {
			if useOrder > order {
				return true
			}
		}
		return false
	}
	callerHasDirectSource := e.callableHasDirectRequestInput(callerCallable) ||
		e.callableHasEntrypointSourceParam(callerCallable) ||
		e.callableHasRecordRead(caller) ||
		e.callableHasDirectCallSource(callerCallable) ||
		e.callableHasDirectSQLReadSource(callerCallable)
	for _, site := range e.callSiteEdges[caller] {
		if site.callee != callee {
			continue
		}
		if callerHasDirectSource && (site.dataCarrier || site.argCarrier || site.receiverCarrier) {
			return true
		}
		if e.callableConsumesActionInput(callee) && site.dataCarrier {
			return true
		}
		if e.callableHasDirectRequestInput(calleeCallable) ||
			e.callableHasEntrypointSourceParam(calleeCallable) ||
			e.callableHasRecordRead(callee) ||
			e.callableHasDirectCallSource(calleeCallable) ||
			e.callableHasDirectSQLReadSource(calleeCallable) ||
			e.callableIsStorageWriter(callee) {
			return true
		}
		if !site.dataCarrier {
			if relevantOrderAfter(site.order) {
				return true
			}
			continue
		}
		if site.assignedRoot == "" {
			return true
		}
		if callRelevantUseAfter(actionRelevantOrders, site.assignedRoot, site.order) {
			return true
		}
	}
	return false
}

func (e *engine) isSQLRelevantReverseCaller(caller string, callee string) bool {
	callerCallable, ok := e.callables[caller]
	if !ok {
		return false
	}
	calleeCallable, ok := e.callables[callee]
	if !ok {
		return false
	}
	sqlRelevantOrders := e.sqlSinkRelevantUseOrders[caller]
	relevantOrderAfter := func(order int) bool {
		for _, useOrder := range sqlRelevantOrders {
			if useOrder > order {
				return true
			}
		}
		return false
	}
	paramIndexes := e.sqlRelevantParamIndexes(calleeCallable)
	receiverRelevant := e.callableHasSQLRelevantReceiverUse(callee)
	for _, site := range e.callSiteEdges[caller] {
		if site.callee != callee {
			continue
		}
		if callSiteSuppliesRuntimeArgAtAnyConsumedParam(site, paramIndexes) {
			return true
		}
		if receiverRelevant && site.receiverCarrier {
			return true
		}
		if !site.dataCarrier {
			if relevantOrderAfter(site.order) {
				return true
			}
			continue
		}
		if site.assignedRoot == "" {
			return true
		}
		if callRelevantUseAfter(sqlRelevantOrders, site.assignedRoot, site.order) {
			return true
		}
	}
	if e.callableHasDirectSink(callerCallable) && len(sqlRelevantOrders) != 0 {
		return true
	}
	return false
}

func callRelevantUseAfter(orders map[string]int, root string, order int) bool {
	if root == "" {
		return false
	}
	arrayPrefix := root + "["
	propPrefix := root + "."
	for key, useOrder := range orders {
		if useOrder <= order {
			continue
		}
		if key == root || strings.HasPrefix(key, arrayPrefix) || strings.HasPrefix(key, propPrefix) {
			return true
		}
	}
	return false
}

func callRelevantRootPresent(orders map[string]int, root string) bool {
	if root == "" {
		return false
	}
	arrayPrefix := root + "["
	propPrefix := root + "."
	for key := range orders {
		if key == root || strings.HasPrefix(key, arrayPrefix) || strings.HasPrefix(key, propPrefix) {
			return true
		}
	}
	return false
}

func (e *engine) callableHasDirectRequestInput(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprVariable:
			if name, ok := typed.Name.(string); ok {
				switch strings.ToUpper(strings.TrimSpace(name)) {
				case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER":
					found = true
				}
			}
		case *ast.ExprArrayDimFetch:
			if name, ok := superglobalArrayRootName(typed.Var); ok {
				switch strings.ToUpper(strings.TrimSpace(name)) {
				case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER":
					found = true
				}
			}
		case *ast.ExprFuncCall:
			if isDirectRequestSourceFunc(identifierText(typed.Name)) {
				found = true
			}
			if len(typed.Args) > 0 && isPHPInputLiteral(argValue(typed.Args[0])) {
				found = true
			}
		case *ast.ExprMethodCall:
			if isRequestGetterMethodCall(typed) {
				found = true
			}
		case *ast.ExprStaticCall:
			className := e.resolveClassNameForCallable(typed.Class, c)
			if isRequestGetterStaticCall(className, identifierText(typed.Name)) || isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
				found = true
			}
		}
	})
	return found
}

func supportsCrossRequestWriterSeeding(family string) bool {
	switch family {
	case "meta_value", "post_meta_value", "user_meta_value", "term_meta_value", "comment_meta_value", "post_record", "post_content", "post_excerpt", "form_data":
		return true
	default:
		return false
	}
}

func (e *engine) forwardRelevantCallees(key string, reverseRelevant map[string]struct{}, anchorRelevant map[string]struct{}, dataReached bool) []forwardEdge {
	out := map[string]bool{}
	callRelevantOrders := e.callSinkRelevantUseOrders[key]
	callOnlyMode := e.allowsSinkOp("call") && len(e.allowedSinkOps) == 1
	outputRelevantOrders := e.outputSinkRelevantUseOrders[key]
	outputOnlyMode := e.allowsSinkOp("output") && len(e.allowedSinkOps) == 1
	sqlRelevantOrders := e.sqlSinkRelevantUseOrders[key]
	sqlOnlyMode := e.allowsSinkOp("sql") && len(e.allowedSinkOps) == 1
	actionRelevantOrders := e.actionSinkRelevantUseOrders[key]
	actionOnlyMode := e.allowsSinkOp("action") && len(e.allowedSinkOps) == 1
	fileRelevantOrders := e.fileSinkRelevantUseOrders[key]
	fileOnlyMode := len(e.allowedSinkOps) == 1 && (e.allowsSinkOp("read") || e.allowsSinkOp("open") || e.allowsSinkOp("write"))
	deleteReturnOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("delete")
	requestGatedDirectSeeds := e.requestReachableDirectSinkSeedMode()
	deleteAnchorOrder := -1
	if deleteReturnOnlyMode {
		for _, site := range e.callSiteEdges[key] {
			if site.callee == "" {
				continue
			}
			if _, ok := reverseRelevant[site.callee]; ok {
				if deleteAnchorOrder == -1 || site.order < deleteAnchorOrder {
					deleteAnchorOrder = site.order
				}
				continue
			}
			if _, ok := anchorRelevant[site.callee]; ok {
				if deleteAnchorOrder == -1 || site.order < deleteAnchorOrder {
					deleteAnchorOrder = site.order
				}
				continue
			}
			if e.callableHasDirectSink(e.callables[site.callee]) {
				if deleteAnchorOrder == -1 || site.order < deleteAnchorOrder {
					deleteAnchorOrder = site.order
				}
				continue
			}
			if e.callableIsStorageWriter(site.callee) {
				if deleteAnchorOrder == -1 || site.order < deleteAnchorOrder {
					deleteAnchorOrder = site.order
				}
			}
		}
	}
	for _, site := range e.callSiteEdges[key] {
		if site.callee == "" {
			continue
		}
		if !site.dataCarrier && !site.argCarrier && !site.receiverCarrier && !site.receiverStateRelevant {
			continue
		}
		if callOnlyMode {
			keep := false
			if site.assignedRoot != "" && callRelevantUseAfter(callRelevantOrders, site.assignedRoot, site.order) {
				keep = true
			}
			if !keep {
				if _, ok := reverseRelevant[site.callee]; ok {
					keep = true
				} else if _, ok := anchorRelevant[site.callee]; ok {
					keep = true
				} else if e.callableHasDirectSink(e.callables[site.callee]) {
					keep = true
				} else if e.callInputConsumingCallables[site.callee] && e.callSiteSuppliesConsumedInput(e.callables[site.callee], site) {
					keep = true
				}
			}
			if !keep {
				continue
			}
		}
		if actionOnlyMode {
			keep := false
			if site.assignedRoot != "" && callRelevantUseAfter(actionRelevantOrders, site.assignedRoot, site.order) {
				keep = true
			}
			if !keep {
				if _, ok := reverseRelevant[site.callee]; ok {
					keep = true
				} else if _, ok := anchorRelevant[site.callee]; ok {
					keep = true
				} else if e.callableHasDirectSink(e.callables[site.callee]) {
					keep = true
				} else if e.callableIsStorageWriter(site.callee) {
					keep = true
				}
			}
			if !keep {
				continue
			}
		}
		if outputOnlyMode {
			keep := false
			if site.assignedRoot != "" && callRelevantUseAfter(outputRelevantOrders, site.assignedRoot, site.order) {
				keep = true
			}
			if !keep {
				if site.assignedRoot == "" {
					for _, useOrder := range outputRelevantOrders {
						if useOrder > site.order {
							keep = true
							break
						}
					}
				}
			}
			if !keep {
				if _, ok := reverseRelevant[site.callee]; ok {
					keep = true
				} else if _, ok := anchorRelevant[site.callee]; ok {
					keep = true
				} else if e.callableHasOutputRelevantBoundary(site.callee) {
					keep = true
				} else if e.callableConsumesOutputInput(site.callee) {
					keep = true
				}
			}
			if !keep {
				continue
			}
		}
		if sqlOnlyMode {
			keep := false
			if site.assignedRoot != "" && callRelevantUseAfter(sqlRelevantOrders, site.assignedRoot, site.order) {
				keep = true
			}
			if !keep {
				if _, ok := reverseRelevant[site.callee]; ok {
					keep = true
				} else if _, ok := anchorRelevant[site.callee]; ok {
					keep = true
				}
			}
			if !keep {
				continue
			}
		}
		if fileOnlyMode {
			keep := false
			if site.assignedRoot != "" && callRelevantUseAfter(fileRelevantOrders, site.assignedRoot, site.order) {
				keep = true
			}
			if !keep {
				if _, ok := reverseRelevant[site.callee]; ok {
					keep = true
				} else if _, ok := anchorRelevant[site.callee]; ok {
					keep = true
				}
			}
			if !keep {
				continue
			}
		}
		if deleteReturnOnlyMode {
			keep := false
			if site.assignedRoot != "" && callRelevantUseAfter(fileRelevantOrders, site.assignedRoot, site.order) {
				keep = true
			}
			if !keep {
				if _, ok := reverseRelevant[site.callee]; ok {
					keep = true
				} else if _, ok := anchorRelevant[site.callee]; ok {
					keep = true
				} else if e.callableHasDirectSink(e.callables[site.callee]) {
					keep = true
				} else if e.callableIsStorageWriter(site.callee) {
					keep = true
				}
			}
			if !keep {
				if site.assignedRoot != "" && e.callableLooksLikeDeleteReturnChurnHelper(site.callee) {
					continue
				}
				if deleteAnchorOrder != -1 && site.order > deleteAnchorOrder {
					continue
				}
			}
		}
		out[site.callee] = true
	}
	anchorOrder := -1
	if e.callableHasDirectSink(e.callables[key]) || dataReached {
		for _, site := range e.callSiteEdges[key] {
			if site.order > anchorOrder {
				anchorOrder = site.order
			}
		}
	}
	for _, site := range e.callSiteEdges[key] {
		if site.callee == "" || site.dataCarrier {
			continue
		}
		if deleteReturnOnlyMode && site.hasReceiver && site.receiverCarrier {
			_, calleeMutatesReceiver := e.receiverMutatingCallables[site.callee]
			if calleeMutatesReceiver {
				if _, ok := out[site.callee]; !ok {
					out[site.callee] = false
				}
				continue
			}
		}
		if e.callableIsStorageWriter(site.callee) {
			if !sqlOnlyMode && !fileOnlyMode {
				if _, ok := out[site.callee]; !ok {
					out[site.callee] = false
				}
			}
			continue
		}
		if _, ok := anchorRelevant[site.callee]; ok {
			if anchorOrder == -1 || site.order < anchorOrder {
				anchorOrder = site.order
			}
			continue
		}
		if e.callableHasDirectSink(e.callables[site.callee]) {
			if anchorOrder == -1 || site.order < anchorOrder {
				anchorOrder = site.order
			}
		}
	}
	if anchorOrder >= 0 {
		for _, site := range e.callSiteEdges[key] {
			if site.callee == "" || site.dataCarrier || site.order > anchorOrder {
				continue
			}
			if callOnlyMode {
				if _, ok := reverseRelevant[site.callee]; !ok {
					if _, ok := anchorRelevant[site.callee]; !ok && !e.directSinkSeedAllowed(site.callee, requestGatedDirectSeeds) {
						continue
					}
				}
			}
			if sqlOnlyMode || fileOnlyMode {
				if _, ok := anchorRelevant[site.callee]; !ok && !e.directSinkSeedAllowed(site.callee, requestGatedDirectSeeds) {
					continue
				}
			}
			if _, ok := out[site.callee]; !ok {
				out[site.callee] = false
			}
		}
	}
	keys := make([]forwardEdge, 0, len(out))
	for callee, byData := range out {
		keys = append(keys, forwardEdge{callee: callee, dataCarrier: byData})
	}
	return keys
}

func callableHasAttachmentDispositionHeaderBefore(e *engine, c callable, beforeLine int) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		call, ok := node.(*ast.ExprFuncCall)
		if !ok || normalizeName(identifierText(call.Name)) != "header" || len(call.Args) == 0 {
			return
		}
		line := call.StartLine()
		if beforeLine > 0 && (line <= 0 || line >= beforeLine) {
			return
		}
		if isAttachmentDispositionHeaderValue(argValue(call.Args[0]), c, e) {
			found = true
		}
	})
	return found
}

func callableHasDownloadDataSource(c callable) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		call, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		switch normalizeName(identifierText(call.Name)) {
		case "file_get_contents", "readfile", "fpassthru":
			found = true
		}
	})
	return found
}

func callableHasDirectDownloadActionSink(e *engine, c callable) bool {
	if !e.callableHasRecordRead(c.Key) && !callableHasDownloadDataSource(c) {
		return false
	}
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.StmtEcho:
			if callableHasAttachmentDispositionHeaderBefore(e, c, typed.StartLine()) {
				found = true
			}
		case *ast.ExprPrint:
			if callableHasAttachmentDispositionHeaderBefore(e, c, typed.StartLine()) {
				found = true
			}
		case *ast.ExprFuncCall:
			if isDownloadOutputFunc(identifierText(typed.Name)) && callableHasAttachmentDispositionHeaderBefore(e, c, typed.StartLine()) {
				found = true
			}
		}
	})
	return found
}

func (e *engine) callableHasDirectSink(c callable) bool {
	if e.allowsSinkOp("sql") && callableHasSQLClauseFilterReturnSink(e, c) {
		return true
	}
	if e.allowsSinkOp("action") && callableHasDirectDownloadActionSink(e, c) {
		return true
	}
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found {
			return
		}
		switch typed := node.(type) {
		case *ast.StmtReturn:
			found = e.allowsSinkOp("output") && engineCallableReturnsPublicMarkup(e, c.Key)
			if !found && e.allowsSinkOp("surface") && e.callableHasPublicTokenIssuanceSurfaceSink(c) {
				found = true
			}
		case *ast.StmtEcho:
			found = e.allowsSinkOp("output") && (e.callableHasRecordRead(c.Key) || (e.callableHasDirectRequestInput(c) && !e.callableNeedsLiteralArgSpecialization(c)))
		case *ast.ExprPrint:
			found = e.allowsSinkOp("output") && (e.callableHasRecordRead(c.Key) || (e.callableHasDirectRequestInput(c) && !e.callableNeedsLiteralArgSpecialization(c)))
		case *ast.ExprEval:
			found = e.allowsSinkOp("call")
		case *ast.ExprShellExec:
			found = e.allowsSinkOp("call")
		case *ast.ExprInclude:
			found = (e.allowsSinkOp("include") && !isDefinitelyStaticIncludePath(typed.Expr)) ||
				e.callableHasStaticIncludedOutputSink(c, typed.Expr)
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(typed.Name))
			if e.allowsSinkOp("call") && isDynamicCallNameExpr(typed.Name) {
				found = true
			}
			if _, ok := directOutputFuncArgIndexes(typed); ok && e.allowsSinkOp("output") &&
				(e.callableHasRecordRead(c.Key) || e.callableHasDirectRequestInput(c)) {
				found = true
			}
			if _, _, _, ok := builtinRedirectHeaderSinkByFunc(name); ok && e.allowsSinkOp("action") {
				found = true
			}
			if e.allowsSinkOp("surface") && e.callableHasIssuedAuthLinkSurfaceSink(c) {
				found = true
			}
			if name == "register_rest_route" && e.allowsSinkOp("surface") && callableHasPublicRestRouteSurfaceSink(e, c, typed) {
				found = true
			}
			if e.allowsSinkOp("surface") && e.callableHasUploadValidationSurfaceSink(c) {
				found = true
			}
			if e.allowsSinkOp("surface") && e.callableHasPredictableIdentifierSurfaceSink(c) {
				found = true
			}
			if _, _, _, ok := unsafeUseFuncArgIndexes(name); ok && e.allowsSinkOp("call") {
				found = true
			}
			if _, _, _, _, ok := privilegeMutationFuncArgPath(name); ok && e.allowsSinkOp("call") {
				found = true
			}
			if _, ok := capabilityMetaPrivilegeValueArgIndex(typed); ok && e.allowsSinkOp("call") {
				found = true
			}
			if _, op, _, _, ok := builtinSinkByFunc(name); ok && e.allowsSinkOp(op) {
				found = true
			}
			if _, _, _, ok := unsafeDeserializationFuncArgIndex(typed); ok && e.allowsSinkOp("call") {
				found = true
			}
			if _, _, _, ok := unsafeDeserializationCallbackArgIndexes(typed); ok && e.allowsSinkOp("call") {
				found = true
			}
			if _, ok := fileUploadSinkArgIndexesByFunc(name); ok && e.allowsSinkOp("write") {
				found = true
			}
			if _, ok := actionSinkModelByFunc(name); ok && e.allowsSinkOp("action") {
				found = true
			}
			if _, _, _, ok := sqlExecutionFuncArgIndex(name, len(typed.Args)); ok && e.allowsSinkOp("sql") {
				found = true
			}
			if isDynamicCallbackHelper(name) && e.allowsSinkOp("call") && len(typed.Args) > 0 &&
				(isDynamicCallbackExpr(argValue(typed.Args[0])) || isDynamicCallbackArrayExpr(argValue(typed.Args[0]))) {
				found = true
			}
			if name == "load_template" && e.allowsSinkOp("include") && len(typed.Args) > 0 && !isDefinitelyStaticIncludePath(argValue(typed.Args[0])) {
				found = true
			}
			if !found && name == "load_template" && len(typed.Args) > 0 && e.callableHasStaticIncludedOutputSink(c, argValue(typed.Args[0])) {
				found = true
			}
			if isDisclosureOutputFunc(name) && e.callableHasRecordRead(c.Key) && e.allowsSinkOp("output") {
				found = true
			}
		case *ast.ExprMethodCall:
			if e.allowsSinkOp("call") && isDynamicCallNameExpr(typed.Name) {
				found = true
			}
			if e.allowsSinkOp("surface") && e.callableHasPublicOAuthCallbackAuthSurfaceSink(c) {
				found = true
			}
			if _, op, _, _, ok := builtinMethodSink(strings.ToLower(identifierText(typed.Name))); ok && e.allowsSinkOp(op) && (op != "delete" || e.deleteMethodSinkMatches(c, typed)) {
				found = true
			}
			if _, ok := fileUploadSinkArgIndexesByMethod(strings.ToLower(identifierText(typed.Name))); ok &&
				e.allowsSinkOp("write") &&
				fileUploadSinkMethodMatchesMethodCall(strings.ToLower(identifierText(typed.Name)), typed, c, e) {
				found = true
			}
			if model, ok := actionSinkModelByMethod(strings.ToLower(identifierText(typed.Name))); ok && e.allowsSinkOp("action") && callableHasActionSinkMethod(e, c, typed, model) {
				found = true
			}
			if _, _, _, ok := sqlExecutionMethodArgIndex(strings.ToLower(identifierText(typed.Name))); ok && e.allowsSinkOp("sql") {
				found = true
			}
			if callableHasSQLIdentifierWriteMethodSink(e, c, typed) && e.allowsSinkOp("sql") {
				found = true
			}
			if callableHasSQLTemplateMethodSink(e, c, typed) && e.allowsSinkOp("sql") {
				found = true
			}
		case *ast.ExprStaticCall:
			if e.allowsSinkOp("call") && isDynamicCallNameExpr(typed.Name) {
				found = true
			}
			if _, op, _, _, ok := builtinMethodSink(strings.ToLower(identifierText(typed.Name))); ok && e.allowsSinkOp(op) && (op != "delete" || e.deleteStaticSinkMatches(c, typed)) {
				found = true
			}
			if model, ok := actionSinkModelByMethod(strings.ToLower(identifierText(typed.Name))); ok && e.allowsSinkOp("action") && callableHasActionSinkStaticCall(e, c, typed, model) {
				found = true
			}
			if callableHasSQLTemplateStaticSink(e, c, typed) && e.allowsSinkOp("sql") {
				found = true
			}
		case *ast.ExprNew:
			if e.allowsSinkOp("call") && isDynamicCallNameExpr(typed.Class) {
				found = true
			}
			if callableHasSQLTemplateConstructorSink(e, c, typed) && e.allowsSinkOp("sql") {
				found = true
			}
		}
	})
	return found
}

func (e *engine) callableHasStaticIncludedOutputSink(current callable, expr ast.Node) bool {
	if !e.allowsSinkOp("output") {
		return false
	}
	for _, key := range e.staticIncludedFileCallableKeys(expr, current) {
		callable, ok := e.callables[key]
		if !ok {
			continue
		}
		found := false
		walkCallableExecutableNodes(callable, func(node ast.Node) {
			if found {
				return
			}
			switch node.(type) {
			case *ast.StmtEcho, *ast.ExprPrint:
				found = true
			}
		})
		if found {
			return true
		}
	}
	return false
}

func callableHasSQLClauseFilterReturnSink(e *engine, c callable) bool {
	hasSQLClauseFilter := false
	for _, entry := range e.directEntryPointsByCallable[c.Key] {
		if entry.Kind != "filter" {
			continue
		}
		if _, ok := sqlClauseFilterModelForHook(entry.Name); ok {
			hasSQLClauseFilter = true
			break
		}
	}
	if !hasSQLClauseFilter {
		return false
	}
	hasReturn := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if hasReturn || node == nil {
			return
		}
		if ret, ok := node.(*ast.StmtReturn); ok && ret.Expr != nil {
			hasReturn = true
		}
	})
	return hasReturn
}

func callableHasPublicRestRouteSurfaceSink(e *engine, c callable, call *ast.ExprFuncCall) bool {
	if call == nil || len(call.Args) < 3 {
		return false
	}
	if !restRouteShowsInIndex(argValue(call.Args[2])) {
		return false
	}
	return restRouteHasDynamicPathComponent(argValue(call.Args[0]), c, e) ||
		restRouteHasDynamicPathComponent(argValue(call.Args[1]), c, e)
}

func callableHasSQLTemplateMethodSink(e *engine, c callable, call *ast.ExprMethodCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if _, _, _, ok := sqlTemplateMethodArgIndex(name); !ok {
		return false
	}
	if name != "prepare" {
		return true
	}
	className := strings.ToLower(strings.TrimPrefix(resolveCallGraphClassExpr(e, c, call.Var, nil), `\`))
	if className != "" && (strings.Contains(className, "wpdb") ||
		strings.Contains(className, "database") ||
		strings.Contains(className, "querybuilder") ||
		strings.Contains(className, "builder") ||
		strings.Contains(className, "db") ||
		strings.Contains(className, "conn")) {
		return true
	}
	if variable, ok := call.Var.(*ast.ExprVariable); ok {
		if name, ok := variable.Name.(string); ok {
			lower := strings.ToLower(strings.TrimSpace(name))
			return strings.Contains(lower, "wpdb") || strings.Contains(lower, "db") || strings.Contains(lower, "conn")
		}
	}
	return false
}

func callableHasSQLIdentifierWriteMethodSink(e *engine, c callable, call *ast.ExprMethodCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if _, _, _, ok := sqlIdentifierWriteMethodArgIndexes(name); !ok {
		return false
	}
	className := strings.ToLower(strings.TrimPrefix(resolveCallGraphClassExpr(e, c, call.Var, nil), `\`))
	if className != "" && (strings.Contains(className, "wpdb") ||
		strings.Contains(className, "database") ||
		strings.Contains(className, "querybuilder") ||
		strings.Contains(className, "builder") ||
		strings.Contains(className, "db") ||
		strings.Contains(className, "conn")) {
		return true
	}
	if variable, ok := call.Var.(*ast.ExprVariable); ok {
		if name, ok := variable.Name.(string); ok {
			lower := strings.ToLower(strings.TrimSpace(name))
			if strings.Contains(lower, "wpdb") || strings.Contains(lower, "db") || strings.Contains(lower, "conn") {
				return true
			}
		}
	}
	if len(call.Args) == 0 {
		return false
	}
	return isLikelySQLTableReference(argValue(call.Args[0]))
}

func deleteSinkReceiverLooksNonFileLike(hint string) bool {
	hint = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(hint), `\`))
	if hint == "" {
		return false
	}
	return strings.Contains(hint, "wpdb") ||
		strings.Contains(hint, "database") ||
		strings.Contains(hint, "querybuilder") ||
		strings.Contains(hint, "builder") ||
		strings.Contains(hint, "db") ||
		strings.Contains(hint, "conn")
}

func (e *engine) deleteMethodSinkMatches(c callable, call *ast.ExprMethodCall) bool {
	if strings.ToLower(identifierText(call.Name)) != "delete" || len(call.Args) == 0 {
		return true
	}
	classHint := resolveCallGraphClassExpr(e, c, call.Var, nil)
	if deleteSinkReceiverLooksNonFileLike(classHint) {
		return false
	}
	if rootHint := valueRootKey(call.Var, c.Class); deleteSinkReceiverLooksNonFileLike(rootHint) {
		return false
	}
	return exprMayProducePathLikeValue(argValue(call.Args[0]))
}

func (e *engine) deleteStaticSinkMatches(c callable, call *ast.ExprStaticCall) bool {
	if strings.ToLower(identifierText(call.Name)) != "delete" || len(call.Args) == 0 {
		return true
	}
	classHint := e.resolveClassNameForCallable(call.Class, c)
	if deleteSinkReceiverLooksNonFileLike(classHint) {
		return false
	}
	return exprMayProducePathLikeValue(argValue(call.Args[0]))
}

func callableHasSQLTemplateStaticSink(e *engine, c callable, call *ast.ExprStaticCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if _, _, _, ok := sqlTemplateMethodArgIndex(name); !ok {
		return false
	}
	if name != "prepare" {
		return true
	}
	className := strings.ToLower(strings.TrimPrefix(e.resolveClassNameForCallable(call.Class, c), `\`))
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

func callableHasSQLTemplateConstructorSink(e *engine, c callable, expr *ast.ExprNew) bool {
	className := resolveClassName(expr.Class, c.Class, e.classParents)
	_, _, _, ok := sqlTemplateConstructorArgIndex(className)
	return ok
}

func callableHasActionSinkMethod(e *engine, c callable, call *ast.ExprMethodCall, model actionSinkModel) bool {
	if model.RequireConfigLike {
		className := resolveCallGraphClassExpr(e, c, call.Var, nil)
		if isConfigLikeReceiverClassName(className) {
			return true
		}
		if variable, ok := call.Var.(*ast.ExprVariable); ok {
			if name, ok := variable.Name.(string); ok {
				return isConfigLikeReceiverVarName(name)
			}
		}
		if property, ok := propertyPathKey(call.Var, c.Class); ok {
			return isConfigLikeReceiverVarName(property)
		}
		return false
	}
	if model.RequireInstallerLike {
		className := resolveCallGraphClassExpr(e, c, call.Var, nil)
		if isInstallerLikeReceiverClassName(className) {
			return true
		}
		if variable, ok := call.Var.(*ast.ExprVariable); ok {
			if name, ok := variable.Name.(string); ok {
				return isInstallerLikeReceiverVarName(name)
			}
		}
		if property, ok := propertyPathKey(call.Var, c.Class); ok {
			return isInstallerLikeReceiverVarName(property)
		}
		return false
	}
	if model.RequireUserLike {
		className := resolveCallGraphClassExpr(e, c, call.Var, nil)
		if isUserLikeReceiverClassName(className) {
			return true
		}
		if variable, ok := call.Var.(*ast.ExprVariable); ok {
			if name, ok := variable.Name.(string); ok {
				return isUserLikeReceiverVarName(name)
			}
		}
		if property, ok := propertyPathKey(call.Var, c.Class); ok {
			return isUserLikeReceiverVarName(property)
		}
		return false
	}
	return true
}

func callableHasActionSinkStaticCall(e *engine, c callable, call *ast.ExprStaticCall, model actionSinkModel) bool {
	className := e.resolveClassNameForCallable(call.Class, c)
	if model.RequireConfigLike {
		return isConfigLikeReceiverClassName(className)
	}
	if model.RequireInstallerLike {
		return isInstallerLikeReceiverClassName(className)
	}
	if model.RequireUserLike {
		return isUserLikeReceiverClassName(className)
	}
	return true
}

func (e *engine) collectDirectCallEdges(c callable) ([]string, []string, []callSiteEdge) {
	out := map[string]struct{}{}
	dataOut := map[string]struct{}{}
	callSites := make([]callSiteEdge, 0)
	classEnv := map[string]string{}
	stringEnv := map[string]string{}
	resolver := e.localArrayLiteralResolver(c)
	literalSpecialized := e.callableHasLiteralArgSpecialization(c.Key)
	var walkStmtList func([]ast.Node, map[string]string, map[string]string)
	stmtOrder := 0
	walkStmtList = func(stmts []ast.Node, classEnv map[string]string, stringEnv map[string]string) {
		for _, stmt := range stmts {
			if skipNestedDeclarationBodies(c, stmt) {
				continue
			}
			stmtOrder++
			switch typed := stmt.(type) {
			case *ast.StmtExpression:
				collectDirectCallsFromExpr(e, c, typed.Expr, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, false)
				updateCallGraphLocalEnvs(e, c, typed.Expr, classEnv, stringEnv)
			case *ast.StmtEcho:
				for _, expr := range typed.Exprs {
					collectDirectCallsFromExpr(e, c, expr, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, false)
				}
			case *ast.StmtIf:
				collectDirectCallsFromExpr(e, c, typed.Cond, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, true)
				if literalSpecialized {
					if truth, ok := e.literalConditionTruthForCallable(typed.Cond, c, map[string]struct{}{}); ok {
						if truth {
							walkStmtList(typed.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
							continue
						}
						handled := false
						allElseifsKnown := true
						for _, elseifNode := range typed.Elseifs {
							elseifStmt, ok := elseifNode.(*ast.StmtElseIf)
							if !ok {
								continue
							}
							collectDirectCallsFromExpr(e, c, elseifStmt.Cond, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, true)
							elseifTruth, elseifKnown := e.literalConditionTruthForCallable(elseifStmt.Cond, c, map[string]struct{}{})
							if !elseifKnown {
								allElseifsKnown = false
								break
							}
							if elseifTruth {
								walkStmtList(elseifStmt.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
								handled = true
								break
							}
						}
						if handled {
							continue
						}
						if allElseifsKnown {
							if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
								walkStmtList(elseStmt.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
							}
							continue
						}
					}
				}
				walkStmtList(typed.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
				for _, elseifNode := range typed.Elseifs {
					elseifStmt, ok := elseifNode.(*ast.StmtElseIf)
					if !ok {
						continue
					}
					collectDirectCallsFromExpr(e, c, elseifStmt.Cond, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, true)
					walkStmtList(elseifStmt.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
				}
				if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
					walkStmtList(elseStmt.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
				}
			case *ast.StmtForeach:
				collectDirectCallsFromExpr(e, c, typed.Expr, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, false)
				walkStmtList(typed.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
			case *ast.StmtReturn:
				collectDirectCallsFromExpr(e, c, typed.Expr, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, false)
			case *ast.StmtSwitch:
				collectDirectCallsFromExpr(e, c, typed.Cond, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, false)
				if literalSpecialized {
					if cases, ok := literalSwitchCasesForCallable(typed, c, e); ok {
						caseClassEnv := cloneStringMap(classEnv)
						caseStringEnv := cloneStringMap(stringEnv)
						for _, caseStmt := range cases {
							if caseStmt.Cond != nil {
								collectDirectCallsFromExpr(e, c, caseStmt.Cond, caseClassEnv, caseStringEnv, resolver, out, dataOut, &callSites, stmtOrder, false)
							}
							walkStmtList(caseStmt.Stmts, caseClassEnv, caseStringEnv)
							if branchDefinitelyAborts(caseStmt.Stmts) {
								break
							}
						}
						continue
					}
				}
				for _, caseNode := range typed.Cases {
					caseStmt, ok := caseNode.(*ast.StmtCase)
					if !ok {
						continue
					}
					collectDirectCallsFromExpr(e, c, caseStmt.Cond, classEnv, stringEnv, resolver, out, dataOut, &callSites, stmtOrder, false)
					walkStmtList(caseStmt.Stmts, cloneStringMap(classEnv), cloneStringMap(stringEnv))
				}
			default:
				for _, block := range childStatementBlocks(stmt) {
					walkStmtList(block, cloneStringMap(classEnv), cloneStringMap(stringEnv))
				}
			}
		}
	}
	walkStmtList(c.Stmts, classEnv, stringEnv)
	keys := make([]string, 0, len(out))
	for key := range out {
		keys = append(keys, key)
	}
	dataKeys := make([]string, 0, len(dataOut))
	for key := range dataOut {
		dataKeys = append(dataKeys, key)
	}
	return keys, dataKeys, callSites
}

func collectDirectCallsFromExpr(e *engine, c callable, node ast.Node, classEnv map[string]string, stringEnv map[string]string, resolver *localArrayLiteralResolver, out map[string]struct{}, dataOut map[string]struct{}, callSites *[]callSiteEdge, stmtOrder int, boolContext bool) {
	var walk func(ast.Node, ast.Node, bool)
	walk = func(current ast.Node, parent ast.Node, boolContext bool) {
		if current == nil {
			return
		}
		switch typed := current.(type) {
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(typed.Name))
			if (name == "do_action" || name == "do_action_ref_array" || name == "apply_filters" || name == "apply_filters_ref_array") && len(typed.Args) > 0 {
				hook := hookDispatchKeyForCallable(argValue(typed.Args[0]), c, e)
				dispatchArgs := typed.Args
				if len(dispatchArgs) > 1 {
					dispatchArgs = dispatchArgs[1:]
				} else {
					dispatchArgs = nil
				}
				carrier := callArgsCarryRuntimeDataAt(dispatchArgs, c, e, current.StartLine(), resolver)
				dispatchLiteralHints := literalArgHintsForArgsWithEnvAndSeen(dispatchArgs, c, e, stringEnv, nil)
				dispatchPathHints := literalArgPathHintsForArgsWithEnvAndSeen(dispatchArgs, c, e, stringEnv, nil, current.StartLine(), resolver)
				for _, key := range e.dispatchCallbackKeys(name, hook) {
					if key == c.Key {
						continue
					}
					if e.currentBatchName == "" && len(e.allowedSinkOps) == 1 {
						if _, ok := e.allowedSinkOps["output"]; ok {
							key = e.maybeSpecializeOutputCallableForBuild(key, dispatchLiteralHints, dispatchPathHints)
						} else {
							key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, dispatchLiteralHints, dispatchPathHints)
						}
					} else {
						key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, dispatchLiteralHints, dispatchPathHints)
					}
					out[key] = struct{}{}
					*callSites = append(*callSites, callSiteEdge{
						callee:          key,
						line:            current.StartLine(),
						order:           stmtOrder,
						dataCarrier:     carrier,
						booleanUse:      boolContext,
						argCarrier:      carrier,
						argCount:        len(dispatchArgs),
						runtimeArgIdxs:  runtimeArgIndexesForArgs(dispatchArgs, c, e, current.StartLine(), resolver),
						hasReceiver:     false,
						receiverCarrier: false,
						assignedRoot:    assignedCallResultRoot(parent, current, c.Class),
						literalArgs:     dispatchLiteralHints,
					})
					if carrier {
						dataOut[key] = struct{}{}
					}
				}
			}
			if callbackKeys := directDispatchCallbackKeys(e, c, name, typed.Args, stringEnv); len(callbackKeys) > 0 {
				carrier := directDispatchCarriesRuntimeArgs(c, e, name, typed.Args, current.StartLine(), resolver)
				dispatchArgs := directDispatchArgs(name, typed.Args)
				dispatchLiteralHints := literalArgHintsForArgsWithEnvAndSeen(dispatchArgs, c, e, stringEnv, nil)
				dispatchPathHints := literalArgPathHintsForArgsWithEnvAndSeen(dispatchArgs, c, e, stringEnv, nil, current.StartLine(), resolver)
				for _, key := range callbackKeys {
					if e.currentBatchName == "" && len(e.allowedSinkOps) == 1 {
						if _, ok := e.allowedSinkOps["output"]; ok {
							key = e.maybeSpecializeOutputCallableForBuild(key, dispatchLiteralHints, dispatchPathHints)
						} else {
							key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, dispatchLiteralHints, dispatchPathHints)
						}
					} else {
						key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, dispatchLiteralHints, dispatchPathHints)
					}
					out[key] = struct{}{}
					*callSites = append(*callSites, callSiteEdge{
						callee:          key,
						line:            current.StartLine(),
						order:           stmtOrder,
						dataCarrier:     carrier,
						booleanUse:      boolContext,
						argCarrier:      carrier,
						argCount:        len(dispatchArgs),
						runtimeArgIdxs:  runtimeArgIndexesForArgs(dispatchArgs, c, e, current.StartLine(), resolver),
						hasReceiver:     false,
						receiverCarrier: false,
						assignedRoot:    assignedCallResultRoot(parent, current, c.Class),
						literalArgs:     dispatchLiteralHints,
					})
					if carrier {
						dataOut[key] = struct{}{}
					}
				}
			}
			hints := literalArgHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil)
			pathHints := literalArgPathHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil, current.StartLine(), resolver)
			if key := e.lookupFunctionKey(c.Namespace, identifierText(typed.Name)); key != "" {
				if e.currentBatchName == "" && len(e.allowedSinkOps) == 1 {
					if _, ok := e.allowedSinkOps["output"]; ok {
						key = e.maybeSpecializeOutputCallableForBuild(key, hints, pathHints)
					} else {
						key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
					}
				} else {
					key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
				}
				out[key] = struct{}{}
				dataCarrier := callCarriesData(parent, current)
				*callSites = append(*callSites, callSiteEdge{
					callee:          key,
					line:            current.StartLine(),
					order:           stmtOrder,
					dataCarrier:     dataCarrier,
					booleanUse:      boolContext,
					argCarrier:      callArgsCarryRuntimeDataAt(typed.Args, c, e, current.StartLine(), resolver),
					argCount:        len(typed.Args),
					runtimeArgIdxs:  runtimeArgIndexesForArgs(typed.Args, c, e, current.StartLine(), resolver),
					hasReceiver:     false,
					receiverCarrier: false,
					assignedRoot:    assignedCallResultRoot(parent, current, c.Class),
					literalArgs:     hints,
				})
				if dataCarrier {
					dataOut[key] = struct{}{}
				}
			}
		case *ast.ExprNew:
			className := e.resolveClassNameForCallable(typed.Class, c)
			hints := literalArgHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil)
			pathHints := literalArgPathHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil, current.StartLine(), resolver)
			if key := e.lookupMethodKey(className, "__construct"); key != "" {
				key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
				out[key] = struct{}{}
				dataCarrier := callCarriesData(parent, current)
				*callSites = append(*callSites, callSiteEdge{
					callee:                key,
					line:                  current.StartLine(),
					order:                 stmtOrder,
					dataCarrier:           dataCarrier,
					booleanUse:            boolContext,
					argCarrier:            callArgsCarryRuntimeDataAt(typed.Args, c, e, current.StartLine(), resolver),
					argCount:              len(typed.Args),
					runtimeArgIdxs:        runtimeArgIndexesForArgs(typed.Args, c, e, current.StartLine(), resolver),
					hasReceiver:           true,
					receiverCarrier:       false,
					receiverStateRelevant: true,
					assignedRoot:          assignedCallResultRoot(parent, current, c.Class),
					literalArgs:           hints,
				})
				if dataCarrier {
					dataOut[key] = struct{}{}
				}
			}
		case *ast.ExprStaticCall:
			className := e.resolveClassNameForCallable(typed.Class, c)
			hints := literalArgHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil)
			pathHints := literalArgPathHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil, current.StartLine(), resolver)
			for _, key := range dynamicStaticMethodKeysForCallable(e, c, className, typed.Name, stringEnv) {
				if e.currentBatchName == "" && len(e.allowedSinkOps) == 1 {
					if _, ok := e.allowedSinkOps["output"]; ok {
						key = e.maybeSpecializeOutputCallableForBuild(key, hints, pathHints)
					} else {
						key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
					}
				} else {
					key = e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
				}
				out[key] = struct{}{}
				dataCarrier := callCarriesData(parent, current) || callCarriesStorageWritePayload(identifierText(typed.Name), typed.Args)
				*callSites = append(*callSites, callSiteEdge{
					callee:          key,
					line:            current.StartLine(),
					order:           stmtOrder,
					dataCarrier:     dataCarrier,
					booleanUse:      boolContext,
					argCarrier:      callArgsCarryRuntimeDataAt(typed.Args, c, e, current.StartLine(), resolver),
					argCount:        len(typed.Args),
					runtimeArgIdxs:  runtimeArgIndexesForArgs(typed.Args, c, e, current.StartLine(), resolver),
					hasReceiver:     false,
					receiverCarrier: false,
					assignedRoot:    assignedCallResultRoot(parent, current, c.Class),
					literalArgs:     hints,
				})
				if dataCarrier {
					dataOut[key] = struct{}{}
				}
			}
		case *ast.ExprMethodCall:
			hints := literalArgHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil)
			pathHints := literalArgPathHintsForArgsWithEnvAndSeen(typed.Args, c, e, stringEnv, nil, current.StartLine(), resolver)
			receiverRoot := receiverRootKey(typed.Var, c.Class)
			receiverStateRelevant := receiverRoot != "" && (!isSimpleLocalReceiverRoot(receiverRoot) || localReceiverRootUsedAfter(typed, c.Stmts, receiverRoot, c.Class))
			for _, className := range resolveCallGraphClassExprCandidates(e, c, typed.Var, classEnv) {
				if key := e.maybeSpecializeRuntimeMethodKeyForLiteralArgsAndPaths(className, strings.ToLower(identifierText(typed.Name)), hints, pathHints); key != "" {
					out[key] = struct{}{}
					dataCarrier := callCarriesData(parent, current) || callCarriesStorageWritePayload(identifierText(typed.Name), typed.Args)
					receiverCarrier := receiverExprCarriesRuntimeDataAt(typed.Var, c, e, current.StartLine(), resolver, map[string]struct{}{})
					*callSites = append(*callSites, callSiteEdge{
						callee:                key,
						line:                  current.StartLine(),
						order:                 stmtOrder,
						dataCarrier:           dataCarrier,
						booleanUse:            boolContext,
						argCarrier:            callArgsCarryRuntimeDataAt(typed.Args, c, e, current.StartLine(), resolver),
						argCount:              len(typed.Args),
						runtimeArgIdxs:        runtimeArgIndexesForArgs(typed.Args, c, e, current.StartLine(), resolver),
						hasReceiver:           true,
						receiverCarrier:       receiverCarrier,
						receiverStateRelevant: receiverStateRelevant,
						assignedRoot:          assignedCallResultRoot(parent, current, c.Class),
						literalArgs:           hints,
					})
					if dataCarrier {
						dataOut[key] = struct{}{}
					}
				}
			}
		}
		for _, name := range current.SubNodeNames() {
			value := current.SubNode(name)
			switch typed := value.(type) {
			case ast.Node:
				walk(typed, current, childCallBooleanContext(current, name, boolContext))
			case []ast.Node:
				for _, child := range typed {
					walk(child, current, childCallBooleanContext(current, name, boolContext))
				}
			}
		}
	}
	walk(node, nil, boolContext)
}

func childCallBooleanContext(parent ast.Node, childName string, inherited bool) bool {
	if inherited {
		return true
	}
	switch parent.(type) {
	case *ast.ExprBooleanNot, *ast.ExprCastBool, *ast.ExprEmpty, *ast.ExprIsset,
		*ast.ExprBinaryOpBooleanAnd, *ast.ExprBinaryOpBooleanOr,
		*ast.ExprBinaryOpLogicalAnd, *ast.ExprBinaryOpLogicalOr, *ast.ExprBinaryOpLogicalXor,
		*ast.ExprBinaryOpEqual, *ast.ExprBinaryOpGreater, *ast.ExprBinaryOpGreaterOrEqual,
		*ast.ExprBinaryOpIdentical, *ast.ExprBinaryOpNotEqual, *ast.ExprBinaryOpNotIdentical,
		*ast.ExprBinaryOpSmaller, *ast.ExprBinaryOpSmallerOrEqual:
		return true
	case *ast.ExprTernary:
		return childName == "Cond"
	default:
		return false
	}
}

func updateCallGraphLocalEnvs(e *engine, c callable, expr ast.Node, classEnv map[string]string, stringEnv map[string]string) {
	switch typed := expr.(type) {
	case *ast.ExprAssign:
		variable, ok := typed.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok {
			return
		}
		className := resolveCallGraphClassExpr(e, c, typed.Expr, classEnv)
		if className == "" {
			className = e.resolveHintClassExpr(c, typed.Expr, classEnv, stringEnv)
		}
		if className != "" {
			classEnv[name] = className
		} else {
			delete(classEnv, name)
		}
		if value := dynamicDispatchStringForCallable(typed.Expr, c, e, stringEnv); value != "" {
			stringEnv[name] = value
		} else {
			delete(stringEnv, name)
		}
	case *ast.ExprAssignRef:
		variable, ok := typed.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok {
			return
		}
		if value := dynamicDispatchStringForCallable(typed.Expr, c, e, stringEnv); value != "" {
			stringEnv[name] = value
		} else {
			delete(stringEnv, name)
		}
	case *ast.ExprAssignOpConcat:
		variable, ok := typed.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok {
			return
		}
		current := dynamicDispatchStringForCallable(typed.Var, c, e, stringEnv)
		next := dynamicDispatchStringForCallable(typed.Expr, c, e, stringEnv)
		if current != "" && next != "" {
			stringEnv[name] = current + next
		} else {
			delete(stringEnv, name)
		}
	}
}

func literalArgHintsForArgs(args []ast.Node, current callable, e *engine) map[int]string {
	return literalArgHintsForArgsWithEnvAndSeen(args, current, e, nil, nil)
}

func literalArgPathHintsForArgs(args []ast.Node, current callable, e *engine, beforeLine int, resolver *localArrayLiteralResolver) map[int]map[string]string {
	return literalArgPathHintsForArgsWithEnvAndSeen(args, current, e, nil, nil, beforeLine, resolver)
}

func literalArgPathHintsForArgsWithEnv(args []ast.Node, current callable, e *engine, stringEnv map[string]string, beforeLine int, resolver *localArrayLiteralResolver) map[int]map[string]string {
	return literalArgPathHintsForArgsWithEnvAndSeen(args, current, e, stringEnv, nil, beforeLine, resolver)
}

func literalArgHintsForArgsWithEnv(args []ast.Node, current callable, e *engine, stringEnv map[string]string) map[int]string {
	return literalArgHintsForArgsWithEnvAndSeen(args, current, e, stringEnv, nil)
}

func literalArgHintsForArgsWithEnvAndSeen(args []ast.Node, current callable, e *engine, stringEnv map[string]string, seen map[string]struct{}) map[int]string {
	out := map[int]string{}
	for idx, arg := range args {
		value := strings.TrimSpace(dynamicDispatchStringForCallable(argValue(arg), current, e, stringEnv))
		if value == "" {
			value = strings.TrimSpace(hookDispatchKeyForCallableWithSeen(argValue(arg), current, e, seen))
		}
		if value == "" {
			continue
		}
		out[idx] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func literalArgPathHintsForArgsWithEnvAndSeen(args []ast.Node, current callable, e *engine, stringEnv map[string]string, seen map[string]struct{}, beforeLine int, resolver *localArrayLiteralResolver) map[int]map[string]string {
	out := map[int]map[string]string{}
	for idx, arg := range args {
		if hints := literalArgPathHintsForNodeWithEnvAndSeen(argValue(arg), current, e, stringEnv, seen, beforeLine, resolver); len(hints) != 0 {
			out[idx] = hints
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func literalArgPathHintsForNodeWithEnvAndSeen(node ast.Node, current callable, e *engine, stringEnv map[string]string, seen map[string]struct{}, beforeLine int, resolver *localArrayLiteralResolver) map[string]string {
	const (
		maxLiteralArgPathHintsPerArg = 8
		maxLiteralArgPathHintDepth   = 2
	)

	if node == nil {
		return nil
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	if resolver != nil {
		if resolved := resolveLocalStructuredExpr(node, resolver, seen); resolved != nil {
			node = resolved
		}
	}
	out := map[string]string{}
	var collect func(ast.Node, []string, int)
	collect = func(currentNode ast.Node, path []string, depth int) {
		if currentNode == nil || len(out) >= maxLiteralArgPathHintsPerArg || depth > maxLiteralArgPathHintDepth {
			return
		}
		if resolver != nil {
			if resolved := resolveLocalStructuredExpr(currentNode, resolver, seen); resolved != nil {
				currentNode = resolved
			}
		}
		arrayNode, ok := currentNode.(*ast.ExprArray)
		if !ok {
			return
		}
		listIndex := 0
		for _, rawItem := range arrayNode.Items {
			if len(out) >= maxLiteralArgPathHintsPerArg {
				return
			}
			item, ok := rawItem.(*ast.ArrayItem)
			if !ok || item.Value == nil {
				continue
			}
			key := ""
			if item.Key != nil {
				if stableKey, ok := stableArrayDimKey(item.Key); ok {
					key = stableKey
				}
			} else {
				key = strconv.Itoa(listIndex)
				listIndex++
			}
			if strings.TrimSpace(key) == "" {
				continue
			}
			nextPath := append(append([]string(nil), path...), key)
			if value := literalArgHintValueForNodeWithEnvAndSeen(argValue(item.Value), current, e, stringEnv, seen); value != "" {
				out[literalArgPathHintKey(nextPath)] = value
			}
			if depth < maxLiteralArgPathHintDepth {
				collect(argValue(item.Value), nextPath, depth+1)
			}
		}
	}
	collect(node, nil, 0)
	if len(out) == 0 {
		return nil
	}
	return out
}

func literalArgHintValueForNodeWithEnvAndSeen(node ast.Node, current callable, e *engine, stringEnv map[string]string, seen map[string]struct{}) string {
	if node == nil {
		return ""
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	if _, isArray := node.(*ast.ExprArray); !isArray {
		if values := e.exactDynamicDispatchValuesForCallableWithState(node, current, stringEnv, newDispatchResolutionState()); len(values) != 0 {
			return encodeLiteralArgHintValues(values)
		}
	}
	if value := strings.TrimSpace(dynamicDispatchStringForCallableWithState(node, current, e, stringEnv, newDispatchResolutionState())); value != "" && !strings.ContainsAny(value, "{}") {
		return value
	}
	if value := strings.TrimSpace(literalStringForCallableWithSeen(node, current, e, seen)); value != "" {
		return value
	}
	if truthy, ok := booleanLiteralForCallable(node, current, e, stringEnv); ok {
		if truthy {
			return "true"
		}
		return "false"
	}
	if number, ok := numericLiteral(node); ok {
		return strings.TrimSpace(fmt.Sprintf("%d", number))
	}
	if value := strings.TrimSpace(literalString(node)); value != "" {
		return value
	}
	return ""
}

func runtimeArgIndexesForArgs(args []ast.Node, current callable, e *engine, beforeLine int, resolver *localArrayLiteralResolver) map[int]struct{} {
	out := map[int]struct{}{}
	for idx, arg := range args {
		if callArgCarriesRuntimeDataAt(argValue(arg), current, e, beforeLine, resolver, map[string]struct{}{}) {
			out[idx] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func callArgsCarryRuntimeData(args []ast.Node, current callable, e *engine) bool {
	return callArgsCarryRuntimeDataAt(args, current, e, 0, nil)
}

func callArgsCarryRuntimeDataAt(args []ast.Node, current callable, e *engine, beforeLine int, resolver *localArrayLiteralResolver) bool {
	for _, arg := range args {
		if callArgCarriesRuntimeDataAt(argValue(arg), current, e, beforeLine, resolver, map[string]struct{}{}) {
			return true
		}
	}
	return false
}

func callArgCarriesRuntimeData(node ast.Node, current callable, e *engine) bool {
	return callArgCarriesRuntimeDataAt(node, current, e, 0, nil, map[string]struct{}{})
}

func receiverExprCarriesRuntimeDataAt(node ast.Node, current callable, e *engine, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) bool {
	if node == nil {
		return false
	}
	switch typed := node.(type) {
	case *ast.ScalarString, *ast.ScalarInt, *ast.ScalarFloat:
		return false
	case *ast.ExprConstFetch:
		name := strings.ToLower(strings.TrimSpace(identifierText(typed.Name)))
		switch name {
		case "true", "false", "null":
			return false
		}
		if literalStringForCallable(node, current, e) != "" {
			return false
		}
		return true
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || name == "" {
			return true
		}
		seenKey := "recvvar:" + name
		if _, ok := seen[seenKey]; ok {
			return true
		}
		seen[seenKey] = struct{}{}
		defer delete(seen, seenKey)
		if expr, line := resolver.latestExpr(name, beforeLine); expr != nil {
			return receiverExprCarriesRuntimeDataAt(expr, current, e, line, resolver, seen)
		}
		return true
	case *ast.ExprStaticCall:
		return callArgsCarryRuntimeDataAt(typed.Args, current, e, beforeLine, resolver)
	case *ast.ExprFuncCall:
		return callArgsCarryRuntimeDataAt(typed.Args, current, e, beforeLine, resolver)
	case *ast.ExprMethodCall:
		return callArgsCarryRuntimeDataAt(typed.Args, current, e, beforeLine, resolver) ||
			receiverExprCarriesRuntimeDataAt(typed.Var, current, e, beforeLine, resolver, seen)
	case *ast.ExprNew:
		return true
	default:
		return callArgCarriesRuntimeDataAt(node, current, e, beforeLine, resolver, seen)
	}
}

func callArgCarriesRuntimeDataAt(node ast.Node, current callable, e *engine, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) bool {
	if node == nil {
		return false
	}
	switch typed := node.(type) {
	case *ast.ScalarString, *ast.ScalarInt, *ast.ScalarFloat:
		return false
	case *ast.ExprConstFetch:
		name := strings.ToLower(strings.TrimSpace(identifierText(typed.Name)))
		switch name {
		case "true", "false", "null":
			return false
		}
		if literalStringForCallable(node, current, e) != "" {
			return false
		}
		return true
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if ok && name != "" {
			if _, visited := seen["var:"+name]; visited {
				return true
			}
			seen["var:"+name] = struct{}{}
			if arrayNode, _ := latestLocalArrayLiteralAssignment(name, current, beforeLine, resolver); arrayNode != nil {
				return callArgCarriesRuntimeDataAt(arrayNode, current, e, beforeLine, resolver, seen)
			}
		}
		return true
	case *ast.ExprArray:
		for _, rawItem := range typed.Items {
			item, ok := rawItem.(*ast.ArrayItem)
			if !ok {
				return true
			}
			if callArgCarriesRuntimeDataAt(item.Key, current, e, beforeLine, resolver, seen) || callArgCarriesRuntimeDataAt(argValue(item.Value), current, e, beforeLine, resolver, seen) {
				return true
			}
		}
		return false
	case *ast.ExprBinaryOpConcat:
		return callArgCarriesRuntimeDataAt(typed.Left, current, e, beforeLine, resolver, seen) || callArgCarriesRuntimeDataAt(typed.Right, current, e, beforeLine, resolver, seen)
	case *ast.ExprArrayDimFetch:
		if rootName, dims, ok := localArrayFetchPath(typed); ok {
			if _, visited := seen["fetch:"+rootName+":"+strings.Join(dims, ".")]; visited {
				return true
			}
			seen["fetch:"+rootName+":"+strings.Join(dims, ".")] = struct{}{}
			arrayNode, _ := latestLocalArrayLiteralAssignment(rootName, current, beforeLine, resolver)
			currentNode := ast.Node(arrayNode)
			for _, dim := range dims {
				nextArray, ok := currentNode.(*ast.ExprArray)
				if !ok {
					currentNode = nil
					break
				}
				currentNode = arrayValueForStringKey(nextArray, dim)
				if currentNode == nil {
					break
				}
			}
			if currentNode != nil {
				return callArgCarriesRuntimeDataAt(currentNode, current, e, beforeLine, resolver, seen)
			}
		}
	}
	if literalStringForCallable(node, current, e) != "" {
		return false
	}
	found := false
	walkNode(node, func(child ast.Node) {
		if found || child == nil {
			return
		}
		switch child.(type) {
		case *ast.ExprVariable, *ast.ExprArrayDimFetch, *ast.ExprPropertyFetch, *ast.ExprStaticPropertyFetch,
			*ast.ExprFuncCall, *ast.ExprMethodCall, *ast.ExprStaticCall, *ast.ExprNew, *ast.ExprShellExec,
			*ast.ExprInclude, *ast.ExprClosure, *ast.ExprArrowFunction:
			found = true
			return
		}
		if root := valueRootKey(child, current.Class); root != "" {
			found = true
		}
	})
	return found
}

func directDispatchCarriesRuntimeArgs(current callable, e *engine, name string, args []ast.Node, beforeLine int, resolver *localArrayLiteralResolver) bool {
	switch name {
	case "call_user_func", "forward_static_call":
		if len(args) <= 1 {
			return false
		}
		return callArgsCarryRuntimeDataAt(args[1:], current, e, beforeLine, resolver)
	case "call_user_func_array", "forward_static_call_array":
		if len(args) < 2 {
			return false
		}
		return callArgCarriesRuntimeDataAt(argValue(args[1]), current, e, beforeLine, resolver, map[string]struct{}{})
	default:
		return false
	}
}

func directDispatchArgs(name string, args []ast.Node) []ast.Node {
	switch name {
	case "call_user_func", "forward_static_call":
		if len(args) <= 1 {
			return nil
		}
		return args[1:]
	default:
		return nil
	}
}

func callCarriesData(parent ast.Node, current ast.Node) bool {
	if parent == nil || current == nil {
		return false
	}
	if exprStmt, ok := parent.(*ast.StmtExpression); ok && exprStmt.Expr == current {
		return false
	}
	return true
}

func callCarriesStorageWritePayload(name string, args []ast.Node) bool {
	if !looksLikeWrapperWriteMethod(strings.ToLower(strings.TrimSpace(name))) || len(args) == 0 {
		return false
	}
	switch argValue(args[0]).(type) {
	case *ast.ExprArray, *ast.ExprArrayDimFetch, *ast.ExprVariable, *ast.ExprPropertyFetch:
		return true
	default:
		return false
	}
}

func resolveCallGraphClassExpr(e *engine, c callable, node ast.Node, classEnv map[string]string) string {
	switch typed := node.(type) {
	case *ast.ExprAssign:
		return resolveCallGraphClassExpr(e, c, typed.Expr, classEnv)
	case *ast.ExprAssignRef:
		return resolveCallGraphClassExpr(e, c, typed.Expr, classEnv)
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		if name == "this" {
			return c.Class
		}
		if c.ParamTypes != nil {
			if className := strings.TrimSpace(c.ParamTypes[strings.TrimSpace(name)]); className != "" {
				return className
			}
		}
		return classEnv[name]
	case *ast.ExprArrayDimFetch:
		if path, ok := localClassPathKey(typed); ok {
			return classEnv[path]
		}
		return ""
	case *ast.ExprNew:
		return e.resolveClassNameForCallable(typed.Class, c)
	case *ast.ExprFuncCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		if key := e.lookupFunctionKey(c.Namespace, identifierText(typed.Name)); key != "" {
			return e.callableReturnClassHint(key)
		}
	case *ast.ExprStaticCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		className := e.resolveClassNameForCallable(typed.Class, c)
		if singletonClass := singletonFactoryReturnClass(identifierText(typed.Name), className); singletonClass != "" {
			return singletonClass
		}
		if key := e.lookupMethodKey(className, strings.ToLower(identifierText(typed.Name))); key != "" {
			if className := e.callableReturnClassHint(key); className != "" {
				return className
			}
			return e.callableReturnedReceiverPropertyClassHint(key, className, "")
		}
	case *ast.ExprMethodCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		receiverClass := resolveCallGraphClassExpr(e, c, typed.Var, classEnv)
		if key := e.existingRuntimeMethodCallable(receiverClass, strings.ToLower(identifierText(typed.Name))); key != "" {
			if className := e.callableReturnClassHint(key); className != "" {
				return className
			}
			previousMethodKey := ""
			if previousCall, ok := typed.Var.(*ast.ExprMethodCall); ok {
				previousReceiverClass := resolveCallGraphClassExpr(e, c, previousCall.Var, classEnv)
				previousMethodKey = e.existingRuntimeMethodCallable(previousReceiverClass, strings.ToLower(identifierText(previousCall.Name)))
			}
			return e.callableReturnedReceiverPropertyClassHint(key, receiverClass, previousMethodKey)
		}
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, c.Class); ok {
			return e.receiverPropertyReturnClassHint(c.Class, path)
		}
	}
	return ""
}

func resolveCallGraphClassExprCandidates(e *engine, c callable, node ast.Node, classEnv map[string]string) []string {
	out := make([]string, 0, 4)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	if className := resolveCallGraphClassExpr(e, c, node, classEnv); className != "" {
		add(className)
		for _, runtimeClass := range e.runtimeCallbackClassRefs(className) {
			add(runtimeClass)
		}
	}
	for _, className := range e.resolveCallbackClassRefs(node, c) {
		add(className)
	}
	return out
}

func taintscanTimingsEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("PHARSER_TAINTSCAN_TIMINGS")))
	return value == "1" || value == "true" || value == "yes"
}

func logTiming(enabled bool, label string, duration time.Duration) {
	if !enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "[taintscan] %s=%s\n", label, duration.Round(time.Millisecond))
}

func (e *engine) collectWordPressFlowContext() {
	e.directPublicCallables = map[string]struct{}{}
	e.directEntryPointsByCallable = map[string][]EntryPoint{}
	for _, key := range e.callOrder {
		e.contexts[key] = FlowContext{}
	}
	for pass := 0; pass < 4; pass++ {
		changed := false
		for _, key := range e.callOrder {
			ctx := e.inspectCallableContext(e.callables[key])
			if entry, ok := e.directFileEntryPoint(e.callables[key]); ok {
				ctx.EntryPoints = append(ctx.EntryPoints, entry)
				e.directEntryPointsByCallable[key] = append(e.directEntryPointsByCallable[key], entry)
				e.directPublicCallables[key] = struct{}{}
			}
			next := normalizeFlowContext(ctx)
			if !reflect.DeepEqual(e.contexts[key], next) {
				e.contexts[key] = next
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for _, key := range e.callOrder {
		for _, reg := range e.collectCallbackRegistrations(e.callables[key]) {
			ctx := e.contexts[reg.TargetKey]
			registrarCtx := e.contexts[key]
			entry := reg.Entry
			if entry.Kind == "rest" && len(reg.PermissionKeys) > 0 {
				permissionCtx := FlowContext{}
				for _, permissionKey := range reg.PermissionKeys {
					permissionCtx = mergeFlowContext(permissionCtx, e.permissionCallbackContext(permissionKey))
				}
				entry.Access = restPermissionContextAccess(entry.Access, permissionCtx)
				ctx = mergeFlowContext(ctx, permissionCtx)
			}
			if entry.Kind == "hook" || entry.Kind == "filter" {
				ctx = mergeFlowContext(ctx, registrarCtx)
			}
			if e.shouldAttachRegistrationEntryPoint(entry) {
				ctx.EntryPoints = append(ctx.EntryPoints, entry)
				e.directEntryPointsByCallable[reg.TargetKey] = append(e.directEntryPointsByCallable[reg.TargetKey], entry)
				e.directPublicCallables[reg.TargetKey] = struct{}{}
			}
			e.contexts[reg.TargetKey] = normalizeFlowContext(ctx)
		}
	}
	for pass := 0; pass < 8; pass++ {
		changed := false
		for _, callerKey := range e.callOrder {
			callerCtx := e.contexts[callerKey]
			if len(callerCtx.EntryPoints) == 0 &&
				len(callerCtx.CapabilityChecks) == 0 &&
				len(callerCtx.NonceChecks) == 0 &&
				len(callerCtx.ValidationChecks) == 0 &&
				len(callerCtx.AuthChecks) == 0 &&
				len(callerCtx.UnauthChecks) == 0 &&
				len(callerCtx.AdminChecks) == 0 &&
				len(callerCtx.AjaxChecks) == 0 {
				continue
			}
			for calleeKey := range e.callEdges[callerKey] {
				next := mergeFlowContext(e.contexts[calleeKey], callerCtx)
				if !reflect.DeepEqual(e.contexts[calleeKey], next) {
					e.contexts[calleeKey] = next
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
}

func directDispatchCallbackKeys(e *engine, c callable, name string, args []ast.Node, stringEnv map[string]string) []string {
	filter := func(keys []string) []string {
		return e.batchRelevantCallbackKeys(keys)
	}
	switch name {
	case "call_user_func", "forward_static_call":
		if len(args) == 0 {
			return nil
		}
		return filter(e.resolveCallbackKeysWithEnv(argValue(args[0]), c, stringEnv))
	case "call_user_func_array", "forward_static_call_array":
		if len(args) < 2 {
			return nil
		}
		return filter(e.resolveCallbackKeysWithEnv(argValue(args[0]), c, stringEnv))
	default:
		return nil
	}
}
