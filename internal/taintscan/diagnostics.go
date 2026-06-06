package taintscan

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

func mergeCountMaps(parts ...map[string]int) map[string]int {
	out := map[string]int{}
	for _, part := range parts {
		for key, value := range part {
			out[key] += value
		}
	}
	return out
}

func topCountEntries(items map[string]int, limit int) []string {
	type entry struct {
		key   string
		count int
	}
	list := make([]entry, 0, len(items))
	for key, count := range items {
		list = append(list, entry{key: key, count: count})
	}
	sort.Slice(list, func(i int, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].key < list[j].key
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, fmt.Sprintf("%s=%d", item.key, item.count))
	}
	return out
}

func summaryDependencyChangeCounts(previous, next summary) map[string]int {
	out := map[string]int{}
	if !reflect.DeepEqual(previous.ReturnSources, next.ReturnSources) {
		out["return-sources"]++
	}
	if !reflect.DeepEqual(previous.ReturnSourceOrigins, next.ReturnSourceOrigins) {
		out["return-source-origins"]++
	}
	if !reflect.DeepEqual(previous.ReturnReceiverPaths, next.ReturnReceiverPaths) {
		out["return-receiver-paths"]++
	}
	if !reflect.DeepEqual(previous.ReturnParams, next.ReturnParams) {
		out["return-params"]++
	}
	if !reflect.DeepEqual(previous.ReturnParamPaths, next.ReturnParamPaths) {
		out["return-param-paths"]++
	}
	if !reflect.DeepEqual(previous.ReturnPathWrites, next.ReturnPathWrites) {
		out["return-path-writes"]++
	}
	if !reflect.DeepEqual(previous.ReturnClasses, next.ReturnClasses) {
		out["return-classes"]++
	}
	if !reflect.DeepEqual(previous.ParamFindings, next.ParamFindings) {
		out["param-findings"]++
	}
	if !reflect.DeepEqual(previous.ReceiverFindings, next.ReceiverFindings) {
		out["receiver-findings"]++
	}
	if !reflect.DeepEqual(previous.StaticWrites, next.StaticWrites) {
		out["static-writes"]++
	}
	if !reflect.DeepEqual(previous.ReceiverWrites, next.ReceiverWrites) {
		out["receiver-writes"]++
	}
	if !reflect.DeepEqual(previous.ReceiverPathWrites, next.ReceiverPathWrites) {
		out["receiver-path-writes"]++
	}
	if !reflect.DeepEqual(previous.ReceiverStorageLinks, next.ReceiverStorageLinks) {
		out["receiver-storage-links"]++
	}
	if !reflect.DeepEqual(previous.StorageWrites, next.StorageWrites) {
		out["storage-writes"]++
	}
	if !reflect.DeepEqual(previous.StoragePathWrites, next.StoragePathWrites) {
		out["storage-path-writes"]++
	}
	return out
}

func summaryWeight(item summary) int {
	weight := len(item.ReturnSources) + len(item.ReturnSourceOrigins) + len(item.ReturnReceiverPaths) + len(item.ReturnParams) + len(item.ReturnParamPaths) + len(item.ReturnClasses) + len(item.SourceFindings)
	for _, templates := range item.ParamFindings {
		weight += len(templates)
	}
	weight += len(item.ReceiverFindings)
	weight += len(item.StaticWrites) + len(item.ReceiverWrites) + len(item.ReceiverPathWrites) + len(item.ReceiverStorageLinks) + len(item.StorageWrites) + len(item.StoragePathWrites)
	return weight
}

func (e *engine) topSummaryContributors(keys []string, limit int) []string {
	type entry struct {
		key    string
		weight int
	}
	list := make([]entry, 0, len(keys))
	for _, key := range keys {
		list = append(list, entry{key: key, weight: summaryWeight(e.summaries[key])})
	}
	sort.Slice(list, func(i int, j int) bool {
		if list[i].weight != list[j].weight {
			return list[i].weight > list[j].weight
		}
		return list[i].key < list[j].key
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, fmt.Sprintf("%s=%d", item.key, item.weight))
	}
	return out
}

func hashStrings(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	h := sha1.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fingerprintBufPool pools *bytes.Buffer for fingerprintJSON to avoid repeated
// growSlice allocations inside json.Marshal. Each corpus case runs in its own
// goroutine, so the pool is shared across the full parallel corpus run.
var fingerprintBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func fingerprintJSON(v any) string {
	buf := fingerprintBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	if err := enc.Encode(v); err != nil || buf.Len() == 0 {
		fingerprintBufPool.Put(buf)
		return ""
	}
	sum := sha1.Sum(buf.Bytes())
	fingerprintBufPool.Put(buf)
	return hex.EncodeToString(sum[:])
}

type summaryDependencyView struct {
	SourceFindings       []findingRecord
	ReturnSources        []Location
	ReturnSourceOrigins  []sourceOriginRef
	ReturnReceiverPaths  []receiverPathRef
	ReturnParams         []int
	ReturnParamPaths     []paramPathRef
	ReturnPathWrites     map[string]taintSummary
	ReturnClasses        []string
	ParamFindings        map[int][]sinkTemplate
	ReceiverFindings     []sinkTemplate
	StaticWrites         map[string]taintSummary
	ReceiverWrites       map[string]taintSummary
	ReceiverPathWrites   map[string]taintSummary
	ReceiverStorageLinks map[string]string
	StorageWrites        map[string]taintSummary
	StoragePathWrites    map[string]taintSummary
}

func summaryDependencyFingerprint(item summary) string {
	return summaryDependencyFingerprintForCallInterest(item, nil, nil, true, false, true, true, nil, true, true, true, nil)
}

func summaryDependencyFingerprintWithStaticWrites(item summary, includeStaticWrites bool) string {
	return summaryDependencyFingerprintForCallInterest(item, nil, nil, includeStaticWrites, false, true, true, nil, true, true, true, nil)
}

func summaryDependencyFingerprintForStaticInterest(item summary, staticReadPaths, staticReadRoots map[string]struct{}, includeStaticWrites bool) string {
	return summaryDependencyFingerprintForCallInterest(item, staticReadPaths, staticReadRoots, includeStaticWrites, false, true, true, nil, true, true, true, nil)
}

func (e *engine) normalizeSummaryForDependencyFingerprint(item summary) summary {
	if e == nil {
		return item
	}
	if e.currentBatchName == "output" {
		item = filterSummaryReceiverEffectsCoveredByStorageLinks(item)
	}
	if e.currentBatchName == "delete" {
		item.StorageWrites = filterDeleteStorageWritesForCallInterest(item.StorageWrites)
		item.StoragePathWrites = filterDeleteStorageWritesForCallInterest(item.StoragePathWrites)
	} else if e.currentBatchName == "include" {
		item = filterSummaryForIncludePathLikeCallInterest(item)
	} else if e.currentBatchUsesPathLikeStorageInterest() {
		item = filterSummaryForFilePathLikeCallInterest(item)
	}
	return item
}

func summaryDependencyFingerprintForCallInterest(item summary, staticReadPaths, staticReadRoots map[string]struct{}, includeStaticWrites bool, includeSourceFindings bool, includeReturns bool, includeParamFlows bool, paramIndexes map[int]struct{}, includeReceiverFlows bool, includeReturnClasses bool, includeStorageWrites bool, allowedReturnPaths map[string]struct{}) string {
	staticWrites := item.StaticWrites
	if !includeStaticWrites {
		staticWrites = nil
	} else if len(staticReadPaths) != 0 || len(staticReadRoots) != 0 {
		staticWrites = filterStaticWritesForInterest(staticWrites, staticReadPaths, staticReadRoots)
	}
	sourceFindings := item.SourceFindings
	if !includeSourceFindings {
		sourceFindings = nil
	}
	var storageWrites map[string]taintSummary
	var storagePathWrites map[string]taintSummary
	if includeStorageWrites {
		storageWrites = filterTransitiveSummaryWritesForCallInterest(item.StorageWrites, includeParamFlows, paramIndexes, includeReceiverFlows)
		storagePathWrites = filterTransitiveSummaryWritesForCallInterest(item.StoragePathWrites, includeParamFlows, paramIndexes, includeReceiverFlows)
	}
	returnSources := item.ReturnSources
	returnSourceOrigins := item.ReturnSourceOrigins
	returnReceiverPaths := filterSummaryReturnReceiverPathsForCallInterest(item.ReturnReceiverPaths, includeReceiverFlows)
	returnParams := filterSummaryReturnParamsForCallInterest(item.ReturnParams, includeParamFlows, paramIndexes)
	returnParamPaths := filterSummaryReturnParamPathsForCallInterest(item.ReturnParamPaths, includeParamFlows, paramIndexes)
	returnPathWrites := filterSummaryWritesForCallInterest(item.ReturnPathWrites, includeParamFlows, paramIndexes, includeReceiverFlows)
	returnClasses := filterReturnClassesForCallInterest(item.ReturnClasses, includeReturnClasses)
	if len(allowedReturnPaths) != 0 {
		returnSources = nil
		returnSourceOrigins = nil
		returnParams = nil
		returnParamPaths = filterSummaryReturnParamPathsForAssignedInterest(returnParamPaths, allowedReturnPaths)
		returnPathWrites = filterSummaryWritesForAssignedInterest(returnPathWrites, allowedReturnPaths)
		returnReceiverPaths = filterSummaryReturnReceiverPathsForAssignedInterest(returnReceiverPaths, allowedReturnPaths)
		returnClasses = nil
	}
	if !includeReturns {
		returnSources = nil
		returnSourceOrigins = nil
		returnReceiverPaths = nil
		returnParams = nil
		returnParamPaths = nil
		returnPathWrites = nil
		returnClasses = nil
	}
	return fingerprintJSON(summaryDependencyView{
		SourceFindings:       sourceFindings,
		ReturnSources:        returnSources,
		ReturnSourceOrigins:  returnSourceOrigins,
		ReturnReceiverPaths:  returnReceiverPaths,
		ReturnParams:         returnParams,
		ReturnParamPaths:     returnParamPaths,
		ReturnPathWrites:     returnPathWrites,
		ReturnClasses:        returnClasses,
		ParamFindings:        filterParamFindingsForCallInterest(item.ParamFindings, includeParamFlows, paramIndexes),
		ReceiverFindings:     filterReceiverFindingsForCallInterest(item.ReceiverFindings, includeReceiverFlows),
		StaticWrites:         staticWrites,
		ReceiverWrites:       filterSummaryWritesForCallInterest(item.ReceiverWrites, includeParamFlows, paramIndexes, includeReceiverFlows),
		ReceiverPathWrites:   filterSummaryWritesForCallInterest(item.ReceiverPathWrites, includeParamFlows, paramIndexes, includeReceiverFlows),
		ReceiverStorageLinks: filterReceiverStorageLinksForCallInterest(item.ReceiverStorageLinks, includeReceiverFlows),
		StorageWrites:        storageWrites,
		StoragePathWrites:    storagePathWrites,
	})
}

func summaryPathRelevantToAssignedInterest(path string, allowedReturnPaths map[string]struct{}) bool {
	if len(allowedReturnPaths) == 0 {
		return true
	}
	for allowed := range allowedReturnPaths {
		if structuralPathsOverlap(path, allowed) {
			return true
		}
	}
	return false
}

func filterSummaryReturnParamPathsForAssignedInterest(paramPaths []paramPathRef, allowedReturnPaths map[string]struct{}) []paramPathRef {
	if len(paramPaths) == 0 || len(allowedReturnPaths) == 0 {
		return paramPaths
	}
	filtered := make([]paramPathRef, 0, len(paramPaths))
	for _, ref := range paramPaths {
		if summaryPathRelevantToAssignedInterest(ref.Path, allowedReturnPaths) {
			filtered = append(filtered, ref)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryReturnReceiverPathsForAssignedInterest(receiverPaths []receiverPathRef, allowedReturnPaths map[string]struct{}) []receiverPathRef {
	if len(receiverPaths) == 0 || len(allowedReturnPaths) == 0 {
		return receiverPaths
	}
	filtered := make([]receiverPathRef, 0, len(receiverPaths))
	for _, ref := range receiverPaths {
		if summaryPathRelevantToAssignedInterest(ref.Path, allowedReturnPaths) {
			filtered = append(filtered, ref)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryWritesForAssignedInterest(writes map[string]taintSummary, allowedReturnPaths map[string]struct{}) map[string]taintSummary {
	if len(writes) == 0 || len(allowedReturnPaths) == 0 {
		return writes
	}
	filtered := map[string]taintSummary{}
	for path, effect := range writes {
		if !summaryPathRelevantToAssignedInterest(path, allowedReturnPaths) {
			continue
		}
		filtered[path] = effect
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryReturnParamsForCallInterest(params []int, includeParamFlows bool, allowedParamIndexes map[int]struct{}) []int {
	if includeParamFlows || len(params) == 0 {
		if len(params) == 0 || len(allowedParamIndexes) == 0 {
			return params
		}
		filtered := make([]int, 0, len(params))
		for _, idx := range params {
			if _, ok := allowedParamIndexes[idx]; ok {
				filtered = append(filtered, idx)
			}
		}
		if len(filtered) == 0 {
			return nil
		}
		return filtered
	}
	return nil
}

func filterSummaryReturnParamPathsForCallInterest(paramPaths []paramPathRef, includeParamFlows bool, allowedParamIndexes map[int]struct{}) []paramPathRef {
	if includeParamFlows || len(paramPaths) == 0 {
		if len(paramPaths) == 0 || len(allowedParamIndexes) == 0 {
			return paramPaths
		}
		filtered := make([]paramPathRef, 0, len(paramPaths))
		for _, ref := range paramPaths {
			if _, ok := allowedParamIndexes[ref.Index]; ok {
				filtered = append(filtered, ref)
			}
		}
		if len(filtered) == 0 {
			return nil
		}
		return filtered
	}
	return nil
}

func filterSummaryReturnReceiverPathsForCallInterest(receiverPaths []receiverPathRef, includeReceiverFlows bool) []receiverPathRef {
	if includeReceiverFlows || len(receiverPaths) == 0 {
		return receiverPaths
	}
	return nil
}

func filterReturnClassesForCallInterest(returnClasses []string, includeReturnClasses bool) []string {
	if includeReturnClasses || len(returnClasses) == 0 {
		return returnClasses
	}
	return nil
}

func filterParamFindingsForCallInterest(findings map[int][]sinkTemplate, includeParamFlows bool, allowedParamIndexes map[int]struct{}) map[int][]sinkTemplate {
	if includeParamFlows || len(findings) == 0 {
		if len(findings) == 0 || len(allowedParamIndexes) == 0 {
			return findings
		}
		filtered := map[int][]sinkTemplate{}
		for idx, items := range findings {
			if _, ok := allowedParamIndexes[idx]; ok {
				filtered[idx] = items
			}
		}
		if len(filtered) == 0 {
			return nil
		}
		return filtered
	}
	return nil
}

func filterSummaryWriteParamsForCallInterest(params []int, includeParamFlows bool, allowedParamIndexes map[int]struct{}) []int {
	if !includeParamFlows || len(params) == 0 {
		if includeParamFlows {
			return params
		}
		return nil
	}
	if len(allowedParamIndexes) == 0 {
		return params
	}
	filtered := make([]int, 0, len(params))
	for _, idx := range params {
		if _, ok := allowedParamIndexes[idx]; ok {
			filtered = append(filtered, idx)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryWriteParamPathsForCallInterest(paramPaths []paramPathRef, includeParamFlows bool, allowedParamIndexes map[int]struct{}) []paramPathRef {
	if !includeParamFlows || len(paramPaths) == 0 {
		if includeParamFlows {
			return paramPaths
		}
		return nil
	}
	if len(allowedParamIndexes) == 0 {
		return paramPaths
	}
	filtered := make([]paramPathRef, 0, len(paramPaths))
	for _, ref := range paramPaths {
		if _, ok := allowedParamIndexes[ref.Index]; ok {
			filtered = append(filtered, ref)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterReceiverFindingsForCallInterest(findings []sinkTemplate, includeReceiverFlows bool) []sinkTemplate {
	if includeReceiverFlows || len(findings) == 0 {
		return findings
	}
	return nil
}

func filterReceiverStorageLinksForCallInterest(links map[string]string, includeReceiverFlows bool) map[string]string {
	if includeReceiverFlows || len(links) == 0 {
		return links
	}
	return nil
}

func filterTransitiveSummaryWritesForCallInterest(writes map[string]taintSummary, includeParamFlows bool, allowedParamIndexes map[int]struct{}, includeReceiverFlows bool) map[string]taintSummary {
	if len(writes) == 0 {
		return nil
	}
	filtered := map[string]taintSummary{}
	for path, effect := range writes {
		effect = filterSummaryWriteForCallInterest(effect, includeParamFlows, allowedParamIndexes, includeReceiverFlows)
		if len(effect.Params) == 0 && len(effect.ParamPaths) == 0 {
			continue
		}
		filtered[path] = effect
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterDeleteStorageWritesForCallInterest(writes map[string]taintSummary) map[string]taintSummary {
	if len(writes) == 0 {
		return nil
	}
	filtered := map[string]taintSummary{}
	for path, effect := range writes {
		if !deleteBatchStorageWriteRelevantToCallInterest(path) {
			continue
		}
		filtered[path] = effect
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterFileBatchStorageWritesForCallInterest(writes map[string]taintSummary) map[string]taintSummary {
	if len(writes) == 0 {
		return nil
	}
	filtered := map[string]taintSummary{}
	for path, effect := range writes {
		if !fileBatchStorageWriteRelevantToCallInterest(path) {
			continue
		}
		filtered[path] = effect
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func (e *engine) currentBatchUsesFileRelevantOrders() bool {
	if len(e.allowedSinkOps) != 0 {
		for op := range e.allowedSinkOps {
			switch op {
			case "delete", "read", "open", "write", "include":
				return true
			}
		}
		return false
	}
	switch e.currentBatchName {
	case "delete", "read", "open", "write", "include":
		return true
	default:
		return false
	}
}

func (e *engine) currentBatchUsesPathLikeStorageInterest() bool {
	if len(e.allowedSinkOps) != 0 {
		for op := range e.allowedSinkOps {
			switch op {
			case "read", "open", "write", "include":
				return true
			}
		}
		return false
	}
	switch e.currentBatchName {
	case "read", "open", "write", "include":
		return true
	default:
		return false
	}
}

func (e *engine) currentBatchUsesAssignedReturnPathInterest() bool {
	switch e.currentBatchName {
	case "output", "call", "action":
		return true
	default:
		return e.currentBatchUsesPathLikeStorageInterest()
	}
}

func (e *engine) currentBatchRelevantUseOrders(key string) map[string]int {
	if e.currentBatchName == "output" {
		return e.outputSinkRelevantUseOrders[key]
	}
	if e.currentBatchName == "include" {
		return e.includeSinkRelevantUseOrders[key]
	}
	if e.currentBatchUsesFileRelevantOrders() {
		return e.fileSinkRelevantUseOrders[key]
	}
	return e.callSinkRelevantUseOrders[key]
}

func (e *engine) outputRelevantAssignedPathsAfter(key string, root string, order int) map[string]struct{} {
	if e.currentBatchName != "output" || root == "" {
		return nil
	}
	rootPaths := e.outputSinkRelevantUsePaths[key]
	if len(rootPaths) == 0 {
		return nil
	}
	pathOrders := rootPaths[root]
	if len(pathOrders) == 0 {
		return nil
	}
	allowed := map[string]struct{}{}
	for path, useOrder := range pathOrders {
		if useOrder <= order {
			continue
		}
		if path == "" {
			return nil
		}
		allowed[path] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func (e *engine) callRelevantAssignedPathsAfter(key string, root string, order int) map[string]struct{} {
	if e.currentBatchName != "call" || root == "" {
		return nil
	}
	rootPaths := e.callSinkRelevantUsePaths[key]
	if len(rootPaths) == 0 {
		return nil
	}
	pathOrders := rootPaths[root]
	if len(pathOrders) == 0 {
		return nil
	}
	allowed := map[string]struct{}{}
	for path, useOrder := range pathOrders {
		if useOrder <= order {
			continue
		}
		if path == "" {
			return nil
		}
		allowed[path] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func (e *engine) actionRelevantAssignedPathsAfter(key string, root string, order int) map[string]struct{} {
	if e.currentBatchName != "action" || root == "" {
		return nil
	}
	rootPaths := e.actionSinkRelevantUsePaths[key]
	if len(rootPaths) == 0 {
		return nil
	}
	pathOrders := rootPaths[root]
	if len(pathOrders) == 0 {
		return nil
	}
	allowed := map[string]struct{}{}
	for path, useOrder := range pathOrders {
		if useOrder <= order {
			continue
		}
		if path == "" {
			return nil
		}
		allowed[path] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func (e *engine) fileRelevantAssignedPathsAfter(key string, root string, order int) map[string]struct{} {
	if !e.currentBatchUsesPathLikeStorageInterest() || root == "" {
		return nil
	}
	rootPaths := e.fileSinkRelevantUsePaths[key]
	if e.currentBatchName == "include" {
		rootPaths = e.includeSinkRelevantUsePaths[key]
	}
	if len(rootPaths) == 0 {
		return nil
	}
	pathOrders := rootPaths[root]
	if len(pathOrders) == 0 {
		return nil
	}
	allowed := map[string]struct{}{}
	for path, useOrder := range pathOrders {
		if useOrder <= order {
			continue
		}
		if path == "" {
			return nil
		}
		allowed[path] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func (e *engine) currentBatchAssignedPathsAfter(key string, root string, order int) map[string]struct{} {
	if e.currentBatchName == "output" {
		return e.outputRelevantAssignedPathsAfter(key, root, order)
	}
	if e.currentBatchName == "call" {
		return e.callRelevantAssignedPathsAfter(key, root, order)
	}
	if e.currentBatchName == "action" {
		return e.actionRelevantAssignedPathsAfter(key, root, order)
	}
	if e.currentBatchUsesPathLikeStorageInterest() {
		return e.fileRelevantAssignedPathsAfter(key, root, order)
	}
	return nil
}

func (e *engine) includeAssignedReturnsForCurrentBatch(site callSiteEdge, includeSourceFindings bool, relevantOrders map[string]int) (bool, bool) {
	includeAssignedReturn := site.assignedRoot != "" && callRelevantUseAfter(relevantOrders, site.assignedRoot, site.order)
	includeReturns := site.dataCarrier || site.assignedRoot != ""
	switch {
	case e.currentBatchName == "call" && site.assignedRoot != "":
		includeReturns = site.dataCarrier && includeAssignedReturn
	case e.currentBatchName == "output" && site.booleanUse && site.assignedRoot == "":
		includeReturns = false
	case e.currentBatchName == "output" && site.assignedRoot != "":
		includeReturns = site.dataCarrier && includeAssignedReturn
	case e.currentBatchUsesFileRelevantOrders() && site.assignedRoot != "" && !includeSourceFindings:
		includeReturns = site.dataCarrier && includeAssignedReturn
	}
	return includeAssignedReturn, includeReturns
}

func (e *engine) callableCanReuseEmptyOutputBooleanSummary(key string) bool {
	if e == nil || key == "" {
		return false
	}
	if len(e.allowedSinkOps) != 1 || !e.allowsSinkOp("output") {
		return false
	}
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	if e.callableHasDirectSink(c) ||
		e.callableIsStorageWriter(key) ||
		e.callableHasSupportedCrossRequestWriter(key) {
		return false
	}
	if !summaryHasNoEffects(e.summaries[key]) {
		return false
	}
	return e.callableHasOnlyBooleanRelevantOutputUses(key)
}

func (e *engine) siteIncludesReceiverFlows(site callSiteEdge, callee string) bool {
	if site.receiverCarrier || site.receiverStateRelevant {
		return true
	}
	if e == nil || e.currentBatchName != "delete" || !site.hasReceiver || callee == "" {
		return false
	}
	calleeCallable, ok := e.callables[callee]
	if !ok {
		return false
	}
	return e.callableConsumesCallReceiver(calleeCallable)
}

func (e *engine) receiverFlowsRequiringStorageWriteInterest(site callSiteEdge, callee string, includeReturns bool, includeParamFlows bool) bool {
	receiverFlows := e.siteIncludesReceiverFlows(site, callee)
	if e.currentBatchName == "output" &&
		includeReturns &&
		!includeParamFlows &&
		e.callableHasPersistentReadOnlyStandaloneSourceSummary(callee, e.summaries[callee]) {
		return site.receiverCarrier
	}
	return receiverFlows
}

func deleteBatchStorageWriteRelevantToCallInterest(path string) bool {
	root := structuralPathRoot(path)
	switch root {
	case "post_meta_value", "user_meta_value", "option_value":
	default:
		return true
	}
	leaf := storagePathLeafField(path)
	if leaf == "" {
		if deleteBatchMetadataWildcardPathTooBroad(path) {
			return false
		}
		return true
	}
	return deleteStorageLeafLooksPathLike(leaf)
}

func deleteBatchMetadataWildcardPathTooBroad(path string) bool {
	root := structuralPathRoot(path)
	switch root {
	case "post_meta_value", "user_meta_value", "option_value", "transient_value":
	default:
		return false
	}
	return strings.Contains(path, "[*][*]")
}

func fileBatchStorageWriteRelevantToCallInterest(path string) bool {
	root := structuralPathRoot(path)
	switch root {
	case "user_meta_value", "option_value":
	default:
		return true
	}
	leaf := storagePathLeafField(path)
	if leaf == "" {
		return false
	}
	return deleteStorageLeafLooksPathLike(leaf)
}

// filterCallBatchStorageReadBucketsForCallInterest drops storage read buckets that are
// too broad to drive meaningful call-batch fingerprint changes. Specifically, wildcard-only
// metadata paths like post_meta_value[*][*] that lack semantic key specificity are excluded.
// This mirrors the delete-batch wildcard pruning for the call batch.
func filterCallBatchStorageReadBucketsForCallInterest(buckets map[string]struct{}) map[string]struct{} {
	if len(buckets) == 0 {
		return nil
	}
	filtered := map[string]struct{}{}
	for bucket := range buckets {
		if deleteBatchMetadataWildcardPathTooBroad(bucket) {
			continue
		}
		filtered[bucket] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

// filterCallBatchStorageReadFamiliesForCallInterest drops storage read families that are
// already covered by specific non-wildcard buckets, or whose only known buckets are all
// too-broad wildcard paths (e.g., post_meta_value[*][*]). In those cases the family-level
// fingerprint contribution is skipped, matching the bucket-level exclusion above.
func filterCallBatchStorageReadFamiliesForCallInterest(families map[string]struct{}, specificBuckets map[string]bool, rawBuckets map[string]struct{}) map[string]struct{} {
	if len(families) == 0 {
		return nil
	}
	// Build a set of families that have at least one non-wildcard bucket in rawBuckets.
	familiesWithNonWildcard := map[string]bool{}
	for bucket := range rawBuckets {
		if deleteBatchMetadataWildcardPathTooBroad(bucket) {
			continue
		}
		family := structuralPathRoot(bucket)
		if family != "" {
			familiesWithNonWildcard[family] = true
		}
	}
	filtered := map[string]struct{}{}
	for family := range families {
		// Drop if covered by a specific non-wildcard bucket path already fingerprinted.
		if specificBuckets[family] {
			continue
		}
		// Drop if the family only had wildcard buckets (no non-wildcard bucket seen).
		if len(rawBuckets) > 0 && !familiesWithNonWildcard[family] {
			continue
		}
		filtered[family] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterDeleteBatchStorageReadBucketsForCallInterest(buckets map[string]struct{}, relevantOrders map[string]int) map[string]struct{} {
	if len(buckets) == 0 {
		return nil
	}
	filtered := map[string]struct{}{}
	for bucket := range buckets {
		if !deleteStorageBucketRelevantToCallInterest(bucket, relevantOrders) {
			continue
		}
		filtered[bucket] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterDeleteBatchStorageReadFamiliesForCallInterest(families map[string]struct{}, specificBuckets map[string]bool, relevantOrders map[string]int) map[string]struct{} {
	if len(families) == 0 {
		return nil
	}
	filtered := map[string]struct{}{}
	for family := range families {
		if specificBuckets[family] {
			continue
		}
		if !deleteStorageFamilyRelevantToCallInterest(family, relevantOrders) {
			continue
		}
		filtered[family] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func storageReadSpecificFamilies(buckets map[string]struct{}) map[string]bool {
	if len(buckets) == 0 {
		return nil
	}
	specific := map[string]bool{}
	for bucket := range buckets {
		family := structuralPathRoot(bucket)
		if bucket != "" && family != "" && bucket != family {
			specific[family] = true
		}
	}
	if len(specific) == 0 {
		return nil
	}
	return specific
}

func deleteStorageReadSpecificFamiliesForCallInterest(buckets map[string]struct{}, relevantOrders map[string]int) map[string]bool {
	if len(buckets) == 0 {
		return nil
	}
	specific := map[string]bool{}
	for bucket := range buckets {
		family := structuralPathRoot(bucket)
		if family == "" {
			continue
		}
		if !deleteStorageBucketRelevantToCallInterest(bucket, relevantOrders) &&
			!deleteStorageFamilyRelevantToStandaloneReturn(family) {
			continue
		}
		if bucket != "" && family != "" && bucket != family {
			specific[family] = true
		}
	}
	if len(specific) == 0 {
		return nil
	}
	return specific
}

func filterFileBatchStorageReadBucketsForCallInterest(buckets map[string]struct{}) map[string]struct{} {
	if len(buckets) == 0 {
		return nil
	}
	filtered := map[string]struct{}{}
	for bucket := range buckets {
		if !fileStorageBucketRelevantToStandaloneReturn(bucket) {
			continue
		}
		filtered[bucket] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterFileBatchStorageReadFamiliesForCallInterest(families map[string]struct{}, specificBuckets map[string]bool) map[string]struct{} {
	if len(families) == 0 {
		return nil
	}
	filtered := map[string]struct{}{}
	for family := range families {
		if specificBuckets[family] {
			continue
		}
		if !fileStorageFamilyRelevantToStandaloneReturn(family) {
			continue
		}
		filtered[family] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryWritesForCallInterest(writes map[string]taintSummary, includeParamFlows bool, allowedParamIndexes map[int]struct{}, includeReceiverFlows bool) map[string]taintSummary {
	if len(writes) == 0 {
		return nil
	}
	filtered := map[string]taintSummary{}
	for path, effect := range writes {
		effect = filterSummaryWriteForCallInterest(effect, includeParamFlows, allowedParamIndexes, includeReceiverFlows)
		if summaryWriteEffectEmpty(effect) {
			continue
		}
		filtered[path] = effect
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryWriteForCallInterest(effect taintSummary, includeParamFlows bool, allowedParamIndexes map[int]struct{}, includeReceiverFlows bool) taintSummary {
	if includeParamFlows && includeReceiverFlows {
		effect.Params = filterSummaryWriteParamsForCallInterest(effect.Params, includeParamFlows, allowedParamIndexes)
		effect.ParamPaths = filterSummaryWriteParamPathsForCallInterest(effect.ParamPaths, includeParamFlows, allowedParamIndexes)
		return effect
	}
	effect.Params = filterSummaryWriteParamsForCallInterest(effect.Params, includeParamFlows, allowedParamIndexes)
	effect.ParamPaths = filterSummaryWriteParamPathsForCallInterest(effect.ParamPaths, includeParamFlows, allowedParamIndexes)
	if !includeReceiverFlows {
		effect.ReceiverPaths = nil
	}
	return effect
}

func summaryWriteEffectEmpty(effect taintSummary) bool {
	return len(effect.Sources) == 0 &&
		len(effect.SourceOrigins) == 0 &&
		len(effect.ReceiverPaths) == 0 &&
		len(effect.Params) == 0 &&
		len(effect.ParamPaths) == 0
}

func filterStaticWritesForInterest(writes map[string]taintSummary, staticReadPaths, staticReadRoots map[string]struct{}) map[string]taintSummary {
	if len(writes) == 0 {
		return nil
	}
	filtered := map[string]taintSummary{}
	for path, effect := range writes {
		if staticWriteRelevantToInterest(path, staticReadPaths, staticReadRoots) {
			filtered[path] = effect
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func staticWriteRelevantToInterest(path string, staticReadPaths, staticReadRoots map[string]struct{}) bool {
	for readPath := range staticReadPaths {
		if structuralPathsOverlap(path, readPath) {
			return true
		}
	}
	for root := range staticReadRoots {
		if structuralPathsOverlap(path, root) {
			return true
		}
	}
	return false
}

func structuralPathsOverlap(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if isStructuralPathPrefix(a, b) || isStructuralPathPrefix(b, a) {
		return true
	}
	return false
}

func isStructuralPathPrefix(prefix, path string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	switch path[len(prefix)] {
	case '[', '.':
		return true
	default:
		return false
	}
}

func isConstStaticStateKey(key string) bool {
	return strings.HasPrefix(key, "const:")
}

func fileStaticStateKeyRelevant(key string) bool {
	if key == "" || isConstStaticStateKey(key) {
		return false
	}
	leaf := strings.TrimPrefix(storagePathLeafField(key), "$")
	if leaf == "" {
		if dollar := strings.LastIndex(key, "$"); dollar != -1 && dollar+1 < len(key) {
			leaf = strings.ToLower(strings.TrimSpace(key[dollar+1:]))
		}
	}
	if leaf == "" {
		return false
	}
	return deleteStorageLeafLooksPathLike(leaf)
}

func filterFileRelevantStaticStateKeys(keys map[string]struct{}) map[string]struct{} {
	if len(keys) == 0 {
		return nil
	}
	filtered := map[string]struct{}{}
	for key := range keys {
		if fileStaticStateKeyRelevant(key) {
			filtered[key] = struct{}{}
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func fileStructuralPathRelevant(path string) bool {
	leaf := strings.TrimPrefix(storagePathLeafField(path), "$")
	if leaf == "" {
		return false
	}
	return deleteStorageLeafLooksPathLike(leaf)
}

func filterFileRelevantParamPathRefs(paramPaths []paramPathRef) []paramPathRef {
	if len(paramPaths) == 0 {
		return nil
	}
	filtered := make([]paramPathRef, 0, len(paramPaths))
	for _, ref := range paramPaths {
		if fileStructuralPathRelevant(ref.Path) {
			filtered = append(filtered, ref)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterFileRelevantReceiverPathRefs(receiverPaths []receiverPathRef) []receiverPathRef {
	if len(receiverPaths) == 0 {
		return nil
	}
	filtered := make([]receiverPathRef, 0, len(receiverPaths))
	for _, ref := range receiverPaths {
		if fileStructuralPathRelevant(ref.Path) {
			filtered = append(filtered, ref)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryWritesForFilePathInterest(writes map[string]taintSummary) map[string]taintSummary {
	if len(writes) == 0 {
		return nil
	}
	filtered := map[string]taintSummary{}
	for path, effect := range writes {
		if !fileStructuralPathRelevant(path) {
			continue
		}
		effect.ParamPaths = filterFileRelevantParamPathRefs(effect.ParamPaths)
		effect.ReceiverPaths = filterFileRelevantReceiverPathRefs(effect.ReceiverPaths)
		if summaryWriteEffectEmpty(effect) {
			continue
		}
		filtered[path] = effect
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterSummaryForFilePathLikeCallInterest(item summary) summary {
	item.ReturnParamPaths = filterFileRelevantParamPathRefs(item.ReturnParamPaths)
	item.ReturnReceiverPaths = filterFileRelevantReceiverPathRefs(item.ReturnReceiverPaths)
	item.ReturnPathWrites = filterSummaryWritesForFilePathInterest(item.ReturnPathWrites)
	return item
}

func filterSummaryForIncludePathLikeCallInterest(item summary) summary {
	item = filterSummaryForFilePathLikeCallInterest(item)
	item.StorageWrites = filterFileBatchStorageWritesForCallInterest(item.StorageWrites)
	item.StoragePathWrites = filterFileBatchStorageWritesForCallInterest(item.StoragePathWrites)
	return item
}

func (e *engine) summaryFingerprint(key string) string {
	if fingerprint, ok := e.summaryFingerprints[key]; ok {
		return fingerprint
	}
	fingerprint := e.callerInvalidationSummaryFingerprint(key, e.summaries[key])
	e.summaryFingerprints[key] = fingerprint
	return fingerprint
}

func (e *engine) callerInvalidationSummaryFingerprint(key string, item summary) string {
	callers := e.reverseCallEdges[key]
	if len(callers) == 0 {
		return ""
	}

	staticReadPaths := map[string]struct{}{}
	staticReadRoots := map[string]struct{}{}
	includeCalleeStaticWrites := false
	includeSourceFindings := false
	includeReturns := false
	includeParamFlows := false
	includeAllParamIndexes := false
	paramIndexes := map[int]struct{}{}
	includeReceiverFlows := false
	includeReturnClasses := false
	includeAllReturnPaths := false
	includeRootOnlyAssignedReturns := false
	returnPaths := map[string]struct{}{}
	includeStorageWrites := false

	for caller := range callers {
		paths := e.staticReadPathsByCallable[caller]
		if e.currentBatchUsesPathLikeStorageInterest() {
			paths = filterFileRelevantStaticStateKeys(paths)
		}
		if len(paths) != 0 {
			includeCalleeStaticWrites = true
			for path := range paths {
				staticReadPaths[path] = struct{}{}
			}
		}
		roots := e.staticReadRootsByCallable[caller]
		if e.currentBatchUsesPathLikeStorageInterest() {
			roots = filterFileRelevantStaticStateKeys(roots)
		}
		if len(roots) != 0 {
			includeCalleeStaticWrites = true
			for root := range roots {
				staticReadRoots[root] = struct{}{}
			}
		}

		relevantOrders := e.currentBatchRelevantUseOrders(caller)

		callerHadSiteInfo := false
		for _, site := range e.callSiteEdges[caller] {
			if site.callee != key {
				continue
			}
			callerHadSiteInfo = true

			siteIncludeSourceFindings := e.callableHasStandaloneSourceFindings(key)
			if e.currentBatchName == "delete" {
				siteIncludeSourceFindings = e.callableHasDeleteRelevantStandaloneSourceFindings(key)
			} else if e.currentBatchUsesPathLikeStorageInterest() {
				siteIncludeSourceFindings = e.callableHasFileRelevantStandaloneSourceFindings(key)
			}
			siteIncludeParamFlows := site.argCarrier || len(site.runtimeArgIdxs) != 0
			siteIncludeReceiverFlows := e.siteIncludesReceiverFlows(site, key)
			siteIncludeAssignedReturn, siteIncludeReturns := e.includeAssignedReturnsForCurrentBatch(site, siteIncludeSourceFindings, relevantOrders)
			siteIncludeReturnClasses := siteIncludeAssignedReturn
			siteStorageReceiverFlows := e.receiverFlowsRequiringStorageWriteInterest(site, key, siteIncludeReturns, siteIncludeParamFlows)
			siteIncludeStorageWrites := true
			if e.currentBatchName == "output" &&
				siteIncludeReturns &&
				!siteIncludeParamFlows &&
				!siteStorageReceiverFlows &&
				e.callableHasPersistentReadOnlyStandaloneSourceSummary(key, item) {
				siteIncludeStorageWrites = false
			}

			includeSourceFindings = includeSourceFindings || siteIncludeSourceFindings
			includeReturns = includeReturns || siteIncludeReturns
			includeParamFlows = includeParamFlows || siteIncludeParamFlows
			includeReceiverFlows = includeReceiverFlows || siteIncludeReceiverFlows
			includeReturnClasses = includeReturnClasses || siteIncludeReturnClasses
			includeStorageWrites = includeStorageWrites || siteIncludeStorageWrites
			if siteIncludeReturns {
				if paths := e.currentBatchAssignedPathsAfter(caller, site.assignedRoot, site.order); len(paths) != 0 {
					for path := range paths {
						returnPaths[path] = struct{}{}
					}
				} else if e.currentBatchName == "output" && siteIncludeAssignedReturn {
					includeRootOnlyAssignedReturns = true
				} else {
					includeAllReturnPaths = true
				}
			}

			if !siteIncludeParamFlows || includeAllParamIndexes {
				continue
			}
			if len(site.runtimeArgIdxs) == 0 {
				includeAllParamIndexes = true
				paramIndexes = nil
				continue
			}
			for idx := range site.runtimeArgIdxs {
				paramIndexes[idx] = struct{}{}
			}
		}

		if callerHadSiteInfo {
			continue
		}

		fallbackIncludeSourceFindings := e.callableHasStandaloneSourceFindings(key)
		if e.currentBatchName == "delete" {
			fallbackIncludeSourceFindings = e.callableHasDeleteRelevantStandaloneSourceFindings(key)
		} else if e.currentBatchUsesPathLikeStorageInterest() {
			fallbackIncludeSourceFindings = e.callableHasFileRelevantStandaloneSourceFindings(key)
		}
		includeSourceFindings = includeSourceFindings || fallbackIncludeSourceFindings
		includeReturns = true
		includeParamFlows = true
		includeAllParamIndexes = true
		paramIndexes = nil
		includeReceiverFlows = true
		includeReturnClasses = true
		includeAllReturnPaths = true
		includeStorageWrites = true
	}

	item = e.normalizeSummaryForDependencyFingerprint(item)

	var allowedParamIndexes map[int]struct{}
	if includeParamFlows && !includeAllParamIndexes && len(paramIndexes) != 0 {
		allowedParamIndexes = paramIndexes
	}
	var allowedReturnPaths map[string]struct{}
	if includeReturns && !includeAllReturnPaths && len(returnPaths) != 0 {
		allowedReturnPaths = returnPaths
	}
	if includeReturns && !includeAllReturnPaths && len(allowedReturnPaths) == 0 && includeRootOnlyAssignedReturns {
		item = collapseSummaryAssignedReturnToRoot(item)
	}

	return summaryDependencyFingerprintForCallInterest(
		item,
		staticReadPaths,
		staticReadRoots,
		includeCalleeStaticWrites,
		includeSourceFindings,
		includeReturns,
		includeParamFlows,
		allowedParamIndexes,
		includeReceiverFlows,
		includeReturnClasses,
		includeStorageWrites,
		allowedReturnPaths,
	)
}

func (e *engine) storageFamilyStateFingerprint(family string) string {
	if fingerprint, ok := e.storageStateFingerprints[family]; ok {
		return fingerprint
	}
	origins := originSet{}
	origins = unionInto(origins, collectStructuralChildren(e.storagePaths, family))
	if familyOrigins, ok := e.storage[family]; ok {
		origins = unionInto(origins, familyOrigins)
	}
	fingerprint := fingerprintJSON(summarizeOrigins(origins))
	e.storageStateFingerprints[family] = fingerprint
	return fingerprint
}

func (e *engine) storagePathStateFingerprint(path string) string {
	if fingerprint, ok := e.storagePathStateFingerprints[path]; ok {
		return fingerprint
	}
	origins := originSet{}
	origins = unionInto(origins, lookupStructuralSelfOrigins(e.storagePaths, path))
	origins = unionInto(origins, collectStructuralChildren(e.storagePaths, path))
	family := structuralPathRoot(path)
	if family != "" {
		if familyOrigins, ok := e.storage[family]; ok {
			origins = unionInto(origins, familyOrigins)
		}
	}
	fingerprint := fingerprintJSON(summarizeOrigins(origins))
	e.storagePathStateFingerprints[path] = fingerprint
	return fingerprint
}

func (e *engine) staticRootStateFingerprint(root string) string {
	if fingerprint, ok := e.staticStateFingerprints[root]; ok {
		return fingerprint
	}
	origins := originSet{}
	origins = unionInto(origins, lookupStructuralSelfOrigins(e.staticProps, root))
	origins = unionInto(origins, collectStructuralChildren(e.staticProps, root))
	fingerprint := fingerprintJSON(summarizeOrigins(origins))
	e.staticStateFingerprints[root] = fingerprint
	return fingerprint
}

func (e *engine) staticPathStateFingerprint(path string) string {
	cacheKey := "path:" + path
	if fingerprint, ok := e.staticStateFingerprints[cacheKey]; ok {
		return fingerprint
	}
	fingerprint := fingerprintJSON(summarizeOrigins(lookupStructuralPathOrigins(e.staticProps, path)))
	e.staticStateFingerprints[cacheKey] = fingerprint
	return fingerprint
}

func (e *engine) callableSummaryInputFingerprint(key string) string {
	if e.callableCanReuseEmptyOutputBooleanSummary(key) {
		return "batch=" + e.currentBatchName + "#bool-empty"
	}
	staticReadPaths := e.staticReadPathsByCallable[key]
	staticReadRoots := e.staticReadRootsByCallable[key]
	if e.currentBatchUsesPathLikeStorageInterest() {
		staticReadPaths = filterFileRelevantStaticStateKeys(staticReadPaths)
		staticReadRoots = filterFileRelevantStaticStateKeys(staticReadRoots)
	}
	if len(e.callEdges[key]) == 0 &&
		len(e.storageReadBucketsByCallable[key]) == 0 &&
		len(e.storageReadFamiliesByCallable[key]) == 0 &&
		len(staticReadPaths) == 0 &&
		len(staticReadRoots) == 0 {
		return "batch=" + e.currentBatchName
	}

	parts := []string{"batch=" + e.currentBatchName}
	includeCalleeStaticWrites := len(staticReadPaths) != 0 || len(staticReadRoots) != 0

	calleeReturnInterest := map[string]bool{}
	calleeSourceFindingInterest := map[string]bool{}
	calleeParamInterest := map[string]bool{}
	calleeParamIndexes := map[string]map[int]struct{}{}
	calleeReceiverInterest := map[string]bool{}
	calleeReturnClassInterest := map[string]bool{}
	calleeReturnPathInterest := map[string]map[string]struct{}{}
	calleeReturnPathUnrestricted := map[string]bool{}
	calleeStorageWriteInterest := map[string]bool{}
	calleeHasSiteInfo := map[string]bool{}
	relevantOrders := e.currentBatchRelevantUseOrders(key)
	for callee := range e.callEdges[key] {
		calleeReturnInterest[callee] = false
		calleeSourceFindingInterest[callee] = false
		calleeParamInterest[callee] = false
		calleeParamIndexes[callee] = nil
		calleeReceiverInterest[callee] = false
		calleeReturnClassInterest[callee] = false
	}
	if sites := e.callSiteEdges[key]; len(sites) != 0 {
		for _, site := range sites {
			if site.callee == "" {
				continue
			}
			calleeHasSiteInfo[site.callee] = true
			includeSourceFindings := e.callableHasStandaloneSourceFindings(site.callee)
			if e.currentBatchName == "delete" {
				includeSourceFindings = e.callableHasDeleteRelevantStandaloneSourceFindings(site.callee)
			} else if e.currentBatchUsesPathLikeStorageInterest() {
				includeSourceFindings = e.callableHasFileRelevantStandaloneSourceFindings(site.callee)
			}
			includeParamFlows := site.argCarrier || len(site.runtimeArgIdxs) != 0
			includeReceiverFlows := e.siteIncludesReceiverFlows(site, site.callee)
			includeAssignedReturn, includeReturns := e.includeAssignedReturnsForCurrentBatch(site, includeSourceFindings, relevantOrders)
			includeReturnClasses := includeAssignedReturn
			includeStorageReceiverFlows := e.receiverFlowsRequiringStorageWriteInterest(site, site.callee, includeReturns, includeParamFlows)
			includeStorageWrites := true
			if e.currentBatchName == "output" &&
				includeReturns &&
				!includeParamFlows &&
				!includeStorageReceiverFlows &&
				e.callableHasPersistentReadOnlyStandaloneSourceSummary(site.callee, e.summaries[site.callee]) {
				includeStorageWrites = false
			}
			if existing, ok := calleeSourceFindingInterest[site.callee]; !ok {
				calleeSourceFindingInterest[site.callee] = includeSourceFindings
			} else {
				calleeSourceFindingInterest[site.callee] = existing || includeSourceFindings
			}
			if existing, ok := calleeReturnInterest[site.callee]; !ok {
				calleeReturnInterest[site.callee] = includeReturns
			} else {
				calleeReturnInterest[site.callee] = existing || includeReturns
			}
			if existing, ok := calleeParamInterest[site.callee]; !ok {
				calleeParamInterest[site.callee] = includeParamFlows
			} else {
				calleeParamInterest[site.callee] = existing || includeParamFlows
			}
			if includeParamFlows && len(site.runtimeArgIdxs) != 0 {
				indexes := calleeParamIndexes[site.callee]
				if indexes == nil {
					indexes = map[int]struct{}{}
				}
				for idx := range site.runtimeArgIdxs {
					indexes[idx] = struct{}{}
				}
				calleeParamIndexes[site.callee] = indexes
			}
			if existing, ok := calleeReceiverInterest[site.callee]; !ok {
				calleeReceiverInterest[site.callee] = includeReceiverFlows
			} else {
				calleeReceiverInterest[site.callee] = existing || includeReceiverFlows
			}
			if existing, ok := calleeReturnClassInterest[site.callee]; !ok {
				calleeReturnClassInterest[site.callee] = includeReturnClasses
			} else {
				calleeReturnClassInterest[site.callee] = existing || includeReturnClasses
			}
			if existing, ok := calleeStorageWriteInterest[site.callee]; !ok {
				calleeStorageWriteInterest[site.callee] = includeStorageWrites
			} else {
				calleeStorageWriteInterest[site.callee] = existing || includeStorageWrites
			}
			if includeReturns {
				if paths := e.currentBatchAssignedPathsAfter(key, site.assignedRoot, site.order); len(paths) != 0 {
					allowed := calleeReturnPathInterest[site.callee]
					if allowed == nil {
						allowed = map[string]struct{}{}
					}
					for path := range paths {
						allowed[path] = struct{}{}
					}
					calleeReturnPathInterest[site.callee] = allowed
				} else {
					calleeReturnPathUnrestricted[site.callee] = true
				}
			}
		}
	}
	for callee := range calleeReturnInterest {
		if !calleeHasSiteInfo[callee] {
			calleeSourceFindingInterest[callee] = e.callableHasStandaloneSourceFindings(callee)
			if e.currentBatchName == "delete" {
				calleeSourceFindingInterest[callee] = e.callableHasDeleteRelevantStandaloneSourceFindings(callee)
			} else if e.currentBatchUsesPathLikeStorageInterest() {
				calleeSourceFindingInterest[callee] = e.callableHasFileRelevantStandaloneSourceFindings(callee)
			}
			calleeReturnInterest[callee] = true
			calleeParamInterest[callee] = true
			calleeParamIndexes[callee] = nil
			calleeReceiverInterest[callee] = true
			calleeReturnClassInterest[callee] = true
			calleeReturnPathUnrestricted[callee] = true
			calleeStorageWriteInterest[callee] = true
		}
	}
	callees := make([]string, 0, len(calleeReturnInterest))
	for callee := range calleeReturnInterest {
		callees = append(callees, callee)
	}
	sort.Strings(callees)
	for _, callee := range callees {
		item := e.normalizeSummaryForDependencyFingerprint(e.summaries[callee])
		parts = append(parts, "callee="+callee+":"+summaryDependencyFingerprintForCallInterest(
			item,
			staticReadPaths,
			staticReadRoots,
			includeCalleeStaticWrites,
			calleeSourceFindingInterest[callee],
			calleeReturnInterest[callee],
			calleeParamInterest[callee],
			calleeParamIndexes[callee],
			calleeReceiverInterest[callee],
			calleeReturnClassInterest[callee],
			calleeStorageWriteInterest[callee],
			func() map[string]struct{} {
				if calleeReturnPathUnrestricted[callee] {
					return nil
				}
				return calleeReturnPathInterest[callee]
			}(),
		))
	}

	rawReadBuckets := e.storageReadBucketsByCallable[key]
	readBuckets := rawReadBuckets
	var specificStorageBuckets map[string]bool
	if e.currentBatchName == "delete" {
		specificStorageBuckets = deleteStorageReadSpecificFamiliesForCallInterest(rawReadBuckets, e.fileSinkRelevantUseOrders[key])
		readBuckets = filterDeleteBatchStorageReadBucketsForCallInterest(readBuckets, e.fileSinkRelevantUseOrders[key])
	} else if e.currentBatchName == "call" {
		readBuckets = filterCallBatchStorageReadBucketsForCallInterest(readBuckets)
		specificStorageBuckets = storageReadSpecificFamilies(readBuckets)
	} else if e.currentBatchUsesPathLikeStorageInterest() {
		readBuckets = filterFileBatchStorageReadBucketsForCallInterest(readBuckets)
		specificStorageBuckets = storageReadSpecificFamilies(readBuckets)
	}
	for _, bucket := range sortedStringSet(readBuckets) {
		parts = append(parts, "storage-path="+bucket+":"+e.storagePathStateFingerprint(bucket))
	}
	readFamilies := e.storageReadFamiliesByCallable[key]
	if e.currentBatchName == "delete" {
		readFamilies = filterDeleteBatchStorageReadFamiliesForCallInterest(readFamilies, specificStorageBuckets, e.fileSinkRelevantUseOrders[key])
	} else if e.currentBatchName == "call" {
		readFamilies = filterCallBatchStorageReadFamiliesForCallInterest(readFamilies, specificStorageBuckets, rawReadBuckets)
	} else if e.currentBatchUsesPathLikeStorageInterest() {
		readFamilies = filterFileBatchStorageReadFamiliesForCallInterest(readFamilies, specificStorageBuckets)
	}
	for _, family := range sortedStringSet(readFamilies) {
		parts = append(parts, "storage-family="+family+":"+e.storageFamilyStateFingerprint(family))
	}

	staticReadPaths = e.staticReadPathsByCallable[key]
	staticReadRoots = e.staticReadRootsByCallable[key]
	if e.currentBatchUsesPathLikeStorageInterest() {
		staticReadPaths = filterFileRelevantStaticStateKeys(staticReadPaths)
		staticReadRoots = filterFileRelevantStaticStateKeys(staticReadRoots)
	}
	specificStaticPaths := map[string]bool{}
	for path := range staticReadPaths {
		root := structuralPathRoot(path)
		if path != "" && root != "" && path != root {
			specificStaticPaths[root] = true
		}
	}
	for _, path := range sortedStringSet(staticReadPaths) {
		parts = append(parts, "static-path="+path+":"+e.staticPathStateFingerprint(path))
	}
	for _, root := range sortedStringSet(staticReadRoots) {
		if specificStaticPaths[root] {
			continue
		}
		parts = append(parts, "static-root="+root+":"+e.staticRootStateFingerprint(root))
	}

	return hashStrings(parts)
}

func (e *engine) callableHasStandaloneSourceFindings(key string) bool {
	if key == "" {
		return false
	}
	if e.callableHasRecordRead(key) {
		return true
	}
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	return e.callableHasDirectRequestInput(c) ||
		e.callableHasEntrypointSourceParam(c) ||
		e.callableHasDirectCallSource(c) ||
		e.callableHasDirectSQLReadSource(c)
}

func (e *engine) callableHasDeleteRelevantStandaloneSourceFindings(key string) bool {
	if !e.callableHasStandaloneSourceFindings(key) {
		return false
	}
	if !e.callableHasRecordRead(key) {
		return true
	}
	if c, ok := e.callables[key]; ok &&
		e.callableHasDirectOutputSyntax(c) &&
		!e.callableHasDirectSink(c) &&
		!e.callableIsStorageWriter(key) &&
		!e.callableHasSupportedCrossRequestWriter(key) &&
		len(e.fileSinkRelevantUseOrders[key]) == 0 {
		return false
	}
	readBuckets := filterDeleteBatchStorageReadBucketsForCallInterest(e.storageReadBucketsByCallable[key], e.fileSinkRelevantUseOrders[key])
	if len(readBuckets) != 0 {
		return true
	}
	readFamilies := filterDeleteBatchStorageReadFamiliesForCallInterest(
		e.storageReadFamiliesByCallable[key],
		deleteStorageReadSpecificFamiliesForCallInterest(e.storageReadBucketsByCallable[key], e.fileSinkRelevantUseOrders[key]),
		e.fileSinkRelevantUseOrders[key],
	)
	if len(readFamilies) != 0 {
		return true
	}
	return len(e.storageReadBucketsByCallable[key]) == 0 && len(e.storageReadFamiliesByCallable[key]) == 0
}

func (e *engine) callableHasFileRelevantStandaloneSourceFindings(key string) bool {
	if !e.callableHasStandaloneSourceFindings(key) {
		return false
	}
	if !e.callableHasRecordRead(key) {
		return true
	}
	if len(e.storageReadBucketsByCallable[key]) == 0 && len(e.storageReadFamiliesByCallable[key]) == 0 {
		return true
	}
	readBuckets := filterFileBatchStorageReadBucketsForCallInterest(e.storageReadBucketsByCallable[key])
	if len(readBuckets) != 0 {
		return true
	}
	readFamilies := filterFileBatchStorageReadFamiliesForCallInterest(e.storageReadFamiliesByCallable[key], map[string]bool{})
	return len(readFamilies) != 0
}

func (e *engine) callableHasRecordReadOnlyStandaloneSource(key string) bool {
	if key == "" || !e.callableHasRecordRead(key) {
		return false
	}
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	return !e.callableHasDirectRequestInput(c) &&
		!e.callableHasEntrypointSourceParam(c) &&
		!e.callableHasDirectCallSource(c) &&
		!e.callableHasDirectSQLReadSource(c)
}

func summaryHasPersistentReadReturnSource(item summary) bool {
	for _, ref := range item.ReturnSourceOrigins {
		if ref.PersistentRead {
			return true
		}
	}
	for _, ref := range item.ReturnReceiverPaths {
		if ref.PersistentRead {
			return true
		}
	}
	for _, ref := range item.ReturnParamPaths {
		if ref.PersistentRead {
			return true
		}
	}
	return false
}

func (e *engine) callableHasPersistentReadOnlyStandaloneSourceSummary(key string, item summary) bool {
	if key == "" {
		return false
	}
	if e.callableHasRecordReadOnlyStandaloneSource(key) {
		return true
	}
	c, ok := e.callables[key]
	if !ok {
		return false
	}
	if e.callableHasDirectRequestInput(c) ||
		e.callableHasEntrypointSourceParam(c) ||
		e.callableHasDirectCallSource(c) ||
		e.callableHasDirectSQLReadSource(c) {
		return false
	}
	return summaryHasPersistentReadReturnSource(item)
}

func deleteStorageBucketRelevantToStandaloneReturn(bucket string) bool {
	root := structuralPathRoot(bucket)
	if root == "" {
		return true
	}
	if root == bucket {
		return deleteStorageFamilyRelevantToStandaloneReturn(root)
	}
	leaf := storagePathLeafField(bucket)
	if leaf == "" {
		return deleteStorageFamilyRelevantToStandaloneReturn(root)
	}
	return deleteStorageLeafLooksPathLike(leaf)
}

func deleteStorageBucketRelevantToCallInterest(bucket string, relevantOrders map[string]int) bool {
	if deleteStorageBucketRelevantToStandaloneReturn(bucket) {
		return true
	}
	if len(relevantOrders) == 0 {
		return false
	}
	return deleteStorageFamilyRelevantToCallInterest(structuralPathRoot(bucket), relevantOrders)
}

func deleteStorageFamilyRelevantToStandaloneReturn(family string) bool {
	switch fileStorageFamilyBaseName(family) {
	case "user_meta_value", "option_value", "transient_value":
		return false
	default:
		return true
	}
}

func deleteStorageFamilyRelevantToCallInterest(family string, relevantOrders map[string]int) bool {
	if deleteStorageFamilyRelevantToStandaloneReturn(family) {
		return true
	}
	if len(relevantOrders) == 0 {
		return false
	}
	switch fileStorageFamilyBaseName(family) {
	case "user_meta_value", "option_value", "transient_value":
		return true
	default:
		return false
	}
}

func fileStorageFamilyRelevantToStandaloneReturn(family string) bool {
	switch fileStorageFamilyBaseName(family) {
	case "user_meta_value", "option_value", "transient_value":
		return false
	default:
		return true
	}
}

func fileStorageFamilyBaseName(family string) string {
	base := structuralPathRoot(family)
	if idx := strings.IndexByte(base, '|'); idx != -1 {
		base = base[:idx]
	}
	return base
}

func fileStorageBucketRelevantToStandaloneReturn(bucket string) bool {
	root := structuralPathRoot(bucket)
	if root == "" {
		return true
	}
	if root == bucket {
		return fileStorageFamilyRelevantToStandaloneReturn(root)
	}
	leaf := storagePathLeafField(bucket)
	if leaf == "" {
		return fileStorageFamilyRelevantToStandaloneReturn(root)
	}
	return deleteStorageLeafLooksPathLike(leaf)
}

func (e *engine) clearStateFingerprints() {
	e.storageStateFingerprints = map[string]string{}
	e.storagePathStateFingerprints = map[string]string{}
	e.staticStateFingerprints = map[string]string{}
}

func batchNameForAllowedOps(ops map[string]struct{}) string {
	if len(ops) == 0 {
		return "all"
	}
	names := sortedStringSet(ops)
	return strings.Join(names, "+")
}
