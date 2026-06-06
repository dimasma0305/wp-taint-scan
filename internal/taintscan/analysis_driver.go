package taintscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dimasma0305/php-parser-go/parsetree"
)

func AnalyzeRoot(root string, excludes []string, workers int) (*Result, error) {
	return AnalyzeRootWithOptions(root, excludes, workers, Options{})
}

func AnalyzeRootWithOptions(root string, excludes []string, workers int, options Options) (*Result, error) {
	started := time.Now()
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	timingsEnabled := taintscanTimingsEnabled()
	phaseStart := time.Now()
	manifest, err := parsetree.BuildManifestForRoot(absRoot, excludes, workers)
	if err != nil {
		return nil, err
	}
	logTiming(timingsEnabled, "manifest", time.Since(phaseStart))
	phaseStart = time.Now()
	files, err := loadFiles(manifest, workers)
	if err != nil {
		return nil, err
	}
	logTiming(timingsEnabled, "load-files", time.Since(phaseStart))

	phaseStart = time.Now()
	base, err := buildBaseEngineForSinkOps(absRoot, files, options.AllowedSinkOps)
	if err != nil {
		return nil, err
	}
	logTiming(timingsEnabled, "build-engine", time.Since(phaseStart))
	phaseStart = time.Now()
	base.heapHardLimit = options.MemoryLimitBytes
	if base.heapHardLimit > 0 {
		stopSampler := base.startHeapSampler()
		defer stopSampler()
	}
	payload := runAnalysisBatches(base, options, timingsEnabled)
	logTiming(timingsEnabled, "engine-run", time.Since(phaseStart))
	logTiming(timingsEnabled, "total", time.Since(started))
	return &Result{
		Target:    absRoot,
		Manifest:  manifest,
		Payload:   payload,
		Callables: len(base.callables),
	}, nil
}

// startHeapSampler runs a background goroutine that samples HeapAlloc into the
// engine's atomic gauge a few times per second, so the hot analysis path reads
// memory pressure with a cheap atomic load instead of a per-callable
// stop-the-world runtime.ReadMemStats. Returns a stop function.
func (e *engine) startHeapSampler() func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(60 * time.Millisecond)
		defer ticker.Stop()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		e.heapGauge.Store(ms.HeapAlloc)
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				runtime.ReadMemStats(&ms)
				e.heapGauge.Store(ms.HeapAlloc)
			}
		}
	}()
	return func() { close(done) }
}

// underMemoryPressure reports whether the sampled heap exceeds the configured
// hard limit. Cheap (atomic load); used to abort in-flight callable analysis.
func (e *engine) underMemoryPressure() bool {
	return e.heapHardLimit > 0 && e.heapGauge != nil && e.heapGauge.Load() > e.heapHardLimit
}

type sinkOpBatch struct {
	name string
	ops  []string
}

func defaultSinkOpBatches() []sinkOpBatch {
	return []sinkOpBatch{
		{name: "delete", ops: []string{"delete"}},
		{name: "read", ops: []string{"read"}},
		{name: "open", ops: []string{"open"}},
		{name: "include", ops: []string{"include"}},
		{name: "write", ops: []string{"write"}},
		{name: "output", ops: []string{"output"}},
		{name: "sql", ops: []string{"sql"}},
		{name: "action", ops: []string{"action"}},
		{name: "call", ops: []string{"call"}},
	}
}

func runAnalysisBatches(base *engine, options Options, timingsEnabled bool) Payload {
	if len(options.AllowedSinkOps) != 0 {
		engine := cloneEngineForOptions(base, options)
		engine.timingsEnabled = timingsEnabled
		engine.currentBatchName = batchNameForAllowedOps(options.AllowedSinkOps)
		payload := engine.run()
		payload.Results = dedupeFinalFindings(payload.Results)
		sort.Slice(payload.Results, func(i int, j int) bool {
			if payload.Results[i].Path != payload.Results[j].Path {
				return payload.Results[i].Path < payload.Results[j].Path
			}
			if payload.Results[i].Start.Line != payload.Results[j].Start.Line {
				return payload.Results[i].Start.Line < payload.Results[j].Start.Line
			}
			if payload.Results[i].CheckID != payload.Results[j].CheckID {
				return payload.Results[i].CheckID < payload.Results[j].CheckID
			}
			if payload.Results[i].Extra.Trace.Source.Path != payload.Results[j].Extra.Trace.Source.Path {
				return payload.Results[i].Extra.Trace.Source.Path < payload.Results[j].Extra.Trace.Source.Path
			}
			if payload.Results[i].Extra.Trace.Source.Line != payload.Results[j].Extra.Trace.Source.Line {
				return payload.Results[i].Extra.Trace.Source.Line < payload.Results[j].Extra.Trace.Source.Line
			}
			return payload.Results[i].Extra.Trace.Callable < payload.Results[j].Extra.Trace.Callable
		})
		sort.Strings(payload.Errors)
		return payload
	}

	merged := Payload{}
	seenFindings := map[string]Finding{}
	seenErrors := map[string]struct{}{}
	for _, batch := range defaultSinkOpBatches() {
		batchOptions := options
		batchOptions.AllowedSinkOps = make(map[string]struct{}, len(batch.ops))
		for _, op := range batch.ops {
			batchOptions.AllowedSinkOps[op] = struct{}{}
		}
		engine := cloneEngineForOptions(base, batchOptions)
		engine.timingsEnabled = timingsEnabled
		engine.currentBatchName = batch.name
		batchStart := time.Now()
		payload := engine.run()
		if timingsEnabled {
			fmt.Fprintf(os.Stderr, "[taintscan] batch=%s findings=%d duration=%s\n", batch.name, len(payload.Results), time.Since(batchStart).Round(time.Millisecond))
		}
		for _, finding := range payload.Results {
			seenFindings[findingKey(finding)] = finding
		}
		for _, err := range payload.Errors {
			if _, ok := seenErrors[err]; ok {
				continue
			}
			seenErrors[err] = struct{}{}
			merged.Errors = append(merged.Errors, err)
		}
	}

	merged.Results = make([]Finding, 0, len(seenFindings))
	for _, finding := range seenFindings {
		merged.Results = append(merged.Results, finding)
	}
	merged.Results = dedupeFinalFindings(merged.Results)
	sort.Slice(merged.Results, func(i int, j int) bool {
		if merged.Results[i].Path != merged.Results[j].Path {
			return merged.Results[i].Path < merged.Results[j].Path
		}
		if merged.Results[i].Start.Line != merged.Results[j].Start.Line {
			return merged.Results[i].Start.Line < merged.Results[j].Start.Line
		}
		if merged.Results[i].CheckID != merged.Results[j].CheckID {
			return merged.Results[i].CheckID < merged.Results[j].CheckID
		}
		if merged.Results[i].Extra.Trace.Source.Path != merged.Results[j].Extra.Trace.Source.Path {
			return merged.Results[i].Extra.Trace.Source.Path < merged.Results[j].Extra.Trace.Source.Path
		}
		if merged.Results[i].Extra.Trace.Source.Line != merged.Results[j].Extra.Trace.Source.Line {
			return merged.Results[i].Extra.Trace.Source.Line < merged.Results[j].Extra.Trace.Source.Line
		}
		return merged.Results[i].Extra.Trace.Callable < merged.Results[j].Extra.Trace.Callable
	})
	sort.Strings(merged.Errors)
	return merged
}

func findingKey(f Finding) string {
	parts := []string{
		f.CheckID,
		f.Path,
		fmt.Sprintf("%d", f.Start.Line),
		f.Extra.Trace.Source.Path,
		fmt.Sprintf("%d", f.Extra.Trace.Source.Line),
		f.Extra.Trace.Callable,
	}
	return strings.Join(parts, "|")
}

func dedupeFinalFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	if len(findings) == 1 {
		if shouldSuppressFinalFinding(findings[0]) {
			return nil
		}
		return findings
	}
	merged := make(map[string]Finding, len(findings))
	collapsedSiteKeys := make(map[string]string, len(findings))
	order := make([]string, 0, len(findings))
	for _, finding := range findings {
		key := finalFindingKey(finding)
		if shouldCollapseFindingSources(finding.CheckID) {
			siteKeys := append([]string{collapsedFindingSourceSiteKey(finding)}, collapsedFindingAlternateSiteKeys(finding)...)
			mergedByAlias := false
			for _, siteKey := range siteKeys {
				if aliasKey, ok := collapsedSiteKeys[siteKey]; ok && shouldCollapseVisibleCallablesAtFindingSite(finding) {
					merged[aliasKey] = mergeFindings(merged[aliasKey], finding)
					for _, k := range siteKeys {
						collapsedSiteKeys[k] = aliasKey
					}
					mergedByAlias = true
					break
				}
				if normalizedFindingCallable(finding.Extra.Trace.Callable) == "" {
					if aliasKey, ok := collapsedSiteKeys[siteKey]; ok {
						merged[aliasKey] = mergeFindings(merged[aliasKey], finding)
						for _, k := range siteKeys {
							collapsedSiteKeys[k] = aliasKey
						}
						mergedByAlias = true
						break
					}
				}
				if aliasKey, ok := collapsedSiteKeys[siteKey]; ok && aliasKey == "visible|"+siteKey+"|" {
					merged[key] = mergeFindings(merged[aliasKey], finding)
					delete(merged, aliasKey)
					for i := range order {
						if order[i] == aliasKey {
							order[i] = key
							break
						}
					}
					for _, k := range siteKeys {
						collapsedSiteKeys[k] = key
					}
					mergedByAlias = true
					break
				}
			}
			if mergedByAlias {
				continue
			}
			for _, siteKey := range siteKeys {
				collapsedSiteKeys[siteKey] = key
			}
		}
		if existing, ok := merged[key]; ok {
			merged[key] = mergeFindings(existing, finding)
			continue
		}
		merged[key] = finding
		order = append(order, key)
	}
	if len(order) == len(findings) {
		unchanged := true
		for _, finding := range findings {
			if shouldSuppressFinalFinding(finding) {
				unchanged = false
				break
			}
		}
		if unchanged {
			return findings
		}
	}
	out := make([]Finding, 0, len(order))
	for _, key := range order {
		finding := merged[key]
		if shouldSuppressFinalFinding(finding) {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func (e *engine) run() Payload {
	if !e.instrumentationEnabled {
		return e.runWithContext(context.Background())
	}
	labels := pprof.Labels("batch", e.currentBatchName)
	ctx := pprof.WithLabels(context.Background(), labels)
	var payload Payload
	pprof.Do(ctx, labels, func(ctx context.Context) {
		trace.WithRegion(ctx, "taintscan.batch", func() {
			payload = e.runWithContext(ctx)
		})
	})
	return payload
}

func (e *engine) runWithContext(ctx context.Context) Payload {
	type analysisResult struct {
		key              string
		next             summary
		duration         time.Duration
		inputFingerprint string
		reused           bool
	}
	type analysisJob struct {
		key              string
		inputFingerprint string
		reuse            bool
	}
	maxWorkers := runtime.GOMAXPROCS(0)
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	relevantKeys := e.relevantCallOrder()
	pending := append([]string(nil), relevantKeys...)
	maxPasses := e.maxPasses
	lastFindingFingerprint := ""
	stableFindingPasses := 0
	sqlOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("sql")
	callOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call")
	outputOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("output")
	surfaceOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("surface")
	if maxPasses <= 0 {
		maxPasses = 20
		if sqlOnlyMode {
			maxPasses = 16
		}
	}
	for pass := 0; pass < maxPasses; pass++ {
		if len(pending) == 0 {
			break
		}
		e.resetPassWarmSummaryCache()
		passNum := pass + 1
		passStart := time.Now()
		changed := false
		changedCount := 0
		reusedCount := 0
		changedKeys := make([]string, 0)
		callerChangedKeys := make([]string, 0)
		beforeStorage := e.storage
		beforeStoragePaths := e.storagePaths
		beforeStaticProps := e.staticProps
		smallPendingDebug := e.timingsEnabled && len(pending) > 0 && len(pending) <= 10
		pendingJobs := make([]analysisJob, 0, len(pending))
		scheduledReuse := 0
		for _, key := range pending {
			inputFingerprint := e.callableSummaryInputFingerprint(key)
			previousFingerprint, hasPreviousFingerprint := e.summaryInputFingerprints[key]
			reuse := hasPreviousFingerprint && previousFingerprint == inputFingerprint
			if reuse {
				scheduledReuse++
			}
			pendingJobs = append(pendingJobs, analysisJob{
				key:              key,
				inputFingerprint: inputFingerprint,
				reuse:            reuse,
			})
		}
		if e.timingsEnabled {
			fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d scheduled_reuse=%d scheduled_analyze=%d\n", e.currentBatchName, passNum, scheduledReuse, len(pendingJobs)-scheduledReuse)
			reuseSample := make([]string, 0, 5)
			analyzeSample := make([]string, 0, 5)
			for _, job := range pendingJobs {
				if job.reuse {
					if len(reuseSample) < 5 {
						reuseSample = append(reuseSample, job.key)
					}
					continue
				}
				if len(analyzeSample) < 5 {
					analyzeSample = append(analyzeSample, job.key)
				}
				if len(reuseSample) >= 5 && len(analyzeSample) >= 5 {
					break
				}
			}
			if len(reuseSample) != 0 {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d scheduled_reuse_sample=%s\n", e.currentBatchName, passNum, strings.Join(reuseSample, ", "))
			}
			if len(analyzeSample) != 0 {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d scheduled_analyze_sample=%s\n", e.currentBatchName, passNum, strings.Join(analyzeSample, ", "))
			}
		}
		workers := boundedAnalysisWorkers(maxWorkers, len(pending))
		if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call") {
			workers = 1
		}
		if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("output") {
			workers = 1
		}
		if len(e.allowedSinkOps) == 1 && e.allowsSinkOp("action") && workers > 2 {
			workers = 2
		}
		if sqlOnlyMode && len(pending) >= 128 && workers < 4 && maxWorkers >= 4 {
			workers = 4
		}
		results := make(chan analysisResult, workers)
		jobs := make(chan analysisJob, len(pending))
		var storageChanged bool
		var storagePathsChanged bool
		var staticPropsChanged bool
		var recomputeDuration time.Duration
		runPass := func(passCtx context.Context) {
			defer e.clearPassWarmSummaryCache()
			changedSummaries := map[string]summary{}
			changedDependencyFingerprints := map[string]string{}
			nextInputFingerprints := map[string]string{}
			summaryChangeKinds := map[string]int{}
			storageRecomputeNeeded := false
			staticRecomputeNeeded := false
			analyzeJob := func(job analysisJob) analysisResult {
				key := job.key
				if smallPendingDebug {
					fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d start-callable=%s\n", e.currentBatchName, passNum, key)
				}
				if job.reuse {
					return analysisResult{
						key:              key,
						next:             e.summaries[key],
						duration:         0,
						inputFingerprint: job.inputFingerprint,
						reused:           true,
					}
				}
				callableStart := time.Now()
				var next summary
				if e.instrumentationEnabled {
					callableLabels := pprof.Labels("batch", e.currentBatchName, "pass", strconv.Itoa(passNum), "callable", key)
					pprof.Do(passCtx, callableLabels, func(callableCtx context.Context) {
						trace.WithRegion(callableCtx, "taintscan.callable", func() {
							next = e.analyzeCallable(e.callables[key])
						})
					})
				} else {
					next = e.analyzeCallable(e.callables[key])
				}
				duration := time.Since(callableStart)
				if smallPendingDebug {
					fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d finish-callable=%s duration=%s\n", e.currentBatchName, passNum, key, duration.Round(time.Millisecond))
				}
				return analysisResult{
					key:              key,
					next:             next,
					duration:         duration,
					inputFingerprint: job.inputFingerprint,
					reused:           false,
				}
			}
			handleResult := func(result analysisResult) {
				key := result.key
				next := result.next
				callableDuration := result.duration
				nextInputFingerprints[key] = result.inputFingerprint
				if result.reused {
					reusedCount++
					return
				}
				if !reflect.DeepEqual(e.summaries[key], next) {
					previous := e.summaries[key]
					previousDependencyFingerprint := e.summaryFingerprint(key)
					nextDependencyFingerprint := summaryDependencyFingerprint(next)
					if e.timingsEnabled {
						summaryChangeKinds = mergeCountMaps(summaryChangeKinds, summaryDependencyChangeCounts(previous, next))
					}
					if !surfaceOnlyMode && !storageRecomputeNeeded && (!reflect.DeepEqual(previous.StorageWrites, next.StorageWrites) || !reflect.DeepEqual(previous.StoragePathWrites, next.StoragePathWrites)) {
						storageRecomputeNeeded = true
					}
					if !staticRecomputeNeeded && !reflect.DeepEqual(previous.StaticWrites, next.StaticWrites) {
						staticRecomputeNeeded = true
					}
					changedSummaries[key] = next
					changedDependencyFingerprints[key] = nextDependencyFingerprint
					changed = true
					changedCount++
					changedKeys = append(changedKeys, key)
					if previousDependencyFingerprint != nextDependencyFingerprint {
						callerChangedKeys = append(callerChangedKeys, key)
					}
				}
				if e.timingsEnabled && callableDuration >= 500*time.Millisecond {
					fmt.Fprintf(os.Stderr, "[taintscan] batch=%s slow-callable pass=%d callable=%s duration=%s\n", e.currentBatchName, passNum, key, callableDuration.Round(time.Millisecond))
				}
			}
			if workers == 1 {
				for _, job := range pendingJobs {
					handleResult(analyzeJob(job))
				}
			} else {
				var wg sync.WaitGroup
				for worker := 0; worker < workers; worker++ {
					wg.Add(1)
					go func(passCtx context.Context) {
						defer wg.Done()
						for job := range jobs {
							results <- analyzeJob(job)
						}
					}(passCtx)
				}
				go func() {
					wg.Wait()
					close(results)
				}()
				for _, job := range pendingJobs {
					jobs <- job
				}
				close(jobs)
				for result := range results {
					handleResult(result)
				}
			}
			for _, key := range changedKeys {
				next, ok := changedSummaries[key]
				if !ok {
					continue
				}
				e.summaries[key] = next
				e.summaryFingerprints[key] = changedDependencyFingerprints[key]
			}
			for key, fingerprint := range nextInputFingerprints {
				e.summaryInputFingerprints[key] = fingerprint
			}
			recomputeStart := time.Now()
			if storageRecomputeNeeded {
				e.recomputeGlobalStorage()
			}
			if staticRecomputeNeeded {
				e.recomputeGlobalStaticProps()
			}
			recomputeDuration = time.Since(recomputeStart)
			if storageRecomputeNeeded {
				storageChanged = !reflect.DeepEqual(beforeStorage, e.storage)
				storagePathsChanged = !reflect.DeepEqual(beforeStoragePaths, e.storagePaths)
			}
			if staticRecomputeNeeded {
				staticPropsChanged = !reflect.DeepEqual(beforeStaticProps, e.staticProps)
			}
			if storageChanged {
				changed = true
			}
			if storagePathsChanged {
				changed = true
			}
			if staticPropsChanged {
				changed = true
			}
			if storageChanged || storagePathsChanged || staticPropsChanged {
				e.clearStateFingerprints()
			}
			if e.timingsEnabled {
				if changes := topCountEntries(summaryChangeKinds, 8); len(changes) > 0 {
					fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d summary-change-kinds=%s\n", e.currentBatchName, passNum, strings.Join(changes, ", "))
				}
			}
		}
		if e.instrumentationEnabled {
			passLabels := pprof.Labels("batch", e.currentBatchName, "pass", strconv.Itoa(passNum))
			pprof.Do(ctx, passLabels, func(passCtx context.Context) {
				trace.WithRegion(passCtx, "taintscan.pass", func() {
					runPass(passCtx)
				})
			})
		} else {
			runPass(ctx)
		}
		if e.timingsEnabled {
			fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d duration=%s changed=%t changed_callables=%d reused_summaries=%d recompute=%s callables=%d relevant=%d pending=%d storage_changed=%t storage_paths_changed=%t static_changed=%t\n", e.currentBatchName, passNum, time.Since(passStart).Round(time.Millisecond), changed, changedCount, reusedCount, recomputeDuration.Round(time.Millisecond), len(e.callOrder), len(relevantKeys), len(pending), storageChanged, storagePathsChanged, staticPropsChanged)
		}
		if !changed {
			stalePendingSet, staleCount := e.collectStaleRelevantCallables(relevantKeys, nil)
			if staleCount == 0 {
				break
			}
			pending = pending[:0]
			for _, key := range relevantKeys {
				if _, ok := stalePendingSet[key]; ok {
					pending = append(pending, key)
				}
			}
			if e.timingsEnabled {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d stale-replay=%d\n", e.currentBatchName, passNum, staleCount)
			}
			continue
		}
		nextPendingSet := map[string]struct{}{}
		for _, key := range callerChangedKeys {
			e.expandPendingWithCallers(nextPendingSet, key)
		}
		callerPendingCount := len(nextPendingSet)
		changedStorageFamilies := map[string]struct{}{}
		if storageChanged {
			changedStorageFamilies = changedMapKeys(beforeStorage, e.storage)
		}
		changedStorageFamilyCount := len(changedStorageFamilies)
		changedStoragePathCount := 0
		changedStoragePathFamilies := map[string]struct{}{}
		changedStoragePathsByFamily := map[string]map[string]struct{}{}
		storageRootCounts := map[string]int{}
		for family := range changedStorageFamilies {
			storageRootCounts["storage:"+family]++
		}
		changedStoragePaths := map[string]struct{}{}
		if storagePathsChanged {
			changedStoragePaths = changedMapKeys(beforeStoragePaths, e.storagePaths)
			for path := range changedStoragePaths {
				changedStoragePathCount++
				root := structuralPathRoot(path)
				if root != "" {
					changedStoragePathFamilies[root] = struct{}{}
					familyPaths := changedStoragePathsByFamily[root]
					if familyPaths == nil {
						familyPaths = map[string]struct{}{}
						changedStoragePathsByFamily[root] = familyPaths
					}
					familyPaths[path] = struct{}{}
					storageRootCounts["storage:"+root]++
				}
				if field := databaseTableColumnFieldForPath(path); field != "" {
					changedStoragePathFamilies[field] = struct{}{}
					storageRootCounts["storage:"+field]++
				}
				if !e.shouldExpandStoragePathReadersForChangedPath(path) {
					continue
				}
				for key := range e.storagePathReadersByExact[path] {
					e.expandPendingWithCallers(nextPendingSet, key)
				}
				bucket := storageStablePathBucket(path)
				for key := range e.storagePathReadersByBucket[bucket] {
					e.expandPendingWithCallers(nextPendingSet, key)
				}
			}
			if e.timingsEnabled && len(changedStoragePaths) > 0 && len(changedStoragePaths) <= 5 {
				paths := sortedStringSet(changedStoragePaths)
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d changed_storage_paths=%s\n", e.currentBatchName, pass+1, strings.Join(paths, ", "))
			}
		}
		storagePathPendingCount := len(nextPendingSet)
		for family := range changedStorageFamilies {
			if _, ok := changedStoragePathFamilies[family]; ok {
				continue
			}
			for key := range e.storageBaseReadersByFamily[family] {
				e.expandPendingWithCallers(nextPendingSet, key)
			}
		}
		for family := range changedStoragePathFamilies {
			if !e.shouldExpandStorageBaseReadersForChangedPathFamily(family, changedStoragePathsByFamily[family]) {
				continue
			}
			for key := range e.storageBaseReadersByFamily[family] {
				e.expandPendingWithCallers(nextPendingSet, key)
			}
		}
		storagePendingCount := len(nextPendingSet)
		changedStaticKeyCount := 0
		staticRootCounts := map[string]int{}
		changedStaticPaths := map[string]struct{}{}
		if staticPropsChanged {
			changedStaticPaths = changedMapKeys(beforeStaticProps, e.staticProps)
			for path := range changedStaticPaths {
				changedStaticKeyCount++
				root := structuralPathRoot(path)
				if root == "" {
					continue
				}
				staticRootCounts["static:"+root]++
				if root == path {
					for key := range e.staticBaseReadersByRoot[root] {
						e.expandPendingWithCallers(nextPendingSet, key)
					}
					continue
				}
				for key := range e.staticPathReadersByExact[path] {
					e.expandPendingWithCallers(nextPendingSet, key)
				}
				bucket := staticPathInvalidationBucket(path)
				for key := range e.staticPathReadersByBucket[bucket] {
					e.expandPendingWithCallers(nextPendingSet, key)
				}
			}
		}
		staticPendingCount := len(nextPendingSet)
		nextPending := make([]string, 0, len(nextPendingSet))
		for _, key := range relevantKeys {
			if _, ok := nextPendingSet[key]; ok {
				nextPending = append(nextPending, key)
			}
		}
		staleInputCount := 0
		staleOnlyMode := len(nextPending) == 0 || (!storageChanged && !storagePathsChanged && !staticPropsChanged && len(callerChangedKeys) == 0)
		if staleOnlyMode {
			stalePendingSet, staleCount := e.collectStaleRelevantCallables(relevantKeys, nextPendingSet)
			if staleCount > 0 {
				staleInputCount = staleCount
				nextPendingSet = stalePendingSet
				nextPending = nextPending[:0]
				for _, key := range relevantKeys {
					if _, ok := nextPendingSet[key]; ok {
						nextPending = append(nextPending, key)
					}
				}
			}
		}
		pending = nextPending
		findingFingerprint := e.sourceFindingFingerprint()
		if e.timingsEnabled {
			displayFingerprint := findingFingerprint
			if displayFingerprint != "" {
				if len(displayFingerprint) > 12 {
					displayFingerprint = displayFingerprint[:12]
				}
			}
			fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d invalidation changed_keys=%d storage_families=%d storage_paths=%d static_keys=%d stale_inputs=%d next_pending=%d findings_fp=%s\n", e.currentBatchName, pass+1, len(changedKeys), changedStorageFamilyCount, changedStoragePathCount, changedStaticKeyCount, staleInputCount, len(pending), displayFingerprint)
			fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d pending-sources caller=%d storage-path=%d storage-family=%d static=%d\n", e.currentBatchName, pass+1, callerPendingCount, storagePathPendingCount, storagePendingCount, staticPendingCount)
			if len(pending) > 0 && len(pending) <= 10 {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d pending_callables=%s\n", e.currentBatchName, pass+1, strings.Join(pending, ", "))
			}
			if roots := topCountEntries(mergeCountMaps(storageRootCounts, staticRootCounts), 5); len(roots) > 0 {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d hot-roots=%s\n", e.currentBatchName, pass+1, strings.Join(roots, ", "))
			}
			if contributors := e.topSummaryContributors(changedKeys, 5); len(contributors) > 0 {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s pass=%d hot-summaries=%s\n", e.currentBatchName, pass+1, strings.Join(contributors, ", "))
			}
		}
		if findingFingerprint != "" && findingFingerprint == lastFindingFingerprint {
			stableFindingPasses++
		} else {
			stableFindingPasses = 0
		}
		lastFindingFingerprint = findingFingerprint
		if staleInputCount > 0 {
			stableFindingPasses = 0
		}
		if sqlOnlyMode && findingFingerprint != "" && stableFindingPasses >= 3 {
			if e.timingsEnabled {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s early-stop=stable-sql-findings pass=%d\n", e.currentBatchName, passNum)
			}
			break
		}
		if callOnlyMode && findingFingerprint != "" && stableFindingPasses >= 2 {
			if e.timingsEnabled {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s early-stop=stable-call-findings pass=%d\n", e.currentBatchName, passNum)
			}
			break
		}
		if outputOnlyMode && findingFingerprint != "" && stableFindingPasses >= 2 {
			if e.timingsEnabled {
				fmt.Fprintf(os.Stderr, "[taintscan] batch=%s early-stop=stable-output-findings pass=%d\n", e.currentBatchName, passNum)
			}
			break
		}
		if staleInputCount == 0 && !storageChanged && !storagePathsChanged && !staticPropsChanged && len(callerChangedKeys) == 0 {
			if stableFindingPasses >= 1 {
				if e.timingsEnabled {
					fmt.Fprintf(os.Stderr, "[taintscan] batch=%s early-stop=stable-findings pass=%d\n", e.currentBatchName, passNum)
				}
				break
			}
		} else if !sqlOnlyMode && !callOnlyMode && !outputOnlyMode {
			stableFindingPasses = 0
		}
	}

	mergedRecords := map[string]findingRecord{}
	for _, key := range e.callOrder {
		for _, record := range e.summaries[key].SourceFindings {
			recordKey := findingRecordKey(record)
			if existing, ok := mergedRecords[recordKey]; ok {
				record.Context = mergeFlowContext(existing.Context, record.Context)
				record.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, record.StoredWriteContext)
			}
			mergedRecords[recordKey] = record
		}
	}
	records := make([]findingRecord, 0, len(mergedRecords))
	for _, record := range mergedRecords {
		records = append(records, record)
	}

	sort.Slice(records, func(i int, j int) bool {
		if records[i].Sink.Path != records[j].Sink.Path {
			return records[i].Sink.Path < records[j].Sink.Path
		}
		if records[i].Sink.Line != records[j].Sink.Line {
			return records[i].Sink.Line < records[j].Sink.Line
		}
		if records[i].RuleID != records[j].RuleID {
			return records[i].RuleID < records[j].RuleID
		}
		return records[i].Callable < records[j].Callable
	})

	results := make([]Finding, 0, len(records))
	for _, record := range records {
		var finding Finding
		finding.CheckID = record.RuleID
		finding.Path = filepath.Join(e.target, filepath.FromSlash(record.Sink.Path))
		finding.Start.Line = record.Sink.Line
		finding.Extra.Message = record.Message
		finding.Extra.Trace = Trace{
			Source:   record.Source,
			Sink:     record.Sink,
			Callable: record.Callable,
		}
		finding.Extra.Context = record.Context
		finding.Extra.StoredWriteContext = record.StoredWriteContext
		results = append(results, finding)
	}
	results = dedupeFinalFindings(results)
	return Payload{Results: results, Errors: []string{}}
}

func (e *engine) shouldExpandStorageBaseReadersForChangedPathFamily(family string, changedPaths map[string]struct{}) bool {
	if family == "" || len(changedPaths) == 0 {
		return true
	}
	if len(e.allowedSinkOps) != 1 {
		return true
	}
	sqlOnlyMode := e.allowsSinkOp("sql")
	fileOnlyMode := e.allowsSinkOp("read") || e.allowsSinkOp("open") || e.allowsSinkOp("write")
	deleteOnlyMode := e.allowsSinkOp("delete")
	callOnlyMode := e.allowsSinkOp("call")
	outputOnlyMode := e.allowsSinkOp("output")
	if deleteOnlyMode {
		relevantDeletePath := false
		for path := range changedPaths {
			if deleteBatchMetadataWildcardPathTooBroad(path) {
				continue
			}
			if deleteStorageBucketRelevantToStandaloneReturn(path) {
				relevantDeletePath = true
				break
			}
		}
		if !relevantDeletePath {
			return false
		}
		if supportsCrossRequestWriterSeeding(family) {
			return true
		}
	} else if callOnlyMode {
		// For call-only batch, wildcard-only metadata path changes are too broad to drive
		// base reader expansion. If all changed paths under this family are wildcard-only
		// metadata paths, skip expansion.
		allTooBroadWildcard := true
		for path := range changedPaths {
			if !deleteBatchMetadataWildcardPathTooBroad(path) {
				allTooBroadWildcard = false
				break
			}
		}
		if allTooBroadWildcard {
			return false
		}
		// Some non-wildcard path changed; expand family readers.
		return true
	} else if !sqlOnlyMode && !fileOnlyMode && !outputOnlyMode {
		return true
	}
	for path := range changedPaths {
		bucket := storageStablePathBucket(path)
		if bucket == "" {
			continue
		}
		if bucket == family || bucket == family+"[*]" {
			continue
		}
		return false
	}
	return true
}

func (e *engine) shouldExpandStoragePathReadersForChangedPath(path string) bool {
	if path == "" {
		return true
	}
	if len(e.allowedSinkOps) != 1 {
		return true
	}
	deleteOnly := e.allowsSinkOp("delete")
	callOnly := e.allowsSinkOp("call")
	if !deleteOnly && !callOnly {
		return true
	}
	if deleteBatchMetadataWildcardPathTooBroad(path) {
		return false
	}
	if deleteOnly {
		return deleteStorageBucketRelevantToStandaloneReturn(path)
	}
	return true
}

func deleteUserMetaPathSupportsReaderExpansion(path string) bool {
	if path == "" {
		return true
	}
	root := structuralPathRoot(path)
	if root != "user_meta_value" {
		return false
	}
	leaf := storagePathLeafField(path)
	if leaf == "" {
		return true
	}
	return deleteStorageLeafLooksPathLike(leaf)
}

func storagePathLeafField(path string) string {
	if path == "" {
		return ""
	}
	if end := strings.LastIndex(path, "]"); end != -1 {
		start := strings.LastIndex(path[:end], "[")
		if start != -1 && start+1 < end {
			leaf := strings.ToLower(strings.TrimSpace(path[start+1 : end]))
			if leaf != "" && leaf != "*" {
				return leaf
			}
		}
	}
	if dot := strings.LastIndex(path, "."); dot != -1 && dot+1 < len(path) {
		leaf := strings.ToLower(strings.TrimSpace(path[dot+1:]))
		if leaf != "" {
			return leaf
		}
	}
	return ""
}

func deleteStorageLeafLooksPathLike(leaf string) bool {
	if leaf == "" {
		return false
	}
	tokens := []string{
		"path",
		"file",
		"upload",
		"avatar",
		"image",
		"photo",
		"icon",
		"thumbnail",
		"attachment",
		"template",
		"directory",
		"dir",
		"tmp",
	}
	for _, token := range tokens {
		if strings.Contains(leaf, token) {
			return true
		}
	}
	return false
}

func (e *engine) collectStaleRelevantCallables(relevantKeys []string, pendingSet map[string]struct{}) (map[string]struct{}, int) {
	if len(relevantKeys) == 0 {
		return pendingSet, 0
	}
	if pendingSet == nil {
		pendingSet = map[string]struct{}{}
	}
	staleCount := 0
	for _, key := range relevantKeys {
		stored, ok := e.summaryInputFingerprints[key]
		if !ok {
			continue
		}
		if stored == e.callableSummaryInputFingerprint(key) {
			continue
		}
		if _, alreadyPending := pendingSet[key]; alreadyPending {
			continue
		}
		pendingSet[key] = struct{}{}
		staleCount++
	}
	return pendingSet, staleCount
}

func boundedAnalysisWorkers(maxWorkers int, pendingCount int) int {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if pendingCount < 1 {
		return 1
	}
	workers := maxWorkers
	if workers > pendingCount {
		workers = pendingCount
	}
	switch {
	case pendingCount >= 256 && workers > 2:
		workers = 2
	case pendingCount >= 128 && workers > 2:
		workers = 2
	}
	if workers < 1 {
		return 1
	}
	return workers
}

func (e *engine) sourceFindingFingerprint() string {
	keys := make([]string, 0)
	for _, key := range e.callOrder {
		for _, record := range e.summaries[key].SourceFindings {
			keys = append(keys, findingRecordKey(record))
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, "\n")
}

func (e *engine) allowsSinkOp(op string) bool {
	if len(e.allowedSinkOps) == 0 {
		return true
	}
	_, ok := e.allowedSinkOps[strings.ToLower(strings.TrimSpace(op))]
	return ok
}
