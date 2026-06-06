package taintscan

import (
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dimasma0305/php-parser-go/ast"
	"github.com/dimasma0305/php-parser-go/parsetree"
)

func TestGetOrComputePassWarmSummarySingleflightForWriteBatch(t *testing.T) {
	e := &engine{
		allowedSinkOps:          map[string]struct{}{"write": {}},
		passWarmSummaryCache:    map[string]summary{},
		passWarmSummaryInflight: map[string]chan struct{}{},
	}

	var computeCalls atomic.Int32
	start := make(chan struct{})
	const workers = 8

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			item := e.getOrComputePassWarmSummary("function::\\demo", func() summary {
				computeCalls.Add(1)
				<-start
				return summary{ReturnParams: []int{0}}
			})
			if len(item.ReturnParams) != 1 || item.ReturnParams[0] != 0 {
				t.Errorf("unexpected warmed summary: %#v", item)
			}
		}()
	}

	time.Sleep(20 * time.Millisecond)
	close(start)
	wg.Wait()

	if got := computeCalls.Load(); got != 1 {
		t.Fatalf("compute called %d times, want 1", got)
	}
}

func TestUsesFileWarmSummariesAllowsCombinedFileBatch(t *testing.T) {
	e := &engine{
		allowedSinkOps: map[string]struct{}{
			"delete": {},
			"open":   {},
			"read":   {},
			"write":  {},
		},
	}

	if !e.usesFileWarmSummaries() {
		t.Fatal("combined file-like batch should allow file warm summaries")
	}
}

func TestAnalyzeCallableWithWarmStackSkipsNonReturningHelperInCombinedFileBatch(t *testing.T) {
	helperKey := `function::\helper`
	e := &engine{
		allowedSinkOps: map[string]struct{}{
			"delete": {},
			"open":   {},
			"read":   {},
			"write":  {},
		},
		callables: map[string]callable{
			helperKey: {
				Key:   helperKey,
				Stmts: []ast.Node{&ast.StmtEcho{}},
			},
		},
	}

	got := e.analyzeCallableWithWarmStack(e.callables[helperKey], map[string]struct{}{`function::\caller`: {}})
	if !summaryHasNoEffects(got) {
		t.Fatalf("combined file batch should synthesize away non-returning helper summary, got %#v", got)
	}
}

func TestRelevantCallOrderSkipsNonReturningFileInertHelperInCombinedFileBatch(t *testing.T) {
	helperKey := `function::\helper`
	sinkKey := `function::\sink`
	e := &engine{
		allowedSinkOps: map[string]struct{}{
			"delete": {},
			"open":   {},
			"read":   {},
			"write":  {},
		},
		callOrder:         []string{helperKey, sinkKey},
		relevantCallables: map[string]struct{}{helperKey: {}, sinkKey: {}},
		callables: map[string]callable{
			helperKey: {
				Key:   helperKey,
				Stmts: []ast.Node{&ast.StmtEcho{}},
			},
			sinkKey: {
				Key: sinkKey,
				Stmts: []ast.Node{
					&ast.StmtExpression{
						Expr: &ast.ExprFuncCall{
							Name: &ast.Name{Name: "file_get_contents"},
							Args: []ast.Node{
								&ast.Arg{Value: &ast.ExprVariable{Name: "path"}},
							},
						},
					},
				},
			},
		},
	}

	if got := e.relevantCallOrder(); len(got) != 1 || got[0] != sinkKey {
		t.Fatalf("relevantCallOrder() = %#v, want only sink kept in combined file batch", got)
	}
}

func TestApplyPathStringToOriginsCapsDeepRelativeParamPath(t *testing.T) {
	path := strings.Repeat("[opt_name]", maxRelativeOriginPathSegments+6)
	origins := applyPathStringToOrigins(makeOriginSet(origin{kind: originParam, paramIdx: 0}), path, Location{})
	if len(origins) != 1 {
		t.Fatalf("origins len = %d, want 1", len(origins))
	}
	for _, item := range origins {
		if item.paramPath == path {
			t.Fatalf("deep relative path was not compacted: %q", item.paramPath)
		}
		if got := countStructuralSegments(item.paramPath); got != maxRelativeOriginPathSegments {
			t.Fatalf("segment count = %d, want %d for %q", got, maxRelativeOriginPathSegments, item.paramPath)
		}
	}
}

func countStructuralSegments(path string) int {
	count := 0
	for path != "" {
		_, rest, ok := nextPathSegment(path)
		if !ok {
			break
		}
		count++
		path = rest
	}
	return count
}

func TestSummaryForKeyLocallyComputesInflightWarmDependency(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "warm-inflight-helper.php"), `<?php
function helper_passthrough($value) {
    return $value;
}

function wrapper($value) {
    return helper_passthrough($value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := "function::\\helper_passthrough"
	wrapperKey := "function::\\wrapper"
	engine.relevantCallables[helperKey] = struct{}{}
	engine.passWarmSummaryInflight = map[string]chan struct{}{
		wrapperKey: make(chan struct{}),
		helperKey:  make(chan struct{}),
	}

	state := analysisState{
		engine:                  engine,
		current:                 engine.callables[wrapperKey],
		summaryWarmCache:        map[string]summary{},
		summaryWarmStack:        map[string]struct{}{wrapperKey: {}},
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}

	done := make(chan summary, 1)
	go func() {
		done <- state.summaryForKey(helperKey)
	}()

	select {
	case warmed := <-done:
		if summaryHasNoEffects(warmed) || len(warmed.ReturnParams) != 1 || warmed.ReturnParams[0] != 0 {
			t.Fatalf("summaryForKey() = %#v, want warmed passthrough summary", warmed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("summaryForKey blocked on inflight warm dependency")
	}
}

func TestAnalyzeCallableDropsUnreplayableReceiverFindingsForFunctionSummary(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "receiver-wrapper.php"), `<?php
class Demo {
    public function get_name() {
        return $this->profile['display_name'];
    }
}

function demo_instance() {
    return new Demo();
}

function wrapper() {
    echo demo_instance()->get_name();
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"
	engine.currentBatchName = "output"

	methodKey := `method::\Demo::get_name`
	wrapperKey := `function::\wrapper`
	methodSummary := engine.analyzeCallable(engine.callables[methodKey])
	if len(methodSummary.ReturnReceiverPaths) == 0 {
		t.Fatalf("method summary lost receiver return paths: %#v", methodSummary)
	}

	wrapperSummary := engine.analyzeCallable(engine.callables[wrapperKey])
	if len(wrapperSummary.ReceiverFindings) != 0 {
		t.Fatalf("wrapper summary kept unreplayable receiver findings: %#v", wrapperSummary.ReceiverFindings)
	}
}

func TestAnalyzeCallableDropsOutputSafePersistentReturnEffectsInOutputBatch(t *testing.T) {
	state := analysisState{
		engine: &engine{
			allowedSinkOps:   map[string]struct{}{"output": {}},
			currentBatchName: "output",
		},
		current: callable{Key: "function::\\helper"},
		returnValue: makeOriginSet(
			origin{
				kind:           originSource,
				source:         Location{Path: "demo.php", Line: 10},
				persistentRead: true,
				outputSafeHTML: true,
			},
			origin{
				kind:           originSource,
				source:         Location{Path: "demo.php", Line: 11},
				persistentRead: true,
			},
		),
	}

	filtered := state.filterCurrentBatchReturnOrigins(state.returnValue)
	if len(filtered) != 1 {
		t.Fatalf("filtered origins len = %d, want 1 (%#v)", len(filtered), filtered)
	}
	for _, item := range filtered {
		if item.outputSafeHTML {
			t.Fatalf("filtered origins kept output-safe item: %#v", item)
		}
		if !item.persistentRead {
			t.Fatalf("filtered origins lost persistent-read item: %#v", item)
		}
	}
}

func TestAnalyzeCallableCompactsActionDirectSinkSummaryToFindingContext(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-direct-sink.php"), `<?php
function save_setting($name, $value) {
    update_option($name, $value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "action"

	sum := engine.analyzeCallable(engine.callables[`function::\save_setting`])
	if len(sum.SourceFindings) == 0 && len(sum.ParamFindings) == 0 && len(sum.ReceiverFindings) == 0 {
		t.Fatalf("summary lost action findings: %#v", sum)
	}
	if len(sum.StorageWrites) != 0 || len(sum.StoragePathWrites) != 0 {
		t.Fatalf("summary kept action storage replay noise: %#v", sum)
	}
	if summaryHasReturnEffects(sum) {
		t.Fatalf("summary unexpectedly kept return effects: %#v", sum)
	}
}

func TestAnalyzeCallableKeepsActionDirectSinkReturnEffects(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-direct-sink-return.php"), `<?php
function save_setting_and_return($name, $value) {
    update_option($name, $value);
    return $value;
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "action"

	sum := engine.analyzeCallable(engine.callables[`function::\save_setting_and_return`])
	if !summaryHasReturnEffects(sum) {
		t.Fatalf("summary lost action return effects: %#v", sum)
	}
	if len(sum.StorageWrites) == 0 && len(sum.StoragePathWrites) == 0 {
		t.Fatalf("summary unexpectedly compacted action storage effects with returns: %#v", sum)
	}
}

func TestSummaryForCurrentCallFiltersOutputAssignedReturnPaths(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[safe]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[safe]": 2,
				},
			},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {
				{
					callee:       "function::\\helper",
					line:         10,
					order:        1,
					assignedRoot: "$value",
				},
			},
		},
		summaries: map[string]summary{
			"function::\\helper": {
				ReturnSources: []Location{{Path: "demo.php", Line: 1}},
				ReturnParamPaths: []paramPathRef{
					{Index: 0, Path: "[safe]"},
					{Index: 0, Path: "[danger]"},
				},
				ReturnPathWrites: map[string]taintSummary{
					"[safe]":   {Params: []int{0}},
					"[danger]": {Params: []int{0}},
				},
			},
		},
		summaryInputFingerprints: map[string]string{
			"function::\\helper": "done",
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\render"},
	}

	got := state.summaryForCurrentCall("function::\\helper", 10)
	if len(got.ReturnSources) != 0 {
		t.Fatalf("summaryForCurrentCall() kept redundant root return sources: %#v", got.ReturnSources)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[safe]" {
		t.Fatalf("summaryForCurrentCall() return param paths = %#v, want only [safe]", got.ReturnParamPaths)
	}
	if len(got.ReturnPathWrites) != 1 || got.ReturnPathWrites["[safe]"].Params[0] != 0 {
		t.Fatalf("summaryForCurrentCall() return path writes = %#v, want only [safe]", got.ReturnPathWrites)
	}
	if _, ok := got.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("summaryForCurrentCall() kept unused [danger] path: %#v", got.ReturnPathWrites)
	}
}

func TestSummaryForCurrentCallKeepsRootReturnsWithoutExplicitAssignedCoverage(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[safe]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[safe]": 2,
				},
			},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {
				{
					callee:       "function::\\helper",
					line:         10,
					order:        1,
					assignedRoot: "$value",
				},
			},
		},
		summaries: map[string]summary{
			"function::\\helper": {
				ReturnSources: []Location{{Path: "demo.php", Line: 1}},
			},
		},
		summaryInputFingerprints: map[string]string{
			"function::\\helper": "done",
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\render"},
	}

	got := state.summaryForCurrentCall("function::\\helper", 10)
	if len(got.ReturnSources) != 1 {
		t.Fatalf("summaryForCurrentCall() dropped root return sources without explicit path coverage: %#v", got.ReturnSources)
	}
}

func TestSummaryForCurrentCallCollapsesOutputAssignedReturnPathsToRootWithoutExplicitPathCoverage(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value": 2,
			},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {{
				callee:       "function::\\helper",
				dataCarrier:  true,
				line:         10,
				order:        1,
				assignedRoot: "$value",
			}},
		},
		summaries: map[string]summary{
			"function::\\helper": {
				ReturnPathWrites: map[string]taintSummary{
					"[safe]":   {Params: []int{0}},
					"[danger]": {Params: []int{0}},
				},
				StoragePathWrites: map[string]taintSummary{
					"option_value[user_login]": {
						SourceOrigins: []sourceOriginRef{{
							Location:       Location{Path: "demo.php", Line: 10},
							PersistentRead: true,
						}},
					},
				},
			},
		},
		summaryInputFingerprints: map[string]string{
			"function::\\helper": "done",
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\render"},
	}

	got := state.summaryForCurrentCall("function::\\helper", 10)
	if len(got.ReturnParams) != 1 || got.ReturnParams[0] != 0 {
		t.Fatalf("summaryForCurrentCall() return params = %#v, want [0]", got.ReturnParams)
	}
	if len(got.ReturnParamPaths) != 0 {
		t.Fatalf("summaryForCurrentCall() kept rootless param paths: %#v", got.ReturnParamPaths)
	}
	if len(got.ReturnPathWrites) != 0 {
		t.Fatalf("summaryForCurrentCall() kept rootless return path writes: %#v", got.ReturnPathWrites)
	}
	if len(got.StorageWrites) != 0 || len(got.StoragePathWrites) != 0 {
		t.Fatalf("summaryForCurrentCall() kept persistent-read storage writes after root collapse: %+v", got)
	}
}

func TestSummaryForCurrentCallFiltersFileAssignedReturnPaths(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"include": {}},
		currentBatchName: "include",
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[path]": 2,
			},
		},
		fileSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[path]": 2,
				},
			},
		},
		includeSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[path]": 2,
			},
		},
		includeSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[path]": 2,
				},
			},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {
				{
					callee:       "function::\\helper",
					line:         10,
					order:        1,
					assignedRoot: "$value",
				},
			},
		},
		summaries: map[string]summary{
			"function::\\helper": {
				ReturnSources: []Location{{Path: "demo.php", Line: 1}},
				ReturnParamPaths: []paramPathRef{
					{Index: 0, Path: "[path]"},
					{Index: 0, Path: "[danger]"},
				},
				ReturnPathWrites: map[string]taintSummary{
					"[path]":   {Params: []int{0}},
					"[danger]": {Params: []int{0}},
				},
			},
		},
		summaryInputFingerprints: map[string]string{
			"function::\\helper": "done",
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\render"},
	}

	got := state.summaryForCurrentCall("function::\\helper", 10)
	if len(got.ReturnSources) != 0 {
		t.Fatalf("summaryForCurrentCall() kept redundant root return sources for file batch: %#v", got.ReturnSources)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[path]" {
		t.Fatalf("summaryForCurrentCall() file return param paths = %#v, want only [path]", got.ReturnParamPaths)
	}
	if len(got.ReturnPathWrites) != 1 || got.ReturnPathWrites["[path]"].Params[0] != 0 {
		t.Fatalf("summaryForCurrentCall() file return path writes = %#v, want only [path]", got.ReturnPathWrites)
	}
	if _, ok := got.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("summaryForCurrentCall() kept unused [danger] file path: %#v", got.ReturnPathWrites)
	}
}

func TestAnalyzeRootOutputAssignedReturnReplaySkipsUnusedHelperPaths(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-assigned-return-projection.php"), `<?php
function helper() {
    return array(
        'safe' => 'ok',
        'danger' => $_GET['msg'],
    );
}
function render() {
    $value = helper();
    echo $value['safe'];
}
render();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected findings from unused helper return path: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootIncludeAssignedReturnReplaySkipsUnusedHelperPaths(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "include-assigned-return-projection.php"), `<?php
function helper() {
    return array(
        'path' => 'safe-template.php',
        'danger' => $_GET['template'],
    );
}
function render() {
    $value = helper();
    include $value['path'];
}
render();
`)
	writePHP(t, filepath.Join(root, "safe-template.php"), `<?php echo "ok";`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "include"
	renderKey := engine.lookupFunctionKey("", "render")
	helperKey := engine.lookupFunctionKey("", "helper")
	if renderKey == "" || helperKey == "" {
		t.Fatalf("missing render/helper keys: render=%q helper=%q", renderKey, helperKey)
	}
	if engine.fileSinkRelevantUsePaths[renderKey]["value"]["[path]"] == 0 {
		t.Fatalf("missing include assigned-return path interest: %#v", engine.fileSinkRelevantUsePaths[renderKey])
	}
	var helperCallLine int
	for _, site := range engine.callSiteEdges[renderKey] {
		if site.callee == helperKey && site.assignedRoot == "value" {
			helperCallLine = site.line
			break
		}
	}
	if helperCallLine == 0 {
		t.Fatalf("missing helper callsite edge: %#v", engine.callSiteEdges[renderKey])
	}
	state := analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	filtered := state.summaryForCurrentCall(helperKey, helperCallLine)
	if len(filtered.ReturnSources) != 0 {
		t.Fatalf("summaryForCurrentCall() kept include helper root return sources: %#v", filtered)
	}
	for _, ref := range filtered.ReturnParamPaths {
		if ref.Path == "[danger]" {
			t.Fatalf("summaryForCurrentCall() kept include helper [danger] path: %#v", filtered)
		}
	}
	if _, ok := filtered.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("summaryForCurrentCall() kept include helper [danger] write: %#v", filtered)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected findings from unused helper include return path: %#v", result.Payload.Results)
	}
}

func TestAnalyzeCallableCompactsOutputBooleanOnlySummary(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-boolean-summary-compaction.php"), `<?php
class Demo {
    public function is_private($user_id) {
        return get_option('secret_flag') === '1';
    }
    public function render() {
        if ($this->is_private(1)) {
            echo 'ok';
        }
    }
}
(new Demo())->render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"
	engine.currentBatchName = "output"

	key := engine.lookupMethodKey(`\Demo`, "is_private")
	if key == "" {
		t.Fatal("missing Demo::is_private key")
	}
	sum := engine.analyzeCallable(engine.callables[key])
	if !summaryHasNoEffects(sum) {
		t.Fatalf("boolean-only output helper summary should be empty, got %#v", sum)
	}
}

func TestAnalyzeCallableCompactsOutputAssignedPathSummary(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		relevantCallables: map[string]struct{}{
			"function::\\render": {},
			"function::\\helper": {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"function::\\helper": {"function::\\render": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {{
				callee:       "function::\\helper",
				order:        1,
				assignedRoot: "$value",
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[safe]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[safe]": 2,
				},
			},
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}
	sum := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
		ReturnParamPaths: []paramPathRef{
			{Index: 0, Path: "[safe]"},
			{Index: 0, Path: "[danger]"},
		},
		ReturnPathWrites: map[string]taintSummary{
			"[safe]":   {Params: []int{0}},
			"[danger]": {Params: []int{0}},
		},
	}

	allowed, ok := state.currentAssignedReturnPathInterest(sum)
	if !ok {
		t.Fatal("currentAssignedReturnPathInterest() did not detect assigned-path-only output use")
	}
	got := filterSummaryForAssignedReturnReplay(sum, allowed)
	if len(got.ReturnSources) != 0 {
		t.Fatalf("assigned-path output helper summary kept root returns: %#v", got.ReturnSources)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[safe]" {
		t.Fatalf("assigned-path output helper summary paths = %#v, want only [safe]", got.ReturnParamPaths)
	}
	if len(got.ReturnPathWrites) != 1 {
		t.Fatalf("assigned-path output helper summary writes = %#v, want one path", got.ReturnPathWrites)
	}
	if _, ok := got.ReturnPathWrites["[safe]"]; !ok {
		t.Fatalf("assigned-path output helper summary dropped demanded [safe] path: %#v", got.ReturnPathWrites)
	}
	if _, ok := got.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("assigned-path output helper summary kept unused [danger] path: %#v", got.ReturnPathWrites)
	}
}

func TestCurrentAssignedReturnPathInterestAllowsFileBatchExplicitPathsWithSourceFindings(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"include": {}},
		currentBatchName: "include",
		relevantCallables: map[string]struct{}{
			"function::\\render": {},
			"function::\\helper": {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"function::\\helper": {"function::\\render": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {{
				callee:       "function::\\helper",
				order:        1,
				assignedRoot: "$value",
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[path]": 2,
			},
		},
		fileSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[path]": 2,
				},
			},
		},
		includeSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[path]": 2,
			},
		},
		includeSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[path]": 2,
				},
			},
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}
	sum := summary{
		SourceFindings: []findingRecord{{
			RuleID: "path-transversal",
			Sink:   Location{Path: "demo.php", Line: 20},
		}},
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
		ReturnParamPaths: []paramPathRef{
			{Index: 0, Path: "[path]"},
			{Index: 0, Path: "[danger]"},
		},
		ReturnPathWrites: map[string]taintSummary{
			"[path]":   {Params: []int{0}},
			"[danger]": {Params: []int{0}},
		},
	}

	allowed, ok := state.currentAssignedReturnPathInterest(sum)
	if !ok {
		t.Fatal("currentAssignedReturnPathInterest() did not allow file-batch explicit return paths with source findings")
	}
	got := filterSummaryForAssignedReturnReplayWithRootDrop(sum, allowed, true)
	if len(got.ReturnSources) != 0 {
		t.Fatalf("file-batch assigned return replay kept root return sources: %#v", got.ReturnSources)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[path]" {
		t.Fatalf("file-batch assigned return replay paths = %#v, want only [path]", got.ReturnParamPaths)
	}
	if _, ok := got.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("file-batch assigned return replay kept unused [danger] path: %#v", got.ReturnPathWrites)
	}
	if len(got.SourceFindings) != 1 {
		t.Fatalf("file-batch assigned return replay should keep standalone source findings for direct handling: %#v", got.SourceFindings)
	}
}

func TestCurrentAssignedReturnPathInterestAllowsCombinedFileBatchExplicitPathsWithSourceFindings(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{
			"delete": {},
			"open":   {},
			"read":   {},
			"write":  {},
		},
		currentBatchName: "delete+open+read+write",
		relevantCallables: map[string]struct{}{
			"function::\\render": {},
			"function::\\helper": {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"function::\\helper": {"function::\\render": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {{
				callee:       "function::\\helper",
				order:        1,
				assignedRoot: "$value",
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[path]": 2,
			},
		},
		fileSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[path]": 2,
				},
			},
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}
	sum := summary{
		SourceFindings: []findingRecord{{
			RuleID: "path-transversal",
			Sink:   Location{Path: "demo.php", Line: 20},
		}},
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
		ReturnParamPaths: []paramPathRef{
			{Index: 0, Path: "[path]"},
			{Index: 0, Path: "[danger]"},
		},
		ReturnPathWrites: map[string]taintSummary{
			"[path]":   {Params: []int{0}},
			"[danger]": {Params: []int{0}},
		},
	}

	allowed, ok := state.currentAssignedReturnPathInterest(sum)
	if !ok {
		t.Fatal("currentAssignedReturnPathInterest() did not allow combined file-batch explicit return paths with source findings")
	}
	got := filterSummaryForAssignedReturnReplayWithRootDrop(sum, allowed, true)
	if len(got.ReturnSources) != 0 {
		t.Fatalf("combined file-batch assigned return replay kept root return sources: %#v", got.ReturnSources)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[path]" {
		t.Fatalf("combined file-batch assigned return replay paths = %#v, want only [path]", got.ReturnParamPaths)
	}
	if _, ok := got.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("combined file-batch assigned return replay kept unused [danger] path: %#v", got.ReturnPathWrites)
	}
	if len(got.SourceFindings) != 1 {
		t.Fatalf("combined file-batch assigned return replay should keep standalone source findings for direct handling: %#v", got.SourceFindings)
	}
}

func TestCurrentAssignedReturnPathInterestKeepsOutputBatchStrictWhenSourceFindingsPresent(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		relevantCallables: map[string]struct{}{
			"function::\\render": {},
			"function::\\helper": {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"function::\\helper": {"function::\\render": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {{
				callee:       "function::\\helper",
				order:        1,
				assignedRoot: "$value",
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[safe]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[safe]": 2,
				},
			},
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}
	sum := summary{
		SourceFindings: []findingRecord{{
			RuleID: "stored-xss",
			Sink:   Location{Path: "demo.php", Line: 20},
		}},
		ReturnParamPaths: []paramPathRef{{Index: 0, Path: "[safe]"}},
		ReturnPathWrites: map[string]taintSummary{
			"[safe]": {Params: []int{0}},
		},
	}

	if _, ok := state.currentAssignedReturnPathInterest(sum); ok {
		t.Fatal("currentAssignedReturnPathInterest() should keep output batches strict when source findings are present")
	}
}

func TestCurrentAssignedReturnPathInterestAllowsOutputBatchWithPersistentReadStorageEffects(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		relevantCallables: map[string]struct{}{
			"function::\\render": {},
			"function::\\helper": {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"function::\\helper": {"function::\\render": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\render": {{
				callee:       "function::\\helper",
				order:        1,
				assignedRoot: "$value",
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\render": {
				"$value[safe]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\render": {
				"$value": {
					"[safe]": 2,
				},
			},
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}
	sum := summary{
		ReturnSources:       []Location{{Path: "demo.php", Line: 10}},
		ReturnSourceOrigins: []sourceOriginRef{{Location: Location{Path: "demo.php", Line: 10}, PersistentRead: true}},
		ReturnParamPaths:    []paramPathRef{{Index: 0, Path: "[safe]"}},
		ReturnPathWrites: map[string]taintSummary{
			"[safe]": {Params: []int{0}},
		},
		StorageWrites: map[string]taintSummary{
			"option_value": {
				SourceOrigins: []sourceOriginRef{{
					Location:       Location{Path: "db.php", Line: 20},
					PersistentRead: true,
				}},
			},
		},
	}

	allowed, ok := state.currentAssignedReturnPathInterest(sum)
	if !ok {
		t.Fatal("currentAssignedReturnPathInterest() did not allow output batch with only persistent-read storage effects")
	}
	if _, ok := allowed["[safe]"]; !ok {
		t.Fatalf("allowed return paths = %#v, want [safe]", allowed)
	}
	if !state.shouldDropAssignedReturnRoots(sum) {
		t.Fatal("shouldDropAssignedReturnRoots() did not enable output root-drop for persistent-read storage helper")
	}
	got := filterSummaryForAssignedReturnReplayWithRootDrop(sum, allowed, state.shouldDropAssignedReturnRoots(sum))
	if len(got.ReturnSources) != 0 || len(got.ReturnSourceOrigins) != 0 {
		t.Fatalf("output assigned return replay kept root returns: %#v", got)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[safe]" {
		t.Fatalf("output assigned return replay paths = %#v, want only [safe]", got.ReturnParamPaths)
	}
	if len(got.StorageWrites) != 0 || len(got.StoragePathWrites) != 0 {
		t.Fatalf("output assigned return replay kept pure persistent-read storage side effects: %#v", got)
	}
}

func TestCurrentAssignedReturnPathInterestAllowsActionBatchAssignedPaths(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"action": {}},
		currentBatchName: "action",
		relevantCallables: map[string]struct{}{
			"function::\\handler": {},
			"function::\\helper":  {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"function::\\helper": {"function::\\handler": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\handler": {{
				callee:       "function::\\helper",
				order:        1,
				assignedRoot: "$value",
			}},
		},
		actionSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\handler": {
				"$value[safe]": 2,
			},
		},
		actionSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\handler": {
				"$value": {
					"[safe]": 2,
				},
			},
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}
	sum := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
		ReturnParamPaths: []paramPathRef{
			{Index: 0, Path: "[safe]"},
			{Index: 0, Path: "[danger]"},
		},
		ReturnPathWrites: map[string]taintSummary{
			"[safe]":   {Params: []int{0}},
			"[danger]": {Params: []int{0}},
		},
	}

	allowed, ok := state.currentAssignedReturnPathInterest(sum)
	if !ok {
		t.Fatal("currentAssignedReturnPathInterest() did not detect action assigned-path use")
	}
	got := filterSummaryForAssignedReturnReplayWithRootDrop(sum, allowed, state.shouldDropAssignedReturnRoots(sum))
	if len(got.ReturnSources) != 0 {
		t.Fatalf("action assigned return replay kept root returns: %#v", got.ReturnSources)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[safe]" {
		t.Fatalf("action assigned return replay paths = %#v, want only [safe]", got.ReturnParamPaths)
	}
	if _, ok := got.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("action assigned return replay kept unused [danger] path: %#v", got.ReturnPathWrites)
	}
}

func TestCurrentAssignedReturnPathInterestAllowsCallBatchAssignedPaths(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"call": {}},
		currentBatchName: "call",
		relevantCallables: map[string]struct{}{
			"function::\\handler": {},
			"function::\\helper":  {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"function::\\helper": {"function::\\handler": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"function::\\handler": {{
				callee:       "function::\\helper",
				order:        1,
				assignedRoot: "$value",
				dataCarrier:  true,
			}},
		},
		callSinkRelevantUseOrders: map[string]map[string]int{
			"function::\\handler": {
				"$value[safe]": 2,
			},
		},
		callSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"function::\\handler": {
				"$value": {
					"[safe]": 2,
				},
			},
		},
	}
	state := analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}
	sum := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
		ReturnParamPaths: []paramPathRef{
			{Index: 0, Path: "[safe]"},
			{Index: 0, Path: "[danger]"},
		},
		ReturnPathWrites: map[string]taintSummary{
			"[safe]":   {Params: []int{0}},
			"[danger]": {Params: []int{0}},
		},
	}

	allowed, ok := state.currentAssignedReturnPathInterest(sum)
	if !ok {
		t.Fatal("currentAssignedReturnPathInterest() did not detect call assigned-path use")
	}
	got := filterSummaryForAssignedReturnReplayWithRootDrop(sum, allowed, state.shouldDropAssignedReturnRoots(sum))
	if len(got.ReturnSources) != 0 {
		t.Fatalf("call assigned return replay kept root returns: %#v", got.ReturnSources)
	}
	if len(got.ReturnParamPaths) != 1 || got.ReturnParamPaths[0].Path != "[safe]" {
		t.Fatalf("call assigned return replay paths = %#v, want only [safe]", got.ReturnParamPaths)
	}
	if _, ok := got.ReturnPathWrites["[danger]"]; ok {
		t.Fatalf("call assigned return replay kept unused [danger] path: %#v", got.ReturnPathWrites)
	}
}

func TestAnalyzeCallableCompactsDeleteRendererSummary(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"delete": {}},
		currentBatchName: "delete",
	}
	state := analysisState{
		engine: engine,
		current: callable{
			Key:   "function::\\render",
			Stmts: []ast.Node{&ast.StmtEcho{}},
		},
	}
	sum := summary{
		SourceFindings: []findingRecord{{
			RuleID: "delete",
			Sink:   Location{Path: "demo.php", Line: 20},
		}},
		ReturnSources:       []Location{{Path: "demo.php", Line: 10}},
		ReturnSourceOrigins: []sourceOriginRef{{Location: Location{Path: "demo.php", Line: 10}}},
		ReturnParamPaths:    []paramPathRef{{Index: 0, Path: "[path]"}},
		ReturnPathWrites: map[string]taintSummary{
			"[path]": {Params: []int{0}},
		},
		ParamFindings: map[int][]sinkTemplate{
			0: {{RuleID: "delete", Sink: Location{Path: "demo.php", Line: 30}}},
		},
		ReceiverWrites: map[string]taintSummary{
			"value": {Params: []int{0}},
		},
	}
	if !state.shouldCompactCurrentDeleteSummaryToRendererContextOnly(sum) {
		t.Fatal("shouldCompactCurrentDeleteSummaryToRendererContextOnly() did not detect direct delete renderer noise")
	}
	got := filterSummaryForDeleteRendererContextOnly(sum)
	if len(got.ParamFindings) != 1 {
		t.Fatalf("delete renderer compaction dropped param findings: %#v", got.ParamFindings)
	}
	if len(got.SourceFindings) != 0 || len(got.ReturnSources) != 0 || len(got.ReturnSourceOrigins) != 0 || len(got.ReturnParamPaths) != 0 || len(got.ReturnPathWrites) != 0 {
		t.Fatalf("delete renderer compaction kept return/source noise: %#v", got)
	}
	if len(got.ReceiverWrites) != 0 {
		t.Fatalf("delete renderer compaction kept receiver writes: %#v", got.ReceiverWrites)
	}
}

func TestAnalyzeCallableDoesNotCompactDeleteRendererSummaryWithDirectRequestSourceFindings(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"delete": {}},
		currentBatchName: "delete",
		callables: map[string]callable{
			"function::\render": {
				Key: "function::\render",
				Stmts: []ast.Node{
					&ast.StmtExpression{Expr: &ast.ExprArrayDimFetch{Var: &ast.ExprVariable{Name: "_GET"}, Dim: &ast.ScalarString{Value: "path"}}},
					&ast.StmtEcho{},
				},
			},
		},
	}
	state := analysisState{
		engine: engine,
		current: callable{
			Key: "function::\render",
			Stmts: []ast.Node{
				&ast.StmtExpression{Expr: &ast.ExprArrayDimFetch{Var: &ast.ExprVariable{Name: "_GET"}, Dim: &ast.ScalarString{Value: "path"}}},
				&ast.StmtEcho{},
			},
		},
	}
	sum := summary{
		SourceFindings: []findingRecord{{
			RuleID: "delete",
			Sink:   Location{Path: "demo.php", Line: 20},
		}},
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	if state.shouldCompactCurrentDeleteSummaryToRendererContextOnly(sum) {
		t.Fatal("shouldCompactCurrentDeleteSummaryToRendererContextOnly() compacted direct-request delete findings")
	}
}

func TestAnalyzeCallableCompactsIncludeRendererSummary(t *testing.T) {
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"include": {}},
		currentBatchName: "include",
		recordReadCallables: map[string]struct{}{
			"function::\\render": {},
		},
		callables: map[string]callable{
			"function::\\render": {
				Key:   "function::\\render",
				Stmts: []ast.Node{&ast.StmtEcho{}},
			},
		},
	}
	state := analysisState{
		engine: engine,
		current: callable{
			Key:   "function::\\render",
			Stmts: []ast.Node{&ast.StmtEcho{}},
		},
	}
	sum := summary{
		SourceFindings: []findingRecord{{
			RuleID: "path-transversal",
			Sink:   Location{Path: "demo.php", Line: 20},
		}},
		ReturnSources:       []Location{{Path: "demo.php", Line: 10}},
		ReturnSourceOrigins: []sourceOriginRef{{Location: Location{Path: "demo.php", Line: 10}}},
		ReturnParamPaths:    []paramPathRef{{Index: 0, Path: "[template_path]"}},
		ReturnPathWrites: map[string]taintSummary{
			"[template_path]": {Params: []int{0}},
		},
		ParamFindings: map[int][]sinkTemplate{
			0: {{RuleID: "path-transversal", Sink: Location{Path: "demo.php", Line: 30}}},
		},
		ReceiverWrites: map[string]taintSummary{
			"value": {Params: []int{0}},
		},
	}
	if !state.shouldCompactCurrentIncludeSummaryToRendererContextOnly(sum) {
		t.Fatal("shouldCompactCurrentIncludeSummaryToRendererContextOnly() did not detect direct include renderer noise")
	}
	got := filterSummaryForDeleteRendererContextOnly(sum)
	if len(got.ParamFindings) != 1 {
		t.Fatalf("include renderer compaction dropped param findings: %#v", got.ParamFindings)
	}
	if len(got.SourceFindings) != 0 || len(got.ReturnSources) != 0 || len(got.ReturnSourceOrigins) != 0 || len(got.ReturnParamPaths) != 0 || len(got.ReturnPathWrites) != 0 {
		t.Fatalf("include renderer compaction kept return/source noise: %#v", got)
	}
	if len(got.ReceiverWrites) != 0 {
		t.Fatalf("include renderer compaction kept receiver writes: %#v", got.ReceiverWrites)
	}
}

func TestFilterCurrentBatchPersistentReadStorageOriginsDropsDirectOutputNoise(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-direct-storage-noise.php"), `<?php
function render() {
    echo get_option('secret_flag');
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"

	key := engine.lookupFunctionKey("", "render")
	if key == "" {
		t.Fatal("missing render key")
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[key],
	}
	writes := map[string]originSet{
		"option_value[secret_flag]": makeOriginSet(origin{
			kind:           originSource,
			source:         Location{Path: "demo.php", Line: 2},
			persistentRead: true,
		}),
	}

	filtered := state.filterCurrentBatchPersistentReadStorageOrigins(writes)
	if filtered != nil {
		t.Fatalf("direct output callable kept persistent-read-only storage effects: %#v", filtered)
	}
}

func TestFilterCurrentBatchPersistentReadStorageOriginsKeepsNonDirectHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-helper-storage-noise.php"), `<?php
function helper() {
    return get_option('secret_flag');
}
function render() {
    echo helper();
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupFunctionKey("", "helper")
	if key == "" {
		t.Fatal("missing helper key")
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[key],
	}
	writes := map[string]originSet{
		"option_value[secret_flag]": makeOriginSet(origin{
			kind:           originSource,
			source:         Location{Path: "demo.php", Line: 2},
			persistentRead: true,
		}),
	}

	filtered := state.filterCurrentBatchPersistentReadStorageOrigins(writes)
	if len(filtered) != 1 {
		t.Fatalf("non-direct helper dropped persistent-read storage effects: %#v", filtered)
	}
	if _, ok := filtered["option_value[secret_flag]"]; !ok {
		t.Fatalf("non-direct helper lost storage key: %#v", filtered)
	}
}
