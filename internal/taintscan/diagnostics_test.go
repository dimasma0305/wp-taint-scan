package taintscan

import (
	"testing"

	"github.com/dimasma0305/php-parser-go/ast"
)

func TestHashStringsSinglePartReturnsInput(t *testing.T) {
	if got := hashStrings([]string{"batch=delete"}); got != "batch=delete" {
		t.Fatalf("hashStrings(single) = %q, want %q", got, "batch=delete")
	}
}

func TestCallableSummaryInputFingerprintFastPathsBatchOnlyCallables(t *testing.T) {
	engine := &engine{currentBatchName: "delete"}
	if got := engine.callableSummaryInputFingerprint("callable"); got != "batch=delete" {
		t.Fatalf("callableSummaryInputFingerprint() = %q, want %q", got, "batch=delete")
	}
}

func TestSummaryDependencyFingerprintIgnoresSourceFindings(t *testing.T) {
	a := summary{
		SourceFindings: []findingRecord{{
			RuleID: "rule-a",
			Source: Location{Path: "a.php", Line: 10},
			Sink:   Location{Path: "a.php", Line: 20},
		}},
	}
	b := summary{
		SourceFindings: []findingRecord{{
			RuleID: "rule-b",
			Source: Location{Path: "b.php", Line: 11},
			Sink:   Location{Path: "b.php", Line: 21},
		}},
	}
	if gotA, gotB := summaryDependencyFingerprint(a), summaryDependencyFingerprint(b); gotA != gotB {
		t.Fatalf("summaryDependencyFingerprint() differs on SourceFindings-only change: %q vs %q", gotA, gotB)
	}
}

func TestSummaryDependencyFingerprintTracksParamFindings(t *testing.T) {
	a := summary{}
	b := summary{
		ParamFindings: map[int][]sinkTemplate{
			0: {{
				RuleID:  "rule-a",
				Message: "msg",
				Sink:    Location{Path: "a.php", Line: 20},
			}},
		},
	}
	if gotA, gotB := summaryDependencyFingerprint(a), summaryDependencyFingerprint(b); gotA == gotB {
		t.Fatalf("summaryDependencyFingerprint() did not change for ParamFindings")
	}
}

func TestSummaryDependencyFingerprintTracksReceiverFindings(t *testing.T) {
	a := summary{}
	b := summary{
		ReceiverFindings: []sinkTemplate{{
			RuleID:       "rule-a",
			Message:      "msg",
			Sink:         Location{Path: "a.php", Line: 20},
			ReceiverPath: "manifest",
		}},
	}
	if gotA, gotB := summaryDependencyFingerprint(a), summaryDependencyFingerprint(b); gotA == gotB {
		t.Fatalf("summaryDependencyFingerprint() did not change for ReceiverFindings")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeSourceFindingGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName:              "read",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		SourceFindings: []findingRecord{{
			RuleID: "rule-a",
			Source: Location{Path: "a.php", Line: 10},
			Sink:   Location{Path: "a.php", Line: 20},
		}},
	}
	engine.summaryFingerprints = map[string]string{}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee SourceFindings-only growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeSourceFindingGrowthForStandaloneSourceCallables(t *testing.T) {
	engine := &engine{
		currentBatchName:              "read",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges:                 map[string][]callSiteEdge{"caller": {{callee: "callee", order: 1}}},
		callables:                     map[string]callable{"callee": {Key: "callee"}},
		recordReadCallables:           map[string]struct{}{"callee": {}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		SourceFindings: []findingRecord{{
			RuleID: "rule-a",
			Source: Location{Path: "a.php", Line: 10},
			Sink:   Location{Path: "a.php", Line: 20},
		}},
	}
	engine.summaryFingerprints = map[string]string{}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatalf("callableSummaryInputFingerprint() did not change on standalone-source callee SourceFindings growth")
	}
}

func TestFilterSummaryForFilePathLikeCallInterestDropsNonPathReturnParamPaths(t *testing.T) {
	item := summary{
		ReturnParamPaths: []paramPathRef{
			{Index: 0, Path: "[file_path]"},
			{Index: 0, Path: "[plan_name]"},
		},
	}
	filtered := filterSummaryForFilePathLikeCallInterest(item)
	if len(filtered.ReturnParamPaths) != 1 {
		t.Fatalf("ReturnParamPaths count = %d, want 1", len(filtered.ReturnParamPaths))
	}
	if filtered.ReturnParamPaths[0].Path != "[file_path]" {
		t.Fatalf("ReturnParamPaths[0].Path = %q, want [file_path]", filtered.ReturnParamPaths[0].Path)
	}
}

func TestFilterSummaryForFilePathLikeCallInterestDropsNonPathReturnReceiverPaths(t *testing.T) {
	item := summary{
		ReturnReceiverPaths: []receiverPathRef{
			{Path: "payload[file_path]"},
			{Path: "payload[plan_name]"},
		},
	}
	filtered := filterSummaryForFilePathLikeCallInterest(item)
	if len(filtered.ReturnReceiverPaths) != 1 {
		t.Fatalf("ReturnReceiverPaths count = %d, want 1", len(filtered.ReturnReceiverPaths))
	}
	if filtered.ReturnReceiverPaths[0].Path != "payload[file_path]" {
		t.Fatalf("ReturnReceiverPaths[0].Path = %q, want payload[file_path]", filtered.ReturnReceiverPaths[0].Path)
	}
}

func TestNormalizeSummaryForDependencyFingerprintDropsReceiverEffectsCoveredByStorageLinksInOutputBatch(t *testing.T) {
	engine := &engine{currentBatchName: "output"}
	persistentRead := summarizeOrigins(makeOriginSet(origin{
		kind:           originSource,
		source:         Location{Path: "demo.php", Line: 10},
		persistentRead: true,
	}))
	item := summary{
		ReceiverWrites: map[string]taintSummary{
			"profile": persistentRead,
		},
		ReceiverPathWrites: map[string]taintSummary{
			"profile[display_name]": persistentRead,
		},
		ReceiverStorageLinks: map[string]string{
			"profile": "user_meta_value",
		},
	}

	filtered := engine.normalizeSummaryForDependencyFingerprint(item)
	if len(filtered.ReceiverWrites) != 0 {
		t.Fatalf("ReceiverWrites = %#v, want empty", filtered.ReceiverWrites)
	}
	if len(filtered.ReceiverPathWrites) != 0 {
		t.Fatalf("ReceiverPathWrites = %#v, want empty", filtered.ReceiverPathWrites)
	}
	if got := filtered.ReceiverStorageLinks["profile"]; got != "user_meta_value" {
		t.Fatalf("ReceiverStorageLinks[profile] = %q, want user_meta_value", got)
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeStaticWriteGrowthWithoutCallerStaticReads(t *testing.T) {
	engine := &engine{
		currentBatchName:              "read",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StaticWrites: map[string]taintSummary{
			`Demo::$script`: summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee StaticWrites-only growth without caller static reads: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeStaticWriteGrowthWhenCallerReadsStatic(t *testing.T) {
	engine := &engine{
		currentBatchName:              "read",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable: map[string]map[string]struct{}{
			"caller": {
				`Demo::$template_path`: {},
			},
		},
		staticProps:             map[string]originSet{},
		staticStateFingerprints: map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StaticWrites: map[string]taintSummary{
			`Demo::$template_path`: summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatalf("callableSummaryInputFingerprint() did not change on callee StaticWrites growth with caller static reads")
	}
}

func TestCallableSummaryInputFingerprintIgnoresUnrelatedCalleeStaticWriteGrowthWhenCallerReadsDifferentStatic(t *testing.T) {
	engine := &engine{
		currentBatchName:              "read",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable: map[string]map[string]struct{}{
			"caller": {
				`Demo::$other`: {},
			},
		},
		staticProps:             map[string]originSet{},
		staticStateFingerprints: map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StaticWrites: map[string]taintSummary{
			`Demo::$template_path`: summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on unrelated callee StaticWrites growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeStaticWriteGrowthForNestedStaticReadPath(t *testing.T) {
	engine := &engine{
		currentBatchName:              "read",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable: map[string]map[string]struct{}{
			"caller": {
				`Demo::$template_path[file_path]`: {},
			},
		},
		staticReadRootsByCallable: map[string]map[string]struct{}{},
		staticProps:               map[string]originSet{},
		staticStateFingerprints:   map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StaticWrites: map[string]taintSummary{
			`Demo::$template_path`: summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatalf("callableSummaryInputFingerprint() did not change on overlapping callee StaticWrites growth for nested static read path")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeReturnGrowthForSideEffectOnlyCall(t *testing.T) {
	engine := &engine{
		currentBatchName: "open",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				dataCarrier: false,
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee return growth for side-effect-only call: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeReturnGrowthWhenFileBatchCallerUsesReturnedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "open",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				dataCarrier: true,
				argCarrier:  true,
				runtimeArgIdxs: map[int]struct{}{
					0: {},
				},
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatalf("callableSummaryInputFingerprint() did not change on callee return growth when file-batch caller uses returned path")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeConcreteStorageWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName:              "delete",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {
				Sources: []Location{{Path: "demo.php", Line: 10}},
			},
		},
		StoragePathWrites: map[string]taintSummary{
			"option_value[demo]": {
				Sources: []Location{{Path: "demo.php", Line: 11}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee concrete storage-write growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeParameterizedStorageWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StorageWrites: map[string]taintSummary{
			"meta_value": {
				Params: []int{0},
			},
		},
		StoragePathWrites: map[string]taintSummary{
			"meta_value[file][path]": {
				ParamPaths: []paramPathRef{{Index: 0, Path: "[file][path]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on callee parameterized storage-write growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeParameterizedStorageWriteGrowthForUnrelatedRuntimeArgIndex(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StorageWrites: map[string]taintSummary{
			"meta_value": {
				Params: []int{1},
			},
		},
		StoragePathWrites: map[string]taintSummary{
			"meta_value[file][path]": {
				ParamPaths: []paramPathRef{{Index: 1, Path: "[file][path]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on unrelated callee parameterized storage-write growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresDeleteUserMetaScalarStorageWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StoragePathWrites: map[string]taintSummary{
			"user_meta_value[*][full_name]": {
				ParamPaths: []paramPathRef{{Index: 0, Path: "[full_name]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on delete-only user-meta scalar storage-write growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksDeleteUserMetaFilePathStorageWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StoragePathWrites: map[string]taintSummary{
			"user_meta_value[*][avatar][file_path]": {
				ParamPaths: []paramPathRef{{Index: 0, Path: "[avatar][file_path]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-only user-meta file-path storage-write growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresDeletePostMetaScalarStorageWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StoragePathWrites: map[string]taintSummary{
			"post_meta_value[*][_tutor_enrolled_by_order_id]": {
				ParamPaths: []paramPathRef{{Index: 0, Path: "[_tutor_enrolled_by_order_id]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on delete-only post-meta scalar storage-write growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksDeletePostMetaFilePathStorageWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StoragePathWrites: map[string]taintSummary{
			"post_meta_value[*][attachment][file_path]": {
				ParamPaths: []paramPathRef{{Index: 0, Path: "[attachment][file_path]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-only post-meta file-path storage-write growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresDeletePostMetaScalarStorageReadGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"caller": {"post_meta_value[*][_tutor_enrolled_by_order_id]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"caller": {"post_meta_value": {}},
		},
		storagePaths: map[string]originSet{
			"post_meta_value[*][_tutor_enrolled_by_order_id]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storage: map[string]originSet{
			"post_meta_value": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storagePathStateFingerprints: map[string]string{},
		storageStateFingerprints:     map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.storagePaths["post_meta_value[*][_tutor_enrolled_by_order_id]"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.storage["post_meta_value"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.clearStateFingerprints()
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on delete-only post-meta scalar storage-read growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksDeletePostMetaThumbnailStorageReadGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"caller": {"post_meta_value[*][_thumbnail_id]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"caller": {"post_meta_value": {}},
		},
		storagePaths: map[string]originSet{
			"post_meta_value[*][_thumbnail_id]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storage: map[string]originSet{
			"post_meta_value": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storagePathStateFingerprints: map[string]string{},
		storageStateFingerprints:     map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.storagePaths["post_meta_value[*][_thumbnail_id]"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.storage["post_meta_value"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.clearStateFingerprints()
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-only post-meta thumbnail storage-read growth")
	}
}

func TestCallableSummaryInputFingerprintTracksDeleteOptionFamilyReadGrowthWhenFileOrdersPresent(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"caller": {"option_value": {}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {"value[file][tmp_name]": 3},
		},
		storagePaths: map[string]originSet{
			"option_value[demo_upload][file][tmp_name]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storage: map[string]originSet{
			"option_value": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storagePathStateFingerprints: map[string]string{},
		storageStateFingerprints:     map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.storagePaths["option_value[demo_upload][file][tmp_name]"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.storage["option_value"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.clearStateFingerprints()
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-only option family read growth with file-relevant use orders")
	}
}

func TestCallableSummaryInputFingerprintTracksDeleteUserMetaIDBucketReadGrowthWhenFileOrdersPresent(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"caller": {"user_meta_value[7]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"caller": {"user_meta_value": {}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {"value[file][tmp_name]": 3},
		},
		storagePaths: map[string]originSet{
			"user_meta_value[7][demo_upload][file][tmp_name]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storage: map[string]originSet{
			"user_meta_value": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storagePathStateFingerprints: map[string]string{},
		storageStateFingerprints:     map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.storagePaths["user_meta_value[7][demo_upload][file][tmp_name]"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.storage["user_meta_value"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.clearStateFingerprints()
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-only user-meta id bucket read growth with file-relevant use orders")
	}
}

func TestCallableSummaryInputFingerprintTracksReadUserMetaScalarStorageWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StoragePathWrites: map[string]taintSummary{
			"user_meta_value[*][full_name]": {
				ParamPaths: []paramPathRef{{Index: 0, Path: "[full_name]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on read-batch user-meta scalar storage-write growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeParamFindingGrowthWithoutCallerArgFlow(t *testing.T) {
	engine := &engine{
		currentBatchName:              "delete",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges:                 map[string][]callSiteEdge{"caller": {{callee: "callee"}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ParamFindings: map[int][]sinkTemplate{
			0: {{
				RuleID:  "rule-a",
				Message: "msg",
				Sink:    Location{Path: "demo.php", Line: 20},
			}},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee ParamFindings growth without caller arg flow: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeParamFindingGrowthWhenCallerHasArgFlow(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ParamFindings: map[int][]sinkTemplate{
			0: {{
				RuleID:  "rule-a",
				Message: "msg",
				Sink:    Location{Path: "demo.php", Line: 20},
			}},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on callee ParamFindings growth with caller arg flow")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeParameterizedStorageWriteGrowthWithoutCallerArgFlow(t *testing.T) {
	engine := &engine{
		currentBatchName:              "delete",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges:                 map[string][]callSiteEdge{"caller": {{callee: "callee"}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StorageWrites: map[string]taintSummary{
			"meta_value": {
				Params: []int{0},
			},
		},
		StoragePathWrites: map[string]taintSummary{
			"meta_value[file][path]": {
				ParamPaths: []paramPathRef{{Index: 0, Path: "[file][path]"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee parameterized storage-write growth without caller arg flow: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeReceiverFindingGrowthWithoutReceiverSite(t *testing.T) {
	engine := &engine{
		currentBatchName:              "delete",
		callEdges:                     map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges:                 map[string][]callSiteEdge{"caller": {{callee: "callee"}}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReceiverFindings: []sinkTemplate{{
			RuleID:       "rule-a",
			Message:      "msg",
			Sink:         Location{Path: "demo.php", Line: 20},
			ReceiverPath: "path",
		}},
		ReceiverWrites: map[string]taintSummary{
			"path": {
				ReceiverPaths: []receiverPathRef{{Path: "path"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee receiver effect growth without receiver site: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeReceiverFindingGrowthWithReceiverSite(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:                "callee",
				hasReceiver:           true,
				receiverStateRelevant: true,
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReceiverFindings: []sinkTemplate{{
			RuleID:       "rule-a",
			Message:      "msg",
			Sink:         Location{Path: "demo.php", Line: 20},
			ReceiverPath: "path",
		}},
		ReceiverWrites: map[string]taintSummary{
			"path": {
				ReceiverPaths: []receiverPathRef{{Path: "path"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on callee receiver effect growth with receiver site")
	}
}

func TestCallableSummaryInputFingerprintTracksDeleteCalleeReceiverFindingGrowthWithConsumedReceiver(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				hasReceiver: true,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		callSinkRelevantUseOrders: map[string]map[string]int{
			"callee": {"this.path": 1},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReceiverFindings: []sinkTemplate{{
			RuleID:       "rule-a",
			Message:      "msg",
			Sink:         Location{Path: "demo.php", Line: 20},
			ReceiverPath: "path",
		}},
		ReceiverWrites: map[string]taintSummary{
			"path": {
				ReceiverPaths: []receiverPathRef{{Path: "path"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete callee receiver effect growth with consumed receiver")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeReceiverFindingGrowthWithoutRelevantReceiverState(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				hasReceiver: true,
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReceiverWrites: map[string]taintSummary{
			"path": {
				ReceiverPaths: []receiverPathRef{{Path: "path"}},
			},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee receiver effect growth without relevant receiver state: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresOutputRecordReadStorageWriteGrowthForReceiverStateOnlySite(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:                "callee",
				dataCarrier:           true,
				hasReceiver:           true,
				receiverStateRelevant: true,
			}},
		},
		recordReadCallables: map[string]struct{}{
			"callee": {},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		outputSinkRelevantUseOrders:   map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {ReturnSources: []Location{{Path: "demo.php", Line: 1}}}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 1}},
		StorageWrites: map[string]taintSummary{
			"option_value": {ReceiverPaths: []receiverPathRef{{Path: "profile_id"}}},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on output record-read storage-write growth for receiver-state-only site: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresOutputReturnGrowthForBooleanOnlySite(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				dataCarrier: true,
				booleanUse:  true,
			}},
		},
		outputSinkRelevantUseOrders:   map[string]map[string]int{"caller": {"html": 2}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
		ReturnParamPaths: []paramPathRef{{
			Index: 0,
			Path:  "[url]",
		}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on output boolean-only callee return growth: %q vs %q", before, after)
	}
}

func TestReceiverFlowsRequiringStorageWriteInterestIgnoresOutputReceiverStateOnlyRecordReadSite(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		recordReadCallables: map[string]struct{}{
			"callee": {},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
	}
	site := callSiteEdge{
		callee:                "callee",
		dataCarrier:           true,
		hasReceiver:           true,
		receiverStateRelevant: true,
	}
	if engine.receiverFlowsRequiringStorageWriteInterest(site, "callee", true, false) {
		t.Fatal("receiver-state-only output record-read site should not keep storage-write interest")
	}
}

func TestReceiverFlowsRequiringStorageWriteInterestKeepsOutputReceiverCarrierRecordReadSite(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		recordReadCallables: map[string]struct{}{
			"callee": {},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
	}
	site := callSiteEdge{
		callee:          "callee",
		dataCarrier:     true,
		hasReceiver:     true,
		receiverCarrier: true,
	}
	if !engine.receiverFlowsRequiringStorageWriteInterest(site, "callee", true, false) {
		t.Fatal("receiver-carried output record-read site should keep storage-write interest")
	}
}

func TestCallableHasPersistentReadOnlyStandaloneSourceSummaryTracksPersistentReturnWrapper(t *testing.T) {
	engine := &engine{
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
	}
	item := summary{
		ReturnSourceOrigins: []sourceOriginRef{{
			Location:       Location{Path: "demo.php", Line: 1},
			PersistentRead: true,
		}},
	}
	if !engine.callableHasPersistentReadOnlyStandaloneSourceSummary("callee", item) {
		t.Fatal("persistent-read wrapper summary should count as standalone persistent source")
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeReturnClassGrowthWithoutCallerCallUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "call",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
			}},
		},
		callSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnClasses: []string{`\Demo`},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee ReturnClasses growth without caller call use: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeReturnClassGrowthWhenCallerUsesReturnedObject(t *testing.T) {
	engine := &engine{
		currentBatchName: "call",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
			}},
		},
		callSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value.method": 2,
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnClasses: []string{`\Demo`},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on callee ReturnClasses growth when caller uses returned object")
	}
}

func TestCallableSummaryInputFingerprintIgnoresOutputReturnClassGrowthWithoutCallerOutputUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value.method": 2,
			},
		},
		outputSinkRelevantUseOrders:   map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnClasses: []string{`\Demo`},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on output-batch return class growth without caller output use: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksOutputReturnClassGrowthWhenCallerUsesReturnedValue(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[html]": 2,
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnClasses: []string{`\Demo`},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on output-batch return class growth with caller output use")
	}
}

func TestCallableSummaryInputFingerprintIgnoresOutputReturnPathGrowthOutsideUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[class]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[class]": 2,
				},
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[unused]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on output-batch return path growth outside used assigned path: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksOutputReturnPathGrowthWithinUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[class]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[class]": 2,
				},
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[class]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on output-batch return path growth within used assigned path")
	}
}

func TestCallableSummaryInputFingerprintIgnoresOutputRecordReadStorageWriteGrowthForReturnOnlyCaller(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[class]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[class]": 2,
				},
			},
		},
		recordReadCallables: map[string]struct{}{
			"callee": {},
		},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"user_meta_value[*][display_name]": {}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		StoragePathWrites: map[string]taintSummary{
			"user_meta_value[user_login]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on output-batch record-read storage write growth for return-only caller: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresOutputReturnPathGrowthForRootAssignedUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value": 2,
			},
		},
		summaries:                     map[string]summary{"callee": {ReturnPathWrites: map[string]taintSummary{"[safe]": {Params: []int{0}}}}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaryFingerprints = map[string]string{}
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[safe]":   {Params: []int{0}},
			"[danger]": {Params: []int{0}},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on output root-only return path growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresReadReturnPathGrowthOutsideUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
		fileSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[path]": 2,
				},
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[unused]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on read-batch return path growth outside used assigned path: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksReadReturnPathGrowthWithinUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
		fileSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[path]": 2,
				},
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[path]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on read-batch return path growth within used assigned path")
	}
}

func TestCallableSummaryInputFingerprintIgnoresDeleteReturnClassGrowthWithoutCallerFileUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value.method": 2,
			},
		},
		fileSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnClasses: []string{`\Demo`},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on delete-batch return class growth without caller file use: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksDeleteReturnClassGrowthWhenCallerUsesReturnedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnClasses: []string{`\Demo`},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-batch return class growth with caller file use")
	}
}

func TestCallableSummaryInputFingerprintIgnoresDeleteHelperReturnGrowthWithoutCallerFileUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on delete-batch helper return growth without caller file use: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksDeleteStandaloneSourceReturnGrowthWithoutCallerFileUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		recordReadCallables:           map[string]struct{}{"callee": {}},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-batch standalone-source return growth without caller file use")
	}
}

func TestCallableSummaryInputFingerprintIgnoresReadHelperReturnGrowthWithoutCallerFileUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on read-batch helper return growth without caller file use: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksReadHelperReturnGrowthWhenCallerUsesReturnedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on read-batch helper return growth with caller file use")
	}
}

func TestCallableSummaryInputFingerprintIgnoresDeleteStandaloneSourceReturnGrowthForNonPathLikeStorageBucket(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		recordReadCallables: map[string]struct{}{"callee": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"option_value[um_cache_userdata_{user_id}]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on delete-batch non-path standalone-source return growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksDeleteStandaloneSourceReturnGrowthForPathLikeStorageBucket(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		recordReadCallables: map[string]struct{}{"callee": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"user_meta_value[*][avatar][file_path]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on delete-batch path-like standalone-source return growth")
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresDeleteOptionValueCacheWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
				order:          1,
			}},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		StoragePathWrites: map[string]taintSummary{
			"option_value[um_cache_userdata_{user_id}][super_admin]": {
				Params: []int{0},
			},
		},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on delete-batch option cache write growth: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintTracksDeleteOptionValuePathLikeWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
				order:          1,
			}},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		StoragePathWrites: map[string]taintSummary{
			"option_value[demo_upload][file][file_path]": {
				Params: []int{0},
			},
		},
	})
	if before == after {
		t.Fatal("callerInvalidationSummaryFingerprint() did not change on delete-batch option path-like write growth")
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresDeleteNonPathStandaloneSourceReturnGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		recordReadCallables: map[string]struct{}{"callee": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"option_value[um_cache_userdata_{user_id}]": {}},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on delete-batch non-path standalone-source return growth: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintTracksDeletePathLikeStandaloneSourceReturnGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		recordReadCallables: map[string]struct{}{"callee": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"user_meta_value[*][avatar][file_path]": {}},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	})
	if before == after {
		t.Fatal("callerInvalidationSummaryFingerprint() did not change on delete-batch path-like standalone-source return growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresReadNonPathStandaloneSourceReturnGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		recordReadCallables: map[string]struct{}{"callee": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"option_value[um_cache_userdata_{user_id}]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on read-batch non-path standalone-source return growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksReadPathLikeStandaloneSourceReturnGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		recordReadCallables: map[string]struct{}{"callee": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"user_meta_value[*][avatar][file_path]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on read-batch path-like standalone-source return growth")
	}
}

func TestCallableHasFileRelevantStateAccessIgnoresConstAndNonPathReads(t *testing.T) {
	engine := &engine{
		staticReadPathsByCallable: map[string]map[string]struct{}{
			"const-only":   {"const:ur_pro_active": {}},
			"nonpath-path": {`\Demo.$state[user_email]`: {}},
			"path-path":    {`\Demo.$state[file_path]`: {}},
		},
		staticReadRootsByCallable: map[string]map[string]struct{}{
			"const-root":   {"const:array_filter_use_both": {}},
			"nonpath-root": {`\Demo.$valid_form_data`: {}},
			"path-root":    {`\Demo.$template_path`: {}},
		},
		receiverMutatingCallables: map[string]struct{}{},
	}

	if engine.callableHasFileRelevantStateAccess("const-only") {
		t.Fatal("callableHasFileRelevantStateAccess() treated const-only static path reads as file-relevant")
	}
	if engine.callableHasFileRelevantStateAccess("const-root") {
		t.Fatal("callableHasFileRelevantStateAccess() treated const-only static root reads as file-relevant")
	}
	if engine.callableHasFileRelevantStateAccess("nonpath-path") {
		t.Fatal("callableHasFileRelevantStateAccess() treated non-path static path reads as file-relevant")
	}
	if engine.callableHasFileRelevantStateAccess("nonpath-root") {
		t.Fatal("callableHasFileRelevantStateAccess() treated non-path static root reads as file-relevant")
	}
	if !engine.callableHasFileRelevantStateAccess("path-path") {
		t.Fatal("callableHasFileRelevantStateAccess() dropped path-like static path reads")
	}
	if !engine.callableHasFileRelevantStateAccess("path-root") {
		t.Fatal("callableHasFileRelevantStateAccess() dropped path-like static root reads")
	}
}

func TestFileStorageBucketRelevantToStandaloneReturnRequiresPathLikeLeaf(t *testing.T) {
	if fileStorageBucketRelevantToStandaloneReturn("transient_value[user_registration_mail_send_failed_count]") {
		t.Fatal("fileStorageBucketRelevantToStandaloneReturn() treated non-path transient leaf as file-relevant")
	}
	if !fileStorageBucketRelevantToStandaloneReturn("transient_value[upload_tmp_path]") {
		t.Fatal("fileStorageBucketRelevantToStandaloneReturn() dropped path-like transient leaf")
	}
	if !fileStorageBucketRelevantToStandaloneReturn("post_meta_value[_thumbnail_id_image]") {
		t.Fatal("fileStorageBucketRelevantToStandaloneReturn() dropped path-like post meta leaf")
	}
	if fileStorageFamilyRelevantToStandaloneReturn("transient_value|ur_emailer") {
		t.Fatal("fileStorageFamilyRelevantToStandaloneReturn() treated class-qualified transient family as file-relevant")
	}
	if fileStorageFamilyRelevantToStandaloneReturn("user_meta_value|ur_email_confirmation") {
		t.Fatal("fileStorageFamilyRelevantToStandaloneReturn() treated class-qualified user meta family as file-relevant")
	}
}

func TestDeleteStorageBucketRelevantToStandaloneReturnRequiresPathLikeLeaf(t *testing.T) {
	if deleteStorageBucketRelevantToStandaloneReturn("user_meta_value[display_name]") {
		t.Fatal("deleteStorageBucketRelevantToStandaloneReturn() treated non-path user meta leaf as delete-relevant")
	}
	if deleteStorageBucketRelevantToStandaloneReturn("post_meta_value[*][_tutor_enrolled_by_order_id]") {
		t.Fatal("deleteStorageBucketRelevantToStandaloneReturn() treated non-delete-relevant post meta leaf as delete-relevant")
	}
	if deleteStorageBucketRelevantToStandaloneReturn("transient_value[mailer_counter]") {
		t.Fatal("deleteStorageBucketRelevantToStandaloneReturn() treated non-path transient leaf as delete-relevant")
	}
	if !deleteStorageBucketRelevantToStandaloneReturn("user_meta_value[upload_tmp_path]") {
		t.Fatal("deleteStorageBucketRelevantToStandaloneReturn() dropped path-like user meta leaf")
	}
	if !deleteStorageBucketRelevantToStandaloneReturn("post_meta_value[*][_thumbnail_id]") {
		t.Fatal("deleteStorageBucketRelevantToStandaloneReturn() dropped thumbnail-linked post meta leaf")
	}
	if deleteStorageFamilyRelevantToStandaloneReturn("option_value|um_profile_desc") {
		t.Fatal("deleteStorageFamilyRelevantToStandaloneReturn() treated class-qualified option family as delete-relevant")
	}
	if deleteStorageFamilyRelevantToStandaloneReturn("user_meta_value|um_cover_photo") {
		t.Fatal("deleteStorageFamilyRelevantToStandaloneReturn() treated class-qualified user meta family as delete-relevant")
	}
	if !deleteStorageFamilyRelevantToStandaloneReturn("post_meta_value|upload_path") {
		t.Fatal("deleteStorageFamilyRelevantToStandaloneReturn() dropped post meta family")
	}
}

func TestDeleteBatchStorageWriteRelevantToCallInterestDropsWildcardOnlyMetadataPaths(t *testing.T) {
	if deleteBatchStorageWriteRelevantToCallInterest("user_meta_value[*][*]") {
		t.Fatal("deleteBatchStorageWriteRelevantToCallInterest() treated wildcard-only user meta path as delete-relevant")
	}
	if deleteBatchStorageWriteRelevantToCallInterest("post_meta_value[*][*]") {
		t.Fatal("deleteBatchStorageWriteRelevantToCallInterest() treated wildcard-only post meta path as delete-relevant")
	}
	if !deleteBatchStorageWriteRelevantToCallInterest("post_meta_value[*][_thumbnail_id]") {
		t.Fatal("deleteBatchStorageWriteRelevantToCallInterest() dropped thumbnail-linked post meta path")
	}
}

func TestCallableHasDeleteRelevantStandaloneSourceFindingsRequiresPathLikeRecordRead(t *testing.T) {
	engine := &engine{
		recordReadCallables: map[string]struct{}{
			"render": {},
			"path":   {},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"render": {"user_meta_value|um_profile_desc": {}},
		},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"path": {"user_meta_value[upload_tmp_path]": {}},
		},
	}
	if engine.callableHasDeleteRelevantStandaloneSourceFindings("render") {
		t.Fatal("callableHasDeleteRelevantStandaloneSourceFindings() treated non-path family-only record read as delete-relevant")
	}
	if !engine.callableHasDeleteRelevantStandaloneSourceFindings("path") {
		t.Fatal("callableHasDeleteRelevantStandaloneSourceFindings() dropped path-like record read")
	}
}

func TestCallableHasDeleteRelevantStandaloneSourceFindingsKeepsFileRelevantMetadataReaders(t *testing.T) {
	engine := &engine{
		recordReadCallables: map[string]struct{}{
			"path": {},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"path": {"value[file][tmp_name]": 3},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"path": {"option_value": {}},
		},
	}
	if !engine.callableHasDeleteRelevantStandaloneSourceFindings("path") {
		t.Fatal("callableHasDeleteRelevantStandaloneSourceFindings() dropped file-relevant metadata reader")
	}
}

func TestCallableHasDeleteRelevantStandaloneSourceFindingsSkipsDirectOutputRenderer(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
		callables: map[string]callable{
			"render": {
				Key:   "render",
				Stmts: []ast.Node{&ast.StmtEcho{}},
			},
		},
		recordReadCallables: map[string]struct{}{
			"render": {},
			"path":   {},
		},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"render": {"user_meta_value[upload_tmp_path]": {}},
			"path":   {"user_meta_value[upload_tmp_path]": {}},
		},
	}
	if engine.callableHasDeleteRelevantStandaloneSourceFindings("render") {
		t.Fatal("callableHasDeleteRelevantStandaloneSourceFindings() treated direct output renderer as delete-relevant")
	}
	if !engine.callableHasDeleteRelevantStandaloneSourceFindings("path") {
		t.Fatal("callableHasDeleteRelevantStandaloneSourceFindings() dropped non-render path helper")
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresReadHelperReturnGrowthWithoutCallerFileUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on read-batch helper return growth without caller file use: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresOutputHelperReturnGrowthWithoutCallerOutputUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value.method": 2,
			},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on output-batch helper return growth without caller output use: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintTracksOutputHelperReturnGrowthWhenCallerUsesReturnedValue(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[html]": 2,
			},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	})
	if before == after {
		t.Fatal("callerInvalidationSummaryFingerprint() did not change on output-batch helper return growth with caller output use")
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresOutputHelperReturnPathGrowthOutsideUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[class]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[class]": 2,
				},
			},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnPathWrites: map[string]taintSummary{
			"[unused]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on output-batch helper return path growth outside used assigned path: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintTracksOutputHelperReturnPathGrowthWithinUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[class]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[class]": 2,
				},
			},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnPathWrites: map[string]taintSummary{
			"[class]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	})
	if before == after {
		t.Fatal("callerInvalidationSummaryFingerprint() did not change on output-batch helper return path growth within used assigned path")
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresOutputRecordReadStorageWriteGrowthForReturnOnlyCaller(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		callables: map[string]callable{
			"callee": {Key: "callee"},
		},
		outputSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[class]": 2,
			},
		},
		outputSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[class]": 2,
				},
			},
		},
		recordReadCallables: map[string]struct{}{
			"callee": {},
		},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"callee": {"user_meta_value[*][display_name]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		StoragePathWrites: map[string]taintSummary{
			"user_meta_value[user_login]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on output-batch record-read storage write growth for return-only caller: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintTracksReadHelperReturnGrowthWhenCallerUsesReturnedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	})
	if before == after {
		t.Fatal("callerInvalidationSummaryFingerprint() did not change on read-batch helper return growth with caller file use")
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresReadHelperReturnPathGrowthOutsideUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
		fileSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[path]": 2,
				},
			},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnPathWrites: map[string]taintSummary{
			"[unused]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on read-batch helper return path growth outside used assigned path: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintTracksReadHelperReturnPathGrowthWithinUsedAssignedPath(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
				order:        1,
			}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			"caller": {
				"$value[path]": 2,
			},
		},
		fileSinkRelevantUsePaths: map[string]map[string]map[string]int{
			"caller": {
				"$value": {
					"[path]": 2,
				},
			},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		ReturnPathWrites: map[string]taintSummary{
			"[path]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	})
	if before == after {
		t.Fatal("callerInvalidationSummaryFingerprint() did not change on read-batch helper return path growth within used assigned path")
	}
}

func TestCallerInvalidationSummaryFingerprintIgnoresNonPathStaticReadInterestInReadBatch(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		staticReadRootsByCallable: map[string]map[string]struct{}{
			"caller": {`\Demo.$valid_form_data`: {}},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		StaticWrites: map[string]taintSummary{
			`\Demo.$valid_form_data`: summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	})
	if before != after {
		t.Fatalf("callerInvalidationSummaryFingerprint() changed on read-batch non-path static write growth: %q vs %q", before, after)
	}
}

func TestCallerInvalidationSummaryFingerprintTracksPathLikeStaticReadInterestInReadBatch(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		reverseCallEdges: map[string]map[string]struct{}{
			"callee": {"caller": {}},
		},
		staticReadRootsByCallable: map[string]map[string]struct{}{
			"caller": {`\Demo.$template_path`: {}},
		},
	}
	before := engine.callerInvalidationSummaryFingerprint("callee", summary{})
	after := engine.callerInvalidationSummaryFingerprint("callee", summary{
		StaticWrites: map[string]taintSummary{
			`\Demo.$template_path`: summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	})
	if before == after {
		t.Fatal("callerInvalidationSummaryFingerprint() dropped read-batch path-like static write growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresNonPathStaticRootsInReadBatch(t *testing.T) {
	engine := &engine{
		currentBatchName:              "read",
		callEdges:                     map[string]map[string]struct{}{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable: map[string]map[string]struct{}{
			"caller": {`\Demo.$valid_form_data`: {}},
		},
	}
	if got := engine.callableSummaryInputFingerprint("caller"); got != "batch=read" {
		t.Fatalf("callableSummaryInputFingerprint() kept non-path static root in read batch: %q", got)
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeReturnPathWriteGrowthWithoutCallerCallUse(t *testing.T) {
	engine := &engine{
		currentBatchName: "call",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
			}},
		},
		callSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[field][label]": {Params: []int{0}},
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on callee ReturnPathWrites growth without caller call use: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresCalleeReturnParamPathGrowthForUnrelatedRuntimeArgIndex(t *testing.T) {
	engine := &engine{
		currentBatchName: "call",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				dataCarrier:    true,
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		callSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnParamPaths: []paramPathRef{{
			Index: 1,
			Path:  "[sub_fields][0][field]",
		}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on unrelated callee ReturnParamPaths growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCalleeReturnParamPathGrowthForMatchingRuntimeArgIndex(t *testing.T) {
	engine := &engine{
		currentBatchName: "call",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:         "callee",
				dataCarrier:    true,
				argCarrier:     true,
				runtimeArgIdxs: map[int]struct{}{0: {}},
			}},
		},
		callSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnParamPaths: []paramPathRef{{
			Index: 0,
			Path:  "[sub_fields][0][field]",
		}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatalf("callableSummaryInputFingerprint() did not change on matching callee ReturnParamPaths growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresReadBatchNonPathReturnParamPathGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				dataCarrier: true,
				argCarrier:  true,
			}},
		},
		fileSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnParamPaths: []paramPathRef{{
			Index: 0,
			Path:  "[membership][post_title]",
		}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on read-batch non-path ReturnParamPaths growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksReadBatchPathLikeReturnParamPathGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				dataCarrier: true,
				argCarrier:  true,
			}},
		},
		fileSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnParamPaths: []paramPathRef{{
			Index: 0,
			Path:  "[upload][file_path]",
		}},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() dropped read-batch path-like ReturnParamPaths growth")
	}
}

func TestCallableSummaryInputFingerprintIgnoresReadBatchNonPathReturnPathWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				dataCarrier: true,
			}},
		},
		fileSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[membership][post_title]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on read-batch non-path ReturnPathWrites growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksReadBatchPathLikeReturnPathWriteGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "read",
		callEdges:        map[string]map[string]struct{}{"caller": {"callee": {}}},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:      "callee",
				dataCarrier: true,
			}},
		},
		fileSinkRelevantUseOrders:     map[string]map[string]int{},
		summaries:                     map[string]summary{"callee": {}},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.summaries["callee"] = summary{
		ReturnPathWrites: map[string]taintSummary{
			"[upload][file_path]": summarizeOrigins(makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			})),
		},
	}
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() dropped read-batch path-like ReturnPathWrites growth")
	}
}

func TestCallableSummaryInputFingerprintReusesEmptyBooleanOnlyOutputSummary(t *testing.T) {
	engine := &engine{
		currentBatchName: "output",
		allowedSinkOps:   map[string]struct{}{"output": {}},
		callables: map[string]callable{
			"helper": {Key: "helper"},
			"caller": {Key: "caller"},
			"callee": {Key: "callee"},
		},
		relevantCallables: map[string]struct{}{
			"helper": {},
			"caller": {},
		},
		reverseCallEdges: map[string]map[string]struct{}{
			"helper": {"caller": {}},
			"callee": {"helper": {}},
		},
		callEdges: map[string]map[string]struct{}{
			"helper": {"callee": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:     "helper",
				booleanUse: true,
			}},
			"helper": {{
				callee:      "callee",
				dataCarrier: true,
			}},
		},
		summaries: map[string]summary{
			"helper": {},
			"callee": {},
		},
		summaryFingerprints:           map[string]string{},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}

	before := engine.callableSummaryInputFingerprint("helper")
	engine.summaries["callee"] = summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 10}},
	}
	after := engine.callableSummaryInputFingerprint("helper")
	if before != "batch=output#bool-empty" {
		t.Fatalf("callableSummaryInputFingerprint() = %q, want bool-empty reuse fingerprint", before)
	}
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed for empty boolean-only output helper: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintIgnoresCallPostMetaWildcardStorageReadGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "call",
		allowedSinkOps:   map[string]struct{}{"call": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"caller": {"post_meta_value[*][*]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"caller": {"post_meta_value": {}},
		},
		storagePaths: map[string]originSet{
			"post_meta_value[*][*]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storage: map[string]originSet{
			"post_meta_value": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storagePathStateFingerprints: map[string]string{},
		storageStateFingerprints:     map[string]string{},
		callSinkRelevantUseOrders:    map[string]map[string]int{},
		summaryFingerprints:          map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.storagePaths["post_meta_value[*][*]"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.storage["post_meta_value"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.clearStateFingerprints()
	after := engine.callableSummaryInputFingerprint("caller")
	if before != after {
		t.Fatalf("callableSummaryInputFingerprint() changed on call-only post-meta wildcard [*][*] storage-read growth: %q vs %q", before, after)
	}
}

func TestCallableSummaryInputFingerprintTracksCallOptionValueSpecificStorageReadGrowth(t *testing.T) {
	engine := &engine{
		currentBatchName: "call",
		allowedSinkOps:   map[string]struct{}{"call": {}},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"caller": {"option_value[*][active_plugins]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{
			"caller": {"option_value": {}},
		},
		storagePaths: map[string]originSet{
			"option_value[*][active_plugins]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storage: map[string]originSet{
			"option_value": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "demo.php", Line: 10},
			}),
		},
		storagePathStateFingerprints: map[string]string{},
		storageStateFingerprints:     map[string]string{},
		callSinkRelevantUseOrders:    map[string]map[string]int{},
		summaryFingerprints:          map[string]string{},
	}
	before := engine.callableSummaryInputFingerprint("caller")
	engine.storagePaths["option_value[*][active_plugins]"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.storage["option_value"] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 20},
	})
	engine.clearStateFingerprints()
	after := engine.callableSummaryInputFingerprint("caller")
	if before == after {
		t.Fatal("callableSummaryInputFingerprint() did not change on call-only option-value specific key storage-read growth")
	}
}
