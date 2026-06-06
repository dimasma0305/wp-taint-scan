package taintscan

import "testing"

func TestShouldSkipBroadDynamicCallbackReplay(t *testing.T) {
	keys := make([]string, broadDynamicCallbackReplayCap+1)
	for i := range keys {
		keys[i] = "function::\\demo_" + string(rune('a'+(i%26)))
	}
	if !shouldSkipBroadCallbackReplay("call", "automator_maybe_parse_{matching_token}", keys) {
		t.Fatal("expected broad open-ended dynamic hook replay to be skipped in call batch")
	}
}

func TestShouldNotSkipBroadDynamicCallbackReplayOutsideCallBatch(t *testing.T) {
	keys := make([]string, broadDynamicCallbackReplayCap+1)
	if shouldSkipBroadCallbackReplay("output", "automator_maybe_parse_{matching_token}", keys) {
		t.Fatal("did not expect broad dynamic hook replay skip outside call batch")
	}
}

func TestShouldNotSkipBroadDynamicCallbackReplayForAnchoredSuffix(t *testing.T) {
	keys := make([]string, broadDynamicCallbackReplayCap+1)
	if shouldSkipBroadCallbackReplay("call", "demo_{token}_suffix", keys) {
		t.Fatal("did not expect replay skip for dynamic hook patterns with anchored suffix")
	}
}

func TestShouldNotSkipBroadDynamicCallbackReplayForSmallFanout(t *testing.T) {
	keys := make([]string, broadDynamicCallbackReplayCap)
	if shouldSkipBroadCallbackReplay("call", "automator_maybe_parse_{matching_token}", keys) {
		t.Fatal("did not expect replay skip below cap")
	}
}

func TestShouldSkipBroadStaticCallbackReplay(t *testing.T) {
	keys := make([]string, broadStaticCallbackReplayCap+1)
	for i := range keys {
		keys[i] = "function::\\demo_" + string(rune('a'+(i%26)))
	}
	if !shouldSkipBroadCallbackReplay("call", "automator_maybe_parse_token", keys) {
		t.Fatal("expected broad static hook replay to be skipped in call batch")
	}
}

func TestShouldNotSkipBroadStaticCallbackReplayBelowCap(t *testing.T) {
	keys := make([]string, broadStaticCallbackReplayCap)
	if shouldSkipBroadCallbackReplay("call", "automator_maybe_parse_token", keys) {
		t.Fatal("did not expect static hook replay skip below cap")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsPersistentReadWrapperInCallBatch(t *testing.T) {
	helperKey := `function::\helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"call": {}},
		currentBatchName: "call",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSourceOrigins: []sourceOriginRef{{
			Location:       Location{Path: "demo.php", Line: 1},
			PersistentRead: true,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, nil, "") {
		t.Fatal("call batch should skip persistent-read-only wrapper state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsPersistentReadWrapperInCallBatch(t *testing.T) {
	helperKey := `function::\callback`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"call": {}},
		currentBatchName: "call",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSourceOrigins: []sourceOriginRef{{
			Location:       Location{Path: "demo.php", Line: 1},
			PersistentRead: true,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCallbackReplay(helperKey, item, nil) {
		t.Fatal("call batch callback replay should skip persistent-read-only wrapper state side effects")
	}
}
