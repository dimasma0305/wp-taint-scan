package taintscan

import "testing"

func TestBoundedAnalysisWorkers(t *testing.T) {
	if got := boundedAnalysisWorkers(16, 0); got != 1 {
		t.Fatalf("boundedAnalysisWorkers(16, 0) = %d, want 1", got)
	}
	if got := boundedAnalysisWorkers(16, 8); got != 8 {
		t.Fatalf("boundedAnalysisWorkers(16, 8) = %d, want 8", got)
	}
	if got := boundedAnalysisWorkers(16, 200); got != 2 {
		t.Fatalf("boundedAnalysisWorkers(16, 200) = %d, want 2", got)
	}
	if got := boundedAnalysisWorkers(16, 400); got != 2 {
		t.Fatalf("boundedAnalysisWorkers(16, 400) = %d, want 2", got)
	}
}

func TestNeedsStorageWriterIndexForSinkOpsSkipsActionOnly(t *testing.T) {
	if needsStorageWriterIndexForSinkOps(map[string]struct{}{"action": {}}) {
		t.Fatal("action-only batches should skip storage-writer indexing")
	}
}

func TestNeedsStorageWriterIndexForSinkOpsSkipsCallOnly(t *testing.T) {
	if needsStorageWriterIndexForSinkOps(map[string]struct{}{"call": {}}) {
		t.Fatal("call-only batches should defer storage-writer indexing")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsBroadSQLFallback(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"sql": {}},
	}
	changed := map[string]struct{}{
		"post_meta_value[*]": {},
	}
	if !engine.shouldExpandStorageBaseReadersForChangedPathFamily("post_meta_value", changed) {
		t.Fatal("broad wildcard-only SQL family change should keep family-wide reader invalidation")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsPreciseSQLFallback(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"sql": {}},
	}
	changed := map[string]struct{}{
		"post_meta_value[*][_EventStartDate]": {},
	}
	if engine.shouldExpandStorageBaseReadersForChangedPathFamily("post_meta_value", changed) {
		t.Fatal("stable-key SQL family change should not keep family-wide reader invalidation")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsPreciseWriteFallback(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"write": {}},
	}
	changed := map[string]struct{}{
		"option_value[wpvivid_api_token][private_key]": {},
	}
	if engine.shouldExpandStorageBaseReadersForChangedPathFamily("option_value", changed) {
		t.Fatal("stable-key write family change should not keep family-wide reader invalidation")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsPreciseOutputFallback(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"output": {}},
	}
	changed := map[string]struct{}{
		"option_value[um_account_tab_order][profile]": {},
	}
	if engine.shouldExpandStorageBaseReadersForChangedPathFamily("option_value", changed) {
		t.Fatal("stable-key output family change should not keep family-wide reader invalidation")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsBroadOutputFallback(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"output": {}},
	}
	changed := map[string]struct{}{
		"user_meta_value[*]": {},
	}
	if !engine.shouldExpandStorageBaseReadersForChangedPathFamily("user_meta_value", changed) {
		t.Fatal("broad wildcard-only output family change should keep family-wide reader invalidation")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsPreciseDeleteFallbackForOptionValue(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	changed := map[string]struct{}{
		"option_value[forminator_current_form_id]": {},
	}
	if engine.shouldExpandStorageBaseReadersForChangedPathFamily("option_value", changed) {
		t.Fatal("stable-key delete option_value change should not keep family-wide reader invalidation")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsDeleteFallbackForCrossRequestFamily(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	changed := map[string]struct{}{
		"post_meta_value[*][_thumbnail_id]": {},
	}
	if !engine.shouldExpandStorageBaseReadersForChangedPathFamily("post_meta_value", changed) {
		t.Fatal("delete batches should keep family-wide reader invalidation for cross-request writer families")
	}
}

func TestShouldExpandStoragePathReadersForChangedPathSkipsDeleteOptionValuePath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	if engine.shouldExpandStoragePathReadersForChangedPath("option_value[forminator_current_form_id]") {
		t.Fatal("delete batches should skip exact/bucket reader invalidation for unsupported option_value paths")
	}
}

func TestShouldExpandStoragePathReadersForChangedPathKeepsDeleteCrossRequestPath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	if !engine.shouldExpandStoragePathReadersForChangedPath("post_meta_value[*][upload][file_path]") {
		t.Fatal("delete batches should keep exact/bucket reader invalidation for supported cross-request paths")
	}
}

func TestShouldExpandStoragePathReadersForChangedPathSkipsDeletePostMetaScalarPath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	if engine.shouldExpandStoragePathReadersForChangedPath("post_meta_value[*][_tutor_enrolled_by_order_id]") {
		t.Fatal("delete batches should skip exact/bucket reader invalidation for non-delete-relevant post meta fields")
	}
}

func TestShouldExpandStoragePathReadersForChangedPathSkipsDeleteUserMetaScalarPath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	if engine.shouldExpandStoragePathReadersForChangedPath("user_meta_value[*][full_name]") {
		t.Fatal("delete batches should skip exact/bucket reader invalidation for non-path-like user_meta fields")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsDeleteUserMetaScalarPath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	changed := map[string]struct{}{
		"user_meta_value[*][full_name]": {},
	}
	if engine.shouldExpandStorageBaseReadersForChangedPathFamily("user_meta_value", changed) {
		t.Fatal("delete batches should skip family-wide reader invalidation for non-path-like user_meta fields")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsDeleteUserMetaFilePath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	changed := map[string]struct{}{
		"user_meta_value[*][upload][file_path]": {},
	}
	if !engine.shouldExpandStorageBaseReadersForChangedPathFamily("user_meta_value", changed) {
		t.Fatal("delete batches should keep family-wide reader invalidation for path-like user_meta fields")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsDeletePostMetaScalarPath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"delete": {}},
	}
	changed := map[string]struct{}{
		"post_meta_value[*][_tutor_enrolled_by_order_id]": {},
	}
	if engine.shouldExpandStorageBaseReadersForChangedPathFamily("post_meta_value", changed) {
		t.Fatal("delete batches should skip family-wide reader invalidation for non-delete-relevant post meta fields")
	}
}

func TestNeedsStorageWriterIndexForSinkOpsSkipsPureSurfaceBatch(t *testing.T) {
	if needsStorageWriterIndexForSinkOps(map[string]struct{}{"surface": {}}) {
		t.Fatal("pure surface batch should not build the global storage-writer index")
	}
}

func TestShouldExpandStoragePathReadersForChangedPathSkipsCallOnlyWildcardMetadataPath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"call": {}},
	}
	if engine.shouldExpandStoragePathReadersForChangedPath("post_meta_value[*][*]") {
		t.Fatal("call-only batches should skip reader invalidation for wildcard-only post_meta paths")
	}
	if engine.shouldExpandStoragePathReadersForChangedPath("user_meta_value[*][*]") {
		t.Fatal("call-only batches should skip reader invalidation for wildcard-only user_meta paths")
	}
	if engine.shouldExpandStoragePathReadersForChangedPath("transient_value[*][*]") {
		t.Fatal("call-only batches should skip reader invalidation for wildcard-only transient paths")
	}
}

func TestShouldExpandStoragePathReadersForChangedPathKeepsCallOnlyExactMetadataPath(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"call": {}},
	}
	if !engine.shouldExpandStoragePathReadersForChangedPath("post_meta_value[*][role]") {
		t.Fatal("call-only batches should keep reader invalidation for specific post_meta key paths")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsCallOnlyAllWildcardPaths(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"call": {}},
	}
	changed := map[string]struct{}{
		"post_meta_value[*][*]": {},
	}
	if engine.shouldExpandStorageBaseReadersForChangedPathFamily("post_meta_value", changed) {
		t.Fatal("call-only batches should skip family-wide reader invalidation when all changed paths are wildcard-only metadata")
	}
}

func TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsCallOnlyWhenExactPathPresent(t *testing.T) {
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"call": {}},
	}
	changed := map[string]struct{}{
		"post_meta_value[*][*]":    {},
		"post_meta_value[*][role]": {}, // specific key present
	}
	if !engine.shouldExpandStorageBaseReadersForChangedPathFamily("post_meta_value", changed) {
		t.Fatal("call-only batches should keep family-wide reader invalidation when at least one specific path is present")
	}
}

func TestDedupeFinalFindingsCollapsesNullSourceTraceDuplicates(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 42},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: "Request-controlled input reaches a sensitive state-changing or administrative action without a definite capability check. Review missing authorization and dynamic capability routing.",
				Trace: Trace{
					Sink:     Location{Path: "admin.php", Line: 42},
					Callable: "method::\\Demo::run",
				},
				Context: FlowContext{
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_nopriv_demo",
						Location: Location{Path: "admin.php", Line: 10},
					}},
				},
				StoredWriteContext: FlowContext{
					EntryPoints: []EntryPoint{{
						Kind:     "rest",
						Route:    "/demo/v1/run",
						Location: Location{Path: "admin.php", Line: 12},
					}},
				},
			},
		},
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 42},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: "Request-controlled input reaches a sensitive state-changing or administrative action without a definite capability check. Review missing authorization and dynamic capability routing.",
				Trace: Trace{
					Sink:     Location{Path: "admin.php", Line: 42},
					Callable: "method::\\Demo::run",
				},
				Context: FlowContext{
					EntryPoints: []EntryPoint{{
						Kind:     "rest",
						Route:    "/demo/v1/run",
						Location: Location{Path: "admin.php", Line: 15},
					}},
				},
				StoredWriteContext: FlowContext{
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_demo_store",
						Location: Location{Path: "admin.php", Line: 18},
					}},
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if len(deduped[0].Extra.Context.EntryPoints) != 2 {
		t.Fatalf("merged context entrypoints = %d, want 2", len(deduped[0].Extra.Context.EntryPoints))
	}
	if len(deduped[0].Extra.StoredWriteContext.EntryPoints) != 2 {
		t.Fatalf("merged stored_write_context entrypoints = %d, want 2", len(deduped[0].Extra.StoredWriteContext.EntryPoints))
	}
}

func TestDedupeFinalFindingsCollapsesPathTraversalDistinctSourcesSameSink(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "path-transversal",
			Path:    "/tmp/plugin/render.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 55},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: pathTransversalMessage,
				Trace: Trace{
					Source:   Location{Path: "render.php", Line: 20},
					Sink:     Location{Path: "render.php", Line: 55},
					Callable: "function::render_demo",
				},
			},
		},
		{
			CheckID: "path-transversal",
			Path:    "/tmp/plugin/render.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 55},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: pathTransversalMessage,
				Trace: Trace{
					Source:   Location{Path: "render.php", Line: 24},
					Sink:     Location{Path: "render.php", Line: 55},
					Callable: "function::render_demo",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
}

func TestDedupeFinalFindingsCollapsesPathTraversalAcrossEquivalentSinkCallables(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "path-transversal",
			Path:    "/tmp/plugin/classes/DisplayController.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 98},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: pathTransversalMessage,
				Trace: Trace{
					Source:   Location{Path: "classes/ObjController.php", Line: 167, Snippet: "$dir .= strtolower( $path[ $i ] ) . '/';"},
					Sink:     Location{Path: "classes/DisplayController.php", Line: 98, Snippet: "include $file;"},
					Callable: "\\Demo\\Controller_A::getview",
				},
			},
		},
		{
			CheckID: "path-transversal",
			Path:    "/tmp/plugin/classes/DisplayController.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 98},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: pathTransversalMessage,
				Trace: Trace{
					Source:   Location{Path: "classes/ObjController.php", Line: 167, Snippet: "$dir .= strtolower( $path[ $i ] ) . '/';"},
					Sink:     Location{Path: "classes/DisplayController.php", Line: 98, Snippet: "include $file;"},
					Callable: "\\Demo\\Controller_B::getview",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Callable != "\\Demo\\Controller_A::getview" {
		t.Fatalf("deduped callable = %q, want \\Demo\\Controller_A::getview", deduped[0].Extra.Trace.Callable)
	}
}

func TestDedupeFinalFindingsCollapsesNoisyRuleToBestRequestSource(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-record-read-to-output-without-cap-check",
			Path:    "/tmp/plugin/logs.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 72},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestRecordOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "logs.php", Line: 40, Snippet: "$value = sanitize_text_field( $helper );"},
					Sink:     Location{Path: "logs.php", Line: 72},
					Callable: "method::\\Demo::show_log",
				},
			},
		},
		{
			CheckID: "wp-request-record-read-to-output-without-cap-check",
			Path:    "/tmp/plugin/logs.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 72},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestRecordOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "logs.php", Line: 12, Snippet: "$id = sanitize_text_field( $_GET['log_id'] );"},
					Sink:     Location{Path: "logs.php", Line: 72},
					Callable: "method::\\Demo::show_log",
				},
			},
		},
		{
			CheckID: "wp-request-record-read-to-output-without-cap-check",
			Path:    "/tmp/plugin/logs.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 72},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestRecordOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "logs.php", Line: 12, Snippet: "$id = sanitize_text_field( $_GET['log_id'] );"},
					Sink:     Location{Path: "logs.php", Line: 72},
					Callable: "file::logs.php",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 12 {
		t.Fatalf("deduped source line = %d, want 12", deduped[0].Extra.Trace.Source.Line)
	}
	if deduped[0].Extra.Trace.Callable != "method::\\Demo::show_log" {
		t.Fatalf("deduped callable = %q, want method::\\\\Demo::show_log", deduped[0].Extra.Trace.Callable)
	}
}

func TestDedupeFinalFindingsCollapsesGenericDeleteRuleToBestRequestSource(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 88},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 40, Snippet: "$path = sanitize_text_field( $helper );"},
					Sink:     Location{Path: "files.php", Line: 88},
					Callable: "function::delete_file",
				},
			},
		},
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 88},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 12, Snippet: "$path = sanitize_text_field( $_GET['path'] );"},
					Sink:     Location{Path: "files.php", Line: 88},
					Callable: "function::delete_file",
				},
			},
		},
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 88},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 12, Snippet: "$path = sanitize_text_field( $_GET['path'] );"},
					Sink:     Location{Path: "files.php", Line: 88},
					Callable: "file::files.php",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 12 {
		t.Fatalf("deduped source line = %d, want 12", deduped[0].Extra.Trace.Source.Line)
	}
	if deduped[0].Extra.Trace.Callable != "function::delete_file" {
		t.Fatalf("deduped callable = %q, want function::delete_file", deduped[0].Extra.Trace.Callable)
	}
}

func TestDedupeFinalFindingsCollapsesFileDeleteSameSinkSnippetCluster(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 3383},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 60, Snippet: "$unique_id = sanitize_text_field($_POST['id']);"},
					Sink:     Location{Path: "files.php", Line: 3383, Snippet: "$ret = unlink($path);"},
					Callable: "function::ajax_callback",
				},
			},
		},
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 3383},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 166, Snippet: "function upload_file($source, $target) {"},
					Sink:     Location{Path: "files.php", Line: 3383, Snippet: "$ret = unlink($path);"},
					Callable: "function::upload_file",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 3383 {
		t.Fatalf("deduped sink line = %d, want 3383", deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsCollapsesUploadApiSurfaceAtSameSinkSite(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "upload-api-surface",
			Path:    "/tmp/plugin/st-wxr-importer.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 522},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: uploadValidationSurfaceMessage,
				Trace: Trace{
					Source:   Location{Path: "class-astra-sites-wp-cli.php", Line: 807, Snippet: "public static function real_mime_types( $defaults, $file, $filename, $mimes, $real_mime ) {"},
					Sink:     Location{Path: "st-wxr-importer.php", Line: 522},
					Callable: "method::\\Demo::real_mime_types_cli",
				},
			},
		},
		{
			CheckID: "upload-api-surface",
			Path:    "/tmp/plugin/st-wxr-importer.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 522},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: uploadValidationSurfaceMessage,
				Trace: Trace{
					Source:   Location{Path: "st-wxr-importer.php", Line: 503, Snippet: "public function real_mime_types( $defaults, $file, $filename, $mimes ) {"},
					Sink:     Location{Path: "st-wxr-importer.php", Line: 522},
					Callable: "method::\\Demo::real_mime_types_importer",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 522 {
		t.Fatalf("deduped sink line = %d, want 522", deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsKeepsUploadApiSurfaceDistinctSinkSites(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "upload-api-surface",
			Path:    "/tmp/plugin/st-wxr-importer.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 522},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: uploadValidationSurfaceMessage,
				Trace: Trace{
					Source:   Location{Path: "class-astra-sites-wp-cli.php", Line: 807, Snippet: "public static function real_mime_types( $defaults, $file, $filename, $mimes, $real_mime ) {"},
					Sink:     Location{Path: "st-wxr-importer.php", Line: 522},
					Callable: "method::\\Demo::real_mime_types_cli",
				},
			},
		},
		{
			CheckID: "upload-api-surface",
			Path:    "/tmp/plugin/st-wxr-importer.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 523},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: uploadValidationSurfaceMessage,
				Trace: Trace{
					Source:   Location{Path: "st-wxr-importer.php", Line: 503, Snippet: "public function real_mime_types( $defaults, $file, $filename, $mimes ) {"},
					Sink:     Location{Path: "st-wxr-importer.php", Line: 523},
					Callable: "method::\\Demo::real_mime_types_importer",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 2", len(deduped))
	}
}

func TestDedupeFinalFindingsKeepsFileDeleteDistinctWhenSinkSnippetDiffers(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 3383},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 60, Snippet: "$unique_id = sanitize_text_field($_POST['id']);"},
					Sink:     Location{Path: "files.php", Line: 3383, Snippet: "$ret = unlink($path);"},
					Callable: "function::ajax_callback",
				},
			},
		},
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 3400},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 166, Snippet: "function upload_file($source, $target) {"},
					Sink:     Location{Path: "files.php", Line: 3400, Snippet: "else return unlink($path);"},
					Callable: "function::upload_file",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 2", len(deduped))
	}
}

func TestDedupeFinalFindingsPrefersPathLikeSourceForFileDeleteCluster(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/array-merge-structural.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 9},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "array-merge-structural.php", Line: 14, Snippet: "array('value' => array('file' => array('file_path' => $_POST['path']))),"},
					Sink:     Location{Path: "array-merge-structural.php", Line: 9, Snippet: "unlink($path);"},
					Callable: "file::array-merge-structural.php",
				},
			},
		},
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/array-merge-structural.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 9},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "array-merge-structural.php", Line: 15, Snippet: "array('value' => array('text' => $_POST['text'])),"},
					Sink:     Location{Path: "array-merge-structural.php", Line: 9, Snippet: "unlink($path);"},
					Callable: "file::array-merge-structural.php",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 14 {
		t.Fatalf("deduped source line = %d, want 14", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsCollapsesSensitiveActionSameSnippetCluster(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 92},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 89, Snippet: "$value = Util_Request::get_string( 'value' );"},
					Sink:     Location{Path: "admin.php", Line: 92, Snippet: "$config_state->set( $key, $value );"},
					Callable: "method::\\Demo::config_state",
				},
			},
		},
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 102},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 99, Snippet: "$value = Util_Request::get_string( 'value' );"},
					Sink:     Location{Path: "admin.php", Line: 102, Snippet: "$config_state->set( $key, $value );"},
					Callable: "method::\\Demo::config_state_master",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 92 {
		t.Fatalf("deduped sink line = %d, want 92", deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsKeepsSensitiveActionDistinctWhenSinkSnippetDiffers(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 92},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 89, Snippet: "$value = Util_Request::get_string( 'value' );"},
					Sink:     Location{Path: "admin.php", Line: 92, Snippet: "$config_state->set( $key, $value );"},
					Callable: "method::\\Demo::config_state",
				},
			},
		},
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 113},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 110, Snippet: "$value = Util_Request::get_string( 'value' );"},
					Sink:     Location{Path: "admin.php", Line: 113, Snippet: "$state_note->set( $key, $value );"},
					Callable: "method::\\Demo::config_state_note",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 2", len(deduped))
	}
}

func TestDedupeFinalFindingsCollapsesRequestPathReadDeleteAcrossEquivalentSinkCallables(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "request-path-read-delete",
			Path:    "/tmp/plugin/bypasser.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 231},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestPathReadDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "backup-heart.php", Line: 56, Snippet: "foreach ($fields as $key => $value) {"},
					Sink:     Location{Path: "bypasser.php", Line: 231, Snippet: "if (file_exists($this->manifest)) @unlink($this->manifest);"},
					Callable: "file::backup-heart.php::\\BMI\\Plugin\\Heart",
				},
			},
		},
		{
			CheckID: "request-path-read-delete",
			Path:    "/tmp/plugin/bypasser.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 231},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestPathReadDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "backup-heart.php", Line: 22, Snippet: "foreach ($_SERVER as $name => $value) {"},
					Sink:     Location{Path: "bypasser.php", Line: 231, Snippet: "if (file_exists($this->manifest)) @unlink($this->manifest);"},
					Callable: "file::backup-heart.php::\\BMI\\Plugin\\Heart",
				},
			},
		},
		{
			CheckID: "request-path-read-delete",
			Path:    "/tmp/plugin/bypasser.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 231},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestPathReadDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "backup-heart.php", Line: 22, Snippet: "foreach ($_SERVER as $name => $value) {"},
					Sink:     Location{Path: "bypasser.php", Line: 231, Snippet: "if (file_exists($this->manifest)) @unlink($this->manifest);"},
					Callable: "file::backup-heart.php::\\BMI\\Plugin\\AltHeart",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 22 {
		t.Fatalf("deduped source line = %d, want 22", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsKeepsRequestPathReadDeleteDistinctSinkSites(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "request-path-read-delete",
			Path:    "/tmp/plugin/bypasser.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 231},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestPathReadDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "backup-heart.php", Line: 22, Snippet: "foreach ($_SERVER as $name => $value) {"},
					Sink:     Location{Path: "bypasser.php", Line: 231, Snippet: "if (file_exists($this->manifest)) @unlink($this->manifest);"},
					Callable: "file::backup-heart.php::\\BMI\\Plugin\\Heart",
				},
			},
		},
		{
			CheckID: "request-path-read-delete",
			Path:    "/tmp/plugin/bypasser.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 245},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestPathReadDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "backup-heart.php", Line: 22, Snippet: "foreach ($_SERVER as $name => $value) {"},
					Sink:     Location{Path: "bypasser.php", Line: 245, Snippet: "if (file_exists($this->manifest)) @unlink($this->manifest);"},
					Callable: "file::backup-heart.php::\\BMI\\Plugin\\Heart",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 2", len(deduped))
	}
}

func TestDedupeFinalFindingsCollapsesUnsafeUseToBestRequestSource(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 20},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 14, Snippet: "$value = sanitize_text_field( $helper );"},
					Sink:     Location{Path: "admin.php", Line: 20},
					Callable: "method::\\Demo::setup_admin",
				},
			},
		},
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 20},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 9, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 20},
					Callable: "method::\\Demo::setup_admin",
				},
			},
		},
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 20},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 9, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 20},
					Callable: "file::admin.php",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 9 {
		t.Fatalf("deduped source line = %d, want 9", deduped[0].Extra.Trace.Source.Line)
	}
	if deduped[0].Extra.Trace.Callable != "method::\\Demo::setup_admin" {
		t.Fatalf("deduped callable = %q, want method::\\\\Demo::setup_admin", deduped[0].Extra.Trace.Callable)
	}
}

func TestDedupeFinalFindingsCollapsesStoredXSSToBestStoredWriteVariant(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/includes/Templates/admin-metaboxes-calcs.html.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 6},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "includes/Admin/Metaboxes/AppendAForm.php", Line: 45, Snippet: "$form_id = absint( $_POST['ninja_form_select'] );"},
					Sink:     Location{Path: "includes/Templates/admin-metaboxes-calcs.html.php", Line: 6},
					Callable: "method::\\NF_Admin_Metaboxes_Calculations::render_metabox",
				},
				StoredWriteContext: FlowContext{
					Access: "capability_checked",
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_nf_ajax_submit",
						Access:   "authenticated",
						Location: Location{Path: "includes/AJAX/Controllers/Submission.php", Line: 29},
					}},
				},
			},
		},
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/includes/Templates/admin-metaboxes-calcs.html.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 6},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "includes/Abstracts/Model.php", Line: 503, Snippet: "$table_data = $wpdb->get_results($obj_query, ARRAY_A);"},
					Sink:     Location{Path: "includes/Templates/admin-metaboxes-calcs.html.php", Line: 6},
					Callable: "method::\\NF_Admin_Metaboxes_Calculations::render_metabox",
				},
				StoredWriteContext: FlowContext{
					Access: "nonce_only",
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_nf_ajax_submit",
						Access:   "authenticated",
						Location: Location{Path: "includes/AJAX/Controllers/Submission.php", Line: 29},
					}},
					NonceChecks: []Location{{
						Path: "includes/AJAX/Controllers/Submission.php",
						Line: 51,
					}},
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Path != "includes/Abstracts/Model.php" || deduped[0].Extra.Trace.Source.Line != 503 {
		t.Fatalf("deduped source = %#v, want includes/Abstracts/Model.php:503", deduped[0].Extra.Trace.Source)
	}
	if deduped[0].Extra.StoredWriteContext.Access != "nonce_only" {
		t.Fatalf("deduped stored_write_context access = %q, want nonce_only", deduped[0].Extra.StoredWriteContext.Access)
	}
}

func TestDedupeFinalFindingsCollapsesUnsafeUseAcrossEquivalentSinkCallables(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 20},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 9, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 20, Snippet: "maybe_unserialize( $value );"},
					Callable: "method::\\Demo::run_a",
				},
			},
		},
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 20},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 9, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 20, Snippet: "maybe_unserialize( $value );"},
					Callable: "method::\\Demo::run_b",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Callable != "method::\\Demo::run_a" {
		t.Fatalf("deduped callable = %q, want method::\\Demo::run_a", deduped[0].Extra.Trace.Callable)
	}
}

func TestDedupeFinalFindingsCollapsesUnsafeUseAssertCluster(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/auth.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 108},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "utils.php", Line: 168, Snippet: "$newtoken = maybe_unserialize( $_POST['token'] );"},
					Sink:     Location{Path: "auth.php", Line: 108, Snippet: "assert( ! empty( $newtoken ) );"},
					Callable: "method::\\Demo::refreshToken",
				},
			},
		},
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/auth.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 109},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "utils.php", Line: 168, Snippet: "$newtoken = maybe_unserialize( $_POST['token'] );"},
					Sink:     Location{Path: "auth.php", Line: 109, Snippet: "assert( ! empty( $newtoken->expires ) );"},
					Callable: "method::\\Demo::refreshToken",
				},
			},
		},
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/auth.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 110},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "utils.php", Line: 168, Snippet: "$newtoken = maybe_unserialize( $_POST['token'] );"},
					Sink:     Location{Path: "auth.php", Line: 110, Snippet: "assert( ! empty( $newtoken->token ) );"},
					Callable: "method::\\Demo::refreshToken",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Sink.Line != 108 {
		t.Fatalf("deduped sink line = %d, want 108", deduped[0].Extra.Trace.Sink.Line)
	}
}

func TestDedupeFinalFindingsKeepsUnsafeUseDistinctForNonAssertSink(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/auth.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 108},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "utils.php", Line: 168, Snippet: "$newtoken = maybe_unserialize( $_POST['token'] );"},
					Sink:     Location{Path: "auth.php", Line: 108, Snippet: "assert( ! empty( $newtoken ) );"},
					Callable: "method::\\Demo::refreshToken",
				},
			},
		},
		{
			CheckID: "unsafe-use",
			Path:    "/tmp/plugin/auth.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 220},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeUseMessage,
				Trace: Trace{
					Source:   Location{Path: "utils.php", Line: 168, Snippet: "$newtoken = maybe_unserialize( $_POST['token'] );"},
					Sink:     Location{Path: "auth.php", Line: 220, Snippet: "call_user_func( $callback, $newtoken );"},
					Callable: "method::\\Demo::refreshToken",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 2", len(deduped))
	}
}

func TestDedupeFinalFindingsCollapsesRequestRecordReadOutputAcrossEquivalentSinkCallables(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-record-read-to-output-without-cap-check",
			Path:    "/tmp/plugin/logs.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 72},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestRecordOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "logs.php", Line: 12, Snippet: "$id = sanitize_text_field( $_GET['log_id'] );"},
					Sink:     Location{Path: "logs.php", Line: 72, Snippet: "echo $row['msg'];"},
					Callable: "method::\\Demo::show_log_a",
				},
			},
		},
		{
			CheckID: "wp-request-record-read-to-output-without-cap-check",
			Path:    "/tmp/plugin/logs.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 72},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestRecordOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "logs.php", Line: 12, Snippet: "$id = sanitize_text_field( $_GET['log_id'] );"},
					Sink:     Location{Path: "logs.php", Line: 72, Snippet: "echo $row['msg'];"},
					Callable: "method::\\Demo::show_log_b",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Callable != "method::\\Demo::show_log_a" {
		t.Fatalf("deduped callable = %q, want method::\\Demo::show_log_a", deduped[0].Extra.Trace.Callable)
	}
}

func TestDedupeFinalFindingsCollapsesRequestRecordReadOutputAcrossRendererLines(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-record-read-to-output-without-cap-check",
			Path:    "/tmp/plugin/email-content.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 114},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestRecordOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "email-content.php", Line: 22, Snippet: "$log = $wpdb->get_row(...);"},
					Sink:     Location{Path: "email-content.php", Line: 114, Snippet: "echo esc_html( $log['from_header'] );"},
					Callable: "method::\\Demo::render_html",
				},
			},
		},
		{
			CheckID: "wp-request-record-read-to-output-without-cap-check",
			Path:    "/tmp/plugin/email-content.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 126},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestRecordOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "email-content.php", Line: 22, Snippet: "$log = $wpdb->get_row(...);"},
					Sink:     Location{Path: "email-content.php", Line: 126, Snippet: "echo esc_html( $log['subject'] );"},
					Callable: "method::\\Demo::render_html",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 114 {
		t.Fatalf("deduped sink line = %d, want 114", deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsCollapsesStoredXSSAcrossEquivalentSinkCallables(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/includes/admin/templates/pages/refer.url.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 43},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "includes/class-wp-statistics-helper.php", Line: 309, Snippet: "$first_day = $wpdb->get_var(...)"},
					Sink:     Location{Path: "includes/admin/templates/pages/refer.url.php", Line: 43},
					Callable: "method::\\WP_STATISTICS\\refer_page::view",
				},
			},
		},
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/includes/admin/templates/pages/refer.url.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 43},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "includes/admin/class-wp-statistics-admin-ajax.php", Line: 293, Snippet: "$referrers = $wpdb->get_results(...)"},
					Sink:     Location{Path: "includes/admin/templates/pages/refer.url.php", Line: 43},
					Callable: "method::\\WP_STATISTICS\\top_visitors_page::view",
				},
				StoredWriteContext: FlowContext{
					Access: "capability_checked",
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_wp_statistics_referrers",
						Access:   "authenticated",
						Location: Location{Path: "includes/admin/class-wp-statistics-admin-ajax.php", Line: 34},
					}},
					NonceChecks: []Location{{
						Path: "includes/admin/class-wp-statistics-admin-ajax.php",
						Line: 269,
					}},
					CapabilityChecks: []Location{{
						Path: "includes/class-wp-statistics-user.php",
						Line: 180,
					}},
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Path != "includes/admin/class-wp-statistics-admin-ajax.php" || deduped[0].Extra.Trace.Source.Line != 293 {
		t.Fatalf("deduped source = %#v, want includes/admin/class-wp-statistics-admin-ajax.php:293", deduped[0].Extra.Trace.Source)
	}
	if deduped[0].Extra.Trace.Callable != "method::\\WP_STATISTICS\\top_visitors_page::view" {
		t.Fatalf("deduped callable = %q, want method::\\\\WP_STATISTICS\\\\top_visitors_page::view", deduped[0].Extra.Trace.Callable)
	}
	if deduped[0].Extra.StoredWriteContext.Access != "capability_checked" {
		t.Fatalf("deduped stored_write_context access = %q, want capability_checked", deduped[0].Extra.StoredWriteContext.Access)
	}
}

func TestDedupeFinalFindingsCollapsesStoredXSSAcrossRendererLines(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/popup.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 11},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 173, Snippet: "$value = get_option( 'popup_content' );"},
					Sink:     Location{Path: "popup.php", Line: 11, Snippet: "echo $popup['headline'];"},
					Callable: "file::popup.php",
				},
			},
		},
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/popup.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 29},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 173, Snippet: "$value = get_option( 'popup_content' );"},
					Sink:     Location{Path: "popup.php", Line: 29, Snippet: "echo $popup['cta'];"},
					Callable: "file::popup.php",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 11 {
		t.Fatalf("deduped sink line = %d, want 11", deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsCollapsesStoredXSSAcrossDistinctCrossFileTemplateLinesToBestSink(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/includes/admin/templates/pages/refer.url.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 9},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "includes/class-wp-statistics-referred.php", Line: 183, Snippet: "$items = Visitor::prepareData(...);"},
					Sink:     Location{Path: "includes/admin/templates/pages/refer.url.php", Line: 5, Snippet: "<?php echo number_format_i18n($total); ?>"},
					Callable: "method::\\WP_STATISTICS\\refer_page::view",
				},
			},
		},
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/includes/admin/templates/pages/refer.url.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 43},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "includes/class-wp-statistics-referred.php", Line: 183, Snippet: "$items = Visitor::prepareData(...);"},
					Sink:     Location{Path: "includes/admin/templates/pages/refer.url.php", Line: 43, Snippet: "echo preg_replace(...);"},
					Callable: "method::\\WP_STATISTICS\\refer_page::view",
				},
			},
		},
		{
			CheckID: "wp-stored-xss-persistent-read-to-output",
			Path:    "/tmp/plugin/includes/admin/templates/pages/refer.url.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 52},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: storedXSSOutputMessage,
				Trace: Trace{
					Source:   Location{Path: "includes/class-wp-statistics-referred.php", Line: 183, Snippet: "$items = Visitor::prepareData(...);"},
					Sink:     Location{Path: "includes/admin/templates/pages/refer.url.php", Line: 52, Snippet: "<?php echo isset($pagination) ? $pagination : ''; ?>"},
					Callable: "method::\\WP_STATISTICS\\refer_page::view",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 43 {
		t.Fatalf("deduped sink line = %d, want 43", deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsCollapsesGenericActionRuleBySinkSite(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 60},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 14, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 60, Snippet: "update_option( 'demo_a', $value );"},
					Callable: "method::\\Demo::save_settings",
				},
			},
		},
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 60},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 16, Snippet: "$value = sanitize_text_field( $_POST['other'] );"},
					Sink:     Location{Path: "admin.php", Line: 60, Snippet: "update_option( 'demo_a', $value );"},
					Callable: "method::\\Demo::save_settings_ajax",
				},
			},
		},
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 64},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 14, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 64, Snippet: "update_option( 'demo_b', $value );"},
					Callable: "method::\\Demo::save_settings",
				},
			},
		},
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 64},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 14, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 64, Snippet: "update_option( 'demo_b', $value );"},
					Callable: "method::\\Demo::save_settings",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 60 {
		t.Fatalf("deduped line = %d, want 60", deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsCollapsesUnsafeDeserializationBySinkSite(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 2864},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "controller-a.php", Line: 12, Snippet: "$value = $_POST['data'];"},
					Sink:     Location{Path: "helpers.php", Line: 2864, Snippet: "return maybe_unserialize( $data );"},
					Callable: "method::\\Demo::load_a",
				},
			},
		},
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 2864},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "controller-b.php", Line: 18, Snippet: "$value = filter_input( INPUT_POST, 'payload', FILTER_DEFAULT );"},
					Sink:     Location{Path: "helpers.php", Line: 2864, Snippet: "return maybe_unserialize( $data );"},
					Callable: "method::\\Demo::load_b",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Path != "/tmp/plugin/helpers.php" || deduped[0].Start.Line != 2864 {
		t.Fatalf("deduped sink = %s:%d, want /tmp/plugin/helpers.php:2864", deduped[0].Path, deduped[0].Start.Line)
	}
}

func TestDedupeFinalFindingsKeepsUnsafeDeserializationSameFileVariants(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 2864},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 200, Snippet: "$rows = $wpdb->get_results( $sql, ARRAY_A );"},
					Sink:     Location{Path: "helpers.php", Line: 2864, Snippet: "return maybe_unserialize( $data );"},
					Callable: "method::\\Demo::get_entries",
				},
			},
		},
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 2864},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 240, Snippet: "$detail_arr = $wpdb->get_results( $sql, ARRAY_A );"},
					Sink:     Location{Path: "helpers.php", Line: 2864, Snippet: "return maybe_unserialize( $data );"},
					Callable: "method::\\Demo::get_lead_detail",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 2", len(deduped))
	}
}

func TestDedupeFinalFindingsCollapsesUnsafeDeserializationSameFileSameSourceCluster(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 2864},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 11113, Snippet: "$coupon_meta = $wpdb->get_var( $sql );"},
					Sink:     Location{Path: "helpers.php", Line: 2864, Snippet: "return maybe_unserialize( $data );"},
					Callable: "method::\\Demo::send_email_a",
				},
			},
		},
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 2864},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 11113, Snippet: "$coupon_meta = $wpdb->get_var( $sql );"},
					Sink:     Location{Path: "helpers.php", Line: 2864, Snippet: "return maybe_unserialize( $data );"},
					Callable: "method::\\Demo::send_email_b",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 11113 {
		t.Fatalf("deduped source line = %d, want 11113", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsCollapsesUnsafeDeserializationFunctionSourceToConcreteSource(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 6034},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "helpers.php", Line: 6028, Snippet: "function demo_maybe_unserialize( $data, $options = array() ) {"},
					Sink:     Location{Path: "helpers.php", Line: 6034, Snippet: "return @unserialize( trim( $data ), $options );"},
					Callable: "method::\\Demo::helper_wrapper",
				},
			},
		},
		{
			CheckID: "unsafe-deserialization",
			Path:    "/tmp/plugin/helpers.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 6034},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: unsafeDeserializationMessage,
				Trace: Trace{
					Source:   Location{Path: "import.php", Line: 146, Snippet: "$form_datas_obj = json_decode( file_get_contents( $_FILES['jsonfile']['tmp_name'] ) );"},
					Sink:     Location{Path: "helpers.php", Line: 6034, Snippet: "return @unserialize( trim( $data ), $options );"},
					Callable: "method::\\Demo::import_form",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 146 {
		t.Fatalf("deduped source line = %d, want 146", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsCollapsesFileUploadBySinkSite(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-file-upload-without-cap-check",
			Path:    "/tmp/plugin/migration.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 756},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileUploadMessage,
				Trace: Trace{
					Source:   Location{Path: "migration.php", Line: 449, Snippet: "$rows = sanitize_text_field( $_GET['rows'] );"},
					Sink:     Location{Path: "migration.php", Line: 756, Snippet: "fwrite($handle, $payload);"},
					Callable: "method::\\Demo::get_old_logs",
				},
			},
		},
		{
			CheckID: "wp-request-file-upload-without-cap-check",
			Path:    "/tmp/plugin/migration.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 756},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileUploadMessage,
				Trace: Trace{
					Source:   Location{Path: "migration.php", Line: 463, Snippet: "$rows = sanitize_text_field( $_POST['rows'] );"},
					Sink:     Location{Path: "migration.php", Line: 756, Snippet: "fwrite($handle, $payload);"},
					Callable: "method::\\Demo::migrate_logs",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
}

func TestDedupeFinalFindingsSuppressesCapabilityCheckedGenericActionRule(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 60},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 14, Snippet: "$value = sanitize_text_field( $_POST['value'] );"},
					Sink:     Location{Path: "admin.php", Line: 60, Snippet: "update_option( 'demo_a', $value );"},
					Callable: "method::\\Demo::save_settings",
				},
				Context: FlowContext{
					Access: "capability_checked",
					CapabilityChecks: []Location{{
						Path:    "admin.php",
						Line:    22,
						Snippet: "if ( current_user_can( 'manage_options' ) ) {",
					}},
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_demo_save_settings",
						Access:   "authenticated",
						Location: Location{Path: "admin.php", Line: 10},
					}},
				},
			},
		},
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 64},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 16, Snippet: "$value = sanitize_text_field( $_POST['other'] );"},
					Sink:     Location{Path: "admin.php", Line: 64, Snippet: "update_option( 'demo_b', $value );"},
					Callable: "method::\\Demo::save_settings_ajax",
				},
				Context: FlowContext{
					Access: "nonce_only",
					NonceChecks: []Location{{
						Path:    "admin.php",
						Line:    30,
						Snippet: "if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'demo' ) ) {",
					}},
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_demo_save_settings_ajax",
						Access:   "authenticated",
						Location: Location{Path: "admin.php", Line: 12},
					}},
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Context.Access != "nonce_only" {
		t.Fatalf("remaining finding access = %q, want nonce_only", deduped[0].Extra.Context.Access)
	}
}

func TestDedupeFinalFindingsSuppressesMixedAdminAjaxActionWhenSinkHasLocalCapabilityAndNonceGuards(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-sensitive-action-without-cap-check",
			Path:    "/tmp/plugin/admin.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 86},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestSensitiveActionMessage,
				Trace: Trace{
					Source:   Location{Path: "admin.php", Line: 63, Snippet: "$groupID = sanitize_text_field($_GET['group']);"},
					Sink:     Location{Path: "admin.php", Line: 86, Snippet: "echo $zip->file();"},
					Callable: "method::\\Demo::export_all",
				},
				Context: FlowContext{
					Access: "capability_checked",
					EntryPoints: []EntryPoint{
						{
							Kind:     "admin_page",
							Name:     "demo",
							Access:   "authenticated",
							Location: Location{Path: "router.php", Line: 12},
						},
						{
							Kind:     "ajax",
							Name:     "wp_ajax_demo_export",
							Access:   "authenticated",
							Location: Location{Path: "router.php", Line: 18},
						},
					},
					CapabilityChecks: []Location{
						{Path: "admin.php", Line: 61, Snippet: "if ($this->validateToken() && $this->validatePermission('manage_options')) {"},
					},
					NonceChecks: []Location{
						{Path: "admin.php", Line: 61, Snippet: "if ($this->validateToken() && $this->validatePermission('manage_options')) {"},
					},
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 0 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 0", len(deduped))
	}
}

func TestDedupeFinalFindingsSuppressesCapabilityCheckedGenericDeleteRule(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 88},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 18, Snippet: "$path = sanitize_text_field( $_POST['path'] );"},
					Sink:     Location{Path: "files.php", Line: 88, Snippet: "unlink( $path );"},
					Callable: "function::delete_file",
				},
				Context: FlowContext{
					Access: "capability_checked",
					CapabilityChecks: []Location{{
						Path:    "files.php",
						Line:    27,
						Snippet: "if ( current_user_can( 'manage_options' ) ) {",
					}},
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_demo_delete_file",
						Access:   "authenticated",
						Location: Location{Path: "files.php", Line: 12},
					}},
				},
			},
		},
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/files.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 92},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "files.php", Line: 22, Snippet: "$path = sanitize_text_field( $_POST['other_path'] );"},
					Sink:     Location{Path: "files.php", Line: 92, Snippet: "unlink( $path );"},
					Callable: "function::delete_file_nonce_only",
				},
				Context: FlowContext{
					Access: "nonce_only",
					NonceChecks: []Location{{
						Path:    "files.php",
						Line:    31,
						Snippet: "if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'demo' ) ) {",
					}},
					EntryPoints: []EntryPoint{{
						Kind:     "ajax",
						Name:     "wp_ajax_demo_delete_file_nonce_only",
						Access:   "authenticated",
						Location: Location{Path: "files.php", Line: 14},
					}},
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("remaining finding check_id = %q", deduped[0].CheckID)
	}
	if deduped[0].Extra.Context.Access != "nonce_only" {
		t.Fatalf("remaining finding access = %q, want nonce_only", deduped[0].Extra.Context.Access)
	}
}

func TestDedupeFinalFindingsKeepsGenericDeleteRuleWhenCapabilityChecksAreRemoteFromSink(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-file-delete-without-cap-check",
			Path:    "/tmp/plugin/library/model/class-form-entry-model.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 1264},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: requestFileDeleteMessage,
				Trace: Trace{
					Source:   Location{Path: "admin/abstracts/class-admin-view-page.php", Line: 601, Snippet: "$id = filter_input( INPUT_POST, 'id', FILTER_VALIDATE_INT );"},
					Sink:     Location{Path: "library/model/class-form-entry-model.php", Line: 1264, Snippet: "wp_delete_file( $path );"},
					Callable: "method::\\Forminator_Admin_View_Page::process_request",
				},
				Context: FlowContext{
					Access: "capability_checked",
					EntryPoints: []EntryPoint{
						{
							Kind:     "admin_page",
							Name:     "forminator-entries",
							Access:   "authenticated",
							Location: Location{Path: "admin/router.php", Line: 10},
						},
						{
							Kind:     "ajax",
							Name:     "wp_ajax_forminator_delete_entry",
							Access:   "authenticated",
							Location: Location{Path: "admin/ajax.php", Line: 20},
						},
					},
					CapabilityChecks: []Location{
						{Path: "admin/classes/class-admin.php", Line: 34, Snippet: "if ( current_user_can( 'manage_options' ) ) {"},
					},
					NonceChecks: []Location{
						{Path: "admin/abstracts/class-admin-view-page.php", Line: 582, Snippet: "if ( ! $nonce || ! wp_verify_nonce( $nonce, 'forminatorEntries' ) ) {"},
					},
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("remaining finding check_id = %q", deduped[0].CheckID)
	}
}

func TestDedupeFinalFindingsCollapsesDistinctRenderCallbackSourcesAtSameSinkSite(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "render-callback-execution",
			Path:    "Inc/Frontend/class-form-processor.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 700},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: renderCallbackMessage,
				Trace: Trace{
					Source:   Location{Path: "Inc/Frontend/class-form-processor.php", Line: 302, Snippet: "$this->data = $this->prepare_post_data(stripslashes_deep($_POST['data']));"},
					Sink:     Location{Path: "Inc/Frontend/class-form-processor.php", Line: 700, Snippet: "$this->placeholdered_data['{thisPermalink}'] = call_user_func($this->placeholdered_data['{thisPermalink}']);"},
					Callable: "\\KaliForms\\Inc\\Frontend\\Form_Processor::form_process",
				},
			},
		},
		{
			CheckID: "render-callback-execution",
			Path:    "Inc/Frontend/class-form-processor.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 700},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: renderCallbackMessage,
				Trace: Trace{
					Source:   Location{Path: "Inc/Frontend/class-form-processor.php", Line: 730, Snippet: "$this->placeholdered_data = apply_filters('demo/render', $this->placeholdered_data);"},
					Sink:     Location{Path: "Inc/Frontend/class-form-processor.php", Line: 700, Snippet: "$this->placeholdered_data['{thisPermalink}'] = call_user_func($this->placeholdered_data['{thisPermalink}']);"},
					Callable: "\\KaliForms\\Inc\\Frontend\\Form_Processor::form_process",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 730 {
		t.Fatalf("deduped source line = %d, want 730", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsPrefersPreparedPostDataRenderCallbackSource(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "render-callback-execution",
			Path:    "Inc/Frontend/class-form-processor.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 700},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: renderCallbackMessage,
				Trace: Trace{
					Source:   Location{Path: "Inc/Frontend/class-form-processor.php", Line: 302, Snippet: "$this->data = $this->prepare_post_data(stripslashes_deep($_POST['data']));"},
					Sink:     Location{Path: "Inc/Frontend/class-form-processor.php", Line: 700, Snippet: "$this->placeholdered_data['{thisPermalink}'] = call_user_func($this->placeholdered_data['{thisPermalink}']);"},
					Callable: "\\KaliForms\\Inc\\Frontend\\Form_Processor::form_process",
				},
			},
		},
		{
			CheckID: "render-callback-execution",
			Path:    "Inc/Frontend/class-form-processor.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 700},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: renderCallbackMessage,
				Trace: Trace{
					Source:   Location{Path: "Inc/Frontend/class-form-processor.php", Line: 730, Snippet: "$id = $_POST['data'][$uploadField];"},
					Sink:     Location{Path: "Inc/Frontend/class-form-processor.php", Line: 700, Snippet: "$this->placeholdered_data['{thisPermalink}'] = call_user_func($this->placeholdered_data['{thisPermalink}']);"},
					Callable: "\\KaliForms\\Inc\\Frontend\\Form_Processor::form_process",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 302 {
		t.Fatalf("deduped source line = %d, want 302", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsCollapsesRenderCallbackSameSourceAcrossCallables(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "render-callback-execution",
			Path:    "inc/admin/sub-menus/abstract-submenu.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 390},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: renderCallbackMessage,
				Trace: Trace{
					Source:   Location{Path: "inc/admin/sub-menus/abstract-submenu.php", Line: 229, Snippet: "$tab = LP_Helper::sanitize_params_submitted( $_REQUEST['tab'] ?? '' );"},
					Sink:     Location{Path: "inc/admin/sub-menus/abstract-submenu.php", Line: 390, Snippet: "call_user_func_array( $callback, array() );"},
					Callable: "\\LP_Abstract_Submenu::page_content",
				},
			},
		},
		{
			CheckID: "render-callback-execution",
			Path:    "inc/admin/sub-menus/abstract-submenu.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 390},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: renderCallbackMessage,
				Trace: Trace{
					Source:   Location{Path: "inc/admin/sub-menus/abstract-submenu.php", Line: 229, Snippet: "$tab = LP_Helper::sanitize_params_submitted( $_REQUEST['tab'] ?? '' );"},
					Sink:     Location{Path: "inc/admin/sub-menus/abstract-submenu.php", Line: 390, Snippet: "call_user_func_array( $callback, array() );"},
					Callable: "\\LP_Submenu_Themes::page_content",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 229 {
		t.Fatalf("deduped source line = %d, want 229", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsCollapsesRenderCallbackDistinctSourcesAndCallablesAtSameSink(t *testing.T) {
	// 16 different REST-API callables all funnelling into the same dynamic-callback
	// sink should collapse to a single finding. The vulnerability is at the sink,
	// not at whichever endpoint triggered it.
	const sinkPath = "fields-shared-callable.php"
	const sinkLine = 71
	makeRCF := func(srcLine int, srcSnippet, callable string) Finding {
		return Finding{
			CheckID: "render-callback-execution",
			Path:    sinkPath,
			Start:   struct{ Line int `json:"line"` }{Line: sinkLine},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: renderCallbackMessage,
				Trace: Trace{
					Source:   Location{Path: "class-recipe-post-rest-api.php", Line: srcLine, Snippet: srcSnippet},
					Sink:     Location{Path: sinkPath, Line: sinkLine},
					Callable: callable,
				},
			},
		}
	}
	findings := []Finding{
		makeRCF(588, "$recipe_id = absint( $request->get_param('recipe_id') );", `\Uncanny_Automator\Recipe_Post_Rest_Api::delete`),
		makeRCF(635, "$recipe_id  = absint( $request->get_param('recipe_id') );", `\Uncanny_Automator\Recipe_Post_Rest_Api::update`),
		makeRCF(841, "$post_id     = absint( $request->get_param('post_id') );", `\Uncanny_Automator\Recipe_Post_Rest_Api::change_post_status`),
		makeRCF(920, "$post_id     = absint( $request->get_param('post_id') );", `\Uncanny_Automator\Recipe_Post_Rest_Api::change_post_recipe_type`),
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1 (same sink should collapse all callables)", len(deduped))
	}
	if deduped[0].Extra.Trace.Sink.Line != sinkLine {
		t.Fatalf("collapsed finding sink line = %d, want %d", deduped[0].Extra.Trace.Sink.Line, sinkLine)
	}
}

func TestDedupeFinalFindingsCollapsesPrivilegeMutationBySinkSite(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-tainted-privilege-mutation",
			Path:    "/tmp/plugin/MembersService.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 217},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: privilegeMutationMessage,
				Trace: Trace{
					Source:   Location{Path: "AJAX.php", Line: 121, Snippet: "$data = apply_filters( 'demo_before_register', isset( $_POST['members_data'] ) ? (array) json_decode( wp_unslash( $_POST['members_data'] ), true ) : array() );"},
					Sink:     Location{Path: "MembersService.php", Line: 217, Snippet: "$user->set_role( $data['role'] );"},
					Callable: "method::\\Demo::register_member",
				},
			},
		},
		{
			CheckID: "wp-request-tainted-privilege-mutation",
			Path:    "/tmp/plugin/MembersService.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 217},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: privilegeMutationMessage,
				Trace: Trace{
					Source:   Location{Path: "import.php", Line: 146, Snippet: "$form_datas_obj = json_decode( file_get_contents( $_FILES['jsonfile']['tmp_name'] ) );"},
					Sink:     Location{Path: "MembersService.php", Line: 217, Snippet: "$user->set_role( $data['role'] );"},
					Callable: "method::\\Demo::upgrade_membership",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Extra.Trace.Source.Line != 121 {
		t.Fatalf("deduped source line = %d, want 121", deduped[0].Extra.Trace.Source.Line)
	}
}

func TestDedupeFinalFindingsKeepsPrivilegeMutationDistinctSinkSites(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-tainted-privilege-mutation",
			Path:    "/tmp/plugin/MembersService.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 217},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: privilegeMutationMessage,
				Trace: Trace{
					Source:   Location{Path: "AJAX.php", Line: 121, Snippet: "$data = apply_filters( 'demo_before_register', isset( $_POST['members_data'] ) ? (array) json_decode( wp_unslash( $_POST['members_data'] ), true ) : array() );"},
					Sink:     Location{Path: "MembersService.php", Line: 217, Snippet: "$user->set_role( $data['role'] );"},
					Callable: "method::\\Demo::register_member",
				},
			},
		},
		{
			CheckID: "wp-request-tainted-privilege-mutation",
			Path:    "/tmp/plugin/MembersRepository.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 38},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: privilegeMutationMessage,
				Trace: Trace{
					Source:   Location{Path: "AJAX.php", Line: 954, Snippet: "$data = isset( $_POST['members_data'] ) ? (array) json_decode( wp_unslash( $_POST['members_data'] ), true ) : array();"},
					Sink:     Location{Path: "MembersRepository.php", Line: 38, Snippet: "$user->set_role( $data['role'] );"},
					Callable: "method::\\Demo::create_member",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 2", len(deduped))
	}
}

func TestDedupeFinalFindingsCollapsesPrivilegeMutationSameSourceSinkSnippetAcrossCallables(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "wp-request-tainted-privilege-mutation",
			Path:    "/tmp/plugin/MembersMenu.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 562},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: privilegeMutationMessage,
				Trace: Trace{
					Source:   Location{Path: "MembersMenu.php", Line: 529, Snippet: "$role           = $_REQUEST['new_role'];"},
					Sink:     Location{Path: "MembersMenu.php", Line: 562, Snippet: "$user->set_role( $role );"},
					Callable: "method::\\Demo::handle_members_actions",
				},
			},
		},
		{
			CheckID: "wp-request-tainted-privilege-mutation",
			Path:    "/tmp/plugin/UsersMenu.php",
			Start: struct {
				Line int `json:"line"`
			}{Line: 1466},
			Extra: struct {
				Message            string      `json:"message"`
				Trace              Trace       `json:"dataflow_trace"`
				Context            FlowContext `json:"context,omitempty"`
				StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
			}{
				Message: privilegeMutationMessage,
				Trace: Trace{
					Source:   Location{Path: "UsersMenu.php", Line: 1433, Snippet: "$role           = $_REQUEST['new_role'];"},
					Sink:     Location{Path: "UsersMenu.php", Line: 1466, Snippet: "$user->set_role( $role );"},
					Callable: "method::\\Demo::handle_user_actions",
				},
			},
		},
	}

	deduped := dedupeFinalFindings(findings)
	if len(deduped) != 1 {
		t.Fatalf("dedupeFinalFindings() len = %d, want 1", len(deduped))
	}
	if deduped[0].Start.Line != 562 {
		t.Fatalf("deduped sink line = %d, want 562", deduped[0].Start.Line)
	}
}

func TestCollectStaleRelevantCallablesAddsFingerprintMismatches(t *testing.T) {
	engine := &engine{
		currentBatchName: "delete",
		relevantCallables: map[string]struct{}{
			"caller": {},
		},
		callEdges: map[string]map[string]struct{}{
			"caller": {"callee": {}},
		},
		callSiteEdges: map[string][]callSiteEdge{
			"caller": {{
				callee:       "callee",
				dataCarrier:  true,
				assignedRoot: "$value",
			}},
		},
		summaries: map[string]summary{
			"callee": {
				ReturnSources: []Location{{Path: "demo.php", Line: 10}},
			},
		},
		summaryFingerprints: map[string]string{},
		summaryInputFingerprints: map[string]string{
			"caller": "batch=delete",
		},
		storageReadBucketsByCallable:  map[string]map[string]struct{}{},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
		staticReadPathsByCallable:     map[string]map[string]struct{}{},
		staticReadRootsByCallable:     map[string]map[string]struct{}{},
	}

	pendingSet, staleCount := engine.collectStaleRelevantCallables([]string{"caller"}, nil)
	if staleCount != 1 {
		t.Fatalf("collectStaleRelevantCallables() staleCount = %d, want 1", staleCount)
	}
	if _, ok := pendingSet["caller"]; !ok {
		t.Fatalf("collectStaleRelevantCallables() did not add caller")
	}
}
