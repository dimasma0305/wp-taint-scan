package main

import (
	"strings"
	"testing"

	"github.com/dimasma0305/php-parser-go/parsetree"
	"github.com/dimasma0305/wp-taint-scan/internal/taintscan"
)

func TestBuildHumanSummaryGroupsBySink(t *testing.T) {
	makeFinding := func(ruleID string, sinkPath string, sinkLine int, sourcePath string, sourceLine int, callable string, entry taintscan.EntryPoint) taintscan.Finding {
		var finding taintscan.Finding
		finding.CheckID = ruleID
		finding.Path = sinkPath
		finding.Start.Line = sinkLine
		finding.Extra.Trace.Source = taintscan.Location{Path: sourcePath, Line: sourceLine}
		finding.Extra.Trace.Sink = taintscan.Location{Path: sinkPath, Line: sinkLine}
		finding.Extra.Trace.Callable = callable
		finding.Extra.Context.Access = "unauthenticated"
		finding.Extra.Context.EntryPoints = []taintscan.EntryPoint{entry}
		return finding
	}

	entry := taintscan.EntryPoint{
		Kind:   "shortcode",
		Name:   "acfe_form",
		Access: "unauthenticated",
		Location: taintscan.Location{
			Path: "includes/modules/form/module-form-shortcode.php",
			Line: 29,
		},
	}
	result := &taintscan.Result{
		Target: "/tmp/demo",
		Manifest: &parsetree.Manifest{
			Counts: parsetree.ManifestCounts{Parsed: 1, Total: 1},
		},
		Callables: 3,
		Payload: taintscan.Payload{
			Results: []taintscan.Finding{
				makeFinding("render-callback-execution", "/tmp/demo/render.php", 151, "front.php", 492, `\acfe_module_form_front::render_form`, entry),
				makeFinding("render-callback-execution", "/tmp/demo/render.php", 151, "front.php", 447, `\acfe_module_form_front::render_form`, entry),
				makeFinding("render-callback-execution", "/tmp/demo/render.php", 151, "hooks.php", 41, `\acfe_module_form_front_render_hooks::prepare_form`, entry),
			},
		},
	}

	summary := buildHumanSummary(result)
	if !strings.Contains(summary, "- Unique sinks: `1`") {
		t.Fatalf("summary missing unique sink count:\n%s", summary)
	}
	if !strings.Contains(summary, "## Sink Groups") {
		t.Fatalf("summary missing sink groups section:\n%s", summary)
	}
	if !strings.Contains(summary, "`render-callback-execution` at `/tmp/demo/render.php:151`: `3` findings, `3` unique sources, `2` callables") {
		t.Fatalf("summary missing grouped sink stats:\n%s", summary)
	}
	if !strings.Contains(summary, "entrypoints=`shortcode:acfe_form:unauthenticated`") {
		t.Fatalf("summary missing grouped entrypoint label:\n%s", summary)
	}
	if !strings.Contains(summary, "source: `front.php:447`") || !strings.Contains(summary, "source: `hooks.php:41`") {
		t.Fatalf("summary missing representative sources:\n%s", summary)
	}
}

func TestBuildHumanSummaryIncludesStoredWriteContext(t *testing.T) {
	var finding taintscan.Finding
	finding.CheckID = "request-path-read-delete"
	finding.Path = "/tmp/demo/delete.php"
	finding.Start.Line = 14
	finding.Extra.Trace.Source = taintscan.Location{Path: "public.php", Line: 9}
	finding.Extra.Trace.Sink = taintscan.Location{Path: "/tmp/demo/delete.php", Line: 14}
	finding.Extra.Trace.Callable = `\StoredDeleteDemo::delete_item`
	finding.Extra.Context.Access = "capability_checked"
	finding.Extra.StoredWriteContext.Access = "unauthenticated"
	finding.Extra.StoredWriteContext.EntryPoints = []taintscan.EntryPoint{{
		Kind:   "ajax",
		Name:   "wp_ajax_nopriv_demo_store",
		Access: "unauthenticated",
		Location: taintscan.Location{
			Path: "stored-delete.php",
			Line: 4,
		},
	}}

	result := &taintscan.Result{
		Target: "/tmp/demo",
		Manifest: &parsetree.Manifest{
			Counts: parsetree.ManifestCounts{Parsed: 1, Total: 1},
		},
		Callables: 1,
		Payload: taintscan.Payload{Results: []taintscan.Finding{finding}},
	}

	summary := buildHumanSummary(result)
	if !strings.Contains(summary, "stored_access=unauthenticated") {
		t.Fatalf("summary missing stored write access:\n%s", summary)
	}
	if !strings.Contains(summary, "stored_entrypoint=ajax:wp_ajax_nopriv_demo_store") {
		t.Fatalf("summary missing stored write entrypoint:\n%s", summary)
	}
}
