package corpuscompare

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dimasma0305/wp-taint-scan/internal/taintscan"
)

func TestSupportedSinkOpsForSQL(t *testing.T) {
	ops, ok, reason := SupportedSinkOps([]string{"bugbounty-note/semgrep/sqli.yaml"})
	if !ok {
		t.Fatalf("expected supported SQL config, got reason=%q", reason)
	}
	if len(ops) != 1 || ops[0] != "sql" {
		t.Fatalf("unexpected sink ops: %#v", ops)
	}
}

func TestResolvePluginDirPrefersFixtureDirOverLiveSlug(t *testing.T) {
	t.Helper()
	rootA := t.TempDir()
	rootB := t.TempDir()
	live := filepath.Join(rootA, "uncanny-automator")
	fixture := filepath.Join(rootB, "uncanny-automator__6.4.0.1")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fixture, 0o755); err != nil {
		t.Fatal(err)
	}

	got := ResolvePluginDir(Case{
		Slug:       "uncanny-automator",
		FixtureDir: "uncanny-automator__6.4.0.1",
	}, []string{rootA, rootB})
	if got != fixture {
		t.Fatalf("expected fixture dir %q, got %q", fixture, got)
	}
}

func TestEffectiveSinkOpsUsesDirectOverride(t *testing.T) {
	ops, ok, reason := EffectiveSinkOps(Case{
		Configs:       []string{"bugbounty-note/semgrep/file-upload.yaml"},
		DirectSinkOps: []string{" delete ", "delete", "read"},
	})
	if !ok {
		t.Fatalf("expected direct sink op override, got reason=%q", reason)
	}
	want := []string{"delete", "read"}
	if len(ops) != len(want) {
		t.Fatalf("unexpected direct sink ops: %#v", ops)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("unexpected direct sink ops: %#v", ops)
		}
	}
}

func TestSupportedSinkOpsForFileUploadAndPrivilegeEscalation(t *testing.T) {
	fileOps, ok, reason := SupportedSinkOps([]string{"bugbounty-note/semgrep/file-upload.yaml"})
	if !ok {
		t.Fatalf("expected supported file-upload config, got reason=%q", reason)
	}
	wantFileOps := []string{"delete", "open", "read", "write"}
	if len(fileOps) != len(wantFileOps) {
		t.Fatalf("unexpected file-upload sink ops: %#v", fileOps)
	}
	for i := range wantFileOps {
		if fileOps[i] != wantFileOps[i] {
			t.Fatalf("unexpected file-upload sink ops: %#v", fileOps)
		}
	}

	privOps, ok, reason := SupportedSinkOps([]string{"bugbounty-note/semgrep/privilege-escalation.yaml"})
	if !ok {
		t.Fatalf("expected supported privilege-escalation config, got reason=%q", reason)
	}
	wantPrivOps := []string{"action", "call", "output", "write"}
	if len(privOps) != len(wantPrivOps) {
		t.Fatalf("unexpected privilege-escalation sink ops: %#v", privOps)
	}
	for i := range wantPrivOps {
		if privOps[i] != wantPrivOps[i] {
			t.Fatalf("unexpected privilege-escalation sink ops: %#v", privOps)
		}
	}
}

func TestCoverageComparableRejectsLoweredBridgeFields(t *testing.T) {
	ok, reason := CoverageComparable(Coverage{
		BridgeReadLocationsAny: []string{"models/Files.php:515"},
	})
	if ok {
		t.Fatal("expected bridge-only coverage to be not comparable")
	}
	if reason == "" {
		t.Fatal("expected reason for bridge-only coverage")
	}
}

func TestPreScanComparisonSkipsCaseWithoutComparableCoverage(t *testing.T) {
	comparison, skip := PreScanComparison(Case{
		Configs: []string{"bugbounty-note/semgrep/file-upload.yaml"},
	})
	if !skip {
		t.Fatal("expected pre-scan skip")
	}
	if comparison.Status != StatusNotComparableYet {
		t.Fatalf("expected not comparable yet, got %#v", comparison)
	}
	if comparison.Reason == "" {
		t.Fatal("expected non-empty reason")
	}
	wantOps := []string{"delete", "open", "read", "write"}
	if len(comparison.SinkOps) != len(wantOps) {
		t.Fatalf("unexpected sink ops: %#v", comparison.SinkOps)
	}
	for i := range wantOps {
		if comparison.SinkOps[i] != wantOps[i] {
			t.Fatalf("unexpected sink ops: %#v", comparison.SinkOps)
		}
	}
}

func TestCompareCaseMatchesRulePathAndSinkLocation(t *testing.T) {
	finding := testFinding(
		"tainted-sql-string",
		"/abs/plugins/ultimate-member/includes/core/class-member-directory-meta.php",
		1072,
		taintscan.Location{Path: "includes/core/class-member-directory-meta.php", Line: 322, Snippet: "$value = $_POST['foo'];"},
		taintscan.Location{Path: "includes/core/class-member-directory-meta.php", Line: 1072, Snippet: "$wpdb->get_col($query);"},
		"\\member_directory_meta::handle_filter_query",
	)
	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/sqli.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny: []string{"tainted-sql-string"},
			FindingPathsAny:   []string{"includes/core/class-member-directory-meta.php"},
			SourceStringsAny:  []string{"function handle_filter_query("},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{finding}})
	if comparison.Status != StatusMatch {
		t.Fatalf("expected match, got %#v", comparison)
	}
}

func TestCompareCaseMissesWhenFindingPathDoesNotMatch(t *testing.T) {
	finding := testFinding(
		"tainted-sql-string",
		"/abs/plugins/ultimate-member/includes/admin/core/packages/2.3.0/functions.php",
		74,
		taintscan.Location{Path: "includes/ajax/class-secure.php", Line: 48, Snippet: "$_REQUEST['capabilities']"},
		taintscan.Location{Path: "includes/admin/core/packages/2.3.0/functions.php", Line: 74, Snippet: "$wpdb->get_var($query);"},
		"\\um_upgrade_usermeta_count230",
	)
	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/sqli.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny: []string{"tainted-sql-string"},
			FindingPathsAny:   []string{"includes/core/class-member-directory-meta.php"},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{finding}})
	if comparison.Status != StatusMiss {
		t.Fatalf("expected miss, got %#v", comparison)
	}
}

func TestCompareCaseMatchesTraceSourceAndSinkLocation(t *testing.T) {
	finding := testFinding(
		"wp-request-record-read-to-output-without-cap-check",
		"/abs/plugins/post-smtp/Postman/PostmanEmailLogs.php",
		72,
		taintscan.Location{Path: "Postman/PostmanEmailLogs.php", Line: 66, Snippet: "$id = sanitize_text_field($_GET['log_id']);"},
		taintscan.Location{Path: "Postman/PostmanEmailLogs.php", Line: 72, Snippet: "echo wp_kses_post($msg);"},
		"\\PostmanEmailLogs::__construct",
	)
	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/privilege-escalation.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny:     []string{"wp-request-record-read-to-output-without-cap-check"},
			FindingPathsAny:       []string{"Postman/PostmanEmailLogs.php"},
			TraceSourceStringsAny: []string{"$_GET['log_id']"},
			TraceSinkLocationsAny: []string{"Postman/PostmanEmailLogs.php:72"},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{finding}})
	if comparison.Status != StatusMatch {
		t.Fatalf("expected match, got %#v", comparison)
	}
}

func TestCompareCasePrefersDirectTraceSourceMatchOverCallableOnlyMatch(t *testing.T) {
	callableOnly := testFinding(
		"tainted-sql-string",
		"/abs/plugins/ultimate-member/includes/core/class-member-directory-meta.php",
		757,
		taintscan.Location{Path: "includes/admin/core/class-admin-metabox.php", Line: 1284, Snippet: "$form_meta = sanitize_form_meta($_POST['form']);"},
		taintscan.Location{Path: "includes/core/class-member-directory-meta.php", Line: 757, Snippet: "$searches[] = $wpdb->prepare(...);"},
		"\\um\\core\\Member_Directory_Meta::ajax_get_members",
	)
	callableOnly.Extra.StoredWriteContext.Access = "nonce_only"

	directTrace := testFinding(
		"tainted-sql-string",
		"/abs/plugins/ultimate-member/includes/core/class-member-directory-meta.php",
		1072,
		taintscan.Location{Path: "includes/core/class-member-directory-meta.php", Line: 846, Snippet: "$sortby = ! empty( $_POST['sorting'] ) ? sanitize_text_field( $_POST['sorting'] ) : $directory_data['sortby'];"},
		taintscan.Location{Path: "includes/core/class-member-directory-meta.php", Line: 1072, Snippet: "\"SELECT SQL_CALC_FOUND_ROWS DISTINCT u.ID"},
		"\\um\\core\\Member_Directory_Meta::ajax_get_members",
	)

	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/sqli.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny:     []string{"tainted-sql-string"},
			FindingPathsAny:       []string{"includes/core/class-member-directory-meta.php"},
			TraceSourceStringsAny: []string{"ajax_get_members", "$_POST['sorting']"},
			TraceSinkLocationsAny: []string{"includes/core/class-member-directory-meta.php:757", "includes/core/class-member-directory-meta.php:1072"},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{callableOnly, directTrace}})
	if comparison.Status != StatusMatch {
		t.Fatalf("expected match, got %#v", comparison)
	}
	if comparison.MatchedFinding == nil {
		t.Fatalf("expected matched finding")
	}
	if comparison.MatchedFinding.Line != 1072 {
		t.Fatalf("expected direct trace finding to be preferred, got %#v", comparison.MatchedFinding)
	}
	if comparison.MatchedFinding.Source.Line != 846 {
		t.Fatalf("expected direct source line 846, got %#v", comparison.MatchedFinding.Source)
	}
}

func TestCompareCaseMatchesStoredWriteEntryLocation(t *testing.T) {
	finding := testFinding(
		"wp-stored-xss-persistent-read-to-output",
		"/abs/plugins/ninja-forms/includes/Templates/admin-metaboxes-calcs.html.php",
		6,
		taintscan.Location{Path: "includes/Abstracts/Model.php", Line: 503, Snippet: "$table_data = $wpdb->get_results($obj_query, ARRAY_A);"},
		taintscan.Location{Path: "includes/Templates/admin-metaboxes-calcs.html.php", Line: 6, Snippet: "echo( ' = ' . $contents[ 'value' ] );"},
		"\\NF_Admin_Metaboxes_Calculations::render_metabox",
	)
	finding.Extra.StoredWriteContext.EntryPoints = []taintscan.EntryPoint{
		{
			Kind:   "ajax",
			Name:   "wp_ajax_nf_ajax_submit",
			Access: "authenticated",
			Location: taintscan.Location{
				Path: "includes/AJAX/Controllers/Submission.php",
				Line: 29,
			},
		},
	}
	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/xss.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny:            []string{"wp-stored-xss-persistent-read-to-output"},
			FindingPathsAny:              []string{"includes/Templates/admin-metaboxes-calcs.html.php"},
			TraceSinkLocationsAny:        []string{"includes/Templates/admin-metaboxes-calcs.html.php:6"},
			StoredWriteEntryLocationsAny: []string{"includes/AJAX/Controllers/Submission.php:29"},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{finding}})
	if comparison.Status != StatusMatch {
		t.Fatalf("expected match, got %#v", comparison)
	}
}

func TestCompareCaseMatchesLegacyFileUploadRuleAlias(t *testing.T) {
	finding := testFinding(
		"wp-request-file-delete-without-cap-check",
		"/abs/plugins/forminator/library/model/class-form-entry-model.php",
		1264,
		taintscan.Location{Path: "library/modules/custom-forms/front/front-action.php", Line: 2844, Snippet: "$submitted_data = Forminator_Core::sanitize_array( $_POST );"},
		taintscan.Location{Path: "library/model/class-form-entry-model.php", Line: 1264, Snippet: "wp_delete_file( $path );"},
		"\\Forminator_Form_Entry_Model::delete_uploads",
	)
	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/file-upload.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny: []string{"file-download-upload"},
			FindingPathsAny:   []string{"library/model/class-form-entry-model.php"},
			SourceStringsAny:  []string{"delete_uploads"},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{finding}})
	if comparison.Status != StatusMatch {
		t.Fatalf("expected match, got %#v", comparison)
	}
}

func TestCompareCaseMatchesLegacyFinancialActionRuleAlias(t *testing.T) {
	finding := testFinding(
		"wp-request-sensitive-action-without-cap-check",
		"/abs/plugins/wpforms/src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php",
		87,
		taintscan.Location{Path: "src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php", Line: 65, Snippet: "$payment_id = absint( $_POST['payment_id'] );"},
		taintscan.Location{Path: "src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php", Line: 87, Snippet: "UpdateHelpers::refund_payment( $payment_id );"},
		"\\WPForms\\Integrations\\Stripe\\Admin\\Payments\\SingleActionsHandler::refund",
	)
	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/privilege-escalation.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny: []string{"wp-ajax-financial-action-without-cap-check"},
			FindingPathsAny:   []string{"src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php"},
			SourceStringsAny:  []string{"UpdateHelpers::refund_payment"},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{finding}})
	if comparison.Status != StatusMatch {
		t.Fatalf("expected match, got %#v", comparison)
	}
}

func TestCompareCaseMatchesFindingPathAgainstTraceSourcePath(t *testing.T) {
	finding := testFinding(
		"wp-request-file-delete-without-cap-check",
		"/abs/plugins/sureforms/admin/views/entries-list-table.php",
		684,
		taintscan.Location{Path: "inc/form-submit.php", Line: 226, Snippet: "wp_handle_upload( $_FILES['field'] );"},
		taintscan.Location{Path: "admin/views/entries-list-table.php", Line: 684, Snippet: "unlink( $file_path );"},
		"\\SRFM\\Inc\\Entries_List_Table::delete_entry_files",
	)
	comparison := CompareCase(Case{
		Configs: []string{"bugbounty-note/semgrep/file-upload.yaml"},
		Coverage: Coverage{
			FindingRuleIDsAny: []string{"wordpress-upload-helper-surface"},
			FindingPathsAny:   []string{"inc/form-submit.php"},
			SourceStringsAny:  []string{"wp_handle_upload"},
		},
	}, taintscan.Payload{Results: []taintscan.Finding{finding}})
	if comparison.Status != StatusMatch {
		t.Fatalf("expected match, got %#v", comparison)
	}
}

func testFinding(ruleID string, path string, line int, source taintscan.Location, sink taintscan.Location, callable string) taintscan.Finding {
	var finding taintscan.Finding
	finding.CheckID = ruleID
	finding.Path = path
	finding.Start.Line = line
	finding.Extra.Trace.Source = source
	finding.Extra.Trace.Sink = sink
	finding.Extra.Trace.Callable = callable
	return finding
}
