package taintscan

import "testing"

func TestFlowContextsEquivalentIgnoresOrderAndDuplicates(t *testing.T) {
	entryREST := EntryPoint{
		Kind:    "rest",
		Name:    "demo",
		Route:   "/demo",
		Methods: "GET",
		Access:  "authenticated",
		Location: Location{
			Path:    "rest.php",
			Line:    10,
			Snippet: "register_rest_route",
		},
	}
	entryAJAX := EntryPoint{
		Kind:    "ajax",
		Name:    "demo_ajax",
		Methods: "POST",
		Access:  "unauthenticated",
		Location: Location{
			Path:    "ajax.php",
			Line:    20,
			Snippet: "wp_ajax_nopriv_demo_ajax",
		},
	}
	capA := Location{Path: "checks.php", Line: 30, Snippet: "current_user_can"}
	capB := Location{Path: "checks.php", Line: 30, Snippet: "manage_options"}
	nonce := Location{Path: "checks.php", Line: 40, Snippet: "check_ajax_referer"}

	left := FlowContext{
		EntryPoints:      []EntryPoint{entryAJAX, entryREST, entryREST},
		CapabilityChecks: []Location{capB, capA, capA},
		NonceChecks:      []Location{nonce},
	}
	right := FlowContext{
		EntryPoints:      []EntryPoint{entryREST, entryAJAX},
		CapabilityChecks: []Location{capA, capB},
		NonceChecks:      []Location{nonce, nonce},
	}

	if !flowContextsEquivalent(left, right) {
		t.Fatalf("expected reordered flow contexts with duplicates to compare equal")
	}
}

func TestFlowContextsEquivalentDetectsDistinctEntryPoints(t *testing.T) {
	base := FlowContext{
		EntryPoints: []EntryPoint{{
			Kind:    "rest",
			Name:    "demo",
			Route:   "/demo",
			Methods: "GET",
			Access:  "authenticated",
			Location: Location{
				Path:    "rest.php",
				Line:    10,
				Snippet: "register_rest_route",
			},
		}},
	}
	other := FlowContext{
		EntryPoints: []EntryPoint{{
			Kind:    "rest",
			Name:    "demo",
			Route:   "/demo",
			Methods: "GET",
			Access:  "permission_callback",
			Location: Location{
				Path:    "rest.php",
				Line:    10,
				Snippet: "register_rest_route",
			},
		}},
	}

	if flowContextsEquivalent(base, other) {
		t.Fatalf("expected distinct entry point access to compare different")
	}
}
