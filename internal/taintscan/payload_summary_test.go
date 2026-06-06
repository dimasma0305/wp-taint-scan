package taintscan

import (
	"testing"
	"time"
)

func TestEnrichPayloadAddsSummaryCountsAndTiming(t *testing.T) {
	var first Finding
	first.CheckID = "unsafe-use"
	var second Finding
	second.CheckID = "unsafe-use"
	var third Finding
	third.CheckID = "tainted-sql-string"

	payload := Payload{
		Results: []Finding{first, second, third},
		Errors:  []string{"parse failed"},
	}

	finishedAt := time.Date(2026, time.March, 28, 12, 34, 56, 0, time.UTC)
	enriched := EnrichPayload(payload, finishedAt, 1500*time.Millisecond)
	if enriched.Summary == nil {
		t.Fatal("summary is nil")
	}
	if enriched.Summary.GeneratedAt != "2026-03-28T12:34:56Z" {
		t.Fatalf("generated_at = %q, want 2026-03-28T12:34:56Z", enriched.Summary.GeneratedAt)
	}
	if enriched.Summary.ElapsedMS != 1500 {
		t.Fatalf("elapsed_ms = %d, want 1500", enriched.Summary.ElapsedMS)
	}
	if enriched.Summary.TotalResults != 3 {
		t.Fatalf("total_results = %d, want 3", enriched.Summary.TotalResults)
	}
	if enriched.Summary.TotalErrors != 1 {
		t.Fatalf("total_errors = %d, want 1", enriched.Summary.TotalErrors)
	}
	if got := enriched.Summary.ResultsPerRule["unsafe-use"]; got != 2 {
		t.Fatalf("results_per_rule[unsafe-use] = %d, want 2", got)
	}
	if got := enriched.Summary.ResultsPerRule["tainted-sql-string"]; got != 1 {
		t.Fatalf("results_per_rule[tainted-sql-string] = %d, want 1", got)
	}
}

func TestEnrichPayloadOmitsEmptyRuleCounts(t *testing.T) {
	enriched := EnrichPayload(Payload{}, time.Date(2026, time.March, 28, 0, 0, 0, 0, time.UTC), 0)
	if enriched.Summary == nil {
		t.Fatal("summary is nil")
	}
	if enriched.Summary.TotalResults != 0 {
		t.Fatalf("total_results = %d, want 0", enriched.Summary.TotalResults)
	}
	if enriched.Summary.ResultsPerRule != nil {
		t.Fatalf("results_per_rule = %#v, want nil", enriched.Summary.ResultsPerRule)
	}
}
