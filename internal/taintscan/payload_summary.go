package taintscan

import "time"

type PayloadSummary struct {
	GeneratedAt    string         `json:"generated_at,omitempty"`
	ElapsedMS      int64          `json:"elapsed_ms,omitempty"`
	TotalResults   int            `json:"total_results"`
	TotalErrors    int            `json:"total_errors"`
	ResultsPerRule map[string]int `json:"results_per_rule,omitempty"`
}

func EnrichPayload(payload Payload, generatedAt time.Time, elapsed time.Duration) Payload {
	payload.Summary = &PayloadSummary{
		GeneratedAt:    generatedAt.UTC().Format(time.RFC3339),
		ElapsedMS:      elapsed.Milliseconds(),
		TotalResults:   len(payload.Results),
		TotalErrors:    len(payload.Errors),
		ResultsPerRule: payloadRuleCounts(payload.Results),
	}
	return payload
}

func payloadRuleCounts(results []Finding) map[string]int {
	if len(results) == 0 {
		return nil
	}
	counts := make(map[string]int, len(results))
	for _, finding := range results {
		counts[finding.CheckID]++
	}
	return counts
}
