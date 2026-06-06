package scanjob

import (
	"sort"
	"strconv"
)

// enginePayload mirrors the subset of taint-results.json the UI needs.
type enginePayload struct {
	Summary *struct {
		ElapsedMS    int64          `json:"elapsed_ms"`
		TotalResults int            `json:"total_results"`
		PerRule      map[string]int `json:"results_per_rule"`
	} `json:"summary"`
	Results []engineFinding `json:"results"`
	Errors  []string        `json:"errors"`
}

type engineLoc struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type engineContext struct {
	Access             string `json:"access"`
	RequiredCapability string `json:"required_capability"`
	MinimumRole        string `json:"minimum_role"`
	EntryPoints        []struct {
		Kind    string `json:"kind"`
		Name    string `json:"name"`
		Route   string `json:"route"`
		Methods string `json:"methods"`
		Access  string `json:"access"`
	} `json:"entrypoints"`
}

type engineFinding struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message string `json:"message"`
		Trace   struct {
			Source   engineLoc `json:"source"`
			Sink     engineLoc `json:"sink"`
			Callable string    `json:"callable"`
		} `json:"dataflow_trace"`
		Context engineContext `json:"context"`
	} `json:"extra"`
}

func projectFinding(raw engineFinding) Finding {
	access := raw.Extra.Context.Access
	f := Finding{
		RuleID:             raw.CheckID,
		Message:            raw.Extra.Message,
		Path:               raw.Path,
		Line:               raw.Start.Line,
		Access:             access,
		Severity:           severityForAccess(access),
		RequiredCapability: raw.Extra.Context.RequiredCapability,
		MinimumRole:        raw.Extra.Context.MinimumRole,
		Source:             Loc{Path: raw.Extra.Trace.Source.Path, Line: raw.Extra.Trace.Source.Line, Snippet: raw.Extra.Trace.Source.Snippet},
		Sink:               Loc{Path: raw.Extra.Trace.Sink.Path, Line: raw.Extra.Trace.Sink.Line, Snippet: raw.Extra.Trace.Sink.Snippet},
		Callable:           raw.Extra.Trace.Callable,
	}
	for _, e := range raw.Extra.Context.EntryPoints {
		f.EntryPoints = append(f.EntryPoints, EntryPoint{
			Kind: e.Kind, Name: e.Name, Route: e.Route, Methods: e.Methods, Access: e.Access,
		})
	}
	f.Key = raw.CheckID + "|" + raw.Path + ":" + strconv.Itoa(raw.Start.Line) +
		"|" + raw.Extra.Trace.Source.Path + ":" + strconv.Itoa(raw.Extra.Trace.Source.Line)
	return f
}

// severityRank orders severities most-exploitable first.
func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 0
	case SevHigh:
		return 1
	case SevMedium:
		return 2
	case SevLow:
		return 3
	default:
		return 4
	}
}

// sortFindings ranks by exploitability (severity), then rule, then location.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := severityRank(fs[i].Severity), severityRank(fs[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		if fs[i].Path != fs[j].Path {
			return fs[i].Path < fs[j].Path
		}
		return fs[i].Line < fs[j].Line
	})
}
