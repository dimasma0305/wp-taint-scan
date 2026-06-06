// Package scanjob runs WordPress plugin taint scans as isolated subprocesses,
// managed by a bounded worker pool with download/result caching. Each job
// downloads a plugin version from WordPress.org, extracts it safely, scans it,
// and projects the engine's findings into a compact, UI-friendly shape.
package scanjob

import "time"

// Status is the lifecycle state of a scan job.
type Status string

const (
	StatusQueued      Status = "queued"
	StatusDownloading Status = "downloading"
	StatusScanning    Status = "scanning"
	StatusDone        Status = "done"
	StatusFailed      Status = "failed"
	StatusSkipped     Status = "skipped" // exceeded the hard memory cap
	StatusCanceled    Status = "canceled"
)

// Terminal reports whether no further state change will occur.
func (s Status) Terminal() bool {
	switch s {
	case StatusDone, StatusFailed, StatusSkipped, StatusCanceled:
		return true
	}
	return false
}

// Severity buckets findings for the UI, derived from the WordPress access tier.
type Severity string

const (
	SevCritical Severity = "critical" // unauthenticated
	SevHigh     Severity = "high"     // authenticated (subscriber/customer reachable)
	SevMedium   Severity = "medium"   // nonce-only (no capability check)
	SevLow      Severity = "low"      // capability-checked (admin self-service etc.)
	SevInfo     Severity = "info"     // surfaces / unknown
)

// severityForAccess maps the engine's access tier to a UI severity.
func severityForAccess(access string) Severity {
	switch access {
	case "unauthenticated":
		return SevCritical
	case "authenticated":
		return SevHigh
	case "nonce_only":
		return SevMedium
	case "capability_checked":
		return SevLow
	case "":
		return SevInfo
	default:
		return SevInfo
	}
}

// Loc is a source location.
type Loc struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

// EntryPoint is a request entry surface (REST route, AJAX action, hook...).
type EntryPoint struct {
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Route   string `json:"route,omitempty"`
	Methods string `json:"methods,omitempty"`
	Access  string `json:"access,omitempty"`
}

// Finding is the UI projection of one engine finding.
type Finding struct {
	RuleID             string       `json:"rule_id"`
	Message            string       `json:"message"`
	Path               string       `json:"path"`
	Line               int          `json:"line"`
	Access             string       `json:"access,omitempty"`
	Severity           Severity     `json:"severity"`
	RequiredCapability string       `json:"required_capability,omitempty"`
	MinimumRole        string       `json:"minimum_role,omitempty"`
	Source             Loc          `json:"source"`
	Sink               Loc          `json:"sink"`
	Callable           string       `json:"callable,omitempty"`
	EntryPoints        []EntryPoint `json:"entrypoints,omitempty"`
	// Key is a stable identity for cross-version diffing.
	Key string `json:"key"`
}

// SeverityCounts is a per-severity tally.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func (c *SeverityCounts) add(s Severity) {
	c.Total++
	switch s {
	case SevCritical:
		c.Critical++
	case SevHigh:
		c.High++
	case SevMedium:
		c.Medium++
	case SevLow:
		c.Low++
	default:
		c.Info++
	}
}

// Job is a single plugin-version scan and its result.
type Job struct {
	ID         string         `json:"id"`
	BatchID    string         `json:"batch_id,omitempty"`
	Slug       string         `json:"slug"`
	PluginName string         `json:"plugin_name,omitempty"`
	Version    string         `json:"version"`
	Status     Status         `json:"status"`
	Error      string         `json:"error,omitempty"`
	QueuedAt   time.Time      `json:"queued_at"`
	StartedAt  time.Time      `json:"started_at,omitempty"`
	FinishedAt time.Time      `json:"finished_at,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
	EngineMS   int64          `json:"engine_ms,omitempty"`
	Findings   []Finding      `json:"findings,omitempty"`
	Counts     SeverityCounts `json:"counts"`
	FromCache  bool           `json:"from_cache,omitempty"`
	Truncated  bool           `json:"truncated,omitempty"` // engine aborted under memory pressure (partial results)
}

// cacheKey identifies a unique scan result (engine version is folded in by the manager).
func cacheKey(slug, version string) string { return slug + "@" + version }
