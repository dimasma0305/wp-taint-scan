package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/scanjob"
	"github.com/dimasma0305/wp-taint-scan/internal/wporg"
)

const maxBatchVersions = 400

type apiServer struct {
	mgr *scanjob.Manager
	wp  *wporg.Client
}

func (s *apiServer) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/plugin", s.handlePlugin)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("GET /api/jobs", s.handleJobs)
	mux.HandleFunc("GET /api/job", s.handleJob)
	mux.HandleFunc("GET /api/job/export", s.handleExport)
	mux.HandleFunc("POST /api/cancel", s.handleCancel)
	mux.HandleFunc("GET /api/diff", s.handleDiff)
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/events", s.handleEvents)
}

func (s *apiServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, 200, &wporg.SearchResult{Plugins: []wporg.Plugin{}})
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	ctx, cancel := contextFrom(r, 30*time.Second)
	defer cancel()
	res, err := s.wp.Search(ctx, q, page, 24)
	if err != nil {
		httpError(w, http.StatusBadGateway, "search failed: "+err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// pluginResponse augments wp.org info with which versions are already scanned.
type pluginResponse struct {
	*wporg.Info
	SortedVersions []string                          `json:"sorted_versions"`
	Scanned        map[string]scanjob.SeverityCounts `json:"scanned"`
}

func (s *apiServer) handlePlugin(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.URL.Query().Get("slug"))
	if !wporg.ValidSlug(slug) {
		httpError(w, http.StatusBadRequest, "invalid slug")
		return
	}
	ctx, cancel := contextFrom(r, 30*time.Second)
	defer cancel()
	info, err := s.wp.Info(ctx, slug)
	if err != nil {
		httpError(w, http.StatusBadGateway, "plugin lookup failed: "+err.Error())
		return
	}
	writeJSON(w, 200, pluginResponse{
		Info:           info,
		SortedVersions: info.SortedVersions(),
		Scanned:        s.mgr.ScannedVersions(slug),
	})
}

type scanRequest struct {
	Slug     string   `json:"slug"`
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
	Mode     string   `json:"mode"` // "selected" | "latest" | "all"
	Force    bool     `json:"force"`
}

func (s *apiServer) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	if !wporg.ValidSlug(req.Slug) {
		httpError(w, http.StatusBadRequest, "invalid slug")
		return
	}

	versions := req.Versions
	name := req.Name
	if req.Mode == "latest" || req.Mode == "all" || len(versions) == 0 {
		ctx, cancel := contextFrom(r, 30*time.Second)
		defer cancel()
		info, err := s.wp.Info(ctx, req.Slug)
		if err != nil {
			httpError(w, http.StatusBadGateway, "plugin lookup failed: "+err.Error())
			return
		}
		if name == "" {
			name = info.Name
		}
		sorted := info.SortedVersions()
		switch req.Mode {
		case "all":
			versions = sorted
		case "latest":
			if len(sorted) > 0 {
				versions = sorted[:1]
			}
		default:
			if len(versions) == 0 && len(sorted) > 0 {
				versions = sorted[:1]
			}
		}
	}

	// Validate + de-duplicate while preserving order, and cap the batch.
	seen := make(map[string]struct{}, len(versions))
	clean := make([]string, 0, len(versions))
	for _, v := range versions {
		v = strings.TrimSpace(v)
		if !wporg.ValidVersion(v) {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		clean = append(clean, v)
		if len(clean) >= maxBatchVersions {
			break
		}
	}
	if len(clean) == 0 {
		httpError(w, http.StatusBadRequest, "no valid versions to scan")
		return
	}

	batchID, jobs := s.mgr.EnqueueBatch(req.Slug, name, clean, req.Force)
	writeJSON(w, 202, map[string]any{"batch_id": batchID, "jobs": jobs, "count": len(jobs)})
}

func (s *apiServer) handleJobs(w http.ResponseWriter, r *http.Request) {
	batch := r.URL.Query().Get("batch")
	writeJSON(w, 200, s.mgr.List(batch))
}

func (s *apiServer) handleJob(w http.ResponseWriter, r *http.Request) {
	job, ok := s.mgr.Get(r.URL.Query().Get("id"))
	if !ok {
		httpError(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, 200, job)
}

func (s *apiServer) handleCancel(w http.ResponseWriter, r *http.Request) {
	if s.mgr.Cancel(r.URL.Query().Get("id")) {
		writeJSON(w, 200, map[string]bool{"canceled": true})
		return
	}
	httpError(w, http.StatusConflict, "job not cancelable")
}

func (s *apiServer) handleDiff(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	slug, a, b := q.Get("slug"), q.Get("a"), q.Get("b")
	if !wporg.ValidSlug(slug) || !wporg.ValidVersion(a) || !wporg.ValidVersion(b) {
		httpError(w, http.StatusBadRequest, "invalid slug/version")
		return
	}
	diff, ok := s.mgr.Diff(slug, a, b)
	if !ok {
		httpError(w, http.StatusNotFound, "both versions must be scanned first")
		return
	}
	writeJSON(w, 200, diff)
}

func (s *apiServer) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.mgr.Stats())
}

func (s *apiServer) handleExport(w http.ResponseWriter, r *http.Request) {
	job, ok := s.mgr.Get(r.URL.Query().Get("id"))
	if !ok {
		httpError(w, http.StatusNotFound, "job not found")
		return
	}
	base := fmt.Sprintf("%s-%s", job.Slug, job.Version)
	if r.URL.Query().Get("format") == "md" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(base)+`.md"`)
		_, _ = w.Write([]byte(renderMarkdown(job)))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(base)+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(job)
}

// handleEvents streams job updates as Server-Sent Events.
func (s *apiServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := s.mgr.Subscribe()
	defer cancel()

	fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case ev, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: job\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func renderMarkdown(job *scanjob.Job) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s %s — taint scan\n\n", orDash(job.PluginName), job.Version)
	fmt.Fprintf(&b, "- Slug: `%s`\n- Status: %s\n- Findings: %d (critical %d, high %d, medium %d, low %d, info %d)\n\n",
		job.Slug, job.Status, job.Counts.Total, job.Counts.Critical, job.Counts.High, job.Counts.Medium, job.Counts.Low, job.Counts.Info)
	if len(job.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	for i, f := range job.Findings {
		fmt.Fprintf(&b, "## %d. [%s] %s\n\n", i+1, strings.ToUpper(string(f.Severity)), f.RuleID)
		fmt.Fprintf(&b, "%s\n\n", f.Message)
		fmt.Fprintf(&b, "- Location: `%s:%d`\n", f.Path, f.Line)
		if f.Access != "" {
			fmt.Fprintf(&b, "- Access: **%s**", f.Access)
			if f.RequiredCapability != "" {
				fmt.Fprintf(&b, " (requires `%s`)", f.RequiredCapability)
			}
			b.WriteString("\n")
		}
		if f.Source.Path != "" {
			fmt.Fprintf(&b, "- Source: `%s:%d`\n", f.Source.Path, f.Source.Line)
		}
		if f.Sink.Path != "" {
			fmt.Fprintf(&b, "- Sink: `%s:%d`\n", f.Sink.Path, f.Sink.Line)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
