package main

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/wporg"
)

const (
	searchPageSize = 24            // results per UI page
	aggPages       = 4             // wp.org pages fetched when filtering/sorting
	aggPerPage     = 50            // results per aggregation fetch
	searchCacheTTL = 90 * time.Second
	searchCacheMax = 64
)

// searchView is the response shape for /api/search.
type searchView struct {
	Plugins []wporg.Plugin `json:"plugins"`
	Page    int            `json:"page"`
	Pages   int            `json:"pages"`
	Results int            `json:"results"`
	Capped  bool           `json:"capped"` // more results exist than were aggregated/filtered
}

type searchCacheEntry struct {
	plugins []wporg.Plugin
	capped  bool
	fetched time.Time
}

func (s *apiServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()
	q := strings.TrimSpace(qp.Get("q"))
	page := atoiDefault(qp.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	sortKey := qp.Get("sort")
	minInstalls := atoiDefault(qp.Get("min_installs"), 0)
	maxInstalls := atoiDefault(qp.Get("max_installs"), 0)
	minRating := atoiDefault(qp.Get("min_rating"), 0)

	ctx, cancel := contextFrom(r, 40*time.Second)
	defer cancel()

	filtering := minInstalls > 0 || maxInstalls > 0 || minRating > 0
	sorting := sortKey != "" && sortKey != "relevance"

	// Fast path: no filter/sort → use wp.org native pagination (whole result set).
	if !filtering && !sorting {
		res, err := s.wp.Query(ctx, wporg.Query{Search: q, Browse: browseForSort(sortKey), Page: page, PerPage: searchPageSize})
		if err != nil {
			httpError(w, http.StatusBadGateway, "search failed: "+err.Error())
			return
		}
		writeJSON(w, 200, searchView{Plugins: res.Plugins, Page: res.Page, Pages: res.Pages, Results: res.Results})
		return
	}

	// Filtered/sorted path: aggregate a window of results, then filter+sort+paginate.
	cands, capped, err := s.aggregate(ctx, q, browseForSort(sortKey))
	if err != nil {
		httpError(w, http.StatusBadGateway, "search failed: "+err.Error())
		return
	}
	out := filterPlugins(cands, minInstalls, maxInstalls, minRating)
	sortPlugins(out, sortKey)

	total := len(out)
	pages := (total + searchPageSize - 1) / searchPageSize
	start := (page - 1) * searchPageSize
	if start > total {
		start = total
	}
	end := start + searchPageSize
	if end > total {
		end = total
	}
	writeJSON(w, 200, searchView{Plugins: out[start:end], Page: page, Pages: pages, Results: total, Capped: capped})
}

// aggregate fetches (and briefly caches) up to aggPages*aggPerPage results for a
// query or browse mode, so filtering/sorting operates on a useful window.
func (s *apiServer) aggregate(ctx context.Context, q, browse string) ([]wporg.Plugin, bool, error) {
	key := "b:" + browse
	if q != "" {
		key = "q:" + q
	}

	s.scMu.Lock()
	if s.searchCache == nil {
		s.searchCache = map[string]*searchCacheEntry{}
	}
	if e, ok := s.searchCache[key]; ok && time.Since(e.fetched) < searchCacheTTL {
		s.scMu.Unlock()
		return e.plugins, e.capped, nil
	}
	s.scMu.Unlock()

	var all []wporg.Plugin
	capped := false
	for p := 1; p <= aggPages; p++ {
		res, err := s.wp.Query(ctx, wporg.Query{Search: q, Browse: browse, Page: p, PerPage: aggPerPage})
		if err != nil {
			if p == 1 {
				return nil, false, err
			}
			break // partial window is fine
		}
		all = append(all, res.Plugins...)
		if p >= res.Pages {
			break
		}
		if p == aggPages && res.Pages > aggPages {
			capped = true
		}
	}

	s.scMu.Lock()
	if len(s.searchCache) >= searchCacheMax {
		s.searchCache = map[string]*searchCacheEntry{}
	}
	s.searchCache[key] = &searchCacheEntry{plugins: all, capped: capped, fetched: time.Now()}
	s.scMu.Unlock()
	return all, capped, nil
}

// filterPlugins returns a new slice (never mutating the cached input) keeping
// plugins within the install range [minInstalls, maxInstalls) and at/above
// minRating. A zero bound means "unbounded".
func filterPlugins(in []wporg.Plugin, minInstalls, maxInstalls, minRating int) []wporg.Plugin {
	out := make([]wporg.Plugin, 0, len(in))
	for _, p := range in {
		if minInstalls > 0 && p.ActiveInstalls < minInstalls {
			continue
		}
		if maxInstalls > 0 && p.ActiveInstalls >= maxInstalls {
			continue
		}
		if minRating > 0 && p.Rating < minRating {
			continue
		}
		out = append(out, p)
	}
	return out
}

// sortPlugins sorts in place by the given key (relevance/"" keeps order).
func sortPlugins(p []wporg.Plugin, key string) {
	switch key {
	case "installs":
		sort.SliceStable(p, func(i, j int) bool { return p[i].ActiveInstalls > p[j].ActiveInstalls })
	case "rating":
		sort.SliceStable(p, func(i, j int) bool {
			if p[i].Rating != p[j].Rating {
				return p[i].Rating > p[j].Rating
			}
			return p[i].NumRatings > p[j].NumRatings
		})
	case "updated":
		sort.SliceStable(p, func(i, j int) bool { return datePrefix(p[i].LastUpdated) > datePrefix(p[j].LastUpdated) })
	case "name":
		sort.SliceStable(p, func(i, j int) bool { return strings.ToLower(p[i].Name) < strings.ToLower(p[j].Name) })
	}
}

// browseForSort maps a sort key to a wp.org browse mode (used only when there is
// no search query, to seed a useful candidate set).
func browseForSort(sortKey string) string {
	switch sortKey {
	case "updated":
		return "updated"
	case "new":
		return "new"
	default:
		return "popular"
	}
}

func datePrefix(s string) string {
	if len(s) >= 10 {
		return s[:10] // YYYY-MM-DD sorts lexically
	}
	return s
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
