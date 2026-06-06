// Package wporg is a small client for the public WordPress.org Plugin API:
// searching plugins by name, listing every released version, and resolving
// version download URLs. It talks only to the hardcoded api.wordpress.org and
// downloads.wordpress.org hosts, and validates every slug/version it accepts,
// so user input can never redirect a request elsewhere (no SSRF) or escape a
// filesystem path.
package wporg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	apiBase      = "https://api.wordpress.org/plugins/info/1.2/"
	downloadBase = "https://downloads.wordpress.org/plugin/"
	userAgent    = "wp-taint-scan/1.0 (+https://github.com/dimasma0305/wp-taint-scan)"
)

var (
	slugRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	versionRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	tagRe     = regexp.MustCompile(`<[^>]*>`)
)

// ValidSlug reports whether s is a safe plugin slug (URL- and path-safe).
func ValidSlug(s string) bool {
	return s != "" && len(s) <= 200 && slugRe.MatchString(s) && !strings.Contains(s, "..")
}

// ValidVersion reports whether v is a safe version token (URL- and path-safe).
func ValidVersion(v string) bool {
	return v != "" && len(v) <= 100 && versionRe.MatchString(v) && !strings.Contains(v, "..")
}

// flexString tolerates the WordPress.org API returning bool/number/null where a
// string is expected (e.g. `"requires_php": false` for plugins with no
// constraint). It always marshals back out as a JSON string.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	switch s {
	case "null", "false", "true", "":
		*f = ""
		return nil
	}
	if s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		*f = flexString(str)
		return nil
	}
	*f = flexString(strings.Trim(s, `"`)) // numbers and other scalars
	return nil
}

// flexMap tolerates the API returning false / [] / null where a string map is
// expected (e.g. `"icons": false` or `"versions": []`), yielding an empty map.
type flexMap map[string]string

func (f *flexMap) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if len(s) == 0 || s[0] != '{' {
		*f = map[string]string{}
		return nil
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		vs := strings.TrimSpace(string(v))
		if len(vs) >= 1 && vs[0] == '"' {
			var str string
			if err := json.Unmarshal(v, &str); err == nil {
				out[k] = str
			}
			continue
		}
		if vs != "null" && vs != "false" {
			out[k] = strings.Trim(vs, `"`)
		}
	}
	*f = out
	return nil
}

// Plugin is the summary record returned by search and embedded in info.
type Plugin struct {
	Slug             string            `json:"slug"`
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Author           string            `json:"author"`
	AuthorName       string            `json:"author_name,omitempty"`
	Rating           int               `json:"rating"`
	NumRatings       int               `json:"num_ratings"`
	ActiveInstalls   int               `json:"active_installs"`
	Downloaded       int64             `json:"downloaded"`
	LastUpdated      string            `json:"last_updated"`
	Added            string            `json:"added"`
	ShortDescription string            `json:"short_description"`
	Icons            flexMap           `json:"icons"`
	Requires         flexString        `json:"requires"`
	Tested           flexString        `json:"tested"`
	RequiresPHP      flexString        `json:"requires_php"`
}

// Icon returns the best available icon URL, or "".
func (p Plugin) Icon() string {
	for _, k := range []string{"svg", "2x", "1x", "default"} {
		if u := p.Icons[k]; u != "" {
			return u
		}
	}
	return ""
}

// SearchResult is one page of search hits.
type SearchResult struct {
	Page    int      `json:"page"`
	Pages   int      `json:"pages"`
	Results int      `json:"results"`
	Plugins []Plugin `json:"plugins"`
}

// Info is the full plugin record including the version->download-url map.
type Info struct {
	Plugin
	Versions     flexMap `json:"versions"`
	DownloadLink string  `json:"download_link"`
}

// Client talks to the WordPress.org Plugin API.
type Client struct {
	HTTP    *http.Client
	apiBase string // overridable for tests
}

// New returns a Client with sane timeouts.
func New() *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		apiBase: apiBase,
	}
}

func (c *Client) base() string {
	if c.apiBase != "" {
		return c.apiBase
	}
	return apiBase
}

// Search queries plugins by free text. page is 1-based; perPage is clamped 1..50.
func (c *Client) Search(ctx context.Context, query string, page, perPage int) (*SearchResult, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 24
	}
	if perPage > 50 {
		perPage = 50
	}
	q := url.Values{}
	q.Set("action", "query_plugins")
	q.Set("request[search]", query)
	q.Set("request[page]", strconv.Itoa(page))
	q.Set("request[per_page]", strconv.Itoa(perPage))
	q.Set("request[fields][icons]", "1")
	q.Set("request[fields][short_description]", "1")
	q.Set("request[fields][active_installs]", "1")

	var raw struct {
		Info struct {
			Page    int `json:"page"`
			Pages   int `json:"pages"`
			Results int `json:"results"`
		} `json:"info"`
		Plugins []Plugin `json:"plugins"`
	}
	if err := c.getJSON(ctx, c.base()+"?"+q.Encode(), &raw); err != nil {
		return nil, err
	}
	for i := range raw.Plugins {
		raw.Plugins[i].AuthorName = stripTags(raw.Plugins[i].Author)
		raw.Plugins[i].ShortDescription = stripTags(raw.Plugins[i].ShortDescription)
	}
	return &SearchResult{
		Page:    raw.Info.Page,
		Pages:   raw.Info.Pages,
		Results: raw.Info.Results,
		Plugins: raw.Plugins,
	}, nil
}

// Info fetches the full record (including all versions) for a single slug.
func (c *Client) Info(ctx context.Context, slug string) (*Info, error) {
	if !ValidSlug(slug) {
		return nil, fmt.Errorf("invalid plugin slug %q", slug)
	}
	q := url.Values{}
	q.Set("action", "plugin_information")
	q.Set("request[slug]", slug)
	q.Set("request[fields][versions]", "1")
	q.Set("request[fields][icons]", "1")
	q.Set("request[fields][short_description]", "1")

	var info Info
	if err := c.getJSON(ctx, c.base()+"?"+q.Encode(), &info); err != nil {
		return nil, err
	}
	if info.Slug == "" {
		return nil, fmt.Errorf("plugin %q not found", slug)
	}
	info.AuthorName = stripTags(info.Author)
	info.ShortDescription = stripTags(info.ShortDescription)
	return &info, nil
}

// SortedVersions returns released versions newest-first. "trunk" is excluded.
func (info *Info) SortedVersions() []string {
	out := make([]string, 0, len(info.Versions))
	for v := range info.Versions {
		if v == "trunk" || v == "" {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return compareVersions(out[i], out[j]) > 0 })
	return out
}

// DownloadURL returns the canonical zip URL for a slug+version.
func DownloadURL(slug, version string) (string, error) {
	if !ValidSlug(slug) {
		return "", fmt.Errorf("invalid slug %q", slug)
	}
	if !ValidVersion(version) {
		return "", fmt.Errorf("invalid version %q", version)
	}
	return downloadBase + slug + "." + version + ".zip", nil
}

func (c *Client) getJSON(ctx context.Context, u string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wordpress.org API status %d", resp.StatusCode)
	}
	// The API returns `false` (not an object) for unknown plugins.
	if strings.TrimSpace(string(body)) == "false" {
		return fmt.Errorf("not found")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode wordpress.org response: %w", err)
	}
	return nil
}

func stripTags(s string) string {
	return strings.TrimSpace(tagRe.ReplaceAllString(s, ""))
}

// compareVersions compares dotted versions numerically with a string fallback.
// Returns >0 if a>b, <0 if a<b, 0 if equal.
func compareVersions(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		// Treat a missing trailing component as "0" so 1.0 == 1.0.0.
		ai, bi := "0", "0"
		if i < len(as) {
			ai = as[i]
		}
		if i < len(bs) {
			bi = bs[i]
		}
		an, aerr := strconv.Atoi(ai)
		bn, berr := strconv.Atoi(bi)
		switch {
		case aerr == nil && berr == nil: // both numeric
			if an != bn {
				if an > bn {
					return 1
				}
				return -1
			}
			continue
		case aerr == nil && berr != nil: // numeric > pre-release suffix (6.0 > 6.0-beta)
			return 1
		case aerr != nil && berr == nil:
			return -1
		default: // both non-numeric: lexical
			if ai != bi {
				if ai > bi {
					return 1
				}
				return -1
			}
		}
	}
	return 0
}

func splitVersion(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
}
