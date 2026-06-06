package scanjob

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/wporg"
)

const (
	maxDownloadBytes = 250 << 20 // 250 MiB compressed cap
	maxExtractBytes  = 1 << 30   // 1 GiB uncompressed cap (zip-bomb guard)
	maxExtractFiles  = 60000
)

// Result is the immutable outcome of one scan, applied to the Job by the manager
// under its lock. The runner never mutates the shared Job (see manager.runJob).
type Result struct {
	Findings  []Finding
	Counts    SeverityCounts
	EngineMS  int64
	Truncated bool
	Skipped   bool   // killed by the memory watchdog
	SkipMsg   string // reason when Skipped
}

// Runner downloads, extracts, and scans a single plugin version.
type Runner struct {
	SelfBin    string        // path to this binary; re-invoked as `-scan-worker`
	CacheDir   string        // root for downloaded zips and extracted sources
	MemLimitMB int           // soft heap ceiling passed to the worker
	HardCapMB  int           // hard RSS cap enforced by the watchdog (0 = off)
	Timeout    time.Duration // per-scan wall-clock limit
	HTTP       *http.Client

	locks sync.Map // cacheKey -> *sync.Mutex, serializing per-version extraction
}

// Run executes the full pipeline for slug@version. setStatus reports progress;
// the validated, immutable Result is returned for the caller to apply.
func (r *Runner) Run(ctx context.Context, slug, version string, setStatus func(Status)) (*Result, error) {
	if !wporg.ValidSlug(slug) {
		return nil, fmt.Errorf("invalid slug %q", slug)
	}
	if !wporg.ValidVersion(version) {
		return nil, fmt.Errorf("invalid version %q", version)
	}

	setStatus(StatusDownloading)
	srcDir, err := r.ensureExtracted(ctx, slug, version)
	if err != nil {
		return nil, fmt.Errorf("download/extract: %w", err)
	}

	setStatus(StatusScanning)
	return r.scan(ctx, srcDir)
}

func (r *Runner) keyLock(key string) *sync.Mutex {
	v, _ := r.locks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ensureExtracted returns a directory holding the plugin source, downloading and
// extracting it (zip-slip safe) on a cache miss. Extraction for a given
// slug@version is serialized so concurrent identical scans share one download.
func (r *Runner) ensureExtracted(ctx context.Context, slug, version string) (string, error) {
	key := slug + "@" + version
	mu := r.keyLock(key)
	mu.Lock()
	defer mu.Unlock()

	srcDir := filepath.Join(r.CacheDir, "src", slug, version)
	marker := filepath.Join(srcDir, ".extracted")
	if _, err := os.Stat(marker); err == nil {
		return srcDir, nil // cache hit (re-checked under the per-key lock)
	}

	zipPath := filepath.Join(r.CacheDir, "zips", slug+"."+version+".zip")
	if _, err := os.Stat(zipPath); err != nil {
		if err := r.download(ctx, slug, version, zipPath); err != nil {
			return "", err
		}
	}

	// Extract into a unique temp dir, then atomically rename into place.
	_ = os.RemoveAll(srcDir)
	if err := os.MkdirAll(filepath.Dir(srcDir), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(srcDir), ".extract-*")
	if err != nil {
		return "", err
	}
	if err := unzipSafe(zipPath, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	if err := os.Rename(tmp, srcDir); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644)
	return srcDir, nil
}

func (r *Runner) download(ctx context.Context, slug, version, dst string) error {
	u, err := wporg.DownloadURL(slug, version)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wp-taint-scan/1.0")
	hc := r.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download status %d for %s", resp.StatusCode, u)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".part-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDownloadBytes+1))
	cerr := tmp.Close()
	if err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if cerr != nil {
		_ = os.Remove(tmpName)
		return cerr
	}
	if n > maxDownloadBytes {
		_ = os.Remove(tmpName)
		return fmt.Errorf("download exceeds %d bytes", maxDownloadBytes)
	}
	return os.Rename(tmpName, dst)
}

// unzipSafe extracts src into dst, rejecting any entry that would escape dst
// (zip-slip) and enforcing total-size / file-count limits (zip-bomb guard).
func unzipSafe(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()

	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var total int64
	var count int
	for _, f := range zr.File {
		count++
		if count > maxExtractFiles {
			return fmt.Errorf("archive has too many entries (>%d)", maxExtractFiles)
		}
		target := filepath.Join(dstAbs, f.Name)
		// Reject path traversal: the cleaned target must stay within dstAbs.
		if target != dstAbs && !strings.HasPrefix(target, dstAbs+string(os.PathSeparator)) {
			return fmt.Errorf("unsafe path in archive: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		// Skip symlinks and other non-regular entries entirely.
		if !f.Mode().IsRegular() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		total += int64(f.UncompressedSize64)
		if total > maxExtractBytes {
			return fmt.Errorf("archive uncompressed size exceeds %d bytes", maxExtractBytes)
		}
		if err := extractFile(f, target); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(rc, maxExtractBytes))
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

// scan runs the engine in an isolated subprocess and returns projected findings.
func (r *Runner) scan(ctx context.Context, srcDir string) (*Result, error) {
	outDir, err := os.MkdirTemp("", "wpts-out-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(outDir)

	scanCtx := ctx
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	args := []string{"-scan-worker", "-target", srcDir, "-output-dir", outDir}
	if r.MemLimitMB > 0 {
		args = append(args, "-mem-limit-mb", strconv.Itoa(r.MemLimitMB))
	}
	cmd := exec.CommandContext(scanCtx, r.SelfBin, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start scan worker: %w", err)
	}

	killedForMemory := watchRSS(scanCtx, cmd, r.HardCapMB)
	waitErr := cmd.Wait()

	if killedForMemory.Load() {
		return &Result{Skipped: true, SkipMsg: fmt.Sprintf("skipped: exceeded %d MiB memory cap", r.HardCapMB)}, nil
	}
	if scanCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("scan timed out after %s", r.Timeout)
	}
	if scanCtx.Err() == context.Canceled {
		return nil, context.Canceled
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("scan worker failed: %s", lastLines(msg, 4))
	}

	return parseResults(filepath.Join(outDir, "taint-results.json"))
}

// parseResults reads the engine's JSON output into an immutable Result.
func parseResults(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read results: %w", err)
	}
	var payload enginePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("decode results: %w", err)
	}
	res := &Result{Findings: make([]Finding, 0, len(payload.Results))}
	if payload.Summary != nil {
		res.EngineMS = payload.Summary.ElapsedMS
	}
	for _, raw := range payload.Results {
		f := projectFinding(raw)
		res.Counts.add(f.Severity)
		res.Findings = append(res.Findings, f)
	}
	for _, e := range payload.Errors {
		le := strings.ToLower(e)
		if strings.Contains(le, "memory") || strings.Contains(le, "abort") {
			res.Truncated = true
		}
	}
	sortFindings(res.Findings)
	return res, nil
}

// StartReaper periodically caps the on-disk cache (zips + extracted sources) at
// maxBytes, deleting least-recently-modified entries first. Returns a stop func.
func (r *Runner) StartReaper(maxBytes int64, every time.Duration) func() {
	if maxBytes <= 0 || every <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			r.reapOnce(maxBytes)
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}()
	return func() { close(stop) }
}

func (r *Runner) reapOnce(maxBytes int64) {
	type entry struct {
		path string
		size int64
		mod  time.Time
	}
	var entries []entry
	var total int64
	// Each extracted version dir and each zip is one evictable unit.
	for _, sub := range []string{"src", "zips"} {
		root := filepath.Join(r.CacheDir, sub)
		dirEntries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, de := range dirEntries {
			// src is nested src/<slug>/<version>; zips is flat zips/<file>.
			if sub == "src" && de.IsDir() {
				slugDir := filepath.Join(root, de.Name())
				vers, _ := os.ReadDir(slugDir)
				for _, v := range vers {
					p := filepath.Join(slugDir, v.Name())
					sz, mod := dirSize(p)
					entries = append(entries, entry{p, sz, mod})
					total += sz
				}
				continue
			}
			p := filepath.Join(root, de.Name())
			info, err := de.Info()
			if err != nil {
				continue
			}
			entries = append(entries, entry{p, info.Size(), info.ModTime()})
			total += info.Size()
		}
	}
	if total <= maxBytes {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mod.Before(entries[j].mod) })
	for _, e := range entries {
		if total <= maxBytes {
			break
		}
		if err := os.RemoveAll(e.path); err == nil {
			total -= e.size
		}
	}
}

func dirSize(path string) (int64, time.Time) {
	var size int64
	var newest time.Time
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return size, newest
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
