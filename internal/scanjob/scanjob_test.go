package scanjob

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// fakeScanner emulates a scan without network or subprocess.
type fakeScanner struct{}

func (fakeScanner) Run(ctx context.Context, slug, version string, setStatus func(Status)) (*Result, error) {
	setStatus(StatusDownloading)
	setStatus(StatusScanning)
	return &Result{
		Findings: []Finding{{RuleID: "r", Severity: SevHigh, Key: slug + version}},
		Counts:   SeverityCounts{High: 1, Total: 1},
		EngineMS: 1,
	}, nil
}

// TestConcurrentScanAndReaders drives the exact interleaving the review flagged:
// workers mutating jobs while HTTP-style readers (List/Get/Stats) and the event
// bus touch the same records. Run with `go test -race`.
func TestConcurrentScanAndReaders(t *testing.T) {
	m := New(Config{Concurrency: 4, Runner: fakeScanner{}})
	defer m.Close()

	ch, cancelSub := m.Subscribe()
	done := make(chan struct{})
	go func() { // drain the event bus, reading the snapshots
		defer close(done)
		for ev := range ch {
			if ev.Job != nil {
				_ = len(ev.Job.Findings)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // readers
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				for _, job := range m.List("") {
					_ = len(job.Findings)
				}
				_ = m.Stats()
				_ = m.ScannedVersions("p")
			}
		}()
	}
	for i := 0; i < 8; i++ { // enqueuers
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				job := m.Enqueue("p", "P", "1."+strconv.Itoa(i*1000+j), "", true)
				if g, ok := m.Get(job.ID); ok {
					_ = len(g.Findings)
				}
			}
		}(i)
	}
	wg.Wait()
	cancelSub()
	<-done
}

func TestSeverityForAccess(t *testing.T) {
	cases := map[string]Severity{
		"unauthenticated":    SevCritical,
		"authenticated":      SevHigh,
		"nonce_only":         SevMedium,
		"capability_checked": SevLow,
		"":                   SevInfo,
		"weird":              SevInfo,
	}
	for access, want := range cases {
		if got := severityForAccess(access); got != want {
			t.Errorf("severityForAccess(%q) = %q, want %q", access, got, want)
		}
	}
}

func TestProjectFindingStableKey(t *testing.T) {
	var raw engineFinding
	raw.CheckID = "wp-x"
	raw.Path = "a.php"
	raw.Start.Line = 10
	raw.Extra.Context.Access = "unauthenticated"
	raw.Extra.Trace.Source.Path = "a.php"
	raw.Extra.Trace.Source.Line = 3
	f := projectFinding(raw)
	if f.Severity != SevCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if projectFinding(raw).Key != f.Key {
		t.Error("key must be deterministic")
	}
}

func TestDiff(t *testing.T) {
	m := New(Config{Concurrency: 1, Runner: &Runner{}})
	mkFinding := func(rule string) Finding {
		f := Finding{RuleID: rule, Path: "p.php", Line: 1, Severity: SevHigh}
		f.Key = rule + "|p.php:1|:0"
		return f
	}
	// Seed two cached versions directly.
	m.cache[cacheKey("plug", "1.0")] = &Job{Slug: "plug", Version: "1.0", Findings: []Finding{mkFinding("a"), mkFinding("b")}}
	m.cache[cacheKey("plug", "2.0")] = &Job{Slug: "plug", Version: "2.0", Findings: []Finding{mkFinding("b"), mkFinding("c")}}

	d, ok := m.Diff("plug", "1.0", "2.0")
	if !ok {
		t.Fatal("diff not found")
	}
	if len(d.Added) != 1 || d.Added[0].RuleID != "c" {
		t.Errorf("added = %+v, want [c]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].RuleID != "a" {
		t.Errorf("removed = %+v, want [a]", d.Removed)
	}
	if len(d.Common) != 1 || d.Common[0].RuleID != "b" {
		t.Errorf("common = %+v, want [b]", d.Common)
	}
	if _, ok := m.Diff("plug", "1.0", "9.9"); ok {
		t.Error("diff should fail when a version is unscanned")
	}
}

// unzipSafe must reject entries that escape the destination directory.
func TestUnzipSafeRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../escape.txt")
	_, _ = w.Write([]byte("pwned"))
	_ = zw.Close()
	_ = f.Close()

	dst := filepath.Join(dir, "out")
	_ = os.MkdirAll(dst, 0o755)
	if err := unzipSafe(zipPath, dst); err == nil {
		t.Fatal("unzipSafe accepted a path-traversal entry")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.txt")); err == nil {
		t.Fatal("zip-slip wrote outside the destination")
	}
}

func TestUnzipSafeNormal(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "ok.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("plugin/main.php")
	_, _ = w.Write([]byte("<?php echo 1;"))
	_ = zw.Close()
	_ = f.Close()

	dst := filepath.Join(dir, "out")
	if err := unzipSafe(zipPath, dst); err != nil {
		t.Fatalf("unzipSafe: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "plugin", "main.php"))
	if err != nil || string(got) != "<?php echo 1;" {
		t.Fatalf("extracted content wrong: %q err=%v", got, err)
	}
}

func TestCacheHitReturnsImmediately(t *testing.T) {
	m := New(Config{Concurrency: 1, Runner: &Runner{}})
	m.cache[cacheKey("plug", "1.0")] = &Job{
		Slug: "plug", Version: "1.0", Status: StatusDone,
		Findings: []Finding{{RuleID: "a", Severity: SevHigh}},
		Counts:   SeverityCounts{High: 1, Total: 1},
	}
	job := m.Enqueue("plug", "Plug", "1.0", "", false)
	if job.Status != StatusDone || !job.FromCache {
		t.Errorf("cache hit should return a done+cached job, got status=%s cached=%v", job.Status, job.FromCache)
	}
	if job.Counts.Total != 1 {
		t.Errorf("cached counts not copied: %+v", job.Counts)
	}
}
