// Command taint-web is a web UI + HTTP API for scanning WordPress plugins with
// the wp-taint-scan engine. It can search plugins by name on WordPress.org, list
// every released version, and scan one version or a whole batch in parallel.
//
// The same binary doubles as the scan worker: the server isolates every scan in
// a child process (`taint-web -scan-worker ...`) with a memory cap, RSS watchdog,
// and timeout, so a pathological mega-plugin can never OOM or crash the server.
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/scanjob"
	"github.com/dimasma0305/wp-taint-scan/internal/taintscan"
	"github.com/dimasma0305/wp-taint-scan/internal/wporg"
)

//go:embed web
var webFS embed.FS

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Worker mode: run one isolated scan and exit. Kept first so the server
	// flags below don't shadow it.
	if len(os.Args) > 1 && os.Args[1] == "-scan-worker" {
		runWorker(os.Args[2:])
		return
	}

	var (
		addr        = flag.String("addr", "127.0.0.1:8080", "listen address (defaults to loopback; the service fetches/execs/writes disk and has no auth — do not expose it without a trusted reverse proxy)")
		cacheDir    = flag.String("cache-dir", defaultCacheDir(), "directory for downloaded plugins and extracted sources")
		concurrency = flag.Int("concurrency", 4, "number of plugin versions scanned in parallel")
		memLimitMB  = flag.Int("mem-limit-mb", 4096, "soft heap ceiling passed to each scan worker")
		hardCapMB   = flag.Int("hard-cap-mb", 8192, "hard RSS cap; a worker exceeding it is killed and the job is skipped (0 = off)")
		timeout     = flag.Duration("timeout", 10*time.Minute, "per-scan wall-clock timeout")
		cacheMaxGB  = flag.Float64("cache-max-gb", 8, "max on-disk cache size before least-recently-used plugins are evicted (0 = unlimited)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("wp-taint-scan", version)
		return
	}

	self, err := os.Executable()
	if err != nil {
		log.Fatalf("resolve executable: %v", err)
	}
	if err := os.MkdirAll(*cacheDir, 0o755); err != nil {
		log.Fatalf("create cache dir: %v", err)
	}

	runner := &scanjob.Runner{
		SelfBin:    self,
		CacheDir:   *cacheDir,
		MemLimitMB: *memLimitMB,
		HardCapMB:  *hardCapMB,
		Timeout:    *timeout,
		HTTP:       &http.Client{Timeout: 5 * time.Minute},
	}
	mgr := scanjob.New(scanjob.Config{Concurrency: *concurrency, Runner: runner})

	if *cacheMaxGB > 0 {
		stop := runner.StartReaper(int64(*cacheMaxGB*float64(1<<30)), 2*time.Minute)
		defer stop()
	}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embed web assets: %v", err)
	}
	srv := &apiServer{mgr: mgr, wp: wporg.New()}

	mux := http.NewServeMux()
	srv.routes(mux)
	mux.Handle("/", http.FileServer(http.FS(sub)))

	display := *addr
	if strings.HasPrefix(display, ":") {
		display = "localhost" + display
	}
	log.Printf("wp-taint-scan web UI on http://%s  (cache: %s, concurrency: %d)", display, *cacheDir, *concurrency)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           withRecover(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// runWorker performs a single scan in this process and writes taint-results.json.
func runWorker(argv []string) {
	fs := flag.NewFlagSet("scan-worker", flag.ExitOnError)
	target := fs.String("target", "", "source directory to scan")
	outputDir := fs.String("output-dir", "", "output directory")
	memLimitMB := fs.Int("mem-limit-mb", 0, "soft heap ceiling in MiB")
	_ = fs.Parse(argv)

	if *target == "" || *outputDir == "" {
		fmt.Fprintln(os.Stderr, "scan-worker: -target and -output-dir are required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir output: %v\n", err)
		os.Exit(1)
	}

	options := taintscan.Options{}
	if *memLimitMB > 0 {
		limit := uint64(*memLimitMB) * 1024 * 1024
		options.MemoryLimitBytes = limit
		debug.SetMemoryLimit(int64(limit + limit/4))
	}

	started := time.Now()
	result, err := taintscan.AnalyzeRootWithOptions(*target, defaultExcludes(), 0, options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		os.Exit(1)
	}
	finished := time.Now()
	result.Payload = taintscan.EnrichPayload(result.Payload, finished, finished.Sub(started))

	payload, err := json.MarshalIndent(result.Payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*outputDir, "taint-results.json"), append(payload, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
}

func defaultExcludes() []string {
	return []string{
		"vendor", "vendor-prefixed", "vendor_prefixed",
		"node_modules", "bower_components",
		"tests", "test", "spec", "freemius",
	}
}

func defaultCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "wp-taint-scan")
	}
	return filepath.Join(os.TempDir(), "wp-taint-scan-cache")
}

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic serving %s: %v", r.URL.Path, rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
