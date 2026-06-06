package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dimasma0305/wp-taint-scan/internal/lowerbundle"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", []string(*m))
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	var target string
	var outputDir string
	var workers int
	var excludes multiFlag

	flag.StringVar(&target, "target", "", "plugin or source directory to lower")
	flag.StringVar(&outputDir, "output-dir", "", "output directory; defaults to tmp/phparser-lower-bundle-<timestamp>")
	flag.IntVar(&workers, "phparser-workers", 0, "worker count for native Go parsing")
	flag.Var(&excludes, "exclude-dir", "directory name to exclude while collecting PHP files. Repeatable.")
	flag.Parse()

	if target == "" {
		fmt.Fprintln(os.Stderr, "-target is required")
		os.Exit(2)
	}
	if outputDir == "" {
		outputDir = filepath.Join("tmp", "phparser-lower-bundle-"+time.Now().UTC().Format("20060102-150405"))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir output dir: %v\n", err)
		os.Exit(1)
	}

	bundlePath := filepath.Join(outputDir, "lowered-bundle.php")
	mapPath := filepath.Join(outputDir, "lowered-mapping.json")
	result, err := lowerbundle.BuildForRoot(target, append(defaultExcludedDirs(), excludes...), bundlePath, mapPath, workers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lower bundle: %v\n", err)
		os.Exit(1)
	}

	readmePath := filepath.Join(outputDir, "README.md")
	readme := fmt.Sprintf("# phparser Lowered Bundle\n\n- Target: `%s`\n- Bundle: `%s`\n- Mapping: `%s`\n- Parsed files: `%d`\n- Skipped files: `%d`\n", result.Target, result.OutputBundle, result.OutputMap, len(result.Files), len(result.SkippedFiles))
	if err := os.WriteFile(readmePath, []byte(readme), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write readme: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(outputDir)
}

func defaultExcludedDirs() []string {
	return []string{
		"vendor",
		"vendor-prefixed",
		"vendor_prefixed",
		"node_modules",
		"bower_components",
		"tests",
		"test",
		"spec",
	}
}
