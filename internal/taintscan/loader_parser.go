package taintscan

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
	"github.com/dimasma0305/php-parser-go/parsetree"
	"github.com/dimasma0305/php-parser-go/parser"
	"github.com/dimasma0305/php-parser-go/phpparser"
)

func loadFiles(manifest *parsetree.Manifest, workers int) ([]sourceFile, error) {
	if workers < 1 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}
	type parseResult struct {
		file sourceFile
		err  error
	}
	jobCh := make(chan parsetree.ManifestFile, len(manifest.Files))
	resultCh := make(chan parseResult, len(manifest.Files))
	for i := 0; i < workers; i++ {
		worker, err := newSourceParserWorker()
		if err != nil {
			return nil, err
		}
		go func() {
			for job := range jobCh {
				sourceBytes, err := os.ReadFile(job.Path)
				if err != nil {
					resultCh <- parseResult{err: err}
					continue
				}
				source := string(sourceBytes)
				stmts, err := worker.parseProgram(source)
				if err != nil {
					resultCh <- parseResult{err: fmt.Errorf("%s: %w", job.Relative, err)}
					continue
				}
				resultCh <- parseResult{
					file: sourceFile{
						FullPath: job.Path,
						Relative: job.Relative,
						Source:   source,
						AST:      stmts,
						Lines:    strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n"),
					},
				}
			}
		}()
	}
	for _, file := range manifest.Files {
		jobCh <- file
	}
	close(jobCh)

	files := make([]sourceFile, 0, len(manifest.Files))
	for range manifest.Files {
		result := <-resultCh
		if result.err != nil {
			return nil, result.err
		}
		files = append(files, result.file)
	}
	sort.Slice(files, func(i int, j int) bool {
		return files[i].Relative < files[j].Relative
	})
	return files, nil
}

type sourceParserWorker struct {
	parsers []parser.Parser
}

func newSourceParserWorker() (sourceParserWorker, error) {
	factory := parser.ParserFactory{}
	versions := []phpparser.PhpVersion{
		phpparser.NewestSupportedPhpVersion(),
		mustPHPVersion("7.4"),
		mustPHPVersion("5.6"),
	}
	worker := sourceParserWorker{parsers: make([]parser.Parser, 0, len(versions))}
	for _, version := range versions {
		p, err := factory.CreateForVersion(version)
		if err != nil {
			return sourceParserWorker{}, err
		}
		worker.parsers = append(worker.parsers, p)
	}
	return worker, nil
}

func (w sourceParserWorker) parseProgram(source string) ([]ast.Node, error) {
	var lastErr error
	for _, p := range w.parsers {
		handler := &phpparser.CollectingErrorHandler{}
		stmts, err := p.Parse(source, handler)
		if err == nil && (!handler.HasErrors() || parser.AllowsRecoverableAnalysisErrors(source, stmts, handler)) {
			return resolveProgramNames(stmts)
		}
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = fmt.Errorf("%s", handler.Errors()[0].Error())
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown parse failure")
	}
	return nil, lastErr
}

func resolveProgramNames(stmts []ast.Node) (out []ast.Node, err error) {
	out = stmts
	defer func() {
		if recover() != nil {
			out = stmts
			err = nil
		}
	}()
	resolver := ast.NewNameResolver(phpparser.ThrowingErrorHandler{}, nil)
	traverser := ast.NewTraverser(resolver)
	resolved, err := traverser.Traverse(stmts)
	if err != nil {
		return stmts, nil
	}
	if resolved == nil {
		return stmts, nil
	}
	return resolved, nil
}

func mustPHPVersion(versionText string) phpparser.PhpVersion {
	version, err := phpparser.PhpVersionFromString(versionText)
	if err != nil {
		panic(err)
	}
	return version
}
