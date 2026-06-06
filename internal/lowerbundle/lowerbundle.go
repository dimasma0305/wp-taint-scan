package lowerbundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
	"github.com/dimasma0305/php-parser-go/parsetree"
	"github.com/dimasma0305/php-parser-go/parser"
	"github.com/dimasma0305/php-parser-go/phpparser"
	"github.com/dimasma0305/php-parser-go/prettyprinter"
)

type File struct {
	FullPath string
	Relative string
	Source   string
	AST      []ast.Node
}

type SkippedFile struct {
	SourcePath string `json:"source_path"`
	Error      string `json:"error"`
}

type Segment struct {
	SourcePath               string `json:"source_path"`
	Kind                     string `json:"kind"`
	SourceFunctionStartLine  int    `json:"source_function_start_line,omitempty"`
	SourceMethodStartLine    int    `json:"source_method_start_line,omitempty"`
	BundleStartLine          int    `json:"bundle_start_line"`
	BundleEndLine            int    `json:"bundle_end_line"`
	LineMap                  []int  `json:"line_map,omitempty"`
}

type Mapping struct {
	Target       string        `json:"target"`
	Bundle       string        `json:"bundle"`
	Segments     []Segment     `json:"segments"`
	SkippedFiles []SkippedFile `json:"skipped_files,omitempty"`
}

type BuildResult struct {
	Target       string
	OutputBundle string
	OutputMap    string
	Files        []File
	SkippedFiles []SkippedFile
	Mapping      Mapping
}

type MethodMeta struct {
	Static bool `json:"static"`
}

type ClassEntry struct {
	FQCN  string
	Class *ast.StmtClass
}

type FunctionEntry struct {
	FQFN     string
	Function *ast.StmtFunction
}

type buildState struct {
	classMethods map[string]map[string]MethodMeta
	classParents map[string]string
	printer      *prettyprinter.Standard
}

type methodLoweringVisitor struct {
	ast.VisitorAdapter
	currentClass string
	classMethods map[string]map[string]MethodMeta
	classParents map[string]string
	env          map[string]string
}

var loweredNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9_]+`)

func BuildForRoot(root string, excludes []string, outputBundle string, outputMap string, workers int) (*BuildResult, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	jobs, err := parsetree.CollectPHPFiles(absRoot, excludes)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("no PHP files found under %s", absRoot)
	}

	files, skipped, err := loadFiles(jobs, workers)
	if err != nil {
		return nil, err
	}

	printer, err := prettyprinter.NewStandard(prettyprinter.Options{})
	if err != nil {
		return nil, err
	}
	state := buildState{
		classMethods: buildClassMethodMap(files),
		classParents: buildClassParentMap(files),
		printer:      printer,
	}

	if err := os.MkdirAll(filepath.Dir(outputBundle), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir bundle dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputMap), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir map dir: %w", err)
	}

	bundleHandle, err := os.Create(outputBundle)
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer bundleHandle.Close()

	if _, err := bundleHandle.WriteString("<?php\n"); err != nil {
		return nil, fmt.Errorf("write bundle header: %w", err)
	}

	currentLine := 1
	segments := make([]Segment, 0, len(files)*4)
	for _, file := range files {
		functions := collectFunctionNodes(file.AST, "")
		for _, entry := range functions {
			fragment, ok := state.functionFragment(entry.Function)
			if !ok {
				continue
			}
			appendBundleFragment(bundleHandle, &currentLine, &segments, fragment.content, Segment{
				SourcePath:              file.Relative,
				Kind:                    "function",
				SourceFunctionStartLine: entry.Function.StartLine(),
				LineMap:                 fragment.lineMap,
			})
		}

		classes := collectClassNodes(file.AST, "")
		for _, entry := range classes {
			for _, stmt := range entry.Class.Stmts {
				method, ok := stmt.(*ast.StmtClassMethod)
				if !ok {
					continue
				}
				fragment, ok := state.loweredMethodFragment(entry.FQCN, method)
				if !ok {
					continue
				}
				appendBundleFragment(bundleHandle, &currentLine, &segments, fragment.content, Segment{
					SourcePath:            file.Relative,
					Kind:                  "lowered_method",
					SourceMethodStartLine: method.StartLine(),
					LineMap:               fragment.lineMap,
				})
			}
		}
	}

	mapping := Mapping{
		Target:       absRoot,
		Bundle:       outputBundle,
		Segments:     segments,
		SkippedFiles: skipped,
	}
	payload, err := json.MarshalIndent(mapping, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode mapping: %w", err)
	}
	if err := os.WriteFile(outputMap, append(payload, '\n'), 0o644); err != nil {
		return nil, fmt.Errorf("write mapping: %w", err)
	}

	return &BuildResult{
		Target:       absRoot,
		OutputBundle: outputBundle,
		OutputMap:    outputMap,
		Files:        files,
		SkippedFiles: skipped,
		Mapping:      mapping,
	}, nil
}

type fragment struct {
	content string
	lineMap []int
}

func (s buildState) functionFragment(function *ast.StmtFunction) (fragment, bool) {
	if function == nil || function.Stmts == nil {
		return fragment{}, false
	}
	content := strings.TrimRight(s.printer.PrettyPrint([]ast.Node{ast.CloneNode(function)}), "\n") + "\n"
	return fragment{
		content: content,
		lineMap: sequentialLineMap(function.StartLine(), content),
	}, true
}

func (s buildState) loweredMethodFragment(currentClass string, method *ast.StmtClassMethod) (fragment, bool) {
	if method == nil || method.Stmts == nil {
		return fragment{}, false
	}

	clonedMethod, ok := ast.CloneNode(method).(*ast.StmtClassMethod)
	if !ok {
		return fragment{}, false
	}

	visitor := &methodLoweringVisitor{
		currentClass: currentClass,
		classMethods: s.classMethods,
		classParents: s.classParents,
		env:          map[string]string{},
	}
	traverser := ast.NewTraverser(visitor)
	rewrittenStmts, err := traverser.Traverse(clonedMethod.Stmts)
	if err != nil {
		return fragment{}, false
	}

	params := make([]ast.Node, 0, len(clonedMethod.Params)+1)
	if !methodIsStatic(clonedMethod) {
		params = append(params, &ast.Param{
			Var: &ast.ExprVariable{Name: "_semgrep_this"},
		})
	}
	params = append(params, clonedMethod.Params...)

	lowered := &ast.StmtFunction{
		ByRef:      clonedMethod.ByRef,
		Name:       &ast.Identifier{Name: loweredFunctionName(currentClass, identifierText(clonedMethod.Name))},
		Params:     params,
		ReturnType: clonedMethod.ReturnType,
		Stmts:      rewrittenStmts,
	}
	comment := fmt.Sprintf("/* semgrep-lowered-source: %d %s::%s */\n", method.StartLine(), strings.TrimPrefix(currentClass, `\`), identifierText(method.Name))
	content := comment + strings.TrimRight(s.printer.PrettyPrint([]ast.Node{lowered}), "\n") + "\n"
	return fragment{
		content: content,
		lineMap: loweredMethodLineMap(method.StartLine(), content),
	}, true
}

func loadFiles(jobs []parsetree.Job, workers int) ([]File, []SkippedFile, error) {
	if workers < 1 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}

	type parseResult struct {
		file    *File
		skipped *SkippedFile
		err     error
	}

	jobCh := make(chan parsetree.Job, len(jobs))
	resultCh := make(chan parseResult, len(jobs))
	for i := 0; i < workers; i++ {
		go func() {
			for job := range jobCh {
				sourceBytes, err := os.ReadFile(job.Path)
				if err != nil {
					resultCh <- parseResult{err: fmt.Errorf("read %s: %w", job.Path, err)}
					continue
				}
				source := string(sourceBytes)
				stmts, err := parseProgram(source)
				if err != nil {
					resultCh <- parseResult{
						skipped: &SkippedFile{
							SourcePath: job.Relative,
							Error:      err.Error(),
						},
					}
					continue
				}
				resultCh <- parseResult{
					file: &File{
						FullPath: job.Path,
						Relative: job.Relative,
						Source:   source,
						AST:      stmts,
					},
				}
			}
		}()
	}
	for _, job := range jobs {
		jobCh <- job
	}
	close(jobCh)

	files := make([]File, 0, len(jobs))
	skipped := make([]SkippedFile, 0)
	for range jobs {
		result := <-resultCh
		if result.err != nil {
			return nil, nil, result.err
		}
		if result.file != nil {
			files = append(files, *result.file)
		}
		if result.skipped != nil {
			skipped = append(skipped, *result.skipped)
		}
	}

	sort.Slice(files, func(i int, j int) bool {
		return files[i].Relative < files[j].Relative
	})
	sort.Slice(skipped, func(i int, j int) bool {
		return skipped[i].SourcePath < skipped[j].SourcePath
	})
	return files, skipped, nil
}

func parseProgram(source string) ([]ast.Node, error) {
	factory := parser.ParserFactory{}
	versions := []phpparser.PhpVersion{
		phpparser.NewestSupportedPhpVersion(),
		mustPHPVersion("7.4"),
		mustPHPVersion("5.6"),
	}
	var lastErr error
	for _, version := range versions {
		p, err := factory.CreateForVersion(version)
		if err != nil {
			return nil, err
		}
		handler := &phpparser.CollectingErrorHandler{}
		stmts, err := p.Parse(source, handler)
		if err == nil && !handler.HasErrors() {
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

func resolveProgramNames(stmts []ast.Node) (_ []ast.Node, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = nil
			_ = recovered
		}
	}()
	resolver := ast.NewNameResolver(phpparser.ThrowingErrorHandler{}, nil)
	traverser := ast.NewTraverser(resolver)
	resolved, err := traverser.Traverse(stmts)
	if err != nil {
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

func buildClassMethodMap(files []File) map[string]map[string]MethodMeta {
	classMethods := map[string]map[string]MethodMeta{}
	for _, file := range files {
		for _, entry := range collectClassNodes(file.AST, "") {
			methods := classMethods[entry.FQCN]
			if methods == nil {
				methods = map[string]MethodMeta{}
				classMethods[entry.FQCN] = methods
			}
			for _, stmt := range entry.Class.Stmts {
				method, ok := stmt.(*ast.StmtClassMethod)
				if !ok || method.Name == nil {
					continue
				}
				methods[strings.ToLower(identifierText(method.Name))] = MethodMeta{
					Static: methodIsStatic(method),
				}
			}
		}
	}
	return classMethods
}

func buildClassParentMap(files []File) map[string]string {
	parents := map[string]string{}
	for _, file := range files {
		for _, entry := range collectClassNodes(file.AST, "") {
			if entry.Class.Extends == nil {
				continue
			}
			parent := resolvedClassName(entry.Class.Extends, entry.FQCN, parents)
			if parent == "" {
				continue
			}
			parents[entry.FQCN] = parent
		}
	}
	return parents
}

func collectClassNodes(nodes []ast.Node, namespace string) []ClassEntry {
	classes := make([]ClassEntry, 0)
	var walk func([]ast.Node, string)
	walk = func(stmts []ast.Node, currentNS string) {
		for _, stmt := range stmts {
			switch typed := stmt.(type) {
			case *ast.StmtNamespace:
				nextNS := namespaceString(typed.Name)
				walk(typed.Stmts, nextNS)
				continue
			case *ast.StmtClass:
				if typed.Name != nil {
					fqcn := qualifiedName(currentNS, identifierText(typed.Name))
					classes = append(classes, ClassEntry{FQCN: fqcn, Class: typed})
				}
			}
			for _, childStmt := range childStatements(stmt) {
				walk(childStmt, currentNS)
			}
		}
	}
	walk(nodes, namespace)
	return classes
}

func collectFunctionNodes(nodes []ast.Node, namespace string) []FunctionEntry {
	functions := make([]FunctionEntry, 0)
	var walk func([]ast.Node, string)
	walk = func(stmts []ast.Node, currentNS string) {
		for _, stmt := range stmts {
			switch typed := stmt.(type) {
			case *ast.StmtNamespace:
				nextNS := namespaceString(typed.Name)
				walk(typed.Stmts, nextNS)
				continue
			case *ast.StmtFunction:
				if typed.Name != nil {
					fqfn := qualifiedName(currentNS, identifierText(typed.Name))
					functions = append(functions, FunctionEntry{FQFN: fqfn, Function: typed})
				}
			}
			for _, childStmt := range childStatements(stmt) {
				walk(childStmt, currentNS)
			}
		}
	}
	walk(nodes, namespace)
	return functions
}

func childStatements(node ast.Node) [][]ast.Node {
	if node == nil {
		return nil
	}
	out := make([][]ast.Node, 0, 4)
	for _, name := range node.SubNodeNames() {
		value := node.SubNode(name)
		switch typed := value.(type) {
		case ast.Node:
			if _, ok := typed.(interface{ NodeType() string }); ok {
				if asStmt, ok := typed.(ast.Node); ok {
					if _, ok := asStmt.(interface{ NodeType() string }); ok {
						if stmtSlice := singleStatement(asStmt); len(stmtSlice) != 0 {
							out = append(out, stmtSlice)
						}
					}
				}
			}
		case []ast.Node:
			stmtSlice := make([]ast.Node, 0, len(typed))
			for _, child := range typed {
				if child != nil {
					stmtSlice = append(stmtSlice, child)
				}
			}
			if len(stmtSlice) != 0 {
				out = append(out, stmtSlice)
			}
		}
	}
	return out
}

func singleStatement(node ast.Node) []ast.Node {
	if node == nil {
		return nil
	}
	if strings.HasPrefix(node.NodeType(), "Stmt_") {
		return []ast.Node{node}
	}
	return nil
}

func (v *methodLoweringVisitor) LeaveNode(node ast.Node) any {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return nil
		}
		if name == "this" {
			replacement := &ast.ExprVariable{Name: "_semgrep_this"}
			ast.CopyNodeAttributes(replacement, typed)
			return replacement
		}
	case *ast.ExprAssign:
		variable, ok := typed.Var.(*ast.ExprVariable)
		if !ok {
			return nil
		}
		name, ok := variable.Name.(string)
		if !ok {
			return nil
		}
		className := resolveExprClass(typed.Expr, v.env, v.currentClass, v.classParents)
		if className == "" {
			delete(v.env, name)
		} else {
			v.env[name] = className
		}
	case *ast.ExprMethodCall:
		methodName := identifierText(typed.Name)
		if methodName == "" {
			return nil
		}
		className := resolveExprClass(typed.Var, v.env, v.currentClass, v.classParents)
		owner := resolveMethodOwnerClass(className, methodName, v.classMethods, v.classParents)
		if owner == "" {
			return nil
		}
		return buildLoweredFuncCall(owner, methodName, typed.Var, typed.Args, v.classMethods)
	case *ast.ExprStaticCall:
		methodName := identifierText(typed.Name)
		if methodName == "" {
			className := resolvedClassName(typed.Class, v.currentClass, v.classParents)
			if className != "" && isSelfStaticOrParentRef(typed.Class) {
				typed.Class = classNameNode(className)
				return typed
			}
			return nil
		}
		className := resolvedClassName(typed.Class, v.currentClass, v.classParents)
		owner := resolveMethodOwnerClass(className, methodName, v.classMethods, v.classParents)
		if owner != "" {
			return buildLoweredStaticCall(owner, methodName, typed.Args, v.classMethods)
		}
		if className != "" && isSelfStaticOrParentRef(typed.Class) {
			typed.Class = classNameNode(className)
			return typed
		}
	case *ast.ExprStaticPropertyFetch:
		className := resolvedClassName(typed.Class, v.currentClass, v.classParents)
		if className != "" && isSelfStaticOrParentRef(typed.Class) {
			typed.Class = classNameNode(className)
			return typed
		}
	case *ast.ExprClassConstFetch:
		className := resolvedClassName(typed.Class, v.currentClass, v.classParents)
		if className != "" && isSelfStaticOrParentRef(typed.Class) {
			typed.Class = classNameNode(className)
			return typed
		}
	case *ast.ExprNew:
		className := resolvedClassName(typed.Class, v.currentClass, v.classParents)
		if className != "" && isSelfStaticOrParentRef(typed.Class) {
			typed.Class = classNameNode(className)
			return typed
		}
	}
	return nil
}

func resolveExprClass(node ast.Node, env map[string]string, currentClass string, classParents map[string]string) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		if name == "this" || name == "_semgrep_this" {
			return currentClass
		}
		return env[name]
	case *ast.ExprNew:
		return resolvedClassName(typed.Class, currentClass, classParents)
	default:
		return ""
	}
}

func resolveMethodOwnerClass(className string, methodName string, classMethods map[string]map[string]MethodMeta, classParents map[string]string) string {
	if strings.TrimSpace(methodName) == "" {
		return ""
	}
	methodKey := strings.ToLower(methodName)
	seen := map[string]bool{}
	for current := className; current != "" && !seen[current]; current = classParents[current] {
		seen[current] = true
		if methods := classMethods[current]; methods != nil {
			if _, ok := methods[methodKey]; ok {
				return current
			}
		}
	}

	owner := ""
	for candidate, methods := range classMethods {
		if _, ok := methods[methodKey]; !ok {
			continue
		}
		if owner != "" && owner != candidate {
			return ""
		}
		owner = candidate
	}
	return owner
}

func buildLoweredFuncCall(ownerClass string, methodName string, varNode ast.Node, args []ast.Node, classMethods map[string]map[string]MethodMeta) ast.Node {
	loweredArgs := make([]ast.Node, 0, len(args)+1)
	methodMeta := classMethods[ownerClass][strings.ToLower(methodName)]
	if !methodMeta.Static {
		loweredArgs = append(loweredArgs, &ast.Arg{Value: ast.CloneNode(varNode)})
	}
	for _, arg := range args {
		loweredArgs = append(loweredArgs, ast.CloneNode(arg))
	}
	return &ast.ExprFuncCall{
		Name: &ast.Name{Name: loweredFunctionName(ownerClass, methodName)},
		Args: loweredArgs,
	}
}

func buildLoweredStaticCall(ownerClass string, methodName string, args []ast.Node, classMethods map[string]map[string]MethodMeta) ast.Node {
	loweredArgs := make([]ast.Node, 0, len(args)+1)
	methodMeta := classMethods[ownerClass][strings.ToLower(methodName)]
	if !methodMeta.Static {
		loweredArgs = append(loweredArgs, &ast.Arg{Value: &ast.ExprVariable{Name: "_semgrep_this"}})
	}
	for _, arg := range args {
		loweredArgs = append(loweredArgs, ast.CloneNode(arg))
	}
	return &ast.ExprFuncCall{
		Name: &ast.Name{Name: loweredFunctionName(ownerClass, methodName)},
		Args: loweredArgs,
	}
}

func methodIsStatic(method *ast.StmtClassMethod) bool {
	return method != nil && method.Flags&phpparser.ModifierStatic != 0
}

func loweredFunctionName(className string, methodName string) string {
	normalized := loweredNameSanitizer.ReplaceAllString(strings.TrimPrefix(className, `\`), "__")
	return "__semgrep_lowered__" + strings.Trim(normalized, "_") + "__" + methodName
}

func resolvedClassName(node ast.Node, currentClass string, classParents map[string]string) string {
	switch typed := node.(type) {
	case *ast.Name:
		value := strings.ToLower(typed.Name)
		switch value {
		case "self", "static":
			return currentClass
		case "parent":
			return classParents[currentClass]
		default:
			if resolved, ok := typed.Attribute("resolvedName"); ok {
				return normalizedResolvedName(resolved, typed.Name)
			}
			return qualifiedName("", typed.Name)
		}
	case *ast.NameFullyQualified:
		return qualifiedName("", typed.Name)
	case *ast.NameRelative:
		return qualifiedName("", typed.Name)
	case *ast.Identifier:
		value := strings.ToLower(typed.Name)
		switch value {
		case "self", "static":
			return currentClass
		case "parent":
			return classParents[currentClass]
		}
	}
	return ""
}

func normalizedResolvedName(value any, fallback string) string {
	switch typed := value.(type) {
	case *ast.Name:
		return qualifiedName("", typed.Name)
	case *ast.NameFullyQualified:
		return qualifiedName("", typed.Name)
	case *ast.NameRelative:
		return qualifiedName("", typed.Name)
	default:
		return qualifiedName("", fallback)
	}
}

func isSelfStaticOrParentRef(node ast.Node) bool {
	switch typed := node.(type) {
	case *ast.Name:
		value := strings.ToLower(typed.Name)
		return value == "self" || value == "static" || value == "parent"
	case *ast.Identifier:
		value := strings.ToLower(typed.Name)
		return value == "self" || value == "static" || value == "parent"
	default:
		return false
	}
}

func classNameNode(className string) ast.Node {
	return &ast.NameFullyQualified{Name: strings.TrimPrefix(className, `\`)}
}

func identifierText(node ast.Node) string {
	switch typed := node.(type) {
	case *ast.Identifier:
		return typed.Name
	case *ast.Name:
		return typed.Name
	case *ast.NameFullyQualified:
		return typed.Name
	case *ast.NameRelative:
		return typed.Name
	default:
		return ""
	}
}

func namespaceString(node ast.Node) string {
	name := identifierText(node)
	if name == "" {
		return ""
	}
	return `\` + strings.TrimPrefix(name, `\`)
}

func qualifiedName(namespace string, name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, `\`) {
		return `\` + strings.TrimPrefix(name, `\`)
	}
	if namespace != "" {
		return namespace + `\` + name
	}
	return `\` + name
}

func appendBundleFragment(handle *os.File, currentLine *int, segments *[]Segment, content string, segment Segment) {
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	fragmentStart := *currentLine + 1
	_, _ = handle.WriteString(content)
	fragmentLineCount := strings.Count(content, "\n")
	segment.BundleStartLine = fragmentStart
	segment.BundleEndLine = fragmentStart + fragmentLineCount - 1
	*segments = append(*segments, segment)
	*currentLine += fragmentLineCount
}

func sequentialLineMap(startLine int, content string) []int {
	lineCount := strings.Count(content, "\n")
	if lineCount == 0 {
		return nil
	}
	lineMap := make([]int, 0, lineCount)
	for i := 0; i < lineCount; i++ {
		lineMap = append(lineMap, startLine+i)
	}
	return lineMap
}

func loweredMethodLineMap(startLine int, content string) []int {
	lineCount := strings.Count(content, "\n")
	if lineCount == 0 {
		return nil
	}
	lineMap := make([]int, 0, lineCount)
	for i := 0; i < lineCount; i++ {
		lineMap = append(lineMap, startLine+i)
	}
	return lineMap
}
