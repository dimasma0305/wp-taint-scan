package taintscan

import (
	"fmt"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

type structuralRoot struct {
	key      string
	isStatic bool
}

func (s *analysisState) copyStructuralAssignEffects(target ast.Node, expr ast.Node) {
	dst, ok := s.structuralRoot(target)
	if !ok {
		return
	}
	s.clearStructuralSubtree(dst)
	switch typed := expr.(type) {
	case *ast.ExprFuncCall:
		if root, ok := storageReadRootForFuncCall(typed); ok {
			s.copyStoragePathsToTarget(dst, root)
		}
		if key := s.resolveFunctionKey(typed.Name); key != "" {
			s.copyInstantiatedSummaryReturnPaths(dst, key, typed.Args, typed.StartLine())
		}
		for _, idx := range structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args)) {
			s.copyStructuralFromExpr(dst, argValue(typed.Args[idx]))
		}
	case *ast.ExprMethodCall:
		if s.copyMethodStorageReadStructure(dst, typed) {
			return
		}
		name := strings.ToLower(identifierText(typed.Name))
		if key := s.resolveMethodKeyWithArgs(s.resolveClassExpr(typed.Var), name, typed.Args); key != "" {
			s.copyInstantiatedSummaryReturnPaths(dst, key, typed.Args, typed.StartLine())
		}
	case *ast.ExprStaticCall:
		if paths, ok := sqlSelectReturnPathsForStaticCall(typed, s); ok {
			dstStore := s.destinationStructuralStore(dst)
			for rel, origins := range paths {
				unionMapEntry(dstStore, dst.key+rel, origins)
			}
			return
		}
		name := strings.ToLower(identifierText(typed.Name))
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if key := s.resolveMethodKeyWithArgs(className, name, typed.Args); key != "" {
			s.copyInstantiatedSummaryReturnPaths(dst, key, typed.Args, typed.StartLine())
		}
	}
	s.copyStructuralFromExpr(dst, expr)
	switch expr.(type) {
	case *ast.ExprFuncCall, *ast.ExprMethodCall, *ast.ExprStaticCall:
		dstStore := s.destinationStructuralStore(dst)
		if _, ok := dstStore[dst.key]; !ok && !hasStructuralChildren(dstStore, dst.key) {
			if origins := s.evalExpr(expr); len(origins) != 0 {
				unionMapEntry(dstStore, dst.key, origins)
			}
		}
	}
}

func (s *analysisState) copyInstantiatedSummaryReturnPaths(dst structuralRoot, summaryKey string, args []ast.Node, callLine int) {
	if summaryKey == "" {
		return
	}
	paths := s.instantiateSummaryReturnPathsForKey(summaryKey, s.summaryForCurrentCall(summaryKey, callLine), args, s.evalArgs(args))
	if len(paths) == 0 {
		return
	}
	dstStore := s.destinationStructuralStore(dst)
	for relPath, origins := range paths {
		unionMapEntry(dstStore, dst.key+relPath, origins)
	}
}

func (s *analysisState) filterReturnValueArgs(call *ast.ExprFuncCall) ([]originSet, []ast.Node, string, bool) {
	name := normalizeName(identifierText(call.Name))
	switch name {
	case "apply_filters":
		if len(call.Args) <= 1 {
			return nil, nil, name, false
		}
		nodes := sliceArgValues(call.Args[1:])
		args := make([]originSet, 0, len(nodes))
		for _, node := range nodes {
			args = append(args, s.evalExpr(node))
		}
		return args, nodes, name, len(nodes) != 0
	case "apply_filters_ref_array":
		if len(call.Args) <= 1 {
			return nil, nil, name, false
		}
		args, nodes, ok := s.evalRefArrayArgs(call.Args, 1)
		return args, nodes, name, ok && len(nodes) != 0
	default:
		return nil, nil, name, false
	}
}

func (s *analysisState) filterReturnStructuralPaths(call *ast.ExprFuncCall) map[string]originSet {
	callbackArgs, callbackNodes, name, ok := s.filterReturnValueArgs(call)
	if !ok || len(callbackNodes) == 0 {
		return nil
	}
	out := map[string]originSet{}
	for rel, origins := range s.collectExprStructuralPaths(callbackNodes[0]) {
		unionMapEntry(out, rel, origins)
	}
	hook := hookDispatchKeyForCallable(argValue(call.Args[0]), s.current, s.engine)
	if hook != "" {
		for _, key := range s.engine.dispatchRelevantCallbackKeys(name, hook) {
			if key == s.current.Key {
				continue
			}
			for rel, origins := range s.instantiateSummaryReturnPathsForKey(key, s.summaryForKey(key), callbackNodes, callbackArgs) {
				unionMapEntry(out, rel, origins)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *analysisState) copyMethodStorageReadStructure(dst structuralRoot, call *ast.ExprMethodCall) bool {
	paths, ok := sqlSelectReturnPathsForMethodCall(call, s)
	if !ok || len(paths) == 0 {
		return false
	}
	dstStore := s.destinationStructuralStore(dst)
	for rel, origins := range paths {
		unionMapEntry(dstStore, dst.key+rel, origins)
	}
	return true
}

func (s *analysisState) captureReturnStructure(expr ast.Node) {
	for relPath, origins := range s.returnStructuralPaths(expr) {
		unionMapEntry(s.returnPathWrites, relPath, origins)
	}
}

func (s *analysisState) returnStructuralPaths(expr ast.Node) map[string]originSet {
	switch typed := expr.(type) {
	case *ast.ExprArray:
		return s.collectExprStructuralPaths(typed)
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			return collectRelativeStructuralPaths(s.propTaint, name)
		}
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			return collectRelativeStructuralPaths(s.propTaint, path)
		}
	case *ast.ExprStaticPropertyFetch:
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			paths := map[string]originSet{}
			for rel, origins := range collectRelativeStructuralPaths(s.engine.staticProps, path) {
				unionMapEntry(paths, rel, origins)
			}
			for rel, origins := range collectRelativeStructuralPaths(s.staticPropTaint, path) {
				unionMapEntry(paths, rel, origins)
			}
			return paths
		}
	case *ast.ExprCastObject:
		if arrayExpr, ok := typed.Expr.(*ast.ExprArray); ok {
			return s.objectLiteralStructuralPaths(arrayExpr)
		}
		return s.returnStructuralPaths(typed.Expr)
	case *ast.ExprTernary:
		out := map[string]originSet{}
		branch := typed.If
		if branch == nil {
			branch = typed.Cond
		}
		for rel, origins := range s.returnStructuralPaths(branch) {
			unionMapEntry(out, rel, origins)
		}
		for rel, origins := range s.returnStructuralPaths(typed.Else) {
			unionMapEntry(out, rel, origins)
		}
		if len(out) != 0 {
			return out
		}
	case *ast.ExprArrayDimFetch:
		if paths := s.collectExprStructuralPaths(typed); len(paths) != 0 {
			return paths
		}
	case *ast.ExprFuncCall:
		out := map[string]originSet{}
		for rel, origins := range s.filterReturnStructuralPaths(typed) {
			unionMapEntry(out, rel, origins)
		}
		for rel, origins := range s.arrayMapCallbackReturnPaths(typed) {
			unionMapEntry(out, rel, origins)
		}
		for _, idx := range structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args)) {
			for rel, origins := range s.returnStructuralPaths(argValue(typed.Args[idx])) {
				unionMapEntry(out, rel, origins)
			}
		}
		if root, ok := storageReadRootForFuncCall(typed); ok {
			for rel, origins := range collectRelativeStructuralPathsFromStorage(s, root) {
				unionMapEntry(out, rel, origins)
			}
		}
		if key := s.resolveFunctionKey(typed.Name); key != "" {
			for rel, origins := range s.instantiateSummaryReturnPathsForKey(key, s.summaryForCurrentCall(key, typed.StartLine()), typed.Args, s.evalArgs(typed.Args)) {
				unionMapEntry(out, rel, origins)
			}
		}
		if len(out) != 0 {
			return out
		}
	case *ast.ExprMethodCall:
		if paths, ok := sqlSelectReturnPathsForMethodCall(typed, s); ok {
			return paths
		}
		name := strings.ToLower(identifierText(typed.Name))
		if key := s.resolveMethodKey(s.resolveClassExpr(typed.Var), name); key != "" {
			return s.instantiateSummaryReturnPathsForKey(key, s.summaryForCurrentCall(key, typed.StartLine()), typed.Args, s.evalArgs(typed.Args))
		}
	case *ast.ExprStaticCall:
		name := strings.ToLower(identifierText(typed.Name))
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if key := s.resolveMethodKey(className, name); key != "" {
			return s.instantiateSummaryReturnPathsForKey(key, s.summaryForCurrentCall(key, typed.StartLine()), typed.Args, s.evalArgs(typed.Args))
		}
	}
	return nil
}

func (s *analysisState) instantiateSummaryReturnPathsForKey(summaryKey string, item summary, argNodes []ast.Node, args []originSet) map[string]originSet {
	if summaryKey == "" {
		return s.instantiateSummaryReturnPaths(item, argNodes, args)
	}
	item = s.summaryForKey(summaryKey)
	if summaryKey == s.current.Key && summaryHasOnlyReturnEffects(item) {
		return s.instantiateSummaryReturnPathsDirectArgs(item, argNodes)
	}
	if s.summaryReturnPathCache == nil {
		s.summaryReturnPathCache = map[string]map[string]originSet{}
	}
	if s.summaryReturnPathActive == nil {
		s.summaryReturnPathActive = map[string]struct{}{}
	}
	cacheKey := summaryKey + "|" + summaryReturnPathArgsKey(argNodes)
	if cached, ok := s.summaryReturnPathCache[cacheKey]; ok {
		return cached
	}
	if _, ok := s.summaryReturnPathActive[cacheKey]; ok {
		return nil
	}
	s.summaryReturnPathActive[cacheKey] = struct{}{}
	out := s.instantiateSummaryReturnPaths(item, argNodes, args)
	delete(s.summaryReturnPathActive, cacheKey)
	// Cap the return-path cache to prevent nested-map OOM on large callables.
	if len(s.summaryReturnPathCache) < 256 {
		s.summaryReturnPathCache[cacheKey] = out
	}
	return out
}

func (s *analysisState) instantiateSummaryReturnPathsDirectArgs(item summary, argNodes []ast.Node) map[string]originSet {
	if len(item.ReturnParams) == 0 && len(item.ReturnParamPaths) == 0 {
		return nil
	}
	out := map[string]originSet{}
	for _, idx := range item.ReturnParams {
		if idx < 0 || idx >= len(argNodes) {
			continue
		}
		for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[idx]), "") {
			unionMapEntry(out, suffix, origins)
		}
	}
	for _, ref := range item.ReturnParamPaths {
		if ref.Index < 0 || ref.Index >= len(argNodes) {
			continue
		}
		for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[ref.Index]), ref.Path) {
			unionMapEntry(out, suffix, origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return compactRelativeStructuralPathsByRoot(out)
}

func summaryReturnPathArgsKey(argNodes []ast.Node) string {
	if len(argNodes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(argNodes))
	for _, node := range argNodes {
		parts = append(parts, fmt.Sprintf("%T:%p", node, node))
	}
	return strings.Join(parts, "|")
}

func (s *analysisState) instantiateSummaryReturnPaths(item summary, argNodes []ast.Node, args []originSet) map[string]originSet {
	if len(item.ReturnParams) == 0 && len(item.ReturnParamPaths) == 0 && len(item.ReturnPathWrites) == 0 {
		return nil
	}
	out := map[string]originSet{}
	for _, idx := range item.ReturnParams {
		if idx < 0 || idx >= len(argNodes) {
			continue
		}
		for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[idx]), "") {
			unionMapEntry(out, suffix, origins)
		}
	}
	for _, ref := range item.ReturnParamPaths {
		if ref.Index < 0 || ref.Index >= len(argNodes) {
			continue
		}
		for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(argNodes[ref.Index]), ref.Path) {
			unionMapEntry(out, suffix, origins)
		}
	}
	for relPath, effect := range item.ReturnPathWrites {
		unionMapEntry(out, relPath, s.instantiateTaintSummaryStatic(effect, args, argNodes))
		for concretePath, origins := range s.instantiateConcreteSummaryPathWrites(relPath, effect, argNodes) {
			unionMapEntry(out, concretePath, origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return compactRelativeStructuralPathsByRoot(out)
}

func (s *analysisState) instantiateConcreteSummaryPathWrites(basePath string, effect taintSummary, argNodes []ast.Node) map[string]originSet {
	if basePath == "" || len(effect.ParamPaths) == 0 || len(argNodes) == 0 {
		return nil
	}
	out := map[string]originSet{}
	for _, ref := range effect.ParamPaths {
		if ref.Index < 0 || ref.Index >= len(argNodes) {
			continue
		}
		for concretePath, origins := range s.instantiateConcreteSummaryPathWritesForRef(basePath, ref, argValue(argNodes[ref.Index])) {
			unionMapEntry(out, concretePath, origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *analysisState) instantiateConcreteSummaryPathWritesForRef(basePath string, ref paramPathRef, node ast.Node) map[string]originSet {
	if node == nil {
		return nil
	}
	paths := s.collectExprStructuralPaths(node)
	if len(paths) == 0 {
		return nil
	}
	out := map[string]originSet{}
	for relPath, origins := range paths {
		concretePath, ok := concretizeSummaryWritePath(basePath, ref.Path, relPath)
		if !ok || concretePath == "" {
			continue
		}
		origins = applyParamPathRefFlags(applyStoredWriteContext(origins, ref.StoredWriteContext), ref)
		unionMapEntry(out, concretePath, origins)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func concretizeSummaryWritePath(basePath string, matchPath string, argRelPath string) (string, bool) {
	captured := make([]string, 0, 2)
	remainder := argRelPath
	wanted := matchPath
	for wanted != "" {
		wantSeg, nextWanted, ok := nextPathSegment(wanted)
		if !ok {
			return "", false
		}
		gotSeg, nextRemainder, ok := nextPathSegment(remainder)
		if !ok || !summaryWritePathSegmentMatches(wantSeg, gotSeg) {
			return "", false
		}
		if wantSeg == "[]" || wantSeg == "*" {
			captured = append(captured, gotSeg)
		}
		wanted = nextWanted
		remainder = nextRemainder
	}
	return substituteSummaryWriteWildcards(basePath, captured) + remainder, true
}

func summaryWritePathSegmentMatches(want string, got string) bool {
	if want == "*" {
		return !strings.HasPrefix(got, ".")
	}
	return structuralPathSegmentMatches(want, got)
}

func substituteSummaryWriteWildcards(path string, captures []string) string {
	if len(captures) == 0 {
		return path
	}
	root := path
	remainder := ""
	if idx := strings.IndexAny(path, "[."); idx >= 0 {
		root = path[:idx]
		remainder = path[idx:]
	} else {
		root = path
	}
	segments := make([]string, 0, 4)
	for remainder != "" {
		seg, rest, ok := nextPathSegment(remainder)
		if !ok {
			if remainder != "" {
				segments = append(segments, remainder)
			}
			remainder = ""
			break
		}
		segments = append(segments, seg)
		remainder = rest
	}
	dynamicIndexes := make([]int, 0, len(segments))
	for idx, seg := range segments {
		if seg == "[]" || seg == "*" {
			dynamicIndexes = append(dynamicIndexes, idx)
		}
	}
	start := len(dynamicIndexes) - len(captures)
	if start < 0 {
		start = 0
	}
	captureIdx := 0
	for i := start; i < len(dynamicIndexes) && captureIdx < len(captures); i++ {
		segments[dynamicIndexes[i]] = captures[captureIdx]
		captureIdx++
	}
	var b strings.Builder
	b.WriteString(root)
	for _, seg := range segments {
		b.WriteString(renderStructuralSegment(seg))
	}
	for ; captureIdx < len(captures); captureIdx++ {
		b.WriteString(renderStructuralSegment(captures[captureIdx]))
	}
	return b.String()
}

func renderStructuralSegment(segment string) string {
	switch {
	case segment == "":
		return ""
	case segment == "[]":
		return "[]"
	case strings.HasPrefix(segment, "."):
		return segment
	default:
		return "[" + strings.ToLower(segment) + "]"
	}
}

func (s *analysisState) instantiateTaintSummaryStatic(item taintSummary, args []originSet, argNodes []ast.Node) originSet {
	out := originsFromTaintSummary(item)
	for _, idx := range item.Params {
		if idx >= 0 && idx < len(args) {
			out = unionInto(out, args[idx])
		}
	}
	for _, ref := range item.ParamPaths {
		if ref.Index >= 0 && ref.Index < len(argNodes) {
			out = unionInto(out, applyParamPathRefFlags(applyStoredWriteContext(s.resolveArgumentPathOriginsStatic(argValue(argNodes[ref.Index]), ref.Path, args), ref.StoredWriteContext), ref))
		}
	}
	return out
}

func (s *analysisState) resolveArgumentPathOriginsStatic(node ast.Node, path string, args []originSet) originSet {
	_ = args
	if node == nil {
		return originSet{}
	}
	if path == "" {
		return s.evalExpr(node)
	}
	if root, ok := s.structuralRoot(node); ok {
		if origins := s.resolveStructuralPathOrigins(root, path); len(origins) != 0 {
			return origins
		}
	}
	switch typed := node.(type) {
	case *ast.ExprArray:
		segment, rest, hasSegment := nextPathSegment(path)
		if !hasSegment {
			return originSet{}
		}
		out := originSet{}
		for _, itemNode := range typed.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			if segment == "[]" || segment == "*" {
				out = out.union(s.resolveArgumentPathOriginsStatic(item.Value, rest, args))
				continue
			}
			if strings.EqualFold(literalString(item.Key), segment) {
				return s.resolveArgumentPathOriginsStatic(item.Value, rest, args)
			}
		}
		return out
	case *ast.ExprFuncCall:
		if origins := lookupStructuralPathOrigins(s.filterReturnStructuralPaths(typed), path); len(origins) != 0 {
			return origins
		}
		argIndexes := structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args))
		if len(argIndexes) != 0 {
			out := originSet{}
			for _, idx := range argIndexes {
				out = out.union(s.resolveArgumentPathOriginsStatic(argValue(typed.Args[idx]), path, args))
			}
			return out
		}
	case *ast.ExprMethodCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.resolveArgumentPathOriginsStatic(argValue(typed.Args[0]), path, args)
		}
		name := strings.ToLower(identifierText(typed.Name))
		if key := s.resolveMethodKey(s.resolveClassExpr(typed.Var), name); key != "" {
			if origins := lookupStructuralPathOrigins(s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)), path); len(origins) != 0 {
				return origins
			}
		}
	case *ast.ExprStaticCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.resolveArgumentPathOriginsStatic(argValue(typed.Args[0]), path, args)
		}
		name := strings.ToLower(identifierText(typed.Name))
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if key := s.resolveMethodKey(className, name); key != "" {
			if origins := lookupStructuralPathOrigins(s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)), path); len(origins) != 0 {
				return origins
			}
		}
	}
	return applyPathStringToOrigins(s.evalExpr(node), path, s.locationForNode(node))
}

func collectRelativeStructuralPaths(store map[string]originSet, root string) map[string]originSet {
	if store == nil || root == "" {
		return nil
	}
	out := map[string]originSet{}
	prefixArray := root + "["
	prefixProp := root + "."
	for path, origins := range store {
		if strings.HasPrefix(path, prefixArray) || strings.HasPrefix(path, prefixProp) {
			out[strings.TrimPrefix(path, root)] = out[strings.TrimPrefix(path, root)].union(origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectRelativeStructuralPathsFromStorage(s *analysisState, root string) map[string]originSet {
	out := map[string]originSet{}
	for rel, origins := range collectRelativeStructuralPaths(s.engine.storagePaths, root) {
		out[rel] = out[rel].union(s.enrichStorageOriginsWithFamilyContext(origins, root+rel))
	}
	for rel, origins := range collectRelativeStructuralPaths(s.storagePathWrites, root) {
		out[rel] = out[rel].union(s.enrichStorageOriginsWithFamilyContext(origins, root+rel))
	}
	return out
}

func returnPathsForSQLColumns(columns []sqlSelectColumn, multipleRows bool, tableRoot string, s *analysisState) map[string]originSet {
	out := map[string]originSet{}
	for _, column := range columns {
		if column.Field == "" || column.Family == "" {
			continue
		}
		relPaths := sqlColumnResultRelativePaths(column.Field, multipleRows)
		if tableRoot != "" && column.StorageField != "" {
			for _, storagePath := range databaseTableColumnStorageRoots(tableRoot, column.StorageField) {
				for _, relPath := range relPaths {
					unionMapEntry(out, relPath, s.storageSelfOrigins(storagePath))
					unionMapEntry(out, relPath, s.storageChildOrigins(storagePath))
				}
				for rel, origins := range collectRelativeStructuralPathsFromStorage(s, storagePath) {
					for _, relPath := range relPaths {
						unionMapEntry(out, relPath+rel, origins)
					}
				}
			}
		}
		for _, relPath := range relPaths {
			unionMapEntry(out, relPath, storageOriginsForFamily(column.Family, s))
		}
		for rel, origins := range collectRelativeStructuralPathsFromStorage(s, column.Family) {
			for _, relPath := range relPaths {
				unionMapEntry(out, relPath+rel, origins)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sqlColumnResultRelativePaths(field string, multipleRows bool) []string {
	field = canonicalDBTableKey(field)
	if field == "" {
		return nil
	}
	prefix := ""
	if multipleRows {
		prefix = "[]"
	}
	return []string{
		prefix + "[" + field + "]",
		prefix + "." + field,
	}
}

func (s *analysisState) structuralRoot(node ast.Node) (structuralRoot, bool) {
	if variable, ok := node.(*ast.ExprVariable); ok {
		name, ok := variable.Name.(string)
		if ok && name != "" {
			if _, isSuperglobal := s.superglobalSource(name, nil, variable); !isSuperglobal {
				return structuralRoot{key: name, isStatic: false}, true
			}
		}
	}
	if key, ok := staticPropertyPathKey(node, s.current.Class, s.engine); ok {
		return structuralRoot{key: key, isStatic: true}, true
	}
	if key, ok := propertyPathKey(node, s.current.Class); ok {
		return structuralRoot{key: key, isStatic: false}, true
	}
	return structuralRoot{}, false
}

func (s *analysisState) clearStructuralSubtree(root structuralRoot) {
	if root.key == "" {
		return
	}
	s.clearStructuralStorageLinks(root.key)
	if root.isStatic {
		clearStructuralPrefix(s.staticPropTaint, root.key)
		return
	}
	clearStructuralPrefix(s.propTaint, root.key)
}

func clearStructuralPrefix(store map[string]originSet, root string) {
	prefixArray := root + "["
	prefixProp := root + "."
	for key := range store {
		if strings.HasPrefix(key, prefixArray) || strings.HasPrefix(key, prefixProp) {
			delete(store, key)
		}
	}
}

func firstStructuralPathSegment(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	switch path[0] {
	case '[':
		end := strings.IndexByte(path, ']')
		if end < 0 {
			return "", false
		}
		segment := path[:end+1]
		if segment == "[]" || segment == "[*]" {
			return "", false
		}
		return segment, true
	case '.':
		rest := path[1:]
		end := len(rest)
		for i := 0; i < len(rest); i++ {
			if rest[i] == '[' || rest[i] == '.' {
				end = i
				break
			}
		}
		if end == 0 {
			return "", false
		}
		return "." + rest[:end], true
	default:
		return "", false
	}
}

func concreteArrayMapKeyPrefixes(paths map[string]originSet) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	for path := range paths {
		segment, ok := firstStructuralPathSegment(path)
		if !ok {
			continue
		}
		if _, exists := seen[segment]; exists {
			continue
		}
		seen[segment] = struct{}{}
		out = append(out, segment)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *analysisState) copySummaryReturnStructure(dst structuralRoot, summary summary, args []ast.Node) {
	evaluatedArgs := s.evalArgs(args)
	dstStore := s.destinationStructuralStore(dst)
	for _, idx := range summary.ReturnParams {
		if idx < 0 || idx >= len(args) {
			continue
		}
		s.copyStructuralFromExpr(dst, argValue(args[idx]))
	}
	for _, ref := range summary.ReturnParamPaths {
		if ref.Index < 0 || ref.Index >= len(args) {
			continue
		}
		for suffix, origins := range s.resolveArgumentStructuralPaths(argValue(args[ref.Index]), ref.Path) {
			dstStore[dst.key+suffix] = dstStore[dst.key+suffix].union(origins)
		}
	}
	for relPath, effect := range summary.ReturnPathWrites {
		fullPath := dst.key + relPath
		dstStore[fullPath] = dstStore[fullPath].union(s.instantiateTaintSummary(effect, evaluatedArgs, args))
	}
}

func (s *analysisState) copyStructuralFromExpr(dst structuralRoot, expr ast.Node) {
	if family, ok := s.structuralStorageFamilyForExpr(expr); ok {
		s.copyStoragePathsToTarget(dst, family)
		if !dst.isStatic && strings.HasPrefix(dst.key, "this.") {
			s.receiverStorageLinks[strings.TrimPrefix(dst.key, "this.")] = family
		}
		return
	}
	if src, ok := s.structuralRoot(expr); ok {
		s.copyStructuralPaths(dst, src)
		return
	}
	switch typed := expr.(type) {
	case *ast.ExprArray:
		s.copyArrayLiteralStructure(dst, typed)
	case *ast.ExprCastObject:
		if arrayExpr, ok := typed.Expr.(*ast.ExprArray); ok {
			s.copyObjectLiteralStructure(dst, arrayExpr)
			return
		}
		s.copyStructuralFromExpr(dst, typed.Expr)
		return
	case *ast.ExprTernary:
		branch := typed.If
		if branch == nil {
			branch = typed.Cond
		}
		s.copyStructuralFromExpr(dst, branch)
		s.copyStructuralFromExpr(dst, typed.Else)
		return
	case *ast.ExprFuncCall:
		if paths := s.filterReturnStructuralPaths(typed); len(paths) != 0 {
			dstStore := s.destinationStructuralStore(dst)
			for rel, origins := range paths {
				unionMapEntry(dstStore, dst.key+rel, origins)
			}
		}
		if paths := s.arrayMapCallbackReturnPaths(typed); len(paths) != 0 {
			dstStore := s.destinationStructuralStore(dst)
			for rel, origins := range paths {
				unionMapEntry(dstStore, dst.key+rel, origins)
			}
		}
		for _, idx := range structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args)) {
			s.copyStructuralFromExpr(dst, argValue(typed.Args[idx]))
		}
	case *ast.ExprMethodCall:
		if len(typed.Args) > 0 && isRequestGetterMethod(strings.ToLower(identifierText(typed.Name))) {
			return
		}
	case *ast.ExprStaticCall:
		if len(typed.Args) > 0 {
			className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
			if isRequestGetterStaticCall(className, identifierText(typed.Name)) || isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
				return
			}
		}
	}
}

func (s *analysisState) arrayMapCallbackReturnPaths(call *ast.ExprFuncCall) map[string]originSet {
	if normalizeName(identifierText(call.Name)) != "array_map" || len(call.Args) < 2 {
		return nil
	}
	callbackKeys := s.engine.resolveExistingCallbackKeys(argValue(call.Args[0]), s.current)
	if len(callbackKeys) == 0 {
		return nil
	}
	elementArgs := make([]ast.Node, 0, len(call.Args)-1)
	for _, arg := range call.Args[1:] {
		elementArgs = append(elementArgs, &ast.ExprArrayDimFetch{Var: argValue(arg)})
	}
	prefixes := []string{"[]"}
	if len(call.Args) == 2 {
		if keyed := concreteArrayMapKeyPrefixes(s.collectExprStructuralPaths(argValue(call.Args[1]))); len(keyed) != 0 {
			prefixes = keyed
		}
	}
	out := map[string]originSet{}
	for _, key := range callbackKeys {
		for rel, origins := range s.instantiateSummaryReturnPathsForKey(key, s.summaryForKey(key), elementArgs, s.evalArgs(elementArgs)) {
			for _, prefix := range prefixes {
				unionMapEntry(out, prefix+rel, origins)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (e *engine) resolveExistingCallbackKeys(node ast.Node, current callable) []string {
	keys := make([]string, 0, 2)
	add := func(key string) {
		if key == "" {
			return
		}
		for _, existing := range keys {
			if existing == key {
				return
			}
		}
		keys = append(keys, key)
	}
	switch typed := node.(type) {
	case *ast.ScalarString:
		name := typed.Value
		if strings.Contains(name, "::") {
			parts := strings.SplitN(name, "::", 2)
			add(e.existingRuntimeMethodCallable(resolveCallbackClassRefString(parts[0], current), parts[1]))
			return keys
		}
		add(e.lookupFunctionKey(current.Namespace, name))
		add(e.existingRuntimeMethodCallable(current.Class, name))
	case *ast.ExprArray:
		items := arrayItems(typed)
		if len(items) < 2 {
			return keys
		}
		methodName := callbackMethodName(items[1])
		for _, className := range e.resolveCallbackClassRefsWithSeen(items[0], current, map[string]struct{}{}) {
			add(e.existingRuntimeMethodCallable(className, methodName))
		}
	}
	return keys
}

func (s *analysisState) copyArrayLiteralStructure(dst structuralRoot, arrayExpr *ast.ExprArray) {
	dstStore := s.destinationStructuralStore(dst)
	for _, itemNode := range arrayExpr.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok {
			continue
		}
		childKey := appendArrayPath(dst.key, item.Key)
		childRoot := structuralRoot{key: childKey, isStatic: dst.isStatic}
		s.copyStructuralFromExpr(childRoot, item.Value)
		if hasStructuralChildren(dstStore, childKey) {
			continue
		}
		origins := s.evalExpr(item.Value)
		if len(origins) == 0 {
			continue
		}
		dstStore[childKey] = dstStore[childKey].union(origins)
	}
}

func (s *analysisState) copyObjectLiteralStructure(dst structuralRoot, arrayExpr *ast.ExprArray) {
	dstStore := s.destinationStructuralStore(dst)
	for _, itemNode := range arrayExpr.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(literalString(item.Key)))
		if key == "" {
			continue
		}
		childKey := dst.key + "." + key
		childRoot := structuralRoot{key: childKey, isStatic: dst.isStatic}
		s.copyStructuralFromExpr(childRoot, item.Value)
		if hasStructuralChildren(dstStore, childKey) {
			continue
		}
		origins := s.evalExpr(item.Value)
		if len(origins) == 0 {
			continue
		}
		dstStore[childKey] = dstStore[childKey].union(origins)
	}
}

func (s *analysisState) objectLiteralStructuralPaths(arrayExpr *ast.ExprArray) map[string]originSet {
	out := map[string]originSet{}
	for _, itemNode := range arrayExpr.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(literalString(item.Key)))
		if key == "" {
			continue
		}
		childPrefix := "." + key
		childPaths := s.collectExprStructuralPaths(item.Value)
		if len(childPaths) == 0 {
			origins := s.evalExpr(item.Value)
			if len(origins) != 0 {
				out[childPrefix] = out[childPrefix].union(origins)
			}
			continue
		}
		for suffix, origins := range childPaths {
			out[childPrefix+suffix] = out[childPrefix+suffix].union(origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *analysisState) copyStructuralPaths(dst structuralRoot, src structuralRoot) {
	if dst.key == "" || src.key == "" {
		return
	}
	s.copyStructuralPathsToMap(s.destinationStructuralStore(dst), dst.key, src)
}

func (s *analysisState) copyStructuralPathsToMap(dst map[string]originSet, dstRoot string, src structuralRoot) {
	if dstRoot == "" || src.key == "" {
		return
	}
	var maps []map[string]originSet
	if src.isStatic {
		maps = append(maps, s.engine.staticProps, s.staticPropTaint)
	} else {
		maps = append(maps, s.propTaint)
	}
	for _, store := range maps {
		copyStructuralPathMap(dst, store, dstRoot, src.key)
	}
}

func pruneCoveredStructuralRoot(store map[string]originSet, root string) {
	if store == nil || root == "" {
		return
	}
	origins, ok := store[root]
	if !ok || len(origins) == 0 {
		return
	}
	if children := collectStructuralChildren(store, root); originSetCoveredBy(origins, children) {
		delete(store, root)
	}
}

func (s *analysisState) copyStoragePathsToTarget(dst structuralRoot, family string) {
	dstStore := s.destinationStructuralStore(dst)
	copyPersistentStructuralPathMap(dstStore, s.engine.storagePaths, dst.key, family)
	copyStructuralPathMap(dstStore, s.storagePathWrites, dst.key, family)
	s.recordStructuralStorageLink(dst.key, family)
	if !dst.isStatic && strings.HasPrefix(dst.key, "this.") {
		s.receiverStorageLinks[strings.TrimPrefix(dst.key, "this.")] = family
	}
}

func (s *analysisState) copyForeachValueStructure(dstNode ast.Node, expr ast.Node) {
	dst, ok := s.structuralRoot(dstNode)
	if !ok {
		return
	}
	if src, ok := s.structuralRoot(expr); ok {
		if family, linked := s.structuralStorageFamilyForRoot(src.key); linked {
			dstStore := s.destinationStructuralStore(dst)
			copyPersistentIteratedPathMap(dstStore, s.engine.storagePaths, dst.key, family)
			copyIteratedPathMap(dstStore, s.storagePathWrites, dst.key, family)
			s.recordStructuralStorageLink(dst.key, family)
			return
		}
		s.copyIteratedStructuralPaths(dst, src)
		return
	}
	if family, ok := s.structuralStorageFamilyForExpr(expr); ok {
		dstStore := s.destinationStructuralStore(dst)
		copyPersistentIteratedPathMap(dstStore, s.engine.storagePaths, dst.key, family)
		copyIteratedPathMap(dstStore, s.storagePathWrites, dst.key, family)
		s.recordStructuralStorageLink(dst.key, family)
	}
}

func (s *analysisState) recordStructuralStorageLink(root string, family string) {
	if s == nil || root == "" || family == "" {
		return
	}
	if s.structuralStorageLinks == nil {
		s.structuralStorageLinks = map[string]string{}
	}
	s.structuralStorageLinks[root] = family
}

func (s *analysisState) clearStructuralStorageLinks(root string) {
	if s == nil || s.structuralStorageLinks == nil || root == "" {
		return
	}
	for key := range s.structuralStorageLinks {
		if key == root {
			delete(s.structuralStorageLinks, key)
			continue
		}
		if _, ok := trimStructuralPrefix(key, root); ok {
			delete(s.structuralStorageLinks, key)
		}
	}
}

func (s *analysisState) structuralStorageFamilyForExpr(expr ast.Node) (string, bool) {
	if family, ok := storageFamilyExpr(expr); ok {
		return family, true
	}
	if src, ok := s.structuralRoot(expr); ok {
		return s.structuralStorageFamilyForRoot(src.key)
	}
	return "", false
}

func (s *analysisState) structuralStorageFamilyForRoot(root string) (string, bool) {
	if s == nil || root == "" {
		return "", false
	}
	for current := root; current != ""; {
		if s.structuralStorageLinks != nil {
			if family := strings.TrimSpace(s.structuralStorageLinks[current]); family != "" {
				return family, true
			}
		}
		if strings.HasPrefix(current, "this.") && s.receiverStorageLinks != nil {
			if family := strings.TrimSpace(s.receiverStorageLinks[strings.TrimPrefix(current, "this.")]); family != "" {
				return family, true
			}
		}
		next, ok := trimTrailingPathSegment(current)
		if !ok {
			break
		}
		current = next
	}
	return "", false
}

func (s *analysisState) copyIteratedStructuralPaths(dst structuralRoot, src structuralRoot) {
	dstStore := s.destinationStructuralStore(dst)
	var maps []map[string]originSet
	if src.isStatic {
		maps = append(maps, s.engine.staticProps, s.staticPropTaint)
	} else {
		maps = append(maps, s.propTaint)
	}
	for _, store := range maps {
		copyIteratedPathMap(dstStore, store, dst.key, src.key)
	}
}

func (s *analysisState) destinationStructuralStore(root structuralRoot) map[string]originSet {
	if root.isStatic {
		return s.staticPropTaint
	}
	return s.propTaint
}

func copyStructuralPathMap(dst map[string]originSet, src map[string]originSet, dstRoot string, srcRoot string) {
	copyStructuralPathMapWithTransform(dst, src, dstRoot, srcRoot, nil)
}

func copyPersistentStructuralPathMap(dst map[string]originSet, src map[string]originSet, dstRoot string, srcRoot string) {
	copyStructuralPathMapWithTransform(dst, src, dstRoot, srcRoot, markPersistentReadOrigins)
}

func copyStructuralPathMapWithTransform(dst map[string]originSet, src map[string]originSet, dstRoot string, srcRoot string, transform func(originSet) originSet) {
	if dst == nil || src == nil || dstRoot == "" || srcRoot == "" {
		return
	}
	if !strings.Contains(srcRoot, "[*]") && !strings.Contains(srcRoot, "[]") {
		prefixArray := srcRoot + "["
		prefixProp := srcRoot + "."
		for key, origins := range src {
			if strings.HasPrefix(key, prefixArray) || strings.HasPrefix(key, prefixProp) {
				dstKey := dstRoot + strings.TrimPrefix(key, srcRoot)
				if transform != nil {
					origins = transform(origins)
				}
				dst[dstKey] = dst[dstKey].union(origins)
			}
		}
		return
	}
	for key, origins := range src {
		remainder, ok := trimStructuralPrefix(key, srcRoot)
		if !ok {
			continue
		}
		dstKey := dstRoot + remainder
		if transform != nil {
			origins = transform(origins)
		}
		dst[dstKey] = dst[dstKey].union(origins)
	}
}

func trimStructuralPrefix(path string, prefix string) (string, bool) {
	pathRoot, pathRemainder := splitStructuralRoot(path)
	prefixRoot, prefixRemainder := splitStructuralRoot(prefix)
	if pathRoot == "" || prefixRoot == "" || pathRoot != prefixRoot {
		return "", false
	}
	remainder := pathRemainder
	wanted := prefixRemainder
	for wanted != "" {
		wantSeg, nextWanted, ok := nextPathSegment(wanted)
		if !ok {
			return "", false
		}
		gotSeg, nextRemainder, ok := nextPathSegment(remainder)
		if !ok || !structuralPatternSegmentMatches(wantSeg, gotSeg) {
			return "", false
		}
		wanted = nextWanted
		remainder = nextRemainder
	}
	return remainder, true
}

func splitStructuralRoot(path string) (string, string) {
	if path == "" {
		return "", ""
	}
	end := len(path)
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '[', '.':
			end = i
			return path[:end], path[end:]
		}
	}
	return path, ""
}

func structuralPatternSegmentMatches(want string, got string) bool {
	switch {
	case want == "[]" || want == "*":
		return !strings.HasPrefix(got, ".")
	case strings.HasPrefix(want, "."):
		return want == got
	default:
		return want == got || got == "*" || got == "[]"
	}
}

func copyIteratedPathMap(dst map[string]originSet, src map[string]originSet, dstRoot string, srcRoot string) {
	copyIteratedPathMapWithTransform(dst, src, dstRoot, srcRoot, nil)
}

func copyPersistentIteratedPathMap(dst map[string]originSet, src map[string]originSet, dstRoot string, srcRoot string) {
	copyIteratedPathMapWithTransform(dst, src, dstRoot, srcRoot, markPersistentReadOrigins)
}

func copyIteratedPathMapWithTransform(dst map[string]originSet, src map[string]originSet, dstRoot string, srcRoot string, transform func(originSet) originSet) {
	if dst == nil || src == nil || dstRoot == "" || srcRoot == "" {
		return
	}
	if !strings.Contains(srcRoot, "[*]") && !strings.Contains(srcRoot, "[]") {
		prefixArray := srcRoot + "["
		prefixProp := srcRoot + "."
		for key, origins := range src {
			if !strings.HasPrefix(key, prefixArray) && !strings.HasPrefix(key, prefixProp) {
				continue
			}
			remainder := strings.TrimPrefix(key, srcRoot)
			if stripped, ok := stripLeadingPathSegment(remainder); ok {
				if transform != nil {
					origins = transform(origins)
				}
				dst[dstRoot+stripped] = dst[dstRoot+stripped].union(origins)
			}
		}
		return
	}
	for key, origins := range src {
		remainder, ok := trimStructuralPrefix(key, srcRoot)
		if !ok {
			continue
		}
		if stripped, ok := stripLeadingPathSegment(remainder); ok {
			if transform != nil {
				origins = transform(origins)
			}
			dst[dstRoot+stripped] = dst[dstRoot+stripped].union(origins)
		}
	}
}

func hasStructuralChildren(store map[string]originSet, root string) bool {
	if store == nil || root == "" {
		return false
	}
	prefixArray := root + "["
	prefixProp := root + "."
	for key := range store {
		if strings.HasPrefix(key, prefixArray) || strings.HasPrefix(key, prefixProp) {
			return true
		}
	}
	return false
}

func stripLeadingPathSegment(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	switch path[0] {
	case '[':
		depth := 0
		for i := 0; i < len(path); i++ {
			switch path[i] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return path[i+1:], true
				}
			}
		}
	case '.':
		for i := 1; i < len(path); i++ {
			if path[i] == '.' || path[i] == '[' {
				return path[i:], true
			}
		}
		return "", true
	}
	return "", false
}

func (s *analysisState) resolveStructuralPathOrigins(root structuralRoot, path string) originSet {
	if root.key == "" {
		return originSet{}
	}
	full := root.key + path
	out := originSet{}
	var stores []map[string]originSet
	if root.isStatic {
		stores = append(stores, s.engine.staticProps, s.staticPropTaint)
	} else {
		stores = append(stores, s.propTaint)
	}
	for _, store := range stores {
		out = out.union(lookupStructuralPathOrigins(store, full))
	}
	return out
}
