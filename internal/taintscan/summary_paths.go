package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (s *analysisState) instantiateTaintSummary(item taintSummary, args []originSet, argNodes []ast.Node) originSet {
	if len(item.Sources) == 0 &&
		len(item.SourceOrigins) == 0 &&
		len(item.ParamPaths) == 0 &&
		len(item.Params) == 1 {
		idx := item.Params[0]
		if idx >= 0 && idx < len(args) {
			return args[idx]
		}
	}
	out := originsFromTaintSummary(item)
	for _, idx := range item.Params {
		if idx >= 0 && idx < len(args) {
			out = unionInto(out, args[idx])
		}
	}
	paramPathCounts := map[int]int{}
	for _, ref := range item.ParamPaths {
		paramPathCounts[ref.Index]++
	}
	if len(s.engine.allowedSinkOps) == 1 && s.engine.allowsSinkOp("action") {
		for _, ref := range item.ParamPaths {
			if ref.Index < 0 || ref.Index >= len(args) {
				continue
			}
			origins := applyStoredWriteContext(args[ref.Index], ref.StoredWriteContext)
			out = unionInto(out, applyParamPathRefFlags(origins, ref))
		}
		return out
	}
	cachedStructuralPaths := map[int]map[string]originSet{}
	cachedArgumentOrigins := map[int]originSet{}
	cachedArgumentLocations := map[int]Location{}
	for _, ref := range item.ParamPaths {
		if ref.Index < 0 || ref.Index >= len(argNodes) {
			continue
		}
		origins := originSet{}
		if paramPathCounts[ref.Index] >= 4 {
			paths, ok := cachedStructuralPaths[ref.Index]
			if !ok {
				paths = s.resolveArgumentStructuralPaths(argValue(argNodes[ref.Index]), "")
				cachedStructuralPaths[ref.Index] = paths
			}
			origins = lookupStructuralPathOrigins(paths, ref.Path)
		}
		if len(origins) == 0 {
			if paramPathCounts[ref.Index] >= 4 {
				argOrigins, ok := cachedArgumentOrigins[ref.Index]
				if !ok {
					argOrigins = s.evalExpr(argValue(argNodes[ref.Index]))
					cachedArgumentOrigins[ref.Index] = argOrigins
					cachedArgumentLocations[ref.Index] = s.locationForNode(argValue(argNodes[ref.Index]))
				}
				origins = applyPathStringToOrigins(argOrigins, ref.Path, cachedArgumentLocations[ref.Index])
			} else {
				origins = s.resolveArgumentPathOrigins(argValue(argNodes[ref.Index]), ref.Path)
			}
		}
		out = unionInto(out, applyParamPathRefFlags(applyStoredWriteContext(origins, ref.StoredWriteContext), ref))
	}
	return out
}

func (s *analysisState) resolveReceiverSummaryOrigins(origins originSet, receiverRoot string) originSet {
	if receiverRoot == "" || len(origins) == 0 {
		return origins
	}
	out := originSet{}
	resolvedCache := map[string]originSet{}
	prefixLookupCache := map[string]originSet{}
	for _, item := range origins {
		if item.kind != originReceiver {
			out = unionInto(out, makeOriginSet(item))
			continue
		}
		resolved, ok := resolvedCache[item.receiverPath]
		if !ok {
			resolved = s.resolveReceiverPathOriginsWithPrefixCache(receiverRoot, item.receiverPath, prefixLookupCache)
			resolvedCache[item.receiverPath] = resolved
		}
		if len(resolved) == 0 {
			out = unionInto(out, makeOriginSet(item))
			continue
		}
		resolved = applyStoredWriteContext(resolved, item.storedWriteContext)
		if item.persistentRead {
			resolved = markPersistentReadOrigins(resolved)
		}
		if item.pathSafe {
			resolved = markPathSafeOrigins(resolved)
		}
		if item.outputSafeHTML {
			resolved = markHTMLOutputSafeOrigins(resolved)
		}
		if item.outputUnsafeHTML {
			resolved = markHTMLOutputUnsafeOrigins(resolved)
		}
		out = unionInto(out, resolved)
	}
	return out
}

func applyParamPathRefFlags(origins originSet, ref paramPathRef) originSet {
	if len(origins) == 0 {
		return origins
	}
	out := origins
	if ref.PersistentRead {
		out = markPersistentReadOrigins(out)
	}
	if ref.PathSafe {
		out = markPathSafeOrigins(out)
	}
	if ref.OutputSafeHTML {
		out = markHTMLOutputSafeOrigins(out)
	}
	if ref.OutputUnsafeHTML {
		out = markHTMLOutputUnsafeOrigins(out)
	}
	return out
}

func (s *analysisState) resolveArgumentPathOrigins(node ast.Node, path string) originSet {
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
	case *ast.ExprArrayDimFetch:
		return s.resolveArgumentPathOrigins(typed.Var, rootlessArrayPath(typed.Dim)+path)
	case *ast.ExprFuncCall:
		if origins := lookupStructuralPathOrigins(s.filterReturnStructuralPaths(typed), path); len(origins) != 0 {
			return origins
		}
		argIndexes := structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args))
		if len(argIndexes) != 0 {
			out := originSet{}
			for _, idx := range argIndexes {
				out = unionInto(out, s.resolveArgumentPathOrigins(argValue(typed.Args[idx]), path))
			}
			return out
		}
	case *ast.ExprMethodCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.resolveArgumentPathOrigins(argValue(typed.Args[0]), path)
		}
		name := strings.ToLower(identifierText(typed.Name))
		if key := s.resolveMethodKeyWithArgs(s.resolveClassExpr(typed.Var), name, typed.Args); key != "" {
			if origins := lookupStructuralPathOrigins(s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)), path); len(origins) != 0 {
				return origins
			}
		}
	case *ast.ExprStaticCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.resolveArgumentPathOrigins(argValue(typed.Args[0]), path)
		}
		name := strings.ToLower(identifierText(typed.Name))
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if key := s.resolveMethodKeyWithArgs(className, name, typed.Args); key != "" {
			if origins := lookupStructuralPathOrigins(s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)), path); len(origins) != 0 {
				return origins
			}
		}
	case *ast.ExprArray:
		segment, rest, ok := nextPathSegment(path)
		if !ok {
			return originSet{}
		}
		if segment == "[]" {
			out := originSet{}
			for _, itemNode := range typed.Items {
				item, ok := itemNode.(*ast.ArrayItem)
				if !ok {
					continue
				}
				out = unionInto(out, s.resolveArgumentPathOrigins(item.Value, rest))
			}
			return out
		}
		for _, itemNode := range typed.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			if strings.EqualFold(literalString(item.Key), segment) {
				return s.resolveArgumentPathOrigins(item.Value, rest)
			}
		}
		return originSet{}
	}
	return applyPathStringToOrigins(s.evalExpr(node), path, s.locationForNode(node))
}

func (s *analysisState) resolveReceiverPathOrigins(receiverRoot string, path string) originSet {
	return s.resolveReceiverPathOriginsWithPrefixCache(receiverRoot, path, nil)
}

func (s *analysisState) resolveReceiverPathOriginsWithPrefixCache(receiverRoot string, path string, prefixLookupCache map[string]originSet) originSet {
	if receiverRoot == "" {
		return originSet{}
	}
	suffix := ""
	if path != "" {
		if strings.HasPrefix(path, "[") {
			suffix = path
		} else {
			suffix = "." + path
		}
	}
	if origins := s.resolveStructuralPathOrigins(structuralRoot{key: receiverRoot}, suffix); len(origins) != 0 {
		return origins
	}
	// Constructor replay often seeds the base receiver write before later
	// methods read a deeper child path from that receiver slot. Fall back to
	// the nearest seeded receiver prefix when no exact structural path exists.
	fullPath := receiverRoot + suffix
	for prefix, ok := trimTrailingPathSegment(fullPath); ok; prefix, ok = trimTrailingPathSegment(prefix) {
		if len(prefix) <= len(receiverRoot) {
			break
		}
		if prefixLookupCache != nil {
			if origins, ok := prefixLookupCache[prefix]; ok {
				if len(origins) != 0 {
					return origins
				}
				continue
			}
		}
		origins := lookupStructuralSelfOrigins(s.propTaint, prefix)
		if prefixLookupCache != nil {
			prefixLookupCache[prefix] = origins
		}
		if len(origins) != 0 {
			return origins
		}
	}
	return originSet{}
}

func (s *analysisState) resolveArgumentStructuralPaths(node ast.Node, path string) map[string]originSet {
	if node == nil {
		return nil
	}
	if root, ok := s.structuralRoot(node); ok {
		if paths := selectRelativeStructuralPaths(collectRelativePathsFromStructuralRoot(root, s), path); len(paths) != 0 {
			return paths
		}
	}
	selected := s.resolveArgumentPathNodes(node, path)
	if len(selected) == 0 {
		switch typed := node.(type) {
		case *ast.ExprArrayDimFetch:
			return s.resolveArgumentStructuralPaths(typed.Var, rootlessArrayPath(typed.Dim)+path)
		case *ast.ExprMethodCall:
			if paths, ok := sqlSelectReturnPathsForMethodCall(typed, s); ok {
				return selectRelativeStructuralPaths(paths, path)
			}
			name := strings.ToLower(identifierText(typed.Name))
			if key := s.resolveMethodKey(s.resolveClassExpr(typed.Var), name); key != "" {
				return selectRelativeStructuralPaths(s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)), path)
			}
		case *ast.ExprStaticCall:
			if paths, ok := sqlSelectReturnPathsForStaticCall(typed, s); ok {
				return selectRelativeStructuralPaths(paths, path)
			}
			name := strings.ToLower(identifierText(typed.Name))
			className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
			if key := s.resolveMethodKey(className, name); key != "" {
				return selectRelativeStructuralPaths(s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)), path)
			}
		}
		return nil
	}
	out := map[string]originSet{}
	for _, selectedNode := range selected {
		for suffix, origins := range s.collectExprStructuralPaths(selectedNode) {
			out[suffix] = out[suffix].union(origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *analysisState) resolveArgumentPathNodes(node ast.Node, path string) []ast.Node {
	if node == nil {
		return nil
	}
	if path == "" {
		return []ast.Node{node}
	}
	switch typed := node.(type) {
	case *ast.ExprArrayDimFetch:
		return s.resolveArgumentPathNodes(typed.Var, rootlessArrayPath(typed.Dim)+path)
	case *ast.ExprFuncCall:
		argIndexes := structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args))
		if len(argIndexes) != 0 {
			out := make([]ast.Node, 0)
			for _, idx := range argIndexes {
				out = append(out, s.resolveArgumentPathNodes(argValue(typed.Args[idx]), path)...)
			}
			return out
		}
	case *ast.ExprMethodCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.resolveArgumentPathNodes(argValue(typed.Args[0]), path)
		}
	case *ast.ExprStaticCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.resolveArgumentPathNodes(argValue(typed.Args[0]), path)
		}
	case *ast.ExprArray:
		segment, rest, ok := nextPathSegment(path)
		if !ok {
			return nil
		}
		out := make([]ast.Node, 0)
		if segment == "[]" || segment == "*" {
			for _, itemNode := range typed.Items {
				item, ok := itemNode.(*ast.ArrayItem)
				if !ok {
					continue
				}
				out = append(out, s.resolveArgumentPathNodes(item.Value, rest)...)
			}
			return out
		}
		for _, itemNode := range typed.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			if strings.EqualFold(literalString(item.Key), segment) {
				out = append(out, s.resolveArgumentPathNodes(item.Value, rest)...)
			}
		}
		return out
	}
	return nil
}

func (s *analysisState) collectExprStructuralPaths(node ast.Node) map[string]originSet {
	switch typed := node.(type) {
	case *ast.ExprVariable, *ast.ExprPropertyFetch, *ast.ExprStaticPropertyFetch:
		if root, ok := s.structuralRoot(node); ok {
			return collectRelativePathsFromStructuralRoot(root, s)
		}
	case *ast.ExprArrayDimFetch:
		return s.resolveArgumentStructuralPaths(typed.Var, rootlessArrayPath(typed.Dim))
	case *ast.ExprTernary:
		out := map[string]originSet{}
		branch := typed.If
		if branch == nil {
			branch = typed.Cond
		}
		for suffix, origins := range s.collectExprStructuralPaths(branch) {
			out[suffix] = out[suffix].union(origins)
		}
		for suffix, origins := range s.collectExprStructuralPaths(typed.Else) {
			out[suffix] = out[suffix].union(origins)
		}
		if len(out) != 0 {
			return out
		}
	case *ast.ExprFuncCall:
		filterPaths := s.filterReturnStructuralPaths(typed)
		callbackPaths := s.arrayMapCallbackReturnPaths(typed)
		argIndexes := structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args))
		if len(argIndexes) != 0 || len(callbackPaths) != 0 || len(filterPaths) != 0 {
			out := map[string]originSet{}
			for suffix, origins := range filterPaths {
				out[suffix] = out[suffix].union(origins)
			}
			for suffix, origins := range callbackPaths {
				out[suffix] = out[suffix].union(origins)
			}
			for _, idx := range argIndexes {
				for suffix, origins := range s.collectExprStructuralPaths(argValue(typed.Args[idx])) {
					out[suffix] = out[suffix].union(origins)
				}
			}
			if len(out) != 0 {
				return out
			}
		}
	case *ast.ExprMethodCall:
		if paths, ok := sqlSelectReturnPathsForMethodCall(typed, s); ok {
			return paths
		}
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.collectExprStructuralPaths(argValue(typed.Args[0]))
		}
		name := strings.ToLower(identifierText(typed.Name))
		if key := s.resolveMethodKey(s.resolveClassExpr(typed.Var), name); key != "" {
			if paths := s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)); len(paths) != 0 {
				return paths
			}
		}
	case *ast.ExprStaticCall:
		if paths, ok := sqlSelectReturnPathsForStaticCall(typed, s); ok {
			return paths
		}
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return s.collectExprStructuralPaths(argValue(typed.Args[0]))
		}
		name := strings.ToLower(identifierText(typed.Name))
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if key := s.resolveMethodKey(className, name); key != "" {
			if paths := s.instantiateSummaryReturnPathsForKey(key, s.engine.summaries[key], typed.Args, s.evalArgs(typed.Args)); len(paths) != 0 {
				return paths
			}
		}
	case *ast.ExprArray:
		out := map[string]originSet{}
		for _, itemNode := range typed.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			childPrefix := rootlessArrayPath(item.Key)
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
		return out
	}
	return nil
}

func selectRelativeStructuralPaths(paths map[string]originSet, prefix string) map[string]originSet {
	if len(paths) == 0 {
		return nil
	}
	if prefix == "" {
		out := map[string]originSet{}
		for rel, origins := range paths {
			unionMapEntry(out, rel, origins)
		}
		return out
	}
	out := map[string]originSet{}
	for rel, origins := range paths {
		if remainder, ok := trimRelativeStructuralPrefix(rel, prefix); ok {
			unionMapEntry(out, remainder, origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func trimRelativeStructuralPrefix(path string, prefix string) (string, bool) {
	remainder := path
	wanted := prefix
	for wanted != "" {
		wantSeg, nextWanted, ok := nextPathSegment(wanted)
		if !ok {
			return "", false
		}
		gotSeg, nextRemainder, ok := nextPathSegment(remainder)
		if !ok || !structuralPathSegmentMatches(wantSeg, gotSeg) {
			return "", false
		}
		wanted = nextWanted
		remainder = nextRemainder
	}
	return remainder, true
}

func structuralPathSegmentMatches(want string, got string) bool {
	switch {
	case want == "[]":
		return !strings.HasPrefix(got, ".")
	case strings.HasPrefix(want, "."):
		return want == got
	default:
		return want == got || got == "*" || got == "[]"
	}
}
