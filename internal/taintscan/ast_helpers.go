package taintscan

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

type dispatchResolutionState struct {
	dynamic  map[string]struct{}
	class    map[string]struct{}
	property map[string]struct{}
}

func newDispatchResolutionState() *dispatchResolutionState {
	return &dispatchResolutionState{
		dynamic:  map[string]struct{}{},
		class:    map[string]struct{}{},
		property: map[string]struct{}{},
	}
}

func newDispatchResolutionStateForPropertyFallback(parent *dispatchResolutionState) *dispatchResolutionState {
	state := newDispatchResolutionState()
	if parent == nil {
		return state
	}
	for key := range parent.property {
		state.property[key] = struct{}{}
	}
	return state
}

func dispatchResolutionKey(kind string, callableKey string, node ast.Node) string {
	if node == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s|%T:%p", kind, callableKey, node, node)
}

func dispatchResolutionEnter(seen map[string]struct{}, key string) bool {
	if seen == nil || key == "" {
		return true
	}
	if _, ok := seen[key]; ok {
		return false
	}
	seen[key] = struct{}{}
	return true
}

func dispatchResolutionLeave(seen map[string]struct{}, key string) {
	if seen == nil || key == "" {
		return
	}
	delete(seen, key)
}

func namespaceString(node ast.Node) string {
	name := identifierText(node)
	if name == "" {
		return ""
	}
	return `\` + strings.TrimPrefix(name, `\`)
}

func identifierText(node ast.Node) string {
	switch typed := node.(type) {
	case *ast.Identifier:
		return typed.Name
	case *ast.VarLikeIdentifier:
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

func normalizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = strings.TrimPrefix(name, `\`)
	return strings.ToLower(name)
}

func isPHPInputLiteral(node ast.Node) bool {
	return strings.EqualFold(literalString(node), "php://input")
}

func literalString(node ast.Node) string {
	switch typed := node.(type) {
	case *ast.ScalarString:
		return typed.Value
	case *ast.ScalarInterpolatedString:
		var builder strings.Builder
		for _, rawPart := range typed.Parts {
			switch part := rawPart.(type) {
			case *ast.InterpolatedStringPart:
				builder.WriteString(part.Value)
			case ast.Node:
				placeholder := hookPlaceholder(part)
				if placeholder == "" {
					return ""
				}
				builder.WriteString("{")
				builder.WriteString(placeholder)
				builder.WriteString("}")
			default:
				return ""
			}
		}
		return builder.String()
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

func literalStringForCallable(node ast.Node, current callable, e *engine) string {
	return literalStringForCallableWithSeen(node, current, e, map[string]struct{}{})
}

func isSecretLikeConfigReadName(name string) bool {
	switch normalizeName(name) {
	case "get_option", "getoption",
		"get_site_option", "getsiteoption",
		"get_network_option", "getnetworkoption",
		"get_transient", "gettransient",
		"get_site_transient", "getsitetransient":
		return true
	default:
		return false
	}
}

func isSecretLikeConfigKey(node ast.Node, current callable, e *engine) bool {
	value := strings.ToLower(strings.TrimSpace(literalStringForCallable(node, current, e)))
	value = strings.Trim(value, `"'`)
	if value == "" {
		return false
	}
	switch {
	case strings.Contains(value, "bearer"):
		return true
	case strings.Contains(value, "token"):
		return true
	case strings.Contains(value, "secret"):
		return true
	case strings.Contains(value, "api_key"), strings.Contains(value, "apikey"):
		return true
	case strings.Contains(value, "auth_key"), strings.Contains(value, "authkey"):
		return true
	default:
		return false
	}
}

func restRouteShowsInIndex(node ast.Node) bool {
	arrayNode, ok := node.(*ast.ExprArray)
	if !ok {
		return true
	}
	showNode := arrayValueForStringKey(arrayNode, "show_in_index")
	if showNode == nil {
		return true
	}
	if truthy, ok := booleanLiteral(showNode); ok {
		return truthy
	}
	return true
}

func restRouteHasDynamicPathComponent(node ast.Node, current callable, e *engine) bool {
	if node == nil {
		return false
	}
	if literal := strings.TrimSpace(literalStringForCallable(node, current, e)); literal != "" {
		return false
	}
	switch node.(type) {
	case *ast.ExprBinaryOpConcat,
		*ast.ScalarInterpolatedString,
		*ast.ExprVariable,
		*ast.ExprPropertyFetch,
		*ast.ExprArrayDimFetch,
		*ast.ExprFuncCall,
		*ast.ExprMethodCall,
		*ast.ExprStaticCall:
		return true
	default:
		return false
	}
}

func literalStringForCallableWithSeen(node ast.Node, current callable, e *engine, seen map[string]struct{}) string {
	if seen == nil {
		seen = map[string]struct{}{}
	}
	switch typed := node.(type) {
	case *ast.ExprBinaryOpConcat:
		left := literalStringForCallableWithSeen(typed.Left, current, e, seen)
		right := literalStringForCallableWithSeen(typed.Right, current, e, seen)
		if left == "" || right == "" {
			return ""
		}
		return left + right
	case *ast.ExprClassConstFetch:
		if strings.EqualFold(identifierText(typed.Name), "class") {
			return resolveClassName(typed.Class, current.Class, e.classParents)
		}
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		if value := e.literalClassConstValue(className, identifierText(typed.Name)); value != "" {
			return value
		}
		return ""
	case *ast.ExprConstFetch:
		if value := e.literalGlobalConstValue(identifierText(typed.Name)); value != "" {
			return value
		}
		return literalString(node)
	case *ast.ExprStaticCall:
		if len(typed.Args) != 0 {
			return ""
		}
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		key := e.ensureRuntimeMethodCallable(className, identifierText(typed.Name))
		return e.literalCallableReturnValue(key, seen)
	case *ast.ExprMethodCall:
		if len(typed.Args) != 0 {
			return ""
		}
		className := ""
		if refs := e.resolveCallbackClassRefsWithSeen(typed.Var, current, seen); len(refs) != 0 {
			className = refs[0]
		}
		if className == "" {
			className = e.resolveMethodCallClass(typed, current)
		}
		if className == "" {
			return ""
		}
		key := e.ensureRuntimeMethodCallable(className, identifierText(typed.Name))
		return e.literalCallableReturnValue(key, seen)
	case *ast.ExprFuncCall:
		if value := literalPathHelperCallValueForCallableWithSeen(typed, current, e, seen); value != "" {
			return value
		}
		if len(typed.Args) != 0 {
			return ""
		}
		if key := e.lookupFunctionKey(current.Namespace, identifierText(typed.Name)); key != "" {
			return e.literalCallableReturnValue(key, seen)
		}
		return ""
	case *ast.ScalarMagicConstDir:
		if file, ok := e.fileIndex[current.SourcePath]; ok {
			return filepath.Dir(file.FullPath)
		}
		return filepath.Dir(current.SourcePath)
	case *ast.ScalarMagicConstFile:
		if file, ok := e.fileIndex[current.SourcePath]; ok {
			return file.FullPath
		}
		return current.SourcePath
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		if hinted := e.literalArgHintForParam(current, name); hinted != "" {
			return hinted
		}
		return e.localLiteralVariableValue(current, name, seen)
	case *ast.ExprArrayDimFetch:
		if hinted := strings.TrimSpace(e.literalArgPathHintForFetch(current, typed)); hinted != "" {
			return hinted
		}
		return ""
	case *ast.ExprPropertyFetch:
		if property, ok := propertyPathKey(typed, current.Class); ok {
			if literal := literalPropertyValueForCurrent(property, current.Class, e); literal != "" {
				return literal
			}
		}
		return ""
	case *ast.ExprStaticPropertyFetch:
		property := strings.ToLower(strings.TrimSpace(identifierText(typed.Name)))
		if property == "" {
			return ""
		}
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		className = e.resolveStaticPropertyOwner(className, property)
		if value := e.literalClassPropertyValue(className, property); value != "" {
			return value
		}
		return ""
	default:
		return literalString(node)
	}
}

func literalPathHelperCallValueForCallableWithSeen(call *ast.ExprFuncCall, current callable, e *engine, seen map[string]struct{}) string {
	if call == nil {
		return ""
	}
	name := normalizeName(identifierText(call.Name))
	if len(call.Args) != 1 {
		return ""
	}
	arg := strings.TrimSpace(literalStringForCallableWithSeen(argValue(call.Args[0]), current, e, seen))
	if arg == "" {
		return ""
	}
	switch name {
	case "dirname":
		return filepath.Dir(arg)
	case "plugin_dir_path":
		return filepath.Clean(filepath.Dir(arg)) + string(filepath.Separator)
	case "trailingslashit":
		if strings.HasSuffix(arg, "/") || strings.HasSuffix(arg, `\`) {
			return arg
		}
		return arg + string(filepath.Separator)
	case "untrailingslashit":
		return strings.TrimRight(arg, `/\`)
	default:
		return ""
	}
}

func literalConstExpr(node ast.Node, namespace string, className string, e *engine) string {
	return literalConstExprWithSourceSeen(node, namespace, className, "", e, map[string]struct{}{})
}

func literalConstExprWithSeen(node ast.Node, namespace string, className string, e *engine, seen map[string]struct{}) string {
	return literalConstExprWithSourceSeen(node, namespace, className, "", e, seen)
}

func literalConstExprWithSource(node ast.Node, namespace string, className string, sourcePath string, e *engine) string {
	return literalConstExprWithSourceSeen(node, namespace, className, sourcePath, e, map[string]struct{}{})
}

func literalConstExprWithSourceSeen(node ast.Node, namespace string, className string, sourcePath string, e *engine, seen map[string]struct{}) string {
	switch typed := node.(type) {
	case *ast.ScalarString:
		return typed.Value
	case *ast.ScalarMagicConstDir:
		if sourcePath != "" {
			if file, ok := e.fileIndex[sourcePath]; ok {
				return filepath.Dir(file.FullPath)
			}
			return filepath.Dir(sourcePath)
		}
		return ""
	case *ast.ScalarMagicConstFile:
		if sourcePath != "" {
			if file, ok := e.fileIndex[sourcePath]; ok {
				return file.FullPath
			}
			return sourcePath
		}
		return ""
	case *ast.ScalarMagicConstNamespace:
		return strings.TrimPrefix(namespace, `\`)
	case *ast.ExprBinaryOpConcat:
		left := literalConstExprWithSourceSeen(typed.Left, namespace, className, sourcePath, e, seen)
		right := literalConstExprWithSourceSeen(typed.Right, namespace, className, sourcePath, e, seen)
		if left == "" || right == "" {
			return ""
		}
		return left + right
	case *ast.ExprConstFetch:
		name := identifierText(typed.Name)
		if value := e.literalGlobalConstValue(name); value != "" {
			return value
		}
		return ""
	case *ast.ExprClassConstFetch:
		if strings.EqualFold(identifierText(typed.Name), "class") {
			return resolveClassName(typed.Class, className, e.classParents)
		}
		resolvedClass := resolveClassName(typed.Class, className, e.classParents)
		constName := identifierText(typed.Name)
		if resolvedClass == "" || constName == "" {
			return ""
		}
		key := resolvedClass + "::" + strings.ToLower(strings.TrimSpace(constName))
		if _, ok := seen[key]; ok {
			return ""
		}
		seen[key] = struct{}{}
		defer delete(seen, key)
		return e.literalClassConstValue(resolvedClass, constName)
	case *ast.ExprStaticPropertyFetch:
		property := strings.ToLower(strings.TrimSpace(identifierText(typed.Name)))
		if property == "" {
			return ""
		}
		resolvedClass := resolveClassName(typed.Class, className, e.classParents)
		resolvedClass = e.resolveStaticPropertyOwner(resolvedClass, property)
		if resolvedClass == "" {
			return ""
		}
		key := resolvedClass + "." + property
		if _, ok := seen[key]; ok {
			return ""
		}
		seen[key] = struct{}{}
		defer delete(seen, key)
		return e.literalClassPropertyValue(resolvedClass, property)
	case *ast.ExprFuncCall:
		if value := literalPathHelperCallValueForConstExprWithSeen(typed, namespace, className, sourcePath, e, seen); value != "" {
			return value
		}
		if len(typed.Args) != 1 {
			return ""
		}
		value := literalConstExprWithSourceSeen(argValue(typed.Args[0]), namespace, className, sourcePath, e, seen)
		if value == "" {
			return ""
		}
		switch strings.ToLower(strings.TrimSpace(identifierText(typed.Name))) {
		case "strtolower":
			return strings.ToLower(value)
		case "strtoupper":
			return strings.ToUpper(value)
		case "trim":
			return strings.TrimSpace(value)
		default:
			return ""
		}
	default:
		return literalString(node)
	}
}

func literalPathHelperCallValueForConstExprWithSeen(call *ast.ExprFuncCall, namespace string, className string, sourcePath string, e *engine, seen map[string]struct{}) string {
	if call == nil {
		return ""
	}
	name := normalizeName(identifierText(call.Name))
	if len(call.Args) != 1 {
		return ""
	}
	arg := strings.TrimSpace(literalConstExprWithSourceSeen(argValue(call.Args[0]), namespace, className, sourcePath, e, seen))
	if arg == "" {
		return ""
	}
	switch name {
	case "dirname":
		return filepath.Dir(arg)
	case "plugin_dir_path":
		return filepath.Clean(filepath.Dir(arg)) + string(filepath.Separator)
	case "trailingslashit":
		if strings.HasSuffix(arg, "/") || strings.HasSuffix(arg, `\`) {
			return arg
		}
		return arg + string(filepath.Separator)
	case "untrailingslashit":
		return strings.TrimRight(arg, `/\`)
	default:
		return ""
	}
}

func (e *engine) literalCallableReturnValue(key string, seen map[string]struct{}) string {
	if key == "" {
		return ""
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	if _, ok := seen[key]; ok {
		return ""
	}
	c, ok := e.callables[key]
	if !ok {
		return ""
	}
	seen[key] = struct{}{}
	defer delete(seen, key)
	var ret ast.Node
	for _, stmt := range c.Stmts {
		switch typed := stmt.(type) {
		case *ast.StmtReturn:
			if ret != nil {
				return ""
			}
			ret = typed.Expr
		case *ast.StmtNop:
			continue
		default:
			return ""
		}
	}
	if ret == nil {
		return ""
	}
	return literalStringForCallableWithSeen(ret, c, e, seen)
}

func (e *engine) localLiteralVariableValue(current callable, name string, seen map[string]struct{}) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	seenKey := "var::" + current.Key + "::" + name
	if _, ok := seen[seenKey]; ok {
		return ""
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)

	value := ""
	matched := false
	ambiguous := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok {
			return
		}
		variable, ok := assign.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		varName, ok := variable.Name.(string)
		if !ok || strings.TrimSpace(varName) != name {
			return
		}
		candidate := literalStringForCallableWithSeen(assign.Expr, current, e, seen)
		if candidate == "" {
			ambiguous = true
			return
		}
		if !matched {
			value = candidate
			matched = true
			return
		}
		if value != candidate {
			ambiguous = true
		}
	})
	if ambiguous || !matched {
		return ""
	}
	return value
}

func (e *engine) localDynamicDispatchVariableValue(current callable, name string, stringEnv map[string]string, state *dispatchResolutionState) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	seenKey := "dynamic-var::" + current.Key + "::" + name
	if !dispatchResolutionEnter(state.dynamic, seenKey) {
		return ""
	}
	defer dispatchResolutionLeave(state.dynamic, seenKey)

	value := ""
	matched := false
	ambiguous := false
	placeholder := "{dynamic}"
	if trimmed := strings.ToLower(strings.TrimSpace(name)); trimmed != "" {
		placeholder = "{" + trimmed + "}"
	}
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok {
			return
		}
		variable, ok := assign.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		varName, ok := variable.Name.(string)
		if !ok || strings.TrimSpace(varName) != name {
			return
		}
		candidate := strings.TrimSpace(dynamicDispatchStringForCallableWithState(assign.Expr, current, e, stringEnv, state))
		if candidate == "" {
			ambiguous = true
			return
		}
		if !matched {
			value = candidate
			matched = true
			return
		}
		if value == candidate {
			return
		}
		if merged := mergeDynamicDispatchCandidates(value, candidate, placeholder); merged != "" {
			value = merged
			return
		}
		if merged := mergeDynamicDispatchCandidates(candidate, value, placeholder); merged != "" {
			value = merged
			return
		}
		if value != candidate {
			ambiguous = true
		}
	})
	if ambiguous || !matched {
		return ""
	}
	return value
}

func mergeDynamicDispatchCandidates(existing string, candidate string, placeholder string) string {
	existing = strings.TrimSpace(existing)
	candidate = strings.TrimSpace(candidate)
	placeholder = strings.TrimSpace(placeholder)
	if existing == "" || candidate == "" || placeholder == "" {
		return ""
	}
	if existing == candidate {
		return existing
	}
	if candidateMatchesDynamicDispatchPattern(candidate, existing) {
		return existing
	}
	prefix := longestCommonPrefix(existing, candidate)
	suffix := longestCommonSuffix(existing, candidate)
	minLen := len(existing)
	if len(candidate) < minLen {
		minLen = len(candidate)
	}
	if len(prefix)+len(suffix) > minLen {
		maxSuffix := minLen - len(prefix)
		if maxSuffix < 0 {
			maxSuffix = 0
		}
		if len(suffix) > maxSuffix {
			suffix = suffix[len(suffix)-maxSuffix:]
		}
	}
	if prefix == "" && suffix == "" {
		return ""
	}
	return prefix + placeholder + suffix
}

func candidateMatchesDynamicDispatchPattern(candidate string, pattern string) bool {
	prefix, suffix, ok := dynamicDispatchPatternParts(pattern)
	if !ok {
		return false
	}
	if prefix != "" && !strings.HasPrefix(candidate, prefix) {
		return false
	}
	if suffix != "" && !strings.HasSuffix(candidate, suffix) {
		return false
	}
	return len(candidate) >= len(prefix)+len(suffix)
}

func dynamicDispatchPatternParts(pattern string) (string, string, bool) {
	pattern = strings.TrimSpace(pattern)
	prefixEnd := strings.Index(pattern, "{")
	suffixStart := strings.LastIndex(pattern, "}")
	if prefixEnd < 0 || suffixStart < prefixEnd {
		return "", "", false
	}
	return pattern[:prefixEnd], pattern[suffixStart+1:], true
}

func longestCommonPrefix(left string, right string) string {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	idx := 0
	for idx < limit && left[idx] == right[idx] {
		idx++
	}
	return left[:idx]
}

func longestCommonSuffix(left string, right string) string {
	limit := len(left)
	if len(right) < limit {
		limit = len(right)
	}
	idx := 0
	for idx < limit && left[len(left)-1-idx] == right[len(right)-1-idx] {
		idx++
	}
	return left[len(left)-idx:]
}

func isDefinitelyStaticIncludePath(node ast.Node) bool {
	switch typed := node.(type) {
	case *ast.ScalarString, *ast.ScalarMagicConstDir, *ast.ScalarMagicConstFile:
		return true
	case *ast.ExprConstFetch:
		return identifierText(typed.Name) != ""
	case *ast.ExprClassConstFetch:
		return identifierText(typed.Class) != "" && identifierText(typed.Name) != ""
	case *ast.ExprBinaryOpConcat:
		return isDefinitelyStaticIncludePath(typed.Left) && isDefinitelyStaticIncludePath(typed.Right)
	case *ast.ScalarInterpolatedString:
		for _, rawPart := range typed.Parts {
			switch part := rawPart.(type) {
			case *ast.InterpolatedStringPart:
				continue
			case ast.Node:
				if !isDefinitelyStaticIncludePath(part) {
					return false
				}
			default:
				return false
			}
		}
		return true
	default:
		return false
	}
}

func exprMayProducePathLikeValue(node ast.Node) bool {
	switch typed := node.(type) {
	case nil:
		return false
	case *ast.ScalarString, *ast.ScalarMagicConstDir, *ast.ScalarMagicConstFile:
		return true
	case *ast.ScalarInterpolatedString:
		return true
	case *ast.ExprBinaryOpConcat:
		return true
	case *ast.ExprVariable,
		*ast.ExprArrayDimFetch,
		*ast.ExprPropertyFetch,
		*ast.ExprStaticPropertyFetch,
		*ast.ExprFuncCall,
		*ast.ExprMethodCall,
		*ast.ExprStaticCall,
		*ast.ExprTernary,
		*ast.ExprBinaryOpCoalesce,
		*ast.ExprCastString:
		return true
	case *ast.ExprConstFetch:
		name := strings.ToLower(strings.TrimSpace(identifierText(typed.Name)))
		return name != "null" && name != "true" && name != "false"
	default:
		return false
	}
}

func (e *engine) staticIncludedFileCallableKey(node ast.Node, current callable) string {
	keys := e.staticIncludedFileCallableKeys(node, current)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func (e *engine) staticIncludedFileCallableKeys(node ast.Node, current callable) []string {
	lookupRelative := func(rel string) []string {
		rel = filepath.ToSlash(filepath.Clean(strings.TrimSpace(rel)))
		if rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
			return nil
		}
		key := "file::" + rel
		if _, ok := e.callables[key]; ok {
			return []string{key}
		}
		return nil
	}
	lookupAbsolute := func(path string) []string {
		path = filepath.Clean(strings.TrimSpace(path))
		if path == "" {
			return nil
		}
		rel, err := filepath.Rel(e.target, path)
		if err != nil {
			return nil
		}
		return lookupRelative(rel)
	}
	lookupPattern := func(pattern string) []string {
		pattern = strings.TrimSpace(strings.Trim(pattern, `"'`))
		if pattern == "" || !strings.Contains(pattern, "{") {
			return nil
		}
		prefixEnd := strings.Index(pattern, "{")
		suffixStart := strings.LastIndex(pattern, "}")
		if prefixEnd < 0 || suffixStart < prefixEnd {
			return nil
		}
		prefix := filepath.Clean(strings.TrimSpace(pattern[:prefixEnd]))
		suffix := filepath.Clean(strings.TrimSpace(pattern[suffixStart+1:]))
		out := make([]string, 0, 8)
		seen := map[string]struct{}{}
		for key, callable := range e.callables {
			if !strings.HasPrefix(key, "file::") {
				continue
			}
			relPath := filepath.ToSlash(strings.TrimPrefix(key, "file::"))
			fullPath := filepath.Clean(callable.SourcePath)
			if file, ok := e.fileIndex[callable.SourcePath]; ok {
				fullPath = filepath.Clean(file.FullPath)
			}
			if prefix != "" && !strings.HasPrefix(fullPath, prefix) && !strings.HasPrefix(relPath, filepath.ToSlash(prefix)) {
				continue
			}
			if suffix != "" && !strings.HasSuffix(fullPath, suffix) && !strings.HasSuffix(relPath, filepath.ToSlash(suffix)) {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, key)
		}
		sort.Strings(out)
		return out
	}

	lookupExactValues := func(values []string) []string {
		if len(values) == 0 {
			return nil
		}
		seen := map[string]struct{}{}
		out := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(strings.Trim(value, `"'`))
			if value == "" {
				continue
			}
			var keys []string
			switch {
			case filepath.IsAbs(value):
				keys = lookupAbsolute(value)
			default:
				keys = lookupRelative(value)
				if len(keys) == 0 {
					if file, ok := e.fileIndex[current.SourcePath]; ok {
						keys = lookupAbsolute(filepath.Join(filepath.Dir(file.FullPath), value))
					}
				}
			}
			for _, key := range keys {
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, key)
			}
		}
		if len(out) == 0 {
			return nil
		}
		sort.Strings(out)
		return out
	}

	if values := e.exactDynamicDispatchValuesForCallable(node, current, nil); len(values) != 0 {
		if keys := lookupExactValues(values); len(keys) != 0 {
			return keys
		}
	}

	literal := strings.TrimSpace(strings.Trim(literalStringForCallable(node, current, e), `"'`))
	if literal != "" {
		if keys := lookupRelative(literal); len(keys) != 0 {
			return keys
		}
		if filepath.IsAbs(literal) {
			if keys := lookupAbsolute(literal); len(keys) != 0 {
				return keys
			}
		}
		if file, ok := e.fileIndex[current.SourcePath]; ok {
			if keys := lookupAbsolute(filepath.Join(filepath.Dir(file.FullPath), literal)); len(keys) != 0 {
				return keys
			}
		}
	}

	dynamic := strings.TrimSpace(strings.Trim(dynamicDispatchStringForCallable(node, current, e, nil), `"'`))
	if keys := lookupPattern(dynamic); len(keys) != 0 {
		return keys
	}
	return nil
}

const maxExactDynamicDispatchValues = 16

func appendUniqueExactDynamicDispatchValue(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, existing := range items {
		if existing == value {
			return items
		}
	}
	return append(items, value)
}

func appendExactDynamicDispatchValues(dst []string, values []string) []string {
	for _, value := range values {
		dst = appendUniqueExactDynamicDispatchValue(dst, value)
		if len(dst) > maxExactDynamicDispatchValues {
			return nil
		}
	}
	return dst
}

func combineExactDynamicDispatchValues(left []string, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	out := make([]string, 0, len(left)*len(right))
	for _, lhs := range left {
		for _, rhs := range right {
			out = appendUniqueExactDynamicDispatchValue(out, lhs+rhs)
			if len(out) > maxExactDynamicDispatchValues {
				return nil
			}
		}
	}
	return out
}

func mergeExactDynamicDispatchValues(groups ...[]string) []string {
	var out []string
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		out = appendExactDynamicDispatchValues(out, group)
		if out == nil {
			return nil
		}
	}
	return out
}

func (e *engine) exactDynamicDispatchValuesForCallable(node ast.Node, current callable, stringEnv map[string]string) []string {
	return e.exactDynamicDispatchValuesForCallableWithState(node, current, stringEnv, newDispatchResolutionState())
}

func (e *engine) exactDynamicDispatchValuesForCallableWithState(node ast.Node, current callable, stringEnv map[string]string, state *dispatchResolutionState) []string {
	if state == nil {
		state = newDispatchResolutionState()
	}
	key := dispatchResolutionKey("exact-dynamic", current.Key, node)
	if !dispatchResolutionEnter(state.dynamic, key) {
		return nil
	}
	defer dispatchResolutionLeave(state.dynamic, key)

	switch typed := node.(type) {
	case nil:
		return nil
	case *ast.ScalarString, *ast.ScalarMagicConstDir, *ast.ScalarMagicConstFile, *ast.ExprConstFetch:
		if value := strings.TrimSpace(dynamicDispatchStringForCallableWithState(node, current, e, stringEnv, state)); value != "" && !strings.Contains(value, "{") {
			return []string{value}
		}
		return nil
	case *ast.ExprBinaryOpConcat:
		return combineExactDynamicDispatchValues(
			e.exactDynamicDispatchValuesForCallableWithState(typed.Left, current, stringEnv, state),
			e.exactDynamicDispatchValuesForCallableWithState(typed.Right, current, stringEnv, state),
		)
	case *ast.ScalarInterpolatedString:
		values := []string{""}
		for _, rawPart := range typed.Parts {
			switch part := rawPart.(type) {
			case *ast.InterpolatedStringPart:
				values = combineExactDynamicDispatchValues(values, []string{part.Value})
			case ast.Node:
				values = combineExactDynamicDispatchValues(values, e.exactDynamicDispatchValuesForCallableWithState(part, current, stringEnv, state))
			default:
				return nil
			}
			if len(values) == 0 {
				return nil
			}
		}
		return values
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			return e.exactDynamicDispatchValuesForVariable(current, name, stringEnv, state)
		}
		return nil
	case *ast.ExprArrayDimFetch:
		if hinted := strings.TrimSpace(e.literalArgPathHintForFetch(current, typed)); hinted != "" && hinted != conflictingLiteralArgHint {
			return []string{hinted}
		}
		return nil
	case *ast.ExprTernary:
		if truthy, ok := booleanLiteralForCallable(typed.Cond, current, e, stringEnv); ok {
			if truthy {
				if typed.If != nil {
					return e.exactDynamicDispatchValuesForCallableWithState(typed.If, current, stringEnv, state)
				}
				return e.exactDynamicDispatchValuesForCallableWithState(typed.Cond, current, stringEnv, state)
			}
			return e.exactDynamicDispatchValuesForCallableWithState(typed.Else, current, stringEnv, state)
		}
		if typed.If == nil {
			return mergeExactDynamicDispatchValues(
				e.exactDynamicDispatchValuesForCallableWithState(typed.Cond, current, stringEnv, state),
				e.exactDynamicDispatchValuesForCallableWithState(typed.Else, current, stringEnv, state),
			)
		}
		return mergeExactDynamicDispatchValues(
			e.exactDynamicDispatchValuesForCallableWithState(typed.If, current, stringEnv, state),
			e.exactDynamicDispatchValuesForCallableWithState(typed.Else, current, stringEnv, state),
		)
	case *ast.ExprFuncCall:
		if isStringDispatchWrapperFunc(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return e.exactDynamicDispatchValuesForCallableWithState(argValue(typed.Args[0]), current, stringEnv, state)
		}
		return nil
	case *ast.ExprMethodCall:
		if isStringDispatchWrapperMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return e.exactDynamicDispatchValuesForCallableWithState(argValue(typed.Args[0]), current, stringEnv, state)
		}
		return nil
	case *ast.ExprStaticCall:
		if isStringDispatchWrapperMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return e.exactDynamicDispatchValuesForCallableWithState(argValue(typed.Args[0]), current, stringEnv, state)
		}
		return nil
	default:
		return nil
	}
}

func (e *engine) exactDynamicDispatchValuesForVariable(current callable, name string, stringEnv map[string]string, state *dispatchResolutionState) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if hinted := strings.TrimSpace(e.literalArgHintForParam(current, name)); hinted != "" && hinted != conflictingLiteralArgHint {
		return []string{hinted}
	}
	if values := e.literalArgIterableValuesForParam(current, name); len(values) != 0 {
		return values
	}
	if stringEnv != nil {
		if value := strings.TrimSpace(stringEnv[name]); value != "" && value != conflictingLiteralArgHint && !strings.Contains(value, "{") {
			return []string{value}
		}
	}
	if values := e.localExactDynamicDispatchValuesForVariable(current, name, stringEnv, state); len(values) != 0 {
		return values
	}
	if values := e.foreachExactDynamicDispatchValuesForVariable(current, name, stringEnv, state); len(values) != 0 {
		return values
	}
	return nil
}

func (e *engine) localExactDynamicDispatchValuesForVariable(current callable, name string, stringEnv map[string]string, state *dispatchResolutionState) []string {
	seenKey := "exact-dynamic-var::" + current.Key + "::" + name
	if !dispatchResolutionEnter(state.dynamic, seenKey) {
		return nil
	}
	defer dispatchResolutionLeave(state.dynamic, seenKey)

	out := []string{}
	matched := false
	ambiguous := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok {
			return
		}
		variable, ok := assign.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		varName, ok := variable.Name.(string)
		if !ok || strings.TrimSpace(varName) != name {
			return
		}
		matched = true
		values := e.exactDynamicDispatchValuesForCallableWithState(assign.Expr, current, stringEnv, state)
		if len(values) == 0 {
			ambiguous = true
			return
		}
		out = appendExactDynamicDispatchValues(out, values)
		if out == nil {
			ambiguous = true
		}
	})
	if ambiguous || !matched || len(out) == 0 {
		return nil
	}
	return out
}

func (e *engine) foreachExactDynamicDispatchValuesForVariable(current callable, name string, stringEnv map[string]string, state *dispatchResolutionState) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	resolver := e.localArrayLiteralResolver(current)
	out := []string{}
	matched := false
	ambiguous := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		foreachNode, ok := node.(*ast.StmtForeach)
		if !ok {
			return
		}
		valueVar, ok := foreachNode.ValueVar.(*ast.ExprVariable)
		if !ok {
			return
		}
		valueName, ok := valueVar.Name.(string)
		if !ok || strings.TrimSpace(valueName) != name {
			return
		}
		matched = true
		values := e.exactDynamicDispatchValuesFromIterable(foreachNode.Expr, current, stringEnv, resolver, state, map[string]struct{}{})
		if len(values) == 0 {
			ambiguous = true
			return
		}
		out = appendExactDynamicDispatchValues(out, values)
		if out == nil {
			ambiguous = true
		}
	})
	if ambiguous || !matched || len(out) == 0 {
		return nil
	}
	return out
}

func (e *engine) exactDynamicDispatchValuesFromIterable(expr ast.Node, current callable, stringEnv map[string]string, resolver *localArrayLiteralResolver, state *dispatchResolutionState, seen map[string]struct{}) []string {
	switch typed := expr.(type) {
	case nil:
		return nil
	case *ast.ExprArray:
		out := []string{}
		for _, item := range arrayItems(typed) {
			values := e.exactDynamicDispatchValuesForCallableWithState(item, current, stringEnv, state)
			if len(values) == 0 {
				return nil
			}
			out = appendExactDynamicDispatchValues(out, values)
			if out == nil {
				return nil
			}
		}
		return out
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return nil
		}
		if values := e.literalArgIterableValuesForParam(current, name); len(values) != 0 {
			return values
		}
		if stringEnv != nil {
			if value := strings.TrimSpace(stringEnv[name]); value != "" && value != conflictingLiteralArgHint && !strings.Contains(value, "{") {
				return []string{value}
			}
		}
		if resolver == nil {
			resolver = e.localArrayLiteralResolver(current)
		}
		if seen == nil {
			seen = map[string]struct{}{}
		}
		seenKey := "exact-iterable::" + current.Key + "::" + name
		if _, ok := seen[seenKey]; ok {
			return nil
		}
		seen[seenKey] = struct{}{}
		defer delete(seen, seenKey)
		if arrayNode, _ := resolver.latest(name, 0); arrayNode != nil {
			return e.exactDynamicDispatchValuesFromIterable(arrayNode, current, stringEnv, resolver, state, seen)
		}
		if latestExpr, _ := resolver.latestExpr(name, 0); latestExpr != nil {
			return e.exactDynamicDispatchValuesFromIterable(latestExpr, current, stringEnv, resolver, state, seen)
		}
	default:
		return e.exactDynamicDispatchValuesForCallableWithState(expr, current, stringEnv, state)
	}
	return nil
}

func hookDispatchKey(node ast.Node, currentClass string, e *engine) string {
	return hookDispatchKeyForCallable(node, callable{Class: currentClass}, e)
}

func hookDispatchKeyForCallable(node ast.Node, current callable, e *engine) string {
	return hookDispatchKeyForCallableWithSeen(node, current, e, map[string]struct{}{})
}

func hookDispatchKeyForCallableWithSeen(node ast.Node, current callable, e *engine, seen map[string]struct{}) string {
	if seen == nil {
		seen = map[string]struct{}{}
	}
	switch typed := node.(type) {
	case *ast.ScalarString:
		return strings.TrimSpace(typed.Value)
	case *ast.ExprBinaryOpConcat:
		left := hookDispatchKeyForCallableWithSeen(typed.Left, current, e, seen)
		right := hookDispatchKeyForCallableWithSeen(typed.Right, current, e, seen)
		if left == "" || right == "" {
			return ""
		}
		return strings.TrimSpace(left + right)
	case *ast.ScalarInterpolatedString:
		var builder strings.Builder
		for _, rawPart := range typed.Parts {
			switch part := rawPart.(type) {
			case *ast.InterpolatedStringPart:
				builder.WriteString(part.Value)
			case ast.Node:
				if literal := strings.TrimSpace(literalStringForCallableWithSeen(part, current, e, seen)); literal != "" {
					builder.WriteString(literal)
					continue
				}
				placeholder := hookPlaceholderForCurrent(part, current.Class, e)
				if placeholder == "" {
					return ""
				}
				builder.WriteString("{")
				builder.WriteString(placeholder)
				builder.WriteString("}")
			default:
				return ""
			}
		}
		return strings.TrimSpace(builder.String())
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			if hinted := e.literalArgHintForParam(current, name); hinted != "" {
				return hinted
			}
			if placeholder := strings.ToLower(strings.TrimSpace(name)); placeholder != "" {
				return "{" + placeholder + "}"
			}
		}
		return strings.TrimSpace(literalString(node))
	case *ast.ExprStaticCall:
		if literal := strings.TrimSpace(literalStringForCallableWithSeen(typed, current, e, seen)); literal != "" {
			return literal
		}
		placeholder := hookPlaceholderForCurrent(typed, current.Class, e)
		if placeholder == "" {
			return ""
		}
		return "{" + placeholder + "}"
	case *ast.ExprClassConstFetch:
		return strings.TrimSpace(literalStringForCallableWithSeen(typed, current, e, seen))
	default:
		return strings.TrimSpace(literalStringForCallableWithSeen(node, current, e, seen))
	}
}

func dynamicDispatchStringForCallable(node ast.Node, current callable, e *engine, stringEnv map[string]string) string {
	return dynamicDispatchStringForCallableWithState(node, current, e, stringEnv, newDispatchResolutionState())
}

func dynamicDispatchStringForCallableWithState(node ast.Node, current callable, e *engine, stringEnv map[string]string, state *dispatchResolutionState) string {
	if state == nil {
		state = newDispatchResolutionState()
	}
	key := dispatchResolutionKey("dynamic", current.Key, node)
	if !dispatchResolutionEnter(state.dynamic, key) {
		return ""
	}
	defer dispatchResolutionLeave(state.dynamic, key)

	switch typed := node.(type) {
	case *ast.ScalarString:
		return strings.TrimSpace(typed.Value)
	case *ast.ScalarMagicConstDir, *ast.ScalarMagicConstFile:
		return strings.TrimSpace(literalStringForCallable(typed, current, e))
	case *ast.ExprConstFetch:
		if truthy, ok := booleanLiteral(typed); ok {
			if truthy {
				return "true"
			}
			return "false"
		}
		return strings.TrimSpace(literalStringForCallable(typed, current, e))
	case *ast.ExprBinaryOpConcat:
		left := dynamicDispatchStringForCallableWithState(typed.Left, current, e, stringEnv, state)
		right := dynamicDispatchStringForCallableWithState(typed.Right, current, e, stringEnv, state)
		if left == "" || right == "" {
			return ""
		}
		return strings.TrimSpace(left + right)
	case *ast.ScalarInterpolatedString:
		var builder strings.Builder
		for _, rawPart := range typed.Parts {
			switch part := rawPart.(type) {
			case *ast.InterpolatedStringPart:
				builder.WriteString(part.Value)
			case ast.Node:
				value := dynamicDispatchStringForCallableWithState(part, current, e, stringEnv, state)
				if value == "" {
					return ""
				}
				builder.WriteString(value)
			default:
				return ""
			}
		}
		return strings.TrimSpace(builder.String())
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			if hinted := e.literalArgHintForParam(current, name); hinted != "" {
				return hinted
			}
			if stringEnv != nil {
				if value := strings.TrimSpace(stringEnv[name]); value != "" && value != conflictingLiteralArgHint {
					return value
				}
			}
			if value := strings.TrimSpace(e.localDynamicDispatchVariableValue(current, name, stringEnv, state)); value != "" {
				return value
			}
			if placeholder := strings.ToLower(strings.TrimSpace(name)); placeholder != "" {
				return "{" + placeholder + "}"
			}
		}
		return ""
	case *ast.ExprArrayDimFetch:
		if hinted := strings.TrimSpace(e.literalArgPathHintForFetch(current, typed)); hinted != "" {
			return hinted
		}
		return ""
	case *ast.ExprPropertyFetch:
		if property, ok := propertyPathKey(typed, current.Class); ok {
			if literal := literalPropertyValueForCurrent(property, current.Class, e); literal != "" {
				return literal
			}
		}
		return ""
	case *ast.ExprStaticPropertyFetch:
		property := strings.ToLower(strings.TrimSpace(identifierText(typed.Name)))
		if property == "" {
			return ""
		}
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		className = e.resolveStaticPropertyOwner(className, property)
		return e.literalClassPropertyValue(className, property)
	case *ast.ExprTernary:
		if truthy, ok := booleanLiteralForCallable(typed.Cond, current, e, stringEnv); ok {
			if truthy {
				if typed.If != nil {
					return dynamicDispatchStringForCallableWithState(typed.If, current, e, stringEnv, state)
				}
				return dynamicDispatchStringForCallableWithState(typed.Cond, current, e, stringEnv, state)
			}
			return dynamicDispatchStringForCallableWithState(typed.Else, current, e, stringEnv, state)
		}
		if value := dynamicDispatchUnknownPlaceholder(typed.Cond, current, e, stringEnv); value != "" {
			return value
		}
		return "{ternary}"
	case *ast.ExprFuncCall:
		if isStringDispatchWrapperFunc(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return dynamicDispatchStringForCallableWithState(argValue(typed.Args[0]), current, e, stringEnv, state)
		}
		return ""
	case *ast.ExprMethodCall:
		if isRequestGetterMethod(identifierText(typed.Name)) {
			return "{" + requestGetterPlaceholder(typed.Args) + "}"
		}
		if isStringDispatchWrapperMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return dynamicDispatchStringForCallableWithState(argValue(typed.Args[0]), current, e, stringEnv, state)
		}
		return ""
	case *ast.ExprStaticCall:
		if isRequestGetterStaticCall(resolveClassName(typed.Class, current.Class, e.classParents), identifierText(typed.Name)) ||
			isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
			return "{" + requestGetterPlaceholder(typed.Args) + "}"
		}
		if isStringDispatchWrapperMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return dynamicDispatchStringForCallableWithState(argValue(typed.Args[0]), current, e, stringEnv, state)
		}
		if placeholder := hookPlaceholderForCurrent(typed, current.Class, e); placeholder != "" {
			return "{" + placeholder + "}"
		}
		return ""
	case *ast.ExprClassConstFetch:
		return strings.TrimSpace(literalStringForCallable(typed, current, e))
	default:
		return ""
	}
}

func booleanLiteralForCallable(node ast.Node, current callable, e *engine, stringEnv map[string]string) (bool, bool) {
	if truthy, ok := booleanLiteral(node); ok {
		return truthy, true
	}
	variable, ok := node.(*ast.ExprVariable)
	if !ok {
		return false, false
	}
	name, ok := variable.Name.(string)
	if !ok {
		return false, false
	}
	if hinted := strings.TrimSpace(e.literalArgHintForParam(current, name)); hinted != "" {
		return parseDynamicDispatchBoolean(hinted)
	}
	if stringEnv != nil {
		if value := strings.TrimSpace(stringEnv[name]); value != "" && value != conflictingLiteralArgHint {
			return parseDynamicDispatchBoolean(value)
		}
	}
	return false, false
}

func parseDynamicDispatchBoolean(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true":
		return true, true
	case "0", "false", "":
		return false, true
	default:
		return false, false
	}
}

func dynamicDispatchUnknownPlaceholder(node ast.Node, current callable, e *engine, stringEnv map[string]string) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				return "{" + name + "}"
			}
		}
	case *ast.ExprMethodCall:
		if isRequestGetterMethod(identifierText(typed.Name)) {
			return "{" + requestGetterPlaceholder(typed.Args) + "}"
		}
	case *ast.ExprStaticCall:
		if isRequestGetterStaticCall(resolveClassName(typed.Class, current.Class, e.classParents), identifierText(typed.Name)) ||
			isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
			return "{" + requestGetterPlaceholder(typed.Args) + "}"
		}
	}
	if placeholder := hookPlaceholderForCurrent(node, current.Class, e); placeholder != "" {
		return "{" + placeholder + "}"
	}
	return ""
}

func isStringDispatchWrapperFunc(name string) bool {
	switch normalizeName(name) {
	case "strtolower", "strtoupper", "trim", "ltrim", "rtrim", "sanitize_text_field", "sanitize_key", "sanitize_file_name", "wp_unslash":
		return true
	default:
		return false
	}
}

func isStringDispatchWrapperMethod(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "tolower", "strtolower", "trim", "sanitize", "sanitize_text_field", "sanitize_key":
		return true
	default:
		return false
	}
}

func dynamicStaticMethodKeysForCallable(e *engine, current callable, className string, nameNode ast.Node, stringEnv map[string]string) []string {
	if className == "" || nameNode == nil {
		return nil
	}
	if name := strings.ToLower(strings.TrimSpace(identifierText(nameNode))); name != "" {
		if key := e.ensureRuntimeMethodCallable(className, name); key != "" {
			return []string{key}
		}
		return nil
	}
	value := strings.ToLower(strings.TrimSpace(dynamicDispatchStringForCallable(nameNode, current, e, stringEnv)))
	if value == "" {
		return nil
	}
	if !strings.Contains(value, "{") {
		if key := e.ensureRuntimeMethodCallable(className, value); key != "" {
			return []string{key}
		}
		return nil
	}
	prefixEnd := strings.Index(value, "{")
	suffixStart := strings.LastIndex(value, "}")
	if prefixEnd < 0 || suffixStart < prefixEnd {
		return nil
	}
	return e.lookupMethodKeysByPattern(className, value[:prefixEnd], value[suffixStart+1:])
}

func hookPlaceholder(node ast.Node) string {
	if path, ok := propertyPathKey(node, ""); ok {
		return strings.ToLower(strings.ReplaceAll(path, ".", "_"))
	}
	switch typed := node.(type) {
	case *ast.ExprStaticCall:
		if isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
			return requestGetterPlaceholder(typed.Args)
		}
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			return strings.ToLower(name)
		}
	case *ast.Identifier:
		return strings.ToLower(typed.Name)
	case *ast.ScalarString:
		return strings.ToLower(typed.Value)
	}
	return ""
}

func hookPlaceholderForCurrent(node ast.Node, currentClass string, e *engine) string {
	if path, ok := staticPropertyPathKey(node, currentClass, e); ok {
		return strings.ToLower(strings.ReplaceAll(path, ".", "_"))
	}
	if path, ok := propertyPathKey(node, currentClass); ok {
		if literal := literalPropertyValueForCurrent(path, currentClass, e); literal != "" {
			return strings.ToLower(strings.TrimSpace(literal))
		}
		return strings.ToLower(strings.ReplaceAll(path, ".", "_"))
	}
	switch typed := node.(type) {
	case *ast.ScalarString:
		return strings.ToLower(typed.Value)
	case *ast.ExprStaticCall:
		if isRequestGetterStaticCall(resolveClassName(typed.Class, currentClass, e.classParents), identifierText(typed.Name)) ||
			isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
			return requestGetterPlaceholder(typed.Args)
		}
	}
	return ""
}

func literalPropertyValueForCurrent(path string, currentClass string, e *engine) string {
	if e == nil || currentClass == "" {
		return ""
	}
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "this.") {
		return ""
	}
	property := strings.TrimPrefix(path, "this.")
	if property == "" || strings.Contains(property, ".") {
		return ""
	}
	return e.literalClassPropertyValue(currentClass, property)
}

func requestGetterPlaceholder(args []ast.Node) string {
	if len(args) > 0 {
		if key := stableRequestGetterKey(argValue(args[0])); key != "" {
			return key
		}
	}
	return "request"
}

func stableRequestGetterKey(node ast.Node) string {
	value := strings.ToLower(strings.TrimSpace(literalString(node)))
	value = strings.Trim(value, `"'`)
	if value != "" {
		return value
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			return strings.ToLower(strings.TrimSpace(name))
		}
	}
	return ""
}

func stableArrayDimKey(node ast.Node) (string, bool) {
	switch typed := node.(type) {
	case *ast.ScalarString:
		if typed.Value == "" {
			return "", false
		}
		return typed.Value, true
	case *ast.ScalarInt:
		return fmt.Sprintf("%d", typed.Value), true
	case *ast.ScalarFloat:
		return fmt.Sprintf("%v", typed.Value), true
	}
	value := literalString(node)
	if value == "" {
		return "", false
	}
	return value, true
}

func appendArrayPath(base string, dim ast.Node) string {
	if base == "" {
		return ""
	}
	if key, ok := stableArrayDimKey(dim); ok {
		return base + "[" + strings.ToLower(key) + "]"
	}
	if dim == nil {
		return base + "[]"
	}
	return base + "[*]"
}

func childStatementBlocks(node ast.Node) [][]ast.Node {
	if node == nil {
		return nil
	}
	var blocks [][]ast.Node
	for _, name := range node.SubNodeNames() {
		value := node.SubNode(name)
		switch typed := value.(type) {
		case []ast.Node:
			stmtBlock := make([]ast.Node, 0, len(typed))
			for _, child := range typed {
				if child != nil && strings.HasPrefix(child.NodeType(), "Stmt_") {
					stmtBlock = append(stmtBlock, child)
				}
			}
			if len(stmtBlock) != 0 {
				blocks = append(blocks, stmtBlock)
			}
		case ast.Node:
			if typed != nil && strings.HasPrefix(typed.NodeType(), "Stmt_") {
				blocks = append(blocks, []ast.Node{typed})
			}
		}
	}
	return blocks
}

func callableIsFileWrapper(c callable) bool {
	return strings.HasPrefix(c.Key, "file::")
}

func isDeclarationStmt(node ast.Node) bool {
	switch node.(type) {
	case *ast.StmtClass, *ast.StmtFunction, *ast.StmtInterface, *ast.StmtTrait:
		return true
	default:
		return false
	}
}

func skipNestedDeclarationBodies(c callable, node ast.Node) bool {
	return callableIsFileWrapper(c) && isDeclarationStmt(node)
}

func walkCallableExecutableNodes(c callable, visit func(ast.Node)) {
	for _, node := range c.Stmts {
		if skipNestedDeclarationBodies(c, node) {
			continue
		}
		walkNode(node, visit)
	}
}

func receiverRootKey(node ast.Node, currentClass string) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			if name == "this" {
				return "this"
			}
			return name
		}
	}
	if path, ok := propertyPathKey(node, currentClass); ok {
		return path
	}
	return ""
}

func localClassPathKey(node ast.Node) (string, bool) {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || name == "" || name == "this" {
			return "", false
		}
		return name, true
	case *ast.ExprArrayDimFetch:
		base, ok := localClassPathKey(typed.Var)
		if !ok || base == "" {
			return "", false
		}
		return appendArrayPath(base, typed.Dim), true
	default:
		return "", false
	}
}

func valueRootKey(node ast.Node, currentClass string) string {
	if path, ok := propertyPathKey(node, currentClass); ok {
		return path
	}
	return receiverRootKey(node, currentClass)
}

func assignedCallResultRoot(parent ast.Node, current ast.Node, currentClass string) string {
	assign, ok := parent.(*ast.ExprAssign)
	if !ok || assign.Expr != current {
		return ""
	}
	return valueRootKey(assign.Var, currentClass)
}

func isCompoundAssignTarget(parent ast.Node, current ast.Node) bool {
	switch typed := parent.(type) {
	case *ast.ExprAssignOpConcat:
		return typed.Var == current
	case *ast.ExprAssignOpPlus:
		return typed.Var == current
	case *ast.ExprAssignOpMinus:
		return typed.Var == current
	case *ast.ExprAssignOpMul:
		return typed.Var == current
	case *ast.ExprAssignOpDiv:
		return typed.Var == current
	case *ast.ExprAssignOpMod:
		return typed.Var == current
	case *ast.ExprAssignOpPow:
		return typed.Var == current
	case *ast.ExprAssignOpBitwiseAnd:
		return typed.Var == current
	case *ast.ExprAssignOpBitwiseOr:
		return typed.Var == current
	case *ast.ExprAssignOpBitwiseXor:
		return typed.Var == current
	case *ast.ExprAssignOpShiftLeft:
		return typed.Var == current
	case *ast.ExprAssignOpShiftRight:
		return typed.Var == current
	case *ast.ExprAssignOpCoalesce:
		return typed.Var == current
	default:
		return false
	}
}

func propertyPathKey(node ast.Node, currentClass string) (string, bool) {
	switch typed := node.(type) {
	case *ast.ExprPropertyFetch:
		root, ok := receiverRootKey(typed.Var, currentClass), false
		if root != "" {
			ok = true
		}
		name := identifierText(typed.Name)
		if !ok || name == "" {
			return "", false
		}
		return root + "." + name, true
	case *ast.ExprArrayDimFetch:
		base, ok := propertyPathKey(typed.Var, currentClass)
		if !ok || base == "" {
			return "", false
		}
		return appendArrayPath(base, typed.Dim), true
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			if name == "this" {
				return "this", true
			}
			return name, true
		}
	}
	return "", false
}

func storageFamilyExpr(node ast.Node) (string, bool) {
	prop, ok := node.(*ast.ExprPropertyFetch)
	if !ok {
		return "", false
	}
	name := strings.ToLower(identifierText(prop.Name))
	if _, ok := storageFamilies[name]; !ok {
		return "", false
	}
	return name, true
}

func storagePathKey(node ast.Node) (string, bool) {
	switch typed := node.(type) {
	case *ast.ExprPropertyFetch:
		return storageFamilyExpr(typed)
	case *ast.ExprArrayDimFetch:
		base, ok := storagePathKey(typed.Var)
		if !ok || base == "" {
			return "", false
		}
		return appendArrayPath(base, typed.Dim), true
	}
	return "", false
}

func globalConstPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	switch strings.ToLower(name) {
	case "true", "false", "null":
		return ""
	default:
		return "const:" + strings.ToLower(name)
	}
}

func staticPropertyPathKey(node ast.Node, currentClass string, e *engine) (string, bool) {
	switch typed := node.(type) {
	case *ast.ExprConstFetch:
		path := globalConstPath(identifierText(typed.Name))
		if path == "" {
			return "", false
		}
		return path, true
	case *ast.ExprStaticPropertyFetch:
		className := resolveClassName(typed.Class, currentClass, e.classParents)
		name := identifierText(typed.Name)
		if className == "" || name == "" {
			return "", false
		}
		className = e.resolveStaticPropertyOwner(className, strings.ToLower(name))
		return className + ".$" + name, true
	case *ast.ExprArrayDimFetch:
		base, ok := staticPropertyPathKey(typed.Var, currentClass, e)
		if !ok || base == "" {
			return "", false
		}
		return appendArrayPath(base, typed.Dim), true
	}
	return "", false
}

func walkNodes(nodes []ast.Node, visit func(ast.Node)) {
	for _, node := range nodes {
		walkNode(node, visit)
	}
}

func walkNodeSlice(nodes []ast.Node, visit func(ast.Node)) {
	for _, child := range nodes {
		walkNode(child, visit)
	}
}

func walkChildValue(value any, visit func(ast.Node)) {
	switch typed := value.(type) {
	case ast.Node:
		walkNode(typed, visit)
	case []ast.Node:
		walkNodeSlice(typed, visit)
	case []any:
		for _, item := range typed {
			if child, ok := item.(ast.Node); ok {
				walkNode(child, visit)
			}
		}
	}
}

func walkNode(node ast.Node, visit func(ast.Node)) {
	if node == nil {
		return
	}
	visit(node)
	switch typed := node.(type) {
	case *ast.Arg:
		walkNode(typed.Name, visit)
		walkNode(typed.Value, visit)
		return
	case *ast.ArrayItem:
		walkNode(typed.Key, visit)
		walkNode(typed.Value, visit)
		return
	case *ast.ExprArrayDimFetch:
		walkNode(typed.Var, visit)
		walkNode(typed.Dim, visit)
		return
	case *ast.ExprAssign:
		walkNode(typed.Var, visit)
		walkNode(typed.Expr, visit)
		return
	case *ast.ExprBinaryOpConcat:
		walkNode(typed.Left, visit)
		walkNode(typed.Right, visit)
		return
	case *ast.ExprFuncCall:
		walkNode(typed.Name, visit)
		walkNodeSlice(typed.Args, visit)
		return
	case *ast.ExprMethodCall:
		walkNode(typed.Var, visit)
		walkNode(typed.Name, visit)
		walkNodeSlice(typed.Args, visit)
		return
	case *ast.ExprPropertyFetch:
		walkNode(typed.Var, visit)
		walkNode(typed.Name, visit)
		return
	case *ast.ExprStaticCall:
		walkNode(typed.Class, visit)
		walkNode(typed.Name, visit)
		walkNodeSlice(typed.Args, visit)
		return
	case *ast.ExprVariable:
		walkChildValue(typed.Name, visit)
		return
	case *ast.ScalarString, *ast.Identifier, *ast.Name, *ast.NameFullyQualified:
		return
	case *ast.StmtExpression:
		walkNode(typed.Expr, visit)
		return
	case *ast.StmtIf:
		walkNode(typed.Cond, visit)
		walkNodeSlice(typed.Stmts, visit)
		walkNodeSlice(typed.Elseifs, visit)
		walkNode(typed.Else, visit)
		return
	// Hot fall-through node types: recurse into concrete fields directly instead
	// of the SubNodeNames()/SubNode() reflection fallback, which allocates a
	// string slice + boxed values per node and dominated allocation in profiling.
	// Traversal order/coverage is identical to the generic walk.
	case *ast.ExprTernary:
		walkNode(typed.Cond, visit)
		walkNode(typed.If, visit)
		walkNode(typed.Else, visit)
		return
	case *ast.ExprArray:
		walkNodeSlice(typed.Items, visit)
		return
	case *ast.StmtForeach:
		walkNode(typed.Expr, visit)
		walkNode(typed.KeyVar, visit)
		walkNode(typed.ValueVar, visit)
		walkNodeSlice(typed.Stmts, visit)
		return
	case *ast.StmtSwitch:
		walkNode(typed.Cond, visit)
		walkNodeSlice(typed.Cases, visit)
		return
	case *ast.StmtCase:
		walkNode(typed.Cond, visit)
		walkNodeSlice(typed.Stmts, visit)
		return
	case *ast.ExprBooleanNot:
		walkNode(typed.Expr, visit)
		return
	case *ast.ExprIsset:
		walkNodeSlice(typed.Vars, visit)
		return
	case *ast.ExprEmpty:
		walkNode(typed.Expr, visit)
		return
	case *ast.ExprNew:
		walkNode(typed.Class, visit)
		walkNodeSlice(typed.Args, visit)
		return
	case *ast.StmtReturn:
		walkNode(typed.Expr, visit)
		return
	case *ast.StmtEcho:
		walkNodeSlice(typed.Exprs, visit)
		return
	case *ast.ExprAssignOpConcat:
		walkNode(typed.Var, visit)
		walkNode(typed.Expr, visit)
		return
	case *ast.ExprBinaryOpBooleanAnd:
		walkNode(typed.Left, visit)
		walkNode(typed.Right, visit)
		return
	case *ast.ExprBinaryOpBooleanOr:
		walkNode(typed.Left, visit)
		walkNode(typed.Right, visit)
		return
	case *ast.ExprBinaryOpIdentical:
		walkNode(typed.Left, visit)
		walkNode(typed.Right, visit)
		return
	case *ast.ExprBinaryOpNotIdentical:
		walkNode(typed.Left, visit)
		walkNode(typed.Right, visit)
		return
	case *ast.ExprBinaryOpEqual:
		walkNode(typed.Left, visit)
		walkNode(typed.Right, visit)
		return
	case *ast.ExprBinaryOpNotEqual:
		walkNode(typed.Left, visit)
		walkNode(typed.Right, visit)
		return
	case *ast.ExprConstFetch:
		walkNode(typed.Name, visit)
		return
	case *ast.StmtElse:
		walkNodeSlice(typed.Stmts, visit)
		return
	case *ast.StmtElseIf:
		walkNode(typed.Cond, visit)
		walkNodeSlice(typed.Stmts, visit)
		return
	case *ast.StmtBreak:
		walkNode(typed.Num, visit)
		return
	case *ast.StmtContinue:
		walkNode(typed.Num, visit)
		return
	}
	for _, name := range node.SubNodeNames() {
		value := node.SubNode(name)
		switch typed := value.(type) {
		case ast.Node:
			walkNode(typed, visit)
		case []ast.Node:
			for _, child := range typed {
				walkNode(child, visit)
			}
		}
	}
}

func locationForCallableNode(e *engine, c callable, node ast.Node) Location {
	loc := Location{
		Path: c.SourcePath,
		Line: c.StartLine,
	}
	if node != nil {
		loc.Line = node.StartLine()
	}
	if e == nil {
		return loc
	}
	file := e.fileIndex[c.SourcePath]
	if loc.Line >= 1 && loc.Line <= len(file.Lines) {
		loc.Snippet = strings.TrimSpace(file.Lines[loc.Line-1])
	}
	return loc
}

func arrayItems(node *ast.ExprArray) []ast.Node {
	if node == nil {
		return nil
	}
	values := make([]ast.Node, 0, len(node.Items))
	for _, itemNode := range node.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok {
			continue
		}
		values = append(values, item.Value)
	}
	return values
}

func arrayValueForStringKey(node *ast.ExprArray, key string) ast.Node {
	if node == nil {
		return nil
	}
	for _, itemNode := range node.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok {
			continue
		}
		if strings.EqualFold(literalString(item.Key), key) {
			return item.Value
		}
	}
	return nil
}

func summarizeOrigins(origins originSet) taintSummary {
	return summarizeOriginsWithCompactedParamPaths(origins, false)
}

func summarizeOriginsCompacted(origins originSet) taintSummary {
	return summarizeOriginsWithCompactedParamPaths(origins, true)
}

func summarizeOriginsWithCompactedParamPaths(origins originSet, compactParamPaths bool) taintSummary {
	out := taintSummary{
		Sources:       make([]Location, 0),
		SourceOrigins: make([]sourceOriginRef, 0),
		ReceiverPaths: make([]receiverPathRef, 0),
		Params:        make([]int, 0),
		ParamPaths:    make([]paramPathRef, 0),
	}
	params := map[int]struct{}{}
	paramPaths := map[string]paramPathRef{}
	sources := map[string]Location{}
	sourceOrigins := map[string]sourceOriginRef{}
	receiverPaths := map[string]receiverPathRef{}
	for _, item := range origins {
		switch item.kind {
		case originParam:
			if item.paramPath != "" || item.persistentRead || item.pathSafe || item.outputSafeHTML || item.outputUnsafeHTML || hasMeaningfulFlowContext(item.storedWriteContext) {
				key := paramPathSyntheticPrefix(item.paramIdx) + item.paramPath
				ref := paramPaths[key]
				ref.Index = item.paramIdx
				ref.Path = item.paramPath
				ref.PersistentRead = ref.PersistentRead || item.persistentRead
				ref.PathSafe = ref.PathSafe || item.pathSafe
				ref.OutputSafeHTML = ref.OutputSafeHTML || item.outputSafeHTML
				ref.OutputUnsafeHTML = ref.OutputUnsafeHTML || item.outputUnsafeHTML
				ref.StoredWriteContext = mergeOptionalFlowContext(ref.StoredWriteContext, item.storedWriteContext)
				paramPaths[key] = ref
				continue
			}
			params[item.paramIdx] = struct{}{}
		case originSource:
			locKey := locationKey(item.source)
			sources[locKey] = item.source
			if item.persistentRead || item.pathSafe || item.outputSafeHTML || item.outputUnsafeHTML || hasMeaningfulFlowContext(item.storedWriteContext) {
				ref := sourceOrigins[locKey]
				ref.Location = item.source
				ref.PersistentRead = ref.PersistentRead || item.persistentRead
				ref.PathSafe = ref.PathSafe || item.pathSafe
				ref.OutputSafeHTML = ref.OutputSafeHTML || item.outputSafeHTML
				ref.OutputUnsafeHTML = ref.OutputUnsafeHTML || item.outputUnsafeHTML
				ref.StoredWriteContext = mergeOptionalFlowContext(ref.StoredWriteContext, item.storedWriteContext)
				sourceOrigins[locKey] = ref
			}
		case originReceiver:
			key := item.receiverPath
			ref := receiverPaths[key]
			ref.Path = item.receiverPath
			ref.PersistentRead = ref.PersistentRead || item.persistentRead
			ref.PathSafe = ref.PathSafe || item.pathSafe
			ref.OutputSafeHTML = ref.OutputSafeHTML || item.outputSafeHTML
			ref.OutputUnsafeHTML = ref.OutputUnsafeHTML || item.outputUnsafeHTML
			ref.StoredWriteContext = mergeOptionalFlowContext(ref.StoredWriteContext, item.storedWriteContext)
			receiverPaths[key] = ref
		}
	}
	for param := range params {
		out.Params = append(out.Params, param)
	}
	sort.Ints(out.Params)
	if compactParamPaths {
		paramPaths = compactParamPathRefsByRoot(paramPaths)
		receiverPaths = compactReceiverPathRefsByRoot(receiverPaths)
	}
	for _, key := range sortedKeys(paramPaths) {
		out.ParamPaths = append(out.ParamPaths, paramPaths[key])
	}
	out.Sources = sortedLocations(sources)
	for _, key := range sortedKeys(sourceOrigins) {
		out.SourceOrigins = append(out.SourceOrigins, sourceOrigins[key])
	}
	for _, key := range sortedKeys(receiverPaths) {
		out.ReceiverPaths = append(out.ReceiverPaths, receiverPaths[key])
	}
	return out
}
