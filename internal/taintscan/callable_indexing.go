package taintscan

import (
	"sort"
	"strconv"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
	"github.com/dimasma0305/php-parser-go/phpparser"
)

func (e *engine) lookupFunctionKey(namespace string, name string) string {
	if name == "" {
		return ""
	}
	if strings.Contains(name, `\`) {
		return e.functions[normalizeName(name)]
	}
	if namespace != "" {
		if key := e.functions[normalizeName(namespace+`\`+name)]; key != "" {
			return key
		}
	}
	if key := e.functions[normalizeName(name)]; key != "" {
		return key
	}
	return e.functions[normalizeName(`\`+name)]
}

func (e *engine) lookupMethodKey(className string, methodName string) string {
	if className == "" || methodName == "" {
		return ""
	}
	seen := map[string]struct{}{}
	current := className
	for current != "" {
		if _, ok := seen[current]; ok {
			break
		}
		seen[current] = struct{}{}
		if methods := e.methods[current]; methods != nil {
			if key, ok := methods[strings.ToLower(methodName)]; ok {
				return key
			}
		}
		current = e.classParents[current]
	}
	return ""
}

func namespaceForClassName(className string) string {
	className = strings.TrimSpace(strings.TrimPrefix(className, `\`))
	if className == "" {
		return ""
	}
	if idx := strings.LastIndex(className, `\`); idx >= 0 {
		return `\` + className[:idx]
	}
	return ""
}

func runtimeMethodCallableKey(className string, methodName string) string {
	return className + "::" + strings.ToLower(strings.TrimSpace(methodName)) + "#runtime"
}

func specializedLiteralCallableKey(baseKey string, hintsKey string) string {
	return baseKey + "#lit:" + hintsKey
}

func baseCallableKeyForLiteralSpecialization(key string) string {
	if idx := strings.Index(key, "#lit:"); idx >= 0 {
		return key[:idx]
	}
	return ""
}

func (e *engine) ensureRuntimeMethodCallable(className string, methodName string) string {
	className = strings.TrimSpace(className)
	methodName = strings.ToLower(strings.TrimSpace(methodName))
	if className == "" || methodName == "" {
		return ""
	}
	if methods := e.methods[className]; methods != nil {
		if key := methods[methodName]; key != "" {
			return key
		}
	}
	key := e.lookupMethodKey(className, methodName)
	if key == "" {
		return ""
	}
	base, ok := e.callables[key]
	if !ok {
		return ""
	}
	if base.Class == className {
		return key
	}
	runtimeKey := runtimeMethodCallableKey(className, methodName)
	if _, ok := e.callables[runtimeKey]; ok {
		return runtimeKey
	}
	base.Key = runtimeKey
	base.Class = className
	base.Namespace = namespaceForClassName(className)
	base.Display = className + "::" + methodName
	e.addCallable(base)
	return runtimeKey
}

func (e *engine) existingRuntimeMethodCallable(className string, methodName string) string {
	className = strings.TrimSpace(className)
	methodName = strings.ToLower(strings.TrimSpace(methodName))
	if className == "" || methodName == "" {
		return ""
	}
	if methods := e.methods[className]; methods != nil {
		if key := methods[methodName]; key != "" {
			return key
		}
	}
	key := e.lookupMethodKey(className, methodName)
	if key == "" {
		return ""
	}
	base, ok := e.callables[key]
	if !ok {
		return ""
	}
	if base.Class == className {
		return key
	}
	runtimeKey := runtimeMethodCallableKey(className, methodName)
	if _, ok := e.callables[runtimeKey]; ok {
		return runtimeKey
	}
	return key
}

func literalArgHintsKey(hints map[int]string) string {
	if len(hints) == 0 {
		return ""
	}
	indexes := make([]int, 0, len(hints))
	for idx := range hints {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	parts := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		value := strings.TrimSpace(hints[idx])
		if value == "" || value == conflictingLiteralArgHint {
			continue
		}
		parts = append(parts, strconv.Itoa(idx)+"="+value)
	}
	return strings.Join(parts, "|")
}

func literalArgPathHintsKey(hints map[int]map[string]string) string {
	if len(hints) == 0 {
		return ""
	}
	indexes := make([]int, 0, len(hints))
	for idx := range hints {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	parts := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		pathHints := hints[idx]
		if len(pathHints) == 0 {
			continue
		}
		paths := make([]string, 0, len(pathHints))
		for path := range pathHints {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		pathParts := make([]string, 0, len(paths))
		for _, path := range paths {
			value := strings.TrimSpace(pathHints[path])
			if value == "" || value == conflictingLiteralArgHint {
				continue
			}
			pathParts = append(pathParts, strconv.Quote(path)+"="+strconv.Quote(value))
		}
		if len(pathParts) == 0 {
			continue
		}
		parts = append(parts, strconv.Itoa(idx)+":"+strings.Join(pathParts, ";"))
	}
	return strings.Join(parts, "|")
}

func literalArgSpecializationKey(hints map[int]string, pathHints map[int]map[string]string) string {
	parts := make([]string, 0, 2)
	if hintKey := literalArgHintsKey(hints); hintKey != "" {
		parts = append(parts, "arg:"+hintKey)
	}
	if pathKey := literalArgPathHintsKey(pathHints); pathKey != "" {
		parts = append(parts, "path:"+pathKey)
	}
	return strings.Join(parts, "||")
}

func (e *engine) callableNeedsLiteralArgSpecialization(current callable) bool {
	if len(current.Params) == 0 {
		return false
	}
	params := map[string]struct{}{}
	for _, param := range current.Params {
		if param == "" {
			continue
		}
		params[param] = struct{}{}
	}
	trackedParams := literalGuardTrackedParams(current, params)
	usesParamPlaceholder := func(value string) bool {
		value = strings.TrimSpace(value)
		if value == "" {
			return false
		}
		for param := range params {
			if strings.Contains(value, "{"+param+"}") {
				return true
			}
		}
		return false
	}
	needed := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if needed {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			if len(typed.Args) == 0 {
				return
			}
			switch normalizeName(identifierText(typed.Name)) {
			case "apply_filters", "apply_filters_ref_array", "do_action", "do_action_ref_array":
				hook := hookDispatchKeyForCallable(argValue(typed.Args[0]), current, e)
				for _, param := range current.Params {
					if strings.Contains(hook, "{"+param+"}") {
						needed = true
						return
					}
				}
			}
		case *ast.StmtIf:
			needed = conditionUsesParamLiteralGuard(typed.Cond, trackedParams)
		case *ast.StmtElseIf:
			needed = conditionUsesParamLiteralGuard(typed.Cond, trackedParams)
		case *ast.StmtSwitch:
			needed = switchUsesParamLiteralGuard(typed, trackedParams)
		case *ast.ExprTernary:
			needed = conditionUsesParamLiteralGuard(typed.Cond, trackedParams)
		case *ast.ExprNew:
			needed = usesParamPlaceholder(dynamicDispatchStringForCallable(typed.Class, current, e, nil))
		}
	})
	return needed
}

func literalGuardTrackedParams(current callable, params map[string]struct{}) map[string]struct{} {
	tracked := map[string]struct{}{}
	for name := range params {
		tracked[name] = struct{}{}
	}
	changed := true
	for changed {
		changed = false
		walkNodes(current.Stmts, func(node ast.Node) {
			assign, ok := node.(*ast.ExprAssign)
			if !ok {
				assignRef, ok := node.(*ast.ExprAssignRef)
				if !ok {
					return
				}
				assign = &ast.ExprAssign{Var: assignRef.Var, Expr: assignRef.Expr}
			}
			target, ok := assign.Var.(*ast.ExprVariable)
			if !ok {
				return
			}
			targetName, ok := target.Name.(string)
			if !ok || targetName == "" {
				return
			}
			if _, ok := tracked[targetName]; ok {
				return
			}
			if !exprUsesTrackedLiteralGuardParam(assign.Expr, tracked) {
				return
			}
			tracked[targetName] = struct{}{}
			changed = true
		})
	}
	return tracked
}

func exprUsesTrackedLiteralGuardParam(node ast.Node, tracked map[string]struct{}) bool {
	switch typed := node.(type) {
	case nil:
		return false
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return false
		}
		_, ok = tracked[name]
		return ok
	case *ast.ExprArrayDimFetch:
		return exprUsesTrackedLiteralGuardParam(typed.Var, tracked)
	case *ast.ExprAssign:
		return exprUsesTrackedLiteralGuardParam(typed.Expr, tracked)
	case *ast.ExprAssignRef:
		return exprUsesTrackedLiteralGuardParam(typed.Expr, tracked)
	case *ast.ExprFuncCall:
		return isPropagatingFunc(normalizeName(identifierText(typed.Name))) &&
			len(typed.Args) > 0 &&
			exprUsesTrackedLiteralGuardParam(argValue(typed.Args[0]), tracked)
	case *ast.ExprMethodCall:
		return isPropagatingMethod(identifierText(typed.Name)) &&
			len(typed.Args) > 0 &&
			exprUsesTrackedLiteralGuardParam(argValue(typed.Args[0]), tracked)
	case *ast.ExprStaticCall:
		return isPropagatingMethod(identifierText(typed.Name)) &&
			len(typed.Args) > 0 &&
			exprUsesTrackedLiteralGuardParam(argValue(typed.Args[0]), tracked)
	default:
		return false
	}
}

func switchUsesParamLiteralGuard(node *ast.StmtSwitch, params map[string]struct{}) bool {
	if node == nil || len(params) == 0 || !nodeUsesTrackedParam(node.Cond, params) {
		return false
	}
	for _, rawCase := range node.Cases {
		caseStmt, ok := rawCase.(*ast.StmtCase)
		if !ok || caseStmt.Cond == nil {
			continue
		}
		if nodeContainsLiteral(caseStmt.Cond) {
			return true
		}
	}
	return false
}

func (e *engine) callableUsesParamLiteralIncludeDispatch(current callable) bool {
	if len(current.Params) == 0 {
		return false
	}
	params := map[string]struct{}{}
	for _, param := range current.Params {
		if param == "" {
			continue
		}
		params[param] = struct{}{}
	}
	needed := false
	usesParamPlaceholder := func(value string) bool {
		value = strings.TrimSpace(value)
		if value == "" {
			return false
		}
		for param := range params {
			if strings.Contains(value, "{"+param+"}") {
				return true
			}
		}
		return false
	}
	foreachUsesParamPlaceholder := func(node *ast.StmtForeach) bool {
		if node == nil {
			return false
		}
		if !nodeUsesTrackedParam(node.Expr, params) && !exprUsesTrackedLiteralGuardParam(node.Expr, params) {
			return false
		}
		valueVar, ok := node.ValueVar.(*ast.ExprVariable)
		if !ok {
			return false
		}
		valueName, ok := valueVar.Name.(string)
		if !ok || strings.TrimSpace(valueName) == "" {
			return false
		}
		needed := false
		walkNodes(node.Stmts, func(child ast.Node) {
			if needed {
				return
			}
			switch typed := child.(type) {
			case *ast.ExprInclude:
				needed = true
			case *ast.ExprFuncCall:
				if normalizeName(identifierText(typed.Name)) != "load_template" || len(typed.Args) == 0 {
					return
				}
				needed = true
			}
		})
		return needed
	}
	walkNodes(current.Stmts, func(node ast.Node) {
		if needed {
			return
		}
		switch typed := node.(type) {
		case *ast.StmtForeach:
			needed = foreachUsesParamPlaceholder(typed)
		case *ast.ExprInclude:
			needed = usesParamPlaceholder(dynamicDispatchStringForCallable(typed.Expr, current, e, nil))
		case *ast.ExprFuncCall:
			if normalizeName(identifierText(typed.Name)) != "load_template" || len(typed.Args) == 0 {
				return
			}
			needed = usesParamPlaceholder(dynamicDispatchStringForCallable(argValue(typed.Args[0]), current, e, nil))
		}
	})
	return needed
}

func conditionUsesParamLiteralGuard(node ast.Node, params map[string]struct{}) bool {
	return nodeUsesTrackedParam(node, params) && nodeContainsLiteral(node)
}

func nodeUsesTrackedParam(node ast.Node, params map[string]struct{}) bool {
	if node == nil || len(params) == 0 {
		return false
	}
	hasParam := false
	walkNode(node, func(child ast.Node) {
		if hasParam {
			return
		}
		variable, ok := child.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok {
			return
		}
		_, hasParam = params[name]
	})
	return hasParam
}

func nodeContainsLiteral(node ast.Node) bool {
	if node == nil {
		return false
	}
	hasLiteral := false
	walkNode(node, func(child ast.Node) {
		if hasLiteral {
			return
		}
		switch typed := child.(type) {
		case *ast.ScalarString, *ast.ScalarInt, *ast.ScalarFloat:
			hasLiteral = true
		case *ast.ExprConstFetch:
			switch strings.ToLower(strings.TrimSpace(identifierText(typed.Name))) {
			case "true", "false", "null":
				hasLiteral = true
			}
		}
	})
	return hasLiteral
}

func (e *engine) maybeSpecializeCallableForLiteralArgs(baseKey string, hints map[int]string) string {
	return e.maybeSpecializeCallableForLiteralArgsAndPaths(baseKey, hints, nil)
}

func (e *engine) maybeSpecializeCallableForLiteralArgsAndPaths(baseKey string, hints map[int]string, pathHints map[int]map[string]string) string {
	if baseKey == "" || (len(hints) == 0 && len(pathHints) == 0) {
		return baseKey
	}
	base, ok := e.callables[baseKey]
	if !ok || len(base.Params) == 0 {
		return baseKey
	}
	needsCallSpecialization := e.callableNeedsLiteralArgSpecialization(base)
	needsOutputIncludeSpecialization := e.currentBatchName == "output" && e.callableUsesParamLiteralIncludeDispatch(base)
	needsOutputFunctionSpecialization := e.currentBatchName == "output" &&
		base.Class == "" &&
		needsCallSpecialization
	needsOutputPathSpecialization := e.currentBatchName == "output" &&
		len(pathHints) != 0 &&
		needsCallSpecialization
	switch {
	case e.currentBatchName == "call":
		if !needsCallSpecialization {
			return baseKey
		}
	case needsOutputIncludeSpecialization:
		// Output-only scans sometimes funnel many literal template files through a single
		// loader helper. Specialize those helpers by file argument so included-template
		// sinks do not collapse into one overly broad summary.
	case needsOutputFunctionSpecialization:
		// Output-heavy plugins often route display helpers through global function wrappers
		// that branch on a literal selector parameter. Limit this to global functions so
		// large stateful methods do not explode across many per-call specializations.
	case needsOutputPathSpecialization:
		// Output-heavy plugins also route large renderer methods through array-backed selector
		// params such as $data['type']. Only specialize those methods when the callsite already
		// provides stable literal subkeys, which keeps the split bounded and data-driven.
	default:
		return baseKey
	}
	return e.ensureLiteralArgSpecializedCallable(baseKey, base, hints, pathHints)
}

func (e *engine) maybeSpecializeOutputCallableForBuild(baseKey string, hints map[int]string, pathHints map[int]map[string]string) string {
	if baseKey == "" || (len(hints) == 0 && len(pathHints) == 0) {
		return baseKey
	}
	base, ok := e.callables[baseKey]
	if !ok || len(base.Params) == 0 {
		return baseKey
	}
	needsCallSpecialization := e.callableNeedsLiteralArgSpecialization(base)
	needsOutputIncludeSpecialization := e.callableUsesParamLiteralIncludeDispatch(base)
	if !needsCallSpecialization && !needsOutputIncludeSpecialization {
		return baseKey
	}
	if needsOutputIncludeSpecialization && !needsCallSpecialization {
		if len(pathHints[0]) == 0 {
			return baseKey
		}
	}
	if base.Class != "" && len(pathHints) == 0 && !needsOutputIncludeSpecialization {
		return baseKey
	}
	return e.ensureLiteralArgSpecializedCallable(baseKey, base, hints, pathHints)
}

func (e *engine) ensureLiteralArgSpecializedCallable(baseKey string, base callable, hints map[int]string, pathHints map[int]map[string]string) string {
	filtered := filterLiteralArgHintsForCallable(base, hints)
	filteredPaths := filterLiteralArgPathHintsForCallable(base, pathHints)
	hintsKey := literalArgSpecializationKey(filtered, filteredPaths)
	if hintsKey == "" {
		return baseKey
	}
	entries := e.specializedLiteralCallables[baseKey]
	if entries == nil {
		entries = map[string]string{}
		e.specializedLiteralCallables[baseKey] = entries
	}
	if key := entries[hintsKey]; key != "" {
		return key
	}
	specialized := base
	specialized.Key = specializedLiteralCallableKey(baseKey, hintsKey)
	if _, exists := e.callables[specialized.Key]; exists {
		entries[hintsKey] = specialized.Key
		return specialized.Key
	}
	e.callables[specialized.Key] = specialized
	e.callOrder = append(e.callOrder, specialized.Key)
	e.summaries[specialized.Key] = summary{ParamFindings: map[int][]sinkTemplate{}}
	if ctx, ok := e.contexts[baseKey]; ok {
		e.contexts[specialized.Key] = ctx
	}
	if hint := e.directReturnHints[baseKey]; hint != "" {
		e.directReturnHints[specialized.Key] = hint
	}
	if path := e.directReturnPropertyHints[baseKey]; path != "" {
		e.directReturnPropertyHints[specialized.Key] = path
	}
	if hints := e.callableReceiverPropertyClasses[baseKey]; len(hints) != 0 {
		e.callableReceiverPropertyClasses[specialized.Key] = hints
	}
	e.literalArgHints[specialized.Key] = filtered
	e.literalArgPathHints[specialized.Key] = filteredPaths
	entries[hintsKey] = specialized.Key
	return specialized.Key
}

func filterLiteralArgHintsForCallable(base callable, hints map[int]string) map[int]string {
	filtered := map[int]string{}
	for idx, value := range hints {
		if idx < 0 || idx >= len(base.Params) {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" || value == conflictingLiteralArgHint || strings.ContainsAny(value, "{}") {
			continue
		}
		filtered[idx] = value
	}
	return filtered
}

func filterLiteralArgPathHintsForCallable(base callable, hints map[int]map[string]string) map[int]map[string]string {
	filtered := map[int]map[string]string{}
	for idx, pathHints := range hints {
		if idx < 0 || idx >= len(base.Params) || len(pathHints) == 0 {
			continue
		}
		entry := map[string]string{}
		for path, value := range pathHints {
			path = strings.TrimSpace(path)
			value = strings.TrimSpace(value)
			if path == "" || value == "" || value == conflictingLiteralArgHint || strings.ContainsAny(value, "{}") {
				continue
			}
			entry[path] = value
		}
		if len(entry) != 0 {
			filtered[idx] = entry
		}
	}
	return filtered
}

func (e *engine) existingSpecializedCallableForLiteralArgs(baseKey string, hints map[int]string) string {
	return e.existingSpecializedCallableForLiteralArgsAndPaths(baseKey, hints, nil)
}

func (e *engine) existingSpecializedCallableForLiteralArgsAndPaths(baseKey string, hints map[int]string, pathHints map[int]map[string]string) string {
	if baseKey == "" || (len(hints) == 0 && len(pathHints) == 0) {
		return baseKey
	}
	base, ok := e.callables[baseKey]
	if !ok || len(base.Params) == 0 {
		return baseKey
	}
	hintsKey := literalArgSpecializationKey(
		filterLiteralArgHintsForCallable(base, hints),
		filterLiteralArgPathHintsForCallable(base, pathHints),
	)
	if hintsKey == "" {
		return baseKey
	}
	if entries := e.specializedLiteralCallables[baseKey]; entries != nil {
		if key := entries[hintsKey]; key != "" {
			return key
		}
	}
	return baseKey
}

func (e *engine) maybeSpecializeMethodKeyForLiteralArgs(className string, methodName string, hints map[int]string) string {
	return e.maybeSpecializeMethodKeyForLiteralArgsAndPaths(className, methodName, hints, nil)
}

func (e *engine) maybeSpecializeMethodKeyForLiteralArgsAndPaths(className string, methodName string, hints map[int]string, pathHints map[int]map[string]string) string {
	key := e.lookupMethodKey(className, methodName)
	if key == "" {
		return ""
	}
	return e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
}

func (e *engine) maybeSpecializeRuntimeMethodKeyForLiteralArgs(className string, methodName string, hints map[int]string) string {
	return e.maybeSpecializeRuntimeMethodKeyForLiteralArgsAndPaths(className, methodName, hints, nil)
}

func (e *engine) maybeSpecializeRuntimeMethodKeyForLiteralArgsAndPaths(className string, methodName string, hints map[int]string, pathHints map[int]map[string]string) string {
	key := e.ensureRuntimeMethodCallable(className, methodName)
	if key == "" {
		return ""
	}
	if e.currentBatchName == "" && len(e.allowedSinkOps) == 1 && e.allowsSinkOp("output") {
		return e.maybeSpecializeOutputCallableForBuild(key, hints, pathHints)
	}
	return e.maybeSpecializeCallableForLiteralArgsAndPaths(key, hints, pathHints)
}

func (e *engine) addCallable(c callable) {
	e.callables[c.Key] = c
	e.callOrder = append(e.callOrder, c.Key)
	e.summaries[c.Key] = summary{ParamFindings: map[int][]sinkTemplate{}}
	if c.Class == "" {
		e.functions[normalizeName(c.Display)] = c.Key
		if !strings.HasPrefix(c.Display, `\`) {
			e.functions[normalizeName(`\`+c.Display)] = c.Key
		}
		return
	}
	methods := e.methods[c.Class]
	if methods == nil {
		methods = map[string]string{}
		e.methods[c.Class] = methods
	}
	methods[strings.ToLower(lastSegment(c.Display))] = c.Key
}

type parentLink struct {
	class  string
	parent string
}

type classLiteralProperty struct {
	class    string
	property string
	value    string
}

type classLiteralConst struct {
	class string
	name  string
	value string
}

type staticPropertyDecl struct {
	class    string
	property string
}

func collectScopeUseAliases(nodes []ast.Node, namespace string) map[string]string {
	out := map[string]string{}
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtUse:
			for _, rawUse := range typed.Uses {
				item, ok := rawUse.(*ast.UseItem)
				if !ok || !useItemIsClassLike(item.Type, typed.Type) {
					continue
				}
				alias, target := useItemAliasTarget(item, namespace)
				if alias == "" || target == "" {
					continue
				}
				out[alias] = target
			}
		case *ast.StmtGroupUse:
			prefix := strings.TrimSpace(identifierText(typed.Prefix))
			for _, rawUse := range typed.Uses {
				item, ok := rawUse.(*ast.UseItem)
				if !ok || !useItemIsClassLike(item.Type, typed.Type) {
					continue
				}
				name := strings.TrimPrefix(strings.TrimSpace(identifierText(item.Name)), `\`)
				if name == "" {
					continue
				}
				fullName := name
				if prefix != "" {
					fullName = strings.TrimPrefix(prefix, `\`) + `\` + name
				}
				alias := strings.ToLower(strings.TrimSpace(identifierText(item.Alias)))
				if alias == "" {
					alias = strings.ToLower(lastSegment(name))
				}
				out[alias] = qualifiedName("", fullName)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func useItemIsClassLike(itemType int, stmtType any) bool {
	if itemType != 0 && itemType != ast.StmtUseTypeUnknown && itemType != ast.StmtUseTypeNormal {
		return false
	}
	if stmt, ok := stmtType.(ast.Node); ok {
		if typed, ok := stmt.(*ast.Identifier); ok {
			value := strings.ToLower(strings.TrimSpace(identifierText(typed)))
			return value == "" || value == "use"
		}
	}
	if value, ok := stmtType.(int); ok {
		return value == ast.StmtUseTypeUnknown || value == ast.StmtUseTypeNormal
	}
	return true
}

func useItemAliasTarget(item *ast.UseItem, namespace string) (string, string) {
	if item == nil {
		return "", ""
	}
	name := strings.TrimPrefix(strings.TrimSpace(identifierText(item.Name)), `\`)
	if name == "" {
		return "", ""
	}
	alias := strings.ToLower(strings.TrimSpace(identifierText(item.Alias)))
	if alias == "" {
		alias = strings.ToLower(lastSegment(name))
	}
	return alias, qualifiedName("", name)
}

func topLevelCallable(file sourceFile) []callable {
	return collectTopLevelCallables(file.AST, "", file.Relative, true, nil)
}

func collectTopLevelCallables(nodes []ast.Node, namespace string, relative string, allowBareKey bool, useAliases map[string]string) []callable {
	out := make([]callable, 0)
	stmts := make([]ast.Node, 0)
	useAliases = mergeStringMaps(useAliases, collectScopeUseAliases(nodes, namespace))
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			out = append(out, collectTopLevelCallables(typed.Stmts, namespaceString(typed.Name), relative, false, nil)...)
		case *ast.StmtFunction, *ast.StmtClass:
		default:
			stmts = append(stmts, stmt)
		}
	}
	if len(stmts) == 0 {
		return out
	}
	key := "file::" + relative
	if namespace != "" && !allowBareKey {
		key = key + "::" + namespace
	}
	entry := callable{
		Key:        key,
		Display:    key,
		SourcePath: relative,
		StartLine:  1,
		Namespace:  namespace,
		UseAliases: cloneStringMap(useAliases),
		Params:     nil,
		Stmts:      stmts,
	}
	entry.HasDirectReturnHintCandidate = directReturnHintCandidateCallable(entry)
	return append([]callable{entry}, out...)
}

func collectFunctionCallables(nodes []ast.Node, namespace string, relative string, useAliases map[string]string) []callable {
	out := make([]callable, 0)
	useAliases = mergeStringMaps(useAliases, collectScopeUseAliases(nodes, namespace))
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			out = append(out, collectFunctionCallables(typed.Stmts, namespaceString(typed.Name), relative, nil)...)
		case *ast.StmtFunction:
			name := qualifiedName(namespace, identifierText(typed.Name))
			item := callable{
				Key:        "function::" + name,
				Display:    name,
				SourcePath: relative,
				StartLine:  typed.StartLine(),
				Namespace:  namespace,
				UseAliases: cloneStringMap(useAliases),
				Params:     extractParams(typed.Params),
				ParamTypes: extractParamTypes(typed.Params, namespace, "", useAliases),
				Stmts:      typed.Stmts,
			}
			item.HasDirectReturnHintCandidate = directReturnHintCandidateCallable(item)
			out = append(out, item)
		default:
			for _, block := range childStatementBlocks(stmt) {
				out = append(out, collectFunctionCallables(block, namespace, relative, useAliases)...)
			}
		}
	}
	return out
}

func collectMethodCallables(nodes []ast.Node, namespace string, relative string, useAliases map[string]string) []callable {
	out := make([]callable, 0)
	useAliases = mergeStringMaps(useAliases, collectScopeUseAliases(nodes, namespace))
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			out = append(out, collectMethodCallables(typed.Stmts, namespaceString(typed.Name), relative, nil)...)
		case *ast.StmtClass:
			className := qualifiedName(namespace, identifierText(typed.Name))
			for _, classStmt := range typed.Stmts {
				method, ok := classStmt.(*ast.StmtClassMethod)
				if !ok {
					continue
				}
				name := identifierText(method.Name)
				item := callable{
					Key:        "method::" + className + "::" + name,
					Display:    className + "::" + name,
					SourcePath: relative,
					StartLine:  method.StartLine(),
					Class:      className,
					Namespace:  namespace,
					UseAliases: cloneStringMap(useAliases),
					Static:     method.Flags&phpparser.ModifierStatic != 0,
					Params:     extractParams(method.Params),
					ParamTypes: extractParamTypes(method.Params, namespace, className, useAliases),
					Stmts:      method.Stmts,
				}
				item.HasDirectReturnHintCandidate = directReturnHintCandidateCallable(item)
				out = append(out, item)
			}
		default:
			for _, block := range childStatementBlocks(stmt) {
				out = append(out, collectMethodCallables(block, namespace, relative, useAliases)...)
			}
		}
	}
	return out
}

func collectClassParents(nodes []ast.Node, namespace string, relative string, useAliases map[string]string) []parentLink {
	out := make([]parentLink, 0)
	useAliases = mergeStringMaps(useAliases, collectScopeUseAliases(nodes, namespace))
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			out = append(out, collectClassParents(typed.Stmts, namespaceString(typed.Name), relative, nil)...)
		case *ast.StmtClass:
			className := qualifiedName(namespace, identifierText(typed.Name))
			parentName := resolveClassNameWithAliases(typed.Extends, className, nil, useAliases)
			if parentName != "" {
				out = append(out, parentLink{class: className, parent: parentName})
			}
		default:
			for _, block := range childStatementBlocks(stmt) {
				out = append(out, collectClassParents(block, namespace, relative, useAliases)...)
			}
		}
	}
	return out
}

func collectClassLiteralProperties(nodes []ast.Node, namespace string, relative string) []classLiteralProperty {
	out := make([]classLiteralProperty, 0)
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			out = append(out, collectClassLiteralProperties(typed.Stmts, namespaceString(typed.Name), relative)...)
		case *ast.StmtClass:
			className := qualifiedName(namespace, identifierText(typed.Name))
			for _, classStmt := range typed.Stmts {
				propertyStmt, ok := classStmt.(*ast.StmtProperty)
				if !ok {
					continue
				}
				for _, propNode := range propertyStmt.Props {
					prop, ok := propNode.(*ast.PropertyItem)
					if !ok {
						continue
					}
					name := strings.ToLower(identifierText(prop.Name))
					value := strings.TrimSpace(literalString(prop.Default))
					if name == "" || value == "" {
						continue
					}
					out = append(out, classLiteralProperty{
						class:    className,
						property: name,
						value:    value,
					})
				}
			}
		default:
			for _, block := range childStatementBlocks(stmt) {
				out = append(out, collectClassLiteralProperties(block, namespace, relative)...)
			}
		}
	}
	return out
}

func (e *engine) indexLiteralStaticPropertyAssignments(nodes []ast.Node, namespace string, currentClass string, relative string) bool {
	changed := false
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			if e.indexLiteralStaticPropertyAssignments(typed.Stmts, namespaceString(typed.Name), currentClass, relative) {
				changed = true
			}
		case *ast.StmtClass:
			className := qualifiedName(namespace, identifierText(typed.Name))
			if e.indexLiteralStaticPropertyAssignments(typed.Stmts, namespace, className, relative) {
				changed = true
			}
		case *ast.StmtExpression:
			if e.indexLiteralStaticPropertyAssignExpr(typed.Expr, currentClass, relative) {
				changed = true
			}
		default:
			for _, block := range childStatementBlocks(stmt) {
				if e.indexLiteralStaticPropertyAssignments(block, namespace, currentClass, relative) {
					changed = true
				}
			}
		}
	}
	return changed
}

func (e *engine) indexLiteralStaticPropertyAssignExpr(expr ast.Node, currentClass string, relative string) bool {
	var target ast.Node
	var valueNode ast.Node
	switch typed := expr.(type) {
	case *ast.ExprAssign:
		target = typed.Var
		valueNode = typed.Expr
	case *ast.ExprAssignRef:
		target = typed.Var
		valueNode = typed.Expr
	default:
		return false
	}
	staticFetch, ok := target.(*ast.ExprStaticPropertyFetch)
	if !ok {
		return false
	}
	property := strings.ToLower(strings.TrimSpace(identifierText(staticFetch.Name)))
	if property == "" {
		return false
	}
	className := resolveClassName(staticFetch.Class, currentClass, e.classParents)
	className = e.resolveStaticPropertyOwner(className, property)
	if className == "" {
		return false
	}
	value := strings.TrimSpace(literalConstExprWithSource(valueNode, namespaceForClassName(className), className, relative, e))
	if value == "" {
		return false
	}
	key := className + "." + property
	if existing := e.literalClassProperties[key]; existing == value {
		return false
	}
	e.indexLiteralClass(className, property, value)
	return true
}

func collectClassLiteralConsts(nodes []ast.Node, namespace string, relative string) []classLiteralConst {
	out := make([]classLiteralConst, 0)
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			out = append(out, collectClassLiteralConsts(typed.Stmts, namespaceString(typed.Name), relative)...)
		case *ast.StmtClass:
			className := qualifiedName(namespace, identifierText(typed.Name))
			for _, classStmt := range typed.Stmts {
				constStmt, ok := classStmt.(*ast.StmtClassConst)
				if !ok {
					continue
				}
				for _, rawConst := range constStmt.Consts {
					item, ok := rawConst.(*ast.Const)
					if !ok {
						continue
					}
					name := strings.ToLower(strings.TrimSpace(identifierText(item.Name)))
					value := strings.TrimSpace(literalString(item.Value))
					if name == "" || value == "" {
						continue
					}
					out = append(out, classLiteralConst{
						class: className,
						name:  name,
						value: value,
					})
				}
			}
		default:
			for _, block := range childStatementBlocks(stmt) {
				out = append(out, collectClassLiteralConsts(block, namespace, relative)...)
			}
		}
	}
	return out
}

func collectStaticPropertyDecls(nodes []ast.Node, namespace string, relative string) []staticPropertyDecl {
	out := make([]staticPropertyDecl, 0)
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			out = append(out, collectStaticPropertyDecls(typed.Stmts, namespaceString(typed.Name), relative)...)
		case *ast.StmtClass:
			className := qualifiedName(namespace, identifierText(typed.Name))
			for _, classStmt := range typed.Stmts {
				propertyStmt, ok := classStmt.(*ast.StmtProperty)
				if !ok || propertyStmt.Flags&phpparser.ModifierStatic == 0 {
					continue
				}
				for _, propNode := range propertyStmt.Props {
					prop, ok := propNode.(*ast.PropertyItem)
					if !ok {
						continue
					}
					name := strings.ToLower(identifierText(prop.Name))
					if name == "" {
						continue
					}
					out = append(out, staticPropertyDecl{
						class:    className,
						property: name,
					})
				}
			}
		default:
			for _, block := range childStatementBlocks(stmt) {
				out = append(out, collectStaticPropertyDecls(block, namespace, relative)...)
			}
		}
	}
	return out
}

func extractParams(params []ast.Node) []string {
	out := make([]string, 0, len(params))
	for _, item := range params {
		param, ok := item.(*ast.Param)
		if !ok {
			continue
		}
		variable, ok := param.Var.(*ast.ExprVariable)
		if !ok {
			continue
		}
		name, ok := variable.Name.(string)
		if !ok || name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func extractParamTypes(params []ast.Node, namespace string, className string, useAliases map[string]string) map[string]string {
	out := map[string]string{}
	scopeClass := className
	if scopeClass == "" && strings.TrimSpace(namespace) != "" {
		scopeClass = qualifiedName(namespace, "__param_scope")
	}
	for _, item := range params {
		param, ok := item.(*ast.Param)
		if !ok {
			continue
		}
		variable, ok := param.Var.(*ast.ExprVariable)
		if !ok {
			continue
		}
		name, ok := variable.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		classRef := resolveClassNameWithAliases(param.Type, scopeClass, nil, useAliases)
		if classRef == "" {
			continue
		}
		out[strings.TrimSpace(name)] = classRef
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (e *engine) indexLiteralClass(className string, property string, value string) {
	if className == "" || property == "" || value == "" {
		return
	}
	e.literalClassProperties[className+"."+property] = value
	key := property + "=" + value
	for _, existing := range e.literalClassIndex[key] {
		if existing == className {
			return
		}
	}
	e.literalClassIndex[key] = append(e.literalClassIndex[key], className)
}

func (e *engine) literalClassPropertyValue(className string, property string) string {
	className = strings.TrimSpace(className)
	property = strings.ToLower(strings.TrimSpace(property))
	if className == "" || property == "" {
		return ""
	}
	for current := className; current != ""; current = e.classParents[current] {
		if value := strings.TrimSpace(e.literalClassProperties[current+"."+property]); value != "" {
			return value
		}
	}
	return ""
}

func (e *engine) inferLiteralFactoryReturnClass(methodName string, args []ast.Node) string {
	name := normalizeName(methodName)
	if len(args) == 0 {
		return ""
	}
	if name == "acf_get_instance" || name == "acf_new_instance" {
		literal := strings.TrimSpace(literalString(argValue(args[0])))
		if literal == "" {
			return ""
		}
		return qualifiedName("", literal)
	}
	if name == "acfe_get_module" {
		literal := strings.TrimSpace(literalString(argValue(args[0])))
		if literal == "" {
			return ""
		}
		return qualifiedName("", "acfe_module_"+literal)
	}
	if name == "getclass" {
		literal := strings.TrimSpace(literalString(argValue(args[0])))
		if literal == "" {
			return ""
		}
		return qualifiedName("", literal)
	}
	if !looksLikeLiteralFactory(methodName) {
		return ""
	}
	literal := strings.ToLower(strings.TrimSpace(literalString(argValue(args[0]))))
	if literal == "" {
		return ""
	}
	for _, property := range preferredFactoryProperties(methodName) {
		candidates := e.literalClassIndex[property+"="+literal]
		if picked := pickFactoryCandidate(candidates, literal); picked != "" {
			return picked
		}
	}
	return ""
}

func (e *engine) indexLiteralClassConst(className string, constName string, value string) {
	if className == "" || constName == "" || value == "" {
		return
	}
	e.literalClassConsts[className+"::"+strings.ToLower(constName)] = value
}

func normalizeGlobalConstName(name string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, `\`)))
}

func (e *engine) indexLiteralGlobalConst(name string, value string) bool {
	name = normalizeGlobalConstName(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return false
	}
	if existing := strings.TrimSpace(e.literalGlobalConsts[name]); existing == value {
		return false
	}
	e.literalGlobalConsts[name] = value
	return true
}

func (e *engine) literalGlobalConstValue(name string) string {
	name = normalizeGlobalConstName(name)
	if name == "" {
		return ""
	}
	return strings.TrimSpace(e.literalGlobalConsts[name])
}

func (e *engine) literalClassConstValue(className string, constName string) string {
	if className == "" || constName == "" {
		return ""
	}
	return strings.TrimSpace(e.literalClassConsts[className+"::"+strings.ToLower(constName)])
}

func (e *engine) indexLiteralGlobalConsts(nodes []ast.Node, namespace string, sourcePath string) bool {
	changed := false
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			if e.indexLiteralGlobalConsts(typed.Stmts, namespaceString(typed.Name), sourcePath) {
				changed = true
			}
		case *ast.StmtConst:
			for _, rawConst := range typed.Consts {
				item, ok := rawConst.(*ast.Const)
				if !ok {
					continue
				}
				name := qualifiedName(namespace, identifierText(item.Name))
				value := literalConstExprWithSource(item.Value, namespace, "", sourcePath, e)
				if e.indexLiteralGlobalConst(name, value) {
					changed = true
				}
			}
		case *ast.StmtExpression:
			call, ok := typed.Expr.(*ast.ExprFuncCall)
			if !ok || !strings.EqualFold(identifierText(call.Name), "define") || len(call.Args) < 2 {
				continue
			}
			name := literalConstExprWithSource(argValue(call.Args[0]), namespace, "", sourcePath, e)
			value := literalConstExprWithSource(argValue(call.Args[1]), namespace, "", sourcePath, e)
			if e.indexLiteralGlobalConst(name, value) {
				changed = true
			}
		case *ast.StmtClass, *ast.StmtFunction:
			continue
		default:
			for _, block := range childStatementBlocks(stmt) {
				if e.indexLiteralGlobalConsts(block, namespace, sourcePath) {
					changed = true
				}
			}
		}
	}
	return changed
}

func (e *engine) indexLiteralClassConsts(nodes []ast.Node, namespace string, sourcePath string) bool {
	changed := false
	for _, stmt := range nodes {
		switch typed := stmt.(type) {
		case *ast.StmtNamespace:
			if e.indexLiteralClassConsts(typed.Stmts, namespaceString(typed.Name), sourcePath) {
				changed = true
			}
		case *ast.StmtClass:
			className := qualifiedName(namespace, identifierText(typed.Name))
			for _, classStmt := range typed.Stmts {
				constStmt, ok := classStmt.(*ast.StmtClassConst)
				if !ok {
					continue
				}
				for _, rawConst := range constStmt.Consts {
					item, ok := rawConst.(*ast.Const)
					if !ok {
						continue
					}
					name := strings.ToLower(strings.TrimSpace(identifierText(item.Name)))
					value := literalConstExprWithSource(item.Value, namespace, className, sourcePath, e)
					if className == "" || name == "" || value == "" {
						continue
					}
					key := className + "::" + name
					if existing := strings.TrimSpace(e.literalClassConsts[key]); existing == value {
						continue
					}
					e.literalClassConsts[key] = value
					changed = true
				}
			}
		}
	}
	return changed
}

func singletonFactoryReturnClass(methodName string, className string) string {
	if className == "" {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(methodName)) {
	case "get_instance", "getinstance", "instance":
		return className
	default:
		return ""
	}
}

func looksLikeLiteralFactory(methodName string) bool {
	name := strings.ToLower(strings.TrimSpace(methodName))
	if name == "" {
		return false
	}
	if strings.Contains(name, "object") || strings.Contains(name, "factory") {
		return true
	}
	return strings.HasPrefix(name, "create") || strings.HasPrefix(name, "make") || strings.HasPrefix(name, "build")
}

func preferredFactoryProperties(methodName string) []string {
	name := strings.ToLower(strings.TrimSpace(methodName))
	switch {
	case strings.Contains(name, "field"):
		return []string{"slug", "type", "name"}
	case strings.Contains(name, "type"):
		return []string{"type", "slug", "name"}
	default:
		return []string{"slug", "type", "name", "key", "id"}
	}
}

func pickFactoryCandidate(candidates []string, literal string) string {
	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	token := normalizeFactoryToken(literal)
	filtered := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		short := normalizeFactoryToken(shortClassName(candidate))
		if short == token || strings.Contains(short, token) {
			filtered = append(filtered, candidate)
		}
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	return ""
}

func normalizeFactoryToken(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
}

func shortClassName(className string) string {
	className = strings.TrimPrefix(className, `\`)
	if idx := strings.LastIndex(className, `\`); idx >= 0 {
		return className[idx+1:]
	}
	return className
}
