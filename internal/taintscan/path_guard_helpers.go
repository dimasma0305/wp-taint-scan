package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (s *analysisState) clearPathSafetyForAssignmentTarget(target ast.Node) {
	variable, ok := target.(*ast.ExprVariable)
	if !ok {
		return
	}
	name, ok := variable.Name.(string)
	if !ok || name == "" {
		return
	}
	if sig, ok := s.varPathExprSig[name]; ok && sig != "" {
		delete(s.safePathExprSigs, sig)
	}
	delete(s.safePathVars, name)
	delete(s.varPathExprSig, name)
}

func (s *analysisState) trackPathExprAssignment(target ast.Node, expr ast.Node) {
	s.clearPathSafetyForAssignmentTarget(target)
	variable, ok := target.(*ast.ExprVariable)
	if !ok {
		return
	}
	name, ok := variable.Name.(string)
	if !ok || name == "" {
		return
	}
	if sig := pathExprSignature(expr, s.current, s.engine); sig != "" {
		s.varPathExprSig[name] = sig
	}
}

func (s *analysisState) markCanonicalPathVariable(name string) {
	if name == "" {
		return
	}
	s.safePathVars[name] = struct{}{}
	if sig := s.varPathExprSig[name]; sig != "" {
		s.safePathExprSigs[sig] = struct{}{}
	}
}

func (s *analysisState) filterPathSinkOrigins(expr ast.Node, origins originSet) originSet {
	if len(origins) == 0 {
		return origins
	}
	if s.pathExprIsCanonical(expr) || pathOriginsAreSafe(origins) {
		return originSet{}
	}
	return origins
}

func (s *analysisState) filterReplayedSinkOrigins(ruleID string, origins originSet) originSet {
	if len(origins) == 0 {
		return origins
	}
	switch ruleID {
	case "path-transversal", "request-path-read-delete":
		if pathOriginsAreSafe(origins) {
			return originSet{}
		}
	case "wp-stored-xss-persistent-read-to-output":
		return unsafePersistentReadOrigins(origins)
	}
	return origins
}

func pathOriginsAreSafe(origins originSet) bool {
	if len(origins) == 0 {
		return false
	}
	for _, item := range origins {
		if !item.pathSafe {
			return false
		}
	}
	return true
}

func (s *analysisState) pathExprIsCanonical(expr ast.Node) bool {
	if expr == nil {
		return false
	}
	if variable, ok := expr.(*ast.ExprVariable); ok {
		if name, ok := variable.Name.(string); ok {
			if _, ok := s.safePathVars[name]; ok {
				return true
			}
		}
	}
	if sig := pathExprSignature(expr, s.current, s.engine); sig != "" {
		_, ok := s.safePathExprSigs[sig]
		return ok
	}
	return false
}

func (s *analysisState) canonicalPathVariablesForTrueBranch(cond ast.Node) map[string]struct{} {
	out := map[string]struct{}{}
	if name, ok := positiveCanonicalRealpathGuardVariable(cond); ok {
		out[name] = struct{}{}
	}
	for name := range guardedVariableNamesForPathCondition(cond) {
		if !strings.HasPrefix(s.varPathExprSig[name], "realpath(") {
			continue
		}
		kinds, ok := s.positivePathGuardKindsForCondition(cond, name)
		if !ok {
			continue
		}
		if kinds.exists && kinds.trustedPrefix {
			out[name] = struct{}{}
		}
	}
	return out
}

func (e *engine) pathSanitizingReturnParamIndex(key string) (int, bool) {
	if key == "" {
		return 0, false
	}
	e.pathSanitizerMu.RLock()
	if e.pathSanitizerCache != nil {
		if item, ok := e.pathSanitizerCache[key]; ok {
			e.pathSanitizerMu.RUnlock()
			return item.ParamIdx, item.OK
		}
	}
	e.pathSanitizerMu.RUnlock()
	callable, ok := e.callables[key]
	if !ok {
		return 0, false
	}
	item := detectPathSanitizingReturnParam(callable)
	e.pathSanitizerMu.Lock()
	if e.pathSanitizerCache == nil {
		e.pathSanitizerCache = map[string]pathSanitizerInfo{}
	}
	e.pathSanitizerCache[key] = item
	e.pathSanitizerMu.Unlock()
	return item.ParamIdx, item.OK
}

func detectPathSanitizingReturnParam(c callable) pathSanitizerInfo {
	guarded := map[string]pathGuardKinds{}
	for _, stmt := range c.Stmts {
		ifStmt, ok := stmt.(*ast.StmtIf)
		if !ok || ifStmt.Else != nil || len(ifStmt.Elseifs) != 0 || !branchDefinitelyAborts(ifStmt.Stmts) {
			continue
		}
		if name, kinds := abortingPathGuardKindsForCondition(ifStmt.Cond); name != "" {
			guarded[name] = guarded[name].merge(kinds)
		}
	}
	for _, stmt := range c.Stmts {
		ret, ok := stmt.(*ast.StmtReturn)
		if !ok {
			continue
		}
		variable, ok := ret.Expr.(*ast.ExprVariable)
		if !ok {
			continue
		}
		name, ok := variable.Name.(string)
		if !ok || name == "" {
			continue
		}
		kinds := guarded[name]
		if kinds.forbiddenToken && kinds.exists {
			for idx, param := range c.Params {
				if param == name {
					return pathSanitizerInfo{ParamIdx: idx, OK: true}
				}
			}
		}
	}
	return pathSanitizerInfo{ParamIdx: -1}
}

type pathGuardKinds struct {
	forbiddenToken bool
	exists         bool
	trustedPrefix  bool
}

func (k pathGuardKinds) merge(next pathGuardKinds) pathGuardKinds {
	return pathGuardKinds{
		forbiddenToken: k.forbiddenToken || next.forbiddenToken,
		exists:         k.exists || next.exists,
		trustedPrefix:  k.trustedPrefix || next.trustedPrefix,
	}
}

func (s *analysisState) positivePathGuardKindsForCondition(node ast.Node, name string) (pathGuardKinds, bool) {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		varName, ok := typed.Name.(string)
		if !ok || varName != name {
			return pathGuardKinds{}, false
		}
		return pathGuardKinds{}, true
	case *ast.ExprBinaryOpBooleanAnd:
		left, ok := s.positivePathGuardKindsForCondition(typed.Left, name)
		if !ok {
			return pathGuardKinds{}, false
		}
		right, ok := s.positivePathGuardKindsForCondition(typed.Right, name)
		if !ok {
			return pathGuardKinds{}, false
		}
		return left.merge(right), true
	case *ast.ExprFuncCall:
		switch normalizeName(identifierText(typed.Name)) {
		case "file_exists", "is_file", "is_dir":
			if len(typed.Args) == 0 || !variableMatchesArg(name, typed.Args[0]) {
				return pathGuardKinds{}, false
			}
			return pathGuardKinds{exists: true}, true
		case "str_starts_with":
			if len(typed.Args) < 2 || !variableMatchesArg(name, typed.Args[0]) {
				return pathGuardKinds{}, false
			}
			if !s.isTrustedPathRootExpr(argValue(typed.Args[1])) {
				return pathGuardKinds{}, false
			}
			return pathGuardKinds{trustedPrefix: true}, true
		}
	case *ast.ExprBinaryOpIdentical:
		if kinds, ok := s.positiveTrustedPrefixGuardVarPair(typed.Left, typed.Right, name); ok {
			return kinds, true
		}
	case *ast.ExprBinaryOpEqual:
		if kinds, ok := s.positiveTrustedPrefixGuardVarPair(typed.Left, typed.Right, name); ok {
			return kinds, true
		}
	}
	return pathGuardKinds{}, false
}

func (s *analysisState) positiveTrustedPrefixGuardVarPair(left, right ast.Node, name string) (pathGuardKinds, bool) {
	if literalInt(left) == 0 {
		if s.callIsTrustedPrefixCheck(right, name) {
			return pathGuardKinds{trustedPrefix: true}, true
		}
	}
	if literalInt(right) == 0 {
		if s.callIsTrustedPrefixCheck(left, name) {
			return pathGuardKinds{trustedPrefix: true}, true
		}
	}
	return pathGuardKinds{}, false
}

func (s *analysisState) callIsTrustedPrefixCheck(node ast.Node, name string) bool {
	call, ok := node.(*ast.ExprFuncCall)
	if !ok {
		return false
	}
	funcName := normalizeName(identifierText(call.Name))
	switch funcName {
	case "strpos", "stripos":
		if len(call.Args) < 2 || !variableMatchesArg(name, call.Args[0]) {
			return false
		}
		return s.isTrustedPathRootExpr(argValue(call.Args[1]))
	}
	return false
}

func (s *analysisState) isTrustedPathRootExpr(node ast.Node) bool {
	if node == nil {
		return false
	}
	if len(s.evalExpr(node)) != 0 {
		return false
	}
	literal := strings.TrimSpace(literalStringForCallableWithSeen(node, s.current, s.engine, map[string]struct{}{}))
	return looksLikeTrustedFilesystemRootLiteral(literal)
}

func looksLikeTrustedFilesystemRootLiteral(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		return false
	}
	if strings.ContainsRune(value, 0) {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return countNonEmptyPathSegments(value) >= 2
	}
	if looksLikeWindowsAbsolutePath(value) {
		return countNonEmptyPathSegments(value[3:]) >= 1
	}
	return false
}

func looksLikeWindowsAbsolutePath(value string) bool {
	if len(value) < 4 {
		return false
	}
	drive := value[0]
	if !((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) {
		return false
	}
	if value[1] != ':' {
		return false
	}
	return value[2] == '\\' || value[2] == '/'
}

func countNonEmptyPathSegments(value string) int {
	count := 0
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if strings.TrimSpace(part) == "" {
			continue
		}
		count++
	}
	return count
}

func abortingPathGuardKindsForCondition(cond ast.Node) (string, pathGuardKinds) {
	names := guardedVariableNamesForPathCondition(cond)
	if len(names) != 1 {
		return "", pathGuardKinds{}
	}
	for name := range names {
		return name, pathGuardKinds{
			forbiddenToken: conditionHasForbiddenPathTokenCheck(cond, name),
			exists:         conditionHasPathExistenceCheck(cond, name),
		}
	}
	return "", pathGuardKinds{}
}

func guardedVariableNamesForPathCondition(node ast.Node) map[string]struct{} {
	out := map[string]struct{}{}
	collectGuardedVariableNamesForPathCondition(node, out)
	return out
}

func collectGuardedVariableNamesForPathCondition(node ast.Node, out map[string]struct{}) {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok && name != "" {
			out[name] = struct{}{}
		}
	case *ast.ExprBooleanNot:
		collectGuardedVariableNamesForPathCondition(typed.Expr, out)
	case *ast.ExprBinaryOpBooleanOr:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpBooleanAnd:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpEqual:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpNotEqual:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpIdentical:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpNotIdentical:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpGreater:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpGreaterOrEqual:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpSmaller:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprBinaryOpSmallerOrEqual:
		collectGuardedVariableNamesForPathCondition(typed.Left, out)
		collectGuardedVariableNamesForPathCondition(typed.Right, out)
	case *ast.ExprFuncCall:
		switch normalizeName(identifierText(typed.Name)) {
		case "strpos", "stripos", "str_contains", "file_exists", "is_dir", "is_string", "strlen":
			if len(typed.Args) > 0 {
				if variable, ok := argValue(typed.Args[0]).(*ast.ExprVariable); ok {
					if name, ok := variable.Name.(string); ok && name != "" {
						out[name] = struct{}{}
					}
				}
			}
		}
	}
}

func conditionHasForbiddenPathTokenCheck(node ast.Node, name string) bool {
	switch typed := node.(type) {
	case *ast.ExprBooleanNot:
		return conditionHasForbiddenPathTokenCheck(typed.Expr, name)
	case *ast.ExprBinaryOpBooleanOr:
		return conditionHasForbiddenPathTokenCheck(typed.Left, name) || conditionHasForbiddenPathTokenCheck(typed.Right, name)
	case *ast.ExprBinaryOpBooleanAnd:
		return conditionHasForbiddenPathTokenCheck(typed.Left, name) || conditionHasForbiddenPathTokenCheck(typed.Right, name)
	case *ast.ExprBinaryOpEqual:
		return conditionHasForbiddenPathTokenCheck(typed.Left, name) || conditionHasForbiddenPathTokenCheck(typed.Right, name)
	case *ast.ExprBinaryOpNotEqual:
		return conditionHasForbiddenPathTokenCheck(typed.Left, name) || conditionHasForbiddenPathTokenCheck(typed.Right, name)
	case *ast.ExprBinaryOpIdentical:
		return conditionHasForbiddenPathTokenCheck(typed.Left, name) || conditionHasForbiddenPathTokenCheck(typed.Right, name)
	case *ast.ExprBinaryOpNotIdentical:
		return conditionHasForbiddenPathTokenCheck(typed.Left, name) || conditionHasForbiddenPathTokenCheck(typed.Right, name)
	case *ast.ExprFuncCall:
		funcName := normalizeName(identifierText(typed.Name))
		switch funcName {
		case "strpos", "stripos":
			if len(typed.Args) < 2 {
				return false
			}
			return variableMatchesArg(name, typed.Args[0]) && literalContainsForbiddenPathToken(argValue(typed.Args[1]))
		case "str_contains":
			if len(typed.Args) < 2 {
				return false
			}
			return variableMatchesArg(name, typed.Args[0]) && literalContainsForbiddenPathToken(argValue(typed.Args[1]))
		}
	}
	return false
}

func conditionHasPathExistenceCheck(node ast.Node, name string) bool {
	switch typed := node.(type) {
	case *ast.ExprBooleanNot:
		return conditionHasPathExistenceCheck(typed.Expr, name)
	case *ast.ExprBinaryOpBooleanOr:
		return conditionHasPathExistenceCheck(typed.Left, name) || conditionHasPathExistenceCheck(typed.Right, name)
	case *ast.ExprBinaryOpBooleanAnd:
		return conditionHasPathExistenceCheck(typed.Left, name) || conditionHasPathExistenceCheck(typed.Right, name)
	case *ast.ExprFuncCall:
		funcName := normalizeName(identifierText(typed.Name))
		if (funcName == "file_exists" || funcName == "is_dir") && len(typed.Args) > 0 {
			return variableMatchesArg(name, typed.Args[0])
		}
	}
	return false
}

func variableMatchesArg(name string, raw ast.Node) bool {
	variable, ok := argValue(raw).(*ast.ExprVariable)
	if !ok {
		return false
	}
	varName, ok := variable.Name.(string)
	return ok && varName == name
}

func literalContainsForbiddenPathToken(node ast.Node) bool {
	value := strings.ToLower(literalString(node))
	if value == "" {
		return false
	}
	switch {
	case strings.Contains(value, "php:"):
		return true
	case strings.Contains(value, "://"):
		return true
	case strings.Contains(value, ".."):
		return true
	case strings.Contains(value, "|"):
		return true
	case strings.Contains(value, "\x00"), strings.Contains(value, "%00"):
		return true
	default:
		return false
	}
}

func canonicalRealpathGuardVariable(cond ast.Node) (string, bool) {
	switch typed := cond.(type) {
	case *ast.ExprBinaryOpNotIdentical:
		return canonicalRealpathGuardVarPair(typed.Left, typed.Right)
	case *ast.ExprBinaryOpNotEqual:
		return canonicalRealpathGuardVarPair(typed.Left, typed.Right)
	default:
		return "", false
	}
}

func positiveCanonicalRealpathGuardVariable(cond ast.Node) (string, bool) {
	switch typed := cond.(type) {
	case *ast.ExprBinaryOpIdentical:
		return canonicalRealpathGuardVarPair(typed.Left, typed.Right)
	case *ast.ExprBinaryOpEqual:
		return canonicalRealpathGuardVarPair(typed.Left, typed.Right)
	default:
		return "", false
	}
}

func canonicalRealpathGuardVarPair(left, right ast.Node) (string, bool) {
	if name, ok := variableComparedToRealpath(left, right); ok {
		return name, true
	}
	return variableComparedToRealpath(right, left)
}

func variableComparedToRealpath(variableNode, realpathNode ast.Node) (string, bool) {
	variable, ok := variableNode.(*ast.ExprVariable)
	if !ok {
		return "", false
	}
	name, ok := variable.Name.(string)
	if !ok || name == "" {
		return "", false
	}
	call, ok := realpathNode.(*ast.ExprFuncCall)
	if !ok || normalizeName(identifierText(call.Name)) != "realpath" || len(call.Args) != 1 {
		return "", false
	}
	argVar, ok := argValue(call.Args[0]).(*ast.ExprVariable)
	if !ok {
		return "", false
	}
	argName, ok := argVar.Name.(string)
	if !ok || argName != name {
		return "", false
	}
	return name, true
}

func branchDefinitelyAborts(stmts []ast.Node) bool {
	for i := len(stmts) - 1; i >= 0; i-- {
		switch typed := stmts[i].(type) {
		case *ast.StmtNop:
			continue
		case *ast.StmtContinue, *ast.StmtBreak, *ast.StmtReturn, *ast.ExprThrow:
			return true
		case *ast.StmtExpression:
			_, ok := typed.Expr.(*ast.ExprExit)
			return ok
		default:
			return false
		}
	}
	return false
}

func pathExprSignature(node ast.Node, current callable, e *engine) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || name == "" {
			return ""
		}
		return "$" + name
	case *ast.ExprArrayDimFetch:
		base := ""
		if name, ok := superglobalArrayRootName(typed.Var); ok {
			base = "$" + strings.ToLower(name)
		} else {
			base = pathExprSignature(typed.Var, current, e)
		}
		if base == "" {
			return ""
		}
		return appendArrayPath(base, typed.Dim)
	case *ast.ScalarString:
		return "str:" + typed.Value
	case *ast.ExprConstFetch:
		name := normalizeName(identifierText(typed.Name))
		if name == "" {
			return ""
		}
		if value := e.literalGlobalConstValue(name); value != "" {
			return "constv:" + value
		}
		return "const:" + name
	case *ast.ExprBinaryOpConcat:
		left := pathExprSignature(typed.Left, current, e)
		right := pathExprSignature(typed.Right, current, e)
		if left == "" || right == "" {
			return ""
		}
		return "concat(" + left + "," + right + ")"
	case *ast.ExprFuncCall:
		name := normalizeName(identifierText(typed.Name))
		if name != "realpath" || len(typed.Args) != 1 {
			return ""
		}
		arg := pathExprSignature(argValue(typed.Args[0]), current, e)
		if arg == "" {
			return ""
		}
		return "realpath(" + arg + ")"
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, current.Class); ok {
			return "prop:" + strings.ToLower(path)
		}
		return ""
	case *ast.ExprStaticPropertyFetch:
		if path, ok := staticPropertyPathKey(typed, current.Class, e); ok {
			return "static:" + strings.ToLower(path)
		}
		return ""
	default:
		return ""
	}
}
