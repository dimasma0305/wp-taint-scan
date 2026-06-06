package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (e *engine) callableHasPublicOAuthCallbackAuthSurfaceSink(c callable) bool {
	if !e.allowsSinkOp("surface") {
		return false
	}
	if !entrypointListHasPublicOAuthCallbackEntry(e.directEntryPointsByCallable[c.Key]) {
		return false
	}
	state := &analysisState{
		engine:  e,
		current: c,
	}
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		call, ok := node.(*ast.ExprMethodCall)
		if !ok {
			return
		}
		if !oauthCallbackNameLike(c.Display) && !oauthCallbackNameLike(identifierText(call.Name)) {
			return
		}
		if callableHasUsersCanRegisterGuardBeforeLine(c, call.StartLine()) {
			return
		}
		if _, ok := oauthCallbackRequestSourceNode(c, call.StartLine()); !ok {
			return
		}
		_, found = state.authCookieSinkForMethodCall(call)
	})
	return found
}

func (s *analysisState) addPublicOAuthCallbackAuthSurfaceFindingForMethodCall(call *ast.ExprMethodCall) {
	if call == nil || !s.engine.allowsSinkOp("surface") {
		return
	}
	if !entrypointListHasPublicOAuthCallbackEntry(s.engine.directEntryPointsByCallable[s.current.Key]) {
		return
	}
	ctx := s.currentContext()
	if !oauthCallbackNameLike(s.current.Display) && !oauthCallbackNameLike(identifierText(call.Name)) {
		return
	}
	if callableHasUsersCanRegisterGuardBeforeLine(s.current, call.StartLine()) {
		return
	}
	sourceNode, ok := oauthCallbackRequestSourceNode(s.current, call.StartLine())
	if !ok {
		return
	}
	sink, ok := s.authCookieSinkForMethodCall(call)
	if !ok {
		return
	}
	s.addSinkFindings(
		"wp-public-oauth-callback-auth-surface",
		publicOAuthCallbackAuthSurfaceMessage,
		makeOriginSet(origin{kind: originSource, source: s.locationForNode(sourceNode)}),
		sink,
		ctx,
	)
}

func callableHasPublicOAuthCallbackEntry(ctx FlowContext) bool {
	return entrypointListHasPublicOAuthCallbackEntry(ctx.EntryPoints)
}

func entrypointListHasPublicOAuthCallbackEntry(entries []EntryPoint) bool {
	for _, entry := range entries {
		switch entry.Kind {
		case "ajax", "admin_post", "front_hook", "rest":
			return true
		}
	}
	return false
}

func oauthCallbackNameLike(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "callback") || strings.Contains(lower, "oauth") || strings.Contains(lower, "login")
}

func callableHasUsersCanRegisterGuardBeforeLine(c callable, beforeLine int) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		line := node.StartLine()
		if beforeLine > 0 && line > 0 && line >= beforeLine {
			return
		}
		stmt, ok := node.(*ast.StmtIf)
		if !ok || stmt == nil {
			return
		}
		if !exprContainsUsersCanRegisterOption(stmt.Cond) {
			return
		}
		if blockReturnsOrExits(stmt.Stmts) {
			found = true
		}
	})
	return found
}

func exprContainsUsersCanRegisterOption(node ast.Node) bool {
	found := false
	walkNode(node, func(n ast.Node) {
		if found || n == nil {
			return
		}
		call, ok := n.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		if normalizeName(identifierText(call.Name)) != "get_option" || len(call.Args) == 0 {
			return
		}
		if strings.EqualFold(strings.Trim(literalString(argValue(call.Args[0])), `"'`), "users_can_register") {
			found = true
		}
	})
	return found
}

func blockReturnsOrExits(nodes []ast.Node) bool {
	for _, node := range nodes {
		switch node.(type) {
		case *ast.StmtReturn, *ast.ExprExit:
			return true
		}
	}
	return false
}

func oauthCallbackRequestSourceNode(c callable, beforeLine int) (ast.Node, bool) {
	var best ast.Node
	bestScore := -1
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if node == nil {
			return
		}
		line := node.StartLine()
		if beforeLine > 0 && line > 0 && line >= beforeLine {
			return
		}
		score := oauthCallbackRequestSourceScore(node)
		if score <= bestScore {
			return
		}
		best = node
		bestScore = score
	})
	return best, best != nil
}

func oauthCallbackRequestSourceScore(node ast.Node) int {
	switch typed := node.(type) {
	case *ast.ExprArrayDimFetch:
		if name, ok := superglobalArrayRootName(typed.Var); ok {
			name = strings.ToUpper(strings.TrimSpace(name))
			if name == "_GET" || name == "_POST" || name == "_REQUEST" {
				if oauthCallbackRequestKeyLike(strings.Trim(literalString(typed.Dim), `"'`)) {
					return 3
				}
			}
		}
	case *ast.ExprFuncCall:
		name := normalizeName(identifierText(typed.Name))
		if name == "filter_input" && len(typed.Args) >= 2 {
			if oauthCallbackRequestKeyLike(strings.Trim(literalString(argValue(typed.Args[1])), `"'`)) {
				return 4
			}
		}
	case *ast.ExprStaticCall:
		name := normalizeName(identifierText(typed.Name))
		if name == "sanitize" && len(typed.Args) >= 2 {
			if oauthCallbackRequestKeyLike(strings.Trim(literalString(argValue(typed.Args[1])), `"'`)) {
				return 5
			}
		}
	}
	return -1
}

func oauthCallbackRequestKeyLike(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "provider", "code", "state", "oauth_token", "oauth_verifier", "token", "userid", "user_id":
		return true
	default:
		return false
	}
}

func (s *analysisState) authCookieSinkForMethodCall(call *ast.ExprMethodCall) (Location, bool) {
	name := strings.ToLower(identifierText(call.Name))
	className := s.resolveClassExpr(call.Var)
	classCandidates := []string{}
	if className != "" {
		classCandidates = append(classCandidates, className)
	} else {
		classCandidates = s.engine.resolveCallbackClassRefs(call.Var, s.current)
		if receiverRootKey(call.Var, s.current.Class) == "this" {
			classCandidates = append(classCandidates, s.current.Class)
		}
	}
	for _, candidate := range classCandidates {
		key := s.resolveMethodKeyWithArgs(candidate, name, call.Args)
		if key == "" {
			continue
		}
		if sink, ok := recursiveAuthCookieSinkForCallable(key, s.engine, map[string]struct{}{}); ok {
			return sink, true
		}
	}
	return Location{}, false
}

func recursiveAuthCookieSinkForCallable(key string, e *engine, seen map[string]struct{}) (Location, bool) {
	if key == "" {
		return Location{}, false
	}
	if _, ok := seen[key]; ok {
		return Location{}, false
	}
	c, ok := e.callables[key]
	if !ok {
		return Location{}, false
	}
	seen[key] = struct{}{}
	defer delete(seen, key)
	var sink Location
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			if normalizeName(identifierText(typed.Name)) == "wp_set_auth_cookie" {
				sink = locationForCallableNode(e, c, typed)
				found = true
			}
		case *ast.ExprMethodCall:
			className := e.resolveCallbackClassRef(typed.Var, c)
			if className == "" {
				className = e.resolveMethodCallClass(typed, c)
			}
			if className == "" && receiverRootKey(typed.Var, c.Class) == "this" {
				className = c.Class
			}
			if className == "" {
				return
			}
			nextKey := e.ensureRuntimeMethodCallable(className, identifierText(typed.Name))
			if nextKey == "" {
				return
			}
			if nextSink, ok := recursiveAuthCookieSinkForCallable(nextKey, e, seen); ok {
				sink = nextSink
				found = true
			}
		}
	})
	if !found {
		return Location{}, false
	}
	return sink, true
}
