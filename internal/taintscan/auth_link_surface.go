package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

type authLinkSurfaceIssue struct {
	Node     ast.Node
	QueryKey string
}

func (s *analysisState) addIssuedAuthLinkSurfaceFindingForFuncCall(call *ast.ExprFuncCall, name string) {
	if call == nil || !s.engine.allowsSinkOp("surface") || !isDisclosureOutputFunc(name) || len(call.Args) == 0 {
		return
	}
	issue, ok := authLinkSurfaceIssueForPayload(argValue(call.Args[0]), s.current, s.engine, s.engine.localArrayLiteralResolver(s.current), call.StartLine())
	if !ok {
		return
	}
	sink, ok := s.engine.companionAuthLinkLoginSinkForClass(s.current.Class, s.current.Key, issue.QueryKey)
	if !ok {
		return
	}
	sourceNode := issue.Node
	if sourceNode == nil {
		sourceNode = call
	}
	s.addSinkFindings(
		"wp-issued-auth-link-surface",
		issuedAuthLinkSurfaceMessage,
		makeOriginSet(origin{kind: originSource, source: s.locationForNode(sourceNode)}),
		sink,
		s.currentContext(),
	)
}

func (e *engine) callableHasIssuedAuthLinkSurfaceSink(c callable) bool {
	if !e.allowsSinkOp("surface") || c.Class == "" {
		return false
	}
	resolver := e.localArrayLiteralResolver(c)
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found {
			return
		}
		call, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		name := normalizeName(identifierText(call.Name))
		if !isDisclosureOutputFunc(name) || len(call.Args) == 0 {
			return
		}
		issue, ok := authLinkSurfaceIssueForPayload(argValue(call.Args[0]), c, e, resolver, call.StartLine())
		if !ok {
			return
		}
		_, found = e.companionAuthLinkLoginSinkForClass(c.Class, c.Key, issue.QueryKey)
	})
	return found
}

func authLinkSurfaceIssueForPayload(payload ast.Node, current callable, e *engine, resolver *localArrayLiteralResolver, beforeLine int) (authLinkSurfaceIssue, bool) {
	payload = resolveAuthLinkSurfaceExpr(payload, current, resolver, beforeLine, map[string]struct{}{})
	arrayNode, ok := payload.(*ast.ExprArray)
	if !ok {
		return authLinkSurfaceIssue{}, false
	}
	for _, field := range []string{"login_url", "loginurl", "auth_url", "authurl"} {
		value := arrayValueForStringKey(arrayNode, field)
		if value == nil {
			continue
		}
		resolved := resolveAuthLinkSurfaceExpr(value, current, resolver, beforeLine, map[string]struct{}{})
		queryKey, ok := authLinkSurfaceQueryKey(resolved, current, e, resolver, beforeLine)
		if !ok || !queryKeyLooksLikeLoginSurface(queryKey) {
			continue
		}
		return authLinkSurfaceIssue{Node: value, QueryKey: queryKey}, true
	}
	return authLinkSurfaceIssue{}, false
}

func resolveAuthLinkSurfaceExpr(expr ast.Node, current callable, resolver *localArrayLiteralResolver, beforeLine int, seen map[string]struct{}) ast.Node {
	if expr == nil {
		return nil
	}
	switch typed := expr.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || name == "" {
			return expr
		}
		key := "var:" + name
		if _, ok := seen[key]; ok {
			return expr
		}
		seen[key] = struct{}{}
		defer delete(seen, key)
		if next, line := resolver.latestExpr(name, beforeLine); next != nil {
			return resolveAuthLinkSurfaceExpr(next, current, resolver, line, seen)
		}
	case *ast.ExprArrayDimFetch:
		name, dims, ok := localArrayFetchPath(typed)
		if !ok {
			return expr
		}
		arrayNode, line := resolver.latest(name, beforeLine)
		if arrayNode == nil {
			return expr
		}
		currentNode := ast.Node(arrayNode)
		for _, dim := range dims {
			nextArray, ok := currentNode.(*ast.ExprArray)
			if !ok {
				return expr
			}
			currentNode = arrayValueForStringKey(nextArray, dim)
			if currentNode == nil {
				return expr
			}
		}
		return resolveAuthLinkSurfaceExpr(currentNode, current, resolver, line, seen)
	}
	return expr
}

func authLinkSurfaceQueryKey(expr ast.Node, current callable, e *engine, resolver *localArrayLiteralResolver, beforeLine int) (string, bool) {
	for _, fragment := range authLinkLiteralFragments(expr, current, e, resolver, beforeLine, map[string]struct{}{}) {
		if key, ok := authLinkQueryKeyFromFragment(fragment); ok {
			return key, true
		}
	}
	return "", false
}

func authLinkLiteralFragments(expr ast.Node, current callable, e *engine, resolver *localArrayLiteralResolver, beforeLine int, seen map[string]struct{}) []string {
	expr = resolveAuthLinkSurfaceExpr(expr, current, resolver, beforeLine, seen)
	switch typed := expr.(type) {
	case nil:
		return nil
	case *ast.ScalarString:
		return []string{typed.Value}
	case *ast.ExprBinaryOpConcat:
		left := authLinkLiteralFragments(typed.Left, current, e, resolver, beforeLine, seen)
		right := authLinkLiteralFragments(typed.Right, current, e, resolver, beforeLine, seen)
		return append(left, right...)
	case *ast.ExprMethodCall:
		className := e.resolveCallbackClassRef(typed.Var, current)
		if className == "" {
			className = e.resolveMethodCallClass(typed, current)
		}
		if className == "" && receiverRootKey(typed.Var, current.Class) == "this" {
			className = current.Class
		}
		if className == "" {
			break
		}
		return authLinkCallableReturnFragments(e.ensureRuntimeMethodCallable(className, identifierText(typed.Name)), e, seen)
	case *ast.ExprStaticCall:
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		if className == "" {
			break
		}
		return authLinkCallableReturnFragments(e.ensureRuntimeMethodCallable(className, identifierText(typed.Name)), e, seen)
	}
	if literal := literalStringForCallable(expr, current, e); literal != "" {
		return []string{literal}
	}
	return nil
}

func authLinkCallableReturnFragments(key string, e *engine, seen map[string]struct{}) []string {
	if key == "" {
		return nil
	}
	if _, ok := seen[key]; ok {
		return nil
	}
	c, ok := e.callables[key]
	if !ok {
		return nil
	}
	seen[key] = struct{}{}
	defer delete(seen, key)
	resolver := e.localArrayLiteralResolver(c)
	out := []string{}
	walkCallableExecutableNodes(c, func(node ast.Node) {
		ret, ok := node.(*ast.StmtReturn)
		if !ok {
			return
		}
		out = append(out, authLinkLiteralFragments(ret.Expr, c, e, resolver, ret.StartLine(), seen)...)
	})
	return out
}

func authLinkQueryKeyFromFragment(fragment string) (string, bool) {
	fragment = strings.TrimSpace(strings.Trim(fragment, `"'`))
	if fragment == "" {
		return "", false
	}
	for _, prefix := range []string{"?", "&"} {
		idx := strings.Index(fragment, prefix)
		if idx < 0 || idx+1 >= len(fragment) {
			continue
		}
		rest := fragment[idx+1:]
		eq := strings.Index(rest, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(rest[:eq])
		if key != "" {
			return key, true
		}
	}
	return "", false
}

func queryKeyLooksLikeLoginSurface(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	return strings.Contains(key, "login") || strings.Contains(key, "auth")
}

func (e *engine) companionAuthLinkLoginSinkForClass(className, issuerKey, queryKey string) (Location, bool) {
	if className == "" || queryKey == "" {
		return Location{}, false
	}
	for _, key := range e.methods[className] {
		if key == "" || key == issuerKey {
			continue
		}
		c, ok := e.callables[key]
		if !ok {
			continue
		}
		if sink, ok := authLinkLoginSinkForCallable(e, c, queryKey); ok {
			return sink, true
		}
	}
	return Location{}, false
}

func authLinkLoginSinkForCallable(e *engine, c callable, queryKey string) (Location, bool) {
	queryRead := false
	sink := Location{}
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if queryRead && hasConcreteLocation(sink) {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprArrayDimFetch:
			if authLinkQueryFetchMatches(typed, queryKey) {
				queryRead = true
			}
		case *ast.ExprFuncCall:
			name := normalizeName(identifierText(typed.Name))
			if name == "filter_input" && authLinkFilterInputMatches(typed, queryKey) {
				queryRead = true
			}
			if name == "wp_set_auth_cookie" {
				sink = locationForCallableNode(e, c, typed)
			}
		}
	})
	if queryRead && hasConcreteLocation(sink) {
		return sink, true
	}
	return Location{}, false
}

func authLinkQueryFetchMatches(fetch *ast.ExprArrayDimFetch, queryKey string) bool {
	name, ok := superglobalArrayRootName(fetch.Var)
	if !ok {
		return false
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	if name != "_GET" && name != "_REQUEST" {
		return false
	}
	return strings.EqualFold(strings.Trim(literalString(fetch.Dim), `"'`), queryKey)
}

func authLinkFilterInputMatches(call *ast.ExprFuncCall, queryKey string) bool {
	if len(call.Args) < 2 {
		return false
	}
	source := strings.ToUpper(strings.TrimSpace(literalString(argValue(call.Args[0]))))
	source = strings.Trim(source, `"'`)
	if source != "INPUT_GET" && source != "INPUT_REQUEST" {
		return false
	}
	return strings.EqualFold(strings.Trim(literalString(argValue(call.Args[1])), `"'`), queryKey)
}
