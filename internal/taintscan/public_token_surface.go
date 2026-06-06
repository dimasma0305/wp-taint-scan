package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (s *analysisState) addPublicTokenIssuanceSurfaceFindingForReturn(stmt *ast.StmtReturn) {
	if stmt == nil || !s.engine.allowsSinkOp("surface") {
		return
	}
	if !callableHasRestSurfaceEntry(s.currentContext()) {
		return
	}
	if callableHasTokenValidationGuardBeforeLine(s.current, stmt.StartLine(), s.engine) {
		return
	}
	for _, item := range tokenSurfaceReturnItems(stmt.Expr) {
		origins := s.evalExpr(item.Value)
		if !originsContainDirectRequestSource(origins) {
			continue
		}
		sink := s.locationForNode(item.Node)
		s.addSinkFindings("wp-rest-token-issuance-surface", publicTokenIssuanceSurfaceMessage, origins, sink, s.currentContext())
	}
}

func (e *engine) callableHasPublicTokenIssuanceSurfaceSink(c callable) bool {
	if !callableHasRestSurfaceEntry(e.contexts[c.Key]) {
		return false
	}
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found {
			return
		}
		ret, ok := node.(*ast.StmtReturn)
		if !ok {
			return
		}
		if callableHasTokenValidationGuardBeforeLine(c, ret.StartLine(), e) {
			return
		}
		found = len(tokenSurfaceReturnItems(ret.Expr)) != 0
	})
	return found
}

type tokenSurfaceReturnItem struct {
	Node  ast.Node
	Value ast.Node
}

func tokenSurfaceReturnItems(expr ast.Node) []tokenSurfaceReturnItem {
	payload := restSurfacePayloadExpr(expr)
	arrayNode, ok := payload.(*ast.ExprArray)
	if !ok {
		return nil
	}
	out := make([]tokenSurfaceReturnItem, 0, 2)
	for _, rawItem := range arrayNode.Items {
		item, ok := rawItem.(*ast.ArrayItem)
		if !ok || item == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(literalString(item.Key)))
		if !isTokenSurfaceFieldName(key) {
			continue
		}
		if !exprLooksLikeIssuedToken(item.Value) {
			continue
		}
		sinkNode := ast.Node(item)
		if item.Value != nil {
			sinkNode = item.Value
		}
		out = append(out, tokenSurfaceReturnItem{
			Node:  sinkNode,
			Value: item.Value,
		})
	}
	return out
}

func restSurfacePayloadExpr(expr ast.Node) ast.Node {
	switch typed := expr.(type) {
	case *ast.ExprFuncCall:
		name := normalizeName(identifierText(typed.Name))
		if (name == "rest_ensure_response" || name == "wp_send_json" || name == "wp_send_json_success") && len(typed.Args) > 0 {
			return argValue(typed.Args[0])
		}
	case *ast.ExprNew:
		className := strings.ToLower(strings.TrimPrefix(resolveClassName(typed.Class, "", nil), `\`))
		if strings.HasSuffix(className, "wp_rest_response") && len(typed.Args) > 0 {
			return argValue(typed.Args[0])
		}
	}
	return expr
}

func isTokenSurfaceFieldName(name string) bool {
	if name == "" {
		return false
	}
	return strings.Contains(name, "token") ||
		strings.Contains(name, "bearer") ||
		strings.Contains(name, "auth_token") ||
		strings.Contains(name, "access_token")
}

func exprLooksLikeIssuedToken(expr ast.Node) bool {
	switch typed := expr.(type) {
	case nil:
		return false
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		return ok && strings.Contains(strings.ToLower(strings.TrimSpace(name)), "token")
	case *ast.ExprMethodCall:
		return tokenIssuanceCallLike(strings.ToLower(identifierText(typed.Name)), typed.Var)
	case *ast.ExprStaticCall:
		return tokenIssuanceCallLike(strings.ToLower(identifierText(typed.Name)), typed.Class)
	case *ast.ExprFuncCall:
		return tokenIssuanceCallLike(normalizeName(identifierText(typed.Name)), nil)
	default:
		return false
	}
}

func tokenIssuanceCallLike(name string, receiver ast.Node) bool {
	if name == "" {
		return false
	}
	if !(strings.Contains(name, "create") || strings.Contains(name, "generate") || strings.Contains(name, "issue") || strings.Contains(name, "refresh")) {
		return false
	}
	if nodeLooksTokenLike(receiver) {
		return true
	}
	return strings.Contains(name, "token") || strings.Contains(name, "nonce") || strings.Contains(name, "auth")
}

func nodeLooksTokenLike(node ast.Node) bool {
	switch typed := node.(type) {
	case nil:
		return false
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		return ok && identifierLooksTokenLike(name)
	case *ast.ExprPropertyFetch:
		return identifierLooksTokenLike(identifierText(typed.Name))
	case *ast.ExprStaticPropertyFetch:
		return identifierLooksTokenLike(identifierText(typed.Name))
	case *ast.Name:
		return identifierLooksTokenLike(identifierText(typed))
	case *ast.NameFullyQualified:
		return identifierLooksTokenLike(identifierText(typed))
	default:
		return identifierLooksTokenLike(identifierText(node))
	}
}

func identifierLooksTokenLike(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	if text == "" {
		return false
	}
	return strings.Contains(text, "token") ||
		strings.Contains(text, "signature") ||
		strings.Contains(text, "bearer") ||
		strings.Contains(text, "auth")
}

func originsContainDirectRequestSource(origins originSet) bool {
	for _, item := range origins {
		if item.kind != originSource {
			continue
		}
		lower := strings.ToLower(item.source.Snippet)
		if strings.Contains(lower, "$_get") ||
			strings.Contains(lower, "$_post") ||
			strings.Contains(lower, "$_request") ||
			strings.Contains(lower, "get_param(") ||
			strings.Contains(lower, "get_json_params(") ||
			strings.Contains(lower, "get_body_params(") ||
			strings.Contains(lower, "get_query_params(") ||
			strings.Contains(lower, "filter_input(") {
			return true
		}
	}
	return false
}

func callableHasRestSurfaceEntry(ctx FlowContext) bool {
	for _, entry := range ctx.EntryPoints {
		if entry.Kind == "rest" {
			return true
		}
	}
	return false
}

func callableHasTokenValidationGuardBeforeLine(c callable, sinkLine int, e *engine) bool {
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found || node == nil || sinkLine <= 0 {
			return
		}
		if line := node.StartLine(); line <= 0 || line >= sinkLine {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			if tokenValidationGuardCallLike(normalizeName(identifierText(typed.Name)), typed.Args) {
				found = true
			}
		case *ast.ExprMethodCall:
			if tokenValidationGuardCallLike(normalizeName(identifierText(typed.Name)), typed.Args) {
				found = true
			}
		case *ast.ExprStaticCall:
			if tokenValidationGuardCallLike(normalizeName(identifierText(typed.Name)), typed.Args) {
				found = true
			}
		}
	})
	return found
}

func tokenValidationGuardCallLike(name string, args []ast.Node) bool {
	if name == "" || !strings.HasPrefix(name, "validate") {
		return false
	}
	if !(strings.Contains(name, "token") || strings.Contains(name, "signature") || strings.Contains(name, "auth")) {
		return false
	}
	if len(args) == 0 {
		return true
	}
	for _, arg := range args {
		if tokenValidationArgLike(argValue(arg)) {
			return true
		}
	}
	return false
}

func tokenValidationArgLike(node ast.Node) bool {
	switch typed := node.(type) {
	case nil:
		return false
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		return ok && identifierLooksTokenLike(name)
	case *ast.ScalarString:
		return identifierLooksTokenLike(typed.Value)
	case *ast.ExprMethodCall:
		return strings.Contains(strings.ToLower(identifierText(typed.Name)), "header")
	case *ast.ExprFuncCall:
		return identifierLooksTokenLike(normalizeName(identifierText(typed.Name)))
	default:
		return identifierLooksTokenLike(identifierText(node))
	}
}
