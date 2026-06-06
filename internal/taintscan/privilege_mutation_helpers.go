package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func privilegeMutationFuncArgPath(name string) (int, string, string, string, bool) {
	switch normalizeName(name) {
	case "wp_insert_user", "wp_update_user":
		return 0, "[role]", "wp-request-tainted-privilege-mutation", privilegeMutationMessage, true
	case "grant_super_admin":
		// grant_super_admin($user_id): the attacker-chosen user id is promoted to
		// super admin; the whole first argument is the privilege-mutation carrier.
		return 0, "", "wp-request-tainted-privilege-mutation", privilegeMutationMessage, true
	default:
		return -1, "", "", "", false
	}
}

// isCapabilityMetaKey reports whether a user-meta key writes the WordPress
// capabilities/role/level meta (e.g. "wp_capabilities", "wp_user_level"),
// which is a direct privilege-escalation primitive when request-controlled.
func isCapabilityMetaKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(strings.Trim(key, `"'`)))
	if key == "" {
		return false
	}
	return strings.HasSuffix(key, "capabilities") || strings.HasSuffix(key, "user_level")
}

// capabilityMetaPrivilegeValueArgIndex returns the value-argument index when a
// *_user_meta / *_metadata call writes the capabilities/level meta key. Such a
// write is a privilege-escalation sink (routes to wp-request-tainted-privilege-
// mutation) rather than the generic sensitive-action rule.
func capabilityMetaPrivilegeValueArgIndex(call *ast.ExprFuncCall) (int, bool) {
	switch normalizeName(identifierText(call.Name)) {
	case "update_user_meta", "add_user_meta":
		if len(call.Args) >= 3 && isCapabilityMetaKey(literalString(argValue(call.Args[1]))) {
			return 2, true
		}
	case "update_metadata", "add_metadata":
		// update_metadata('user', $object_id, $meta_key, $meta_value, ...)
		if len(call.Args) >= 4 &&
			strings.EqualFold(strings.TrimSpace(strings.Trim(literalString(argValue(call.Args[0])), `"'`)), "user") &&
			isCapabilityMetaKey(literalString(argValue(call.Args[2]))) {
			return 3, true
		}
	}
	return -1, false
}

func resolveArgumentPathNodesForCallable(current callable, node ast.Node, path string, beforeLine int) []ast.Node {
	return resolveArgumentPathNodesForCallableWithSeen(current, node, path, beforeLine, map[string]struct{}{})
}

func resolveArgumentPathNodesForCallableWithSeen(current callable, node ast.Node, path string, beforeLine int, seen map[string]struct{}) []ast.Node {
	if node == nil {
		return nil
	}
	node = argValue(node)
	if path == "" {
		return []ast.Node{node}
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return nil
		}
		seenKey := strings.TrimSpace(name) + "::" + path
		if _, ok := seen[seenKey]; ok {
			return nil
		}
		seen[seenKey] = struct{}{}
		if expr, line := latestLocalVariablePathExpr(current, name, path, beforeLine); expr != nil {
			return resolveArgumentPathNodesForCallableWithSeen(current, expr, "", line, seen)
		}
		resolver := newLocalArrayLiteralResolver(current)
		if expr, line := resolver.latestExpr(name, beforeLine); expr != nil {
			return resolveArgumentPathNodesForCallableWithSeen(current, expr, path, line, seen)
		}
		return nil
	case *ast.ExprArrayDimFetch:
		return resolveArgumentPathNodesForCallableWithSeen(current, typed.Var, rootlessArrayPath(typed.Dim)+path, beforeLine, seen)
	case *ast.ExprFuncCall:
		argIndexes := structuralPropagatingArgIndexes(identifierText(typed.Name), len(typed.Args))
		if len(argIndexes) == 0 {
			return nil
		}
		out := make([]ast.Node, 0)
		for _, idx := range argIndexes {
			out = append(out, resolveArgumentPathNodesForCallableWithSeen(current, argValue(typed.Args[idx]), path, beforeLine, seen)...)
		}
		return out
	case *ast.ExprMethodCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return resolveArgumentPathNodesForCallableWithSeen(current, argValue(typed.Args[0]), path, beforeLine, seen)
		}
	case *ast.ExprStaticCall:
		if isPropagatingMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return resolveArgumentPathNodesForCallableWithSeen(current, argValue(typed.Args[0]), path, beforeLine, seen)
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
				out = append(out, resolveArgumentPathNodesForCallableWithSeen(current, item.Value, rest, beforeLine, seen)...)
			}
			return out
		}
		for _, itemNode := range typed.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			if strings.EqualFold(literalString(item.Key), segment) {
				out = append(out, resolveArgumentPathNodesForCallableWithSeen(current, item.Value, rest, beforeLine, seen)...)
			}
		}
		return out
	}
	return nil
}

func latestLocalVariablePathExpr(current callable, name string, path string, beforeLine int) (ast.Node, int) {
	name = strings.TrimSpace(name)
	path = strings.TrimSpace(path)
	if name == "" || path == "" || len(current.Stmts) == 0 {
		return nil, -1
	}
	var best ast.Node
	bestLine := -1
	walkNodes(current.Stmts, func(node ast.Node) {
		assign, ok := node.(*ast.ExprAssign)
		if !ok {
			return
		}
		line := assign.StartLine()
		if line <= 0 {
			return
		}
		if beforeLine > 0 && line >= beforeLine {
			return
		}
		root, targetPath, ok := localVariableRootAndPath(assign.Var)
		if !ok || !strings.EqualFold(root, name) || targetPath != path {
			return
		}
		if line > bestLine {
			best = assign.Expr
			bestLine = line
		}
	})
	return best, bestLine
}

func localVariableRootAndPath(node ast.Node) (string, string, bool) {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return "", "", false
		}
		return name, "", true
	case *ast.ExprArrayDimFetch:
		root, path, ok := localVariableRootAndPath(typed.Var)
		if !ok {
			return "", "", false
		}
		return root, path + rootlessArrayPath(typed.Dim), true
	default:
		return "", "", false
	}
}

func privilegeMutationNodesAllLowPrivilegeRoles(current callable, nodes []ast.Node, beforeLine int) bool {
	if len(nodes) == 0 {
		return false
	}
	resolver := newLocalArrayLiteralResolver(current)
	for _, node := range nodes {
		if !exprGuaranteedLowPrivilegeRole(current, node, beforeLine, resolver, map[string]struct{}{}) {
			return false
		}
	}
	return true
}

func exprGuaranteedLowPrivilegeRole(current callable, node ast.Node, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) bool {
	if node == nil {
		return false
	}
	node = argValue(node)
	if isLowPrivilegeRoleLiteral(literalString(node)) {
		return true
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return false
		}
		seenKey := strings.TrimSpace(name)
		if _, ok := seen[seenKey]; ok {
			return false
		}
		seen[seenKey] = struct{}{}
		expr, line := resolver.latestExpr(name, beforeLine)
		if expr == nil {
			return false
		}
		return exprGuaranteedLowPrivilegeRole(current, expr, line, resolver, seen)
	case *ast.ExprTernary:
		if typed.If != nil && ternaryRestrictsRoleToLowPrivilege(typed, current, beforeLine, resolver, seen) {
			return true
		}
		if typed.If == nil {
			return exprGuaranteedLowPrivilegeRole(current, typed.Cond, beforeLine, resolver, seen) &&
				exprGuaranteedLowPrivilegeRole(current, typed.Else, beforeLine, resolver, seen)
		}
		return exprGuaranteedLowPrivilegeRole(current, typed.If, beforeLine, resolver, seen) &&
			exprGuaranteedLowPrivilegeRole(current, typed.Else, beforeLine, resolver, seen)
	case *ast.ExprFuncCall:
		if isStringDispatchWrapperFunc(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return exprGuaranteedLowPrivilegeRole(current, argValue(typed.Args[0]), beforeLine, resolver, seen)
		}
	case *ast.ExprMethodCall:
		if isStringDispatchWrapperMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return exprGuaranteedLowPrivilegeRole(current, argValue(typed.Args[0]), beforeLine, resolver, seen)
		}
	case *ast.ExprStaticCall:
		if isStringDispatchWrapperMethod(identifierText(typed.Name)) && len(typed.Args) > 0 {
			return exprGuaranteedLowPrivilegeRole(current, argValue(typed.Args[0]), beforeLine, resolver, seen)
		}
	}
	return false
}

func ternaryRestrictsRoleToLowPrivilege(node *ast.ExprTernary, current callable, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) bool {
	if node == nil || node.If == nil {
		return false
	}
	condCall, ok := argValue(node.Cond).(*ast.ExprFuncCall)
	if !ok || normalizeName(identifierText(condCall.Name)) != "in_array" || len(condCall.Args) < 2 {
		return false
	}
	needle := argValue(condCall.Args[0])
	haystack := argValue(condCall.Args[1])
	if !sameRoleExpr(node.If, needle) {
		return false
	}
	if !arrayExprContainsOnlyLowPrivilegeRoles(current, haystack, beforeLine, resolver, seen) {
		return false
	}
	return exprGuaranteedLowPrivilegeRole(current, node.Else, beforeLine, resolver, seen)
}

func sameRoleExpr(lhs ast.Node, rhs ast.Node) bool {
	lhs = argValue(lhs)
	rhs = argValue(rhs)
	switch left := lhs.(type) {
	case *ast.ExprVariable:
		right, ok := rhs.(*ast.ExprVariable)
		if !ok {
			return false
		}
		leftName, ok := left.Name.(string)
		if !ok {
			return false
		}
		rightName, ok := right.Name.(string)
		if !ok {
			return false
		}
		return strings.EqualFold(strings.TrimSpace(leftName), strings.TrimSpace(rightName))
	case *ast.ExprFuncCall:
		if isStringDispatchWrapperFunc(identifierText(left.Name)) && len(left.Args) > 0 {
			return sameRoleExpr(argValue(left.Args[0]), rhs)
		}
	case *ast.ExprMethodCall:
		if isStringDispatchWrapperMethod(identifierText(left.Name)) && len(left.Args) > 0 {
			return sameRoleExpr(argValue(left.Args[0]), rhs)
		}
	case *ast.ExprStaticCall:
		if isStringDispatchWrapperMethod(identifierText(left.Name)) && len(left.Args) > 0 {
			return sameRoleExpr(argValue(left.Args[0]), rhs)
		}
	}
	return false
}

func arrayExprContainsOnlyLowPrivilegeRoles(current callable, node ast.Node, beforeLine int, resolver *localArrayLiteralResolver, seen map[string]struct{}) bool {
	if node == nil {
		return false
	}
	node = argValue(node)
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return false
		}
		seenKey := "array::" + strings.TrimSpace(name)
		if _, ok := seen[seenKey]; ok {
			return false
		}
		seen[seenKey] = struct{}{}
		expr, line := resolver.latestExpr(name, beforeLine)
		if expr == nil {
			return false
		}
		return arrayExprContainsOnlyLowPrivilegeRoles(current, expr, line, resolver, seen)
	case *ast.ExprArray:
		items := arrayItems(typed)
		if len(items) == 0 {
			return false
		}
		for _, item := range items {
			if !exprGuaranteedLowPrivilegeRole(current, item, beforeLine, resolver, seen) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isLowPrivilegeRoleLiteral(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "subscriber", "customer":
		return true
	default:
		return false
	}
}
