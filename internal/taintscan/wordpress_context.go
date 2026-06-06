package taintscan

import (
	"strconv"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (e *engine) inspectCallableContext(c callable) FlowContext {
	ctx := FlowContext{}
	walkNodes(c.Stmts, func(node ast.Node) {
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			switch normalizeName(identifierText(typed.Name)) {
			case "check_ajax_referer", "check_admin_referer":
				ctx.NonceChecks = append(ctx.NonceChecks, locationForCallableNode(e, c, typed))
			case "wp_send_json_error", "wp_die":
				ctx.ValidationChecks = append(ctx.ValidationChecks, locationForCallableNode(e, c, typed))
			}
		case *ast.ExprExit:
			ctx.ValidationChecks = append(ctx.ValidationChecks, locationForCallableNode(e, c, typed))
		case *ast.StmtExpression:
			switch expr := typed.Expr.(type) {
			case *ast.ExprFuncCall:
				helper := e.statementGuardHelperContextForFuncCall(expr, c)
				if hasGuardSignals(helper) {
					e.mergeHelperGuardContext(helper, &ctx)
				}
			case *ast.ExprMethodCall:
				helper := e.statementGuardHelperContextForMethodCall(expr, c)
				if hasGuardSignals(helper) {
					e.mergeHelperGuardContext(helper, &ctx)
				}
			case *ast.ExprStaticCall:
				helper := e.statementGuardHelperContextForStaticCall(expr, c)
				if hasGuardSignals(helper) {
					e.mergeHelperGuardContext(helper, &ctx)
				}
			}
		case *ast.StmtIf:
			e.inspectGuardCondition(typed.Cond, c, &ctx)
			for _, elseifNode := range typed.Elseifs {
				elseifStmt, ok := elseifNode.(*ast.StmtElseIf)
				if !ok {
					continue
				}
				e.inspectGuardCondition(elseifStmt.Cond, c, &ctx)
			}
		case *ast.StmtWhile:
			e.inspectGuardCondition(typed.Cond, c, &ctx)
		case *ast.StmtDo:
			e.inspectGuardCondition(typed.Cond, c, &ctx)
		case *ast.StmtFor:
			for _, cond := range typed.Cond {
				e.inspectGuardCondition(cond, c, &ctx)
			}
		case *ast.StmtReturn:
			e.inspectGuardCondition(typed.Expr, c, &ctx)
		}
	})
	return normalizeFlowContext(ctx)
}

func (e *engine) permissionCallbackContext(key string) FlowContext {
	c, ok := e.callables[key]
	if !ok {
		return FlowContext{}
	}
	return normalizeFlowContext(e.inspectCallableContext(c))
}

func (e *engine) inspectGuardCondition(node ast.Node, current callable, ctx *FlowContext) {
	e.inspectGuardConditionWithSeen(node, current, ctx, map[string]struct{}{})
}

func (e *engine) inspectGuardConditionWithSeen(node ast.Node, current callable, ctx *FlowContext, seenVars map[string]struct{}) {
	switch typed := node.(type) {
	case nil:
		return
	case *ast.ExprFuncCall:
		if !e.recordGuardCall(typed, current, ctx) {
			helper := e.guardHelperContextForFuncCall(typed, current)
			if hasGuardSignals(helper) {
				e.mergeHelperGuardContext(helper, ctx)
				return
			}
			if isGuardPassthroughFunc(identifierText(typed.Name)) {
				for _, arg := range typed.Args[1:] {
					e.inspectGuardConditionWithSeen(argValue(arg), current, ctx, seenVars)
				}
			}
		}
	case *ast.ExprMethodCall:
		if !e.recordGuardMethodCall(typed, current, ctx) {
			e.mergeHelperGuardContext(e.guardHelperContextForMethodCall(typed, current), ctx)
		}
	case *ast.ExprStaticCall:
		if !e.recordGuardStaticCall(typed, current, ctx) {
			e.mergeHelperGuardContext(e.guardHelperContextForStaticCall(typed, current), ctx)
		}
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			e.mergeHelperGuardContext(e.guardLocalVariableContext(current, name, seenVars), ctx)
		}
	case *ast.ExprBooleanNot:
		e.inspectNegativeGuardConditionWithSeen(typed.Expr, current, ctx, seenVars)
	case *ast.ExprBinaryOpBooleanAnd:
		e.inspectGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpBooleanOr:
		e.inspectGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpLogicalAnd:
		e.inspectGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpLogicalOr:
		e.inspectGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpIdentical:
		e.inspectBooleanComparison(typed.Left, typed.Right, true, current, ctx)
	case *ast.ExprBinaryOpEqual:
		e.inspectBooleanComparison(typed.Left, typed.Right, true, current, ctx)
	case *ast.ExprBinaryOpNotIdentical:
		e.inspectBooleanComparison(typed.Left, typed.Right, false, current, ctx)
	case *ast.ExprBinaryOpNotEqual:
		e.inspectBooleanComparison(typed.Left, typed.Right, false, current, ctx)
	case *ast.ExprBinaryOpGreater:
		e.inspectPositiveNumericComparison(typed.Left, typed.Right, current, ctx)
		e.inspectPositiveNumericComparison(typed.Right, typed.Left, current, ctx)
	case *ast.ExprBinaryOpGreaterOrEqual:
		e.inspectPositiveNumericComparison(typed.Left, typed.Right, current, ctx)
		e.inspectPositiveNumericComparison(typed.Right, typed.Left, current, ctx)
	case *ast.ExprTernary:
		e.inspectGuardConditionWithSeen(typed.Cond, current, ctx, seenVars)
	}
}

func (e *engine) mergeHelperGuardContext(helper FlowContext, ctx *FlowContext) {
	if len(helper.CapabilityChecks) == 0 &&
		len(helper.NonceChecks) == 0 &&
		len(helper.ValidationChecks) == 0 &&
		len(helper.AuthChecks) == 0 &&
		len(helper.UnauthChecks) == 0 &&
		len(helper.AdminChecks) == 0 &&
		len(helper.AjaxChecks) == 0 {
		return
	}
	ctx.CapabilityChecks = mergeCappedLocations(ctx.CapabilityChecks, helper.CapabilityChecks, maxFlowContextLocations)
	ctx.NonceChecks = mergeCappedLocations(ctx.NonceChecks, helper.NonceChecks, maxFlowContextLocations)
	ctx.ValidationChecks = mergeCappedLocations(ctx.ValidationChecks, helper.ValidationChecks, maxFlowContextLocations)
	ctx.AuthChecks = mergeCappedLocations(ctx.AuthChecks, helper.AuthChecks, maxFlowContextLocations)
	ctx.UnauthChecks = mergeCappedLocations(ctx.UnauthChecks, helper.UnauthChecks, maxFlowContextLocations)
	ctx.AdminChecks = mergeCappedLocations(ctx.AdminChecks, helper.AdminChecks, maxFlowContextLocations)
	ctx.AjaxChecks = mergeCappedLocations(ctx.AjaxChecks, helper.AjaxChecks, maxFlowContextLocations)
}

func shouldMergeStatementGuardHelper(helper FlowContext) bool {
	return len(helper.EntryPoints) == 0 && len(helper.ValidationChecks) > 0
}

func statementGuardHelperContext(helper FlowContext) FlowContext {
	out := FlowContext{
		CapabilityChecks: append([]Location(nil), helper.CapabilityChecks...),
		NonceChecks:      append([]Location(nil), helper.NonceChecks...),
		ValidationChecks: append([]Location(nil), helper.ValidationChecks...),
		AdminChecks:      append([]Location(nil), helper.AdminChecks...),
		AjaxChecks:       append([]Location(nil), helper.AjaxChecks...),
	}
	if len(helper.AuthChecks) > 0 {
		out.AuthChecks = append(out.AuthChecks, helper.AuthChecks...)
	}
	if len(helper.UnauthChecks) > 0 {
		// A statement helper that aborts on logged-out users implies the caller continues
		// on the authenticated path after the helper returns.
		out.AuthChecks = append(out.AuthChecks, helper.UnauthChecks...)
	}
	return normalizeFlowContext(out)
}

func (e *engine) statementGuardHelperContextForFuncCall(call *ast.ExprFuncCall, current callable) FlowContext {
	helper := e.guardHelperContextForFuncCall(call, current)
	if !shouldMergeStatementGuardHelper(helper) {
		return FlowContext{}
	}
	return e.statementGuardHelperContextForKey(helper, e.resolveGuardFunctionKey(call.Name, current))
}

func (e *engine) statementGuardHelperContextForMethodCall(call *ast.ExprMethodCall, current callable) FlowContext {
	helper := e.guardHelperContextForMethodCall(call, current)
	if !shouldMergeStatementGuardHelper(helper) {
		return FlowContext{}
	}
	className := e.resolveCallbackClassRef(call.Var, current)
	if className == "" {
		className = e.resolveMethodCallClass(call, current)
	}
	key := ""
	if className != "" {
		key = e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name)))
	}
	return e.statementGuardHelperContextForKey(helper, key)
}

func (e *engine) statementGuardHelperContextForStaticCall(call *ast.ExprStaticCall, current callable) FlowContext {
	helper := e.guardHelperContextForStaticCall(call, current)
	if !shouldMergeStatementGuardHelper(helper) {
		return FlowContext{}
	}
	className := resolveClassName(call.Class, current.Class, e.classParents)
	key := ""
	if className != "" {
		key = e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name)))
	}
	return e.statementGuardHelperContextForKey(helper, key)
}

func (e *engine) statementGuardHelperContextForKey(helper FlowContext, key string) FlowContext {
	out := statementGuardHelperContext(helper)
	if len(out.AuthChecks) != 0 || key == "" {
		return out
	}
	c, ok := e.callables[key]
	if !ok {
		return out
	}
	out.AuthChecks = append(out.AuthChecks, e.statementGuardWeakAuthFallback(c, map[string]struct{}{})...)
	return normalizeFlowContext(out)
}

func (e *engine) statementGuardWeakAuthFallback(c callable, seen map[string]struct{}) []Location {
	if c.Key == "" {
		return nil
	}
	e.statementGuardWeakAuthMu.RLock()
	if cached, ok := e.statementGuardWeakAuthCache[c.Key]; ok && cached.Computed {
		e.statementGuardWeakAuthMu.RUnlock()
		return append([]Location(nil), cached.Locations...)
	}
	e.statementGuardWeakAuthMu.RUnlock()
	if _, ok := seen[c.Key]; ok {
		return nil
	}
	seen[c.Key] = struct{}{}
	defer delete(seen, c.Key)

	var authChecks []Location
	walkNodes(c.Stmts, func(node ast.Node) {
		switch typed := node.(type) {
		case *ast.ExprFuncCall:
			switch normalizeName(identifierText(typed.Name)) {
			case "current_user_can", "user_can":
				if !e.isDefiniteCapabilityGuardCall(typed, c) {
					authChecks = append(authChecks, locationForCallableNode(e, c, typed))
					return
				}
			}
			if key := e.resolveGuardFunctionKey(typed.Name, c); key != "" {
				if callee, ok := e.callables[key]; ok {
					authChecks = append(authChecks, e.statementGuardWeakAuthFallback(callee, seen)...)
				}
			}
		case *ast.ExprMethodCall:
			switch normalizeName(identifierText(typed.Name)) {
			case "current_user_can", "user_can":
				if !e.isDefiniteCapabilityGuardMethodCall(typed, c) {
					authChecks = append(authChecks, locationForCallableNode(e, c, typed))
					return
				}
			}
			className := e.resolveCallbackClassRef(typed.Var, c)
			if className == "" {
				className = e.resolveMethodCallClass(typed, c)
			}
			if className != "" {
				if key := e.lookupMethodKey(className, strings.ToLower(identifierText(typed.Name))); key != "" {
					if callee, ok := e.callables[key]; ok {
						authChecks = append(authChecks, e.statementGuardWeakAuthFallback(callee, seen)...)
					}
				}
			}
		case *ast.ExprStaticCall:
			switch normalizeName(identifierText(typed.Name)) {
			case "current_user_can", "user_can":
				if !e.isDefiniteCapabilityGuardStaticCall(typed, c) {
					authChecks = append(authChecks, locationForCallableNode(e, c, typed))
					return
				}
			}
			className := resolveClassName(typed.Class, c.Class, e.classParents)
			if className != "" {
				if key := e.lookupMethodKey(className, strings.ToLower(identifierText(typed.Name))); key != "" {
					if callee, ok := e.callables[key]; ok {
						authChecks = append(authChecks, e.statementGuardWeakAuthFallback(callee, seen)...)
					}
				}
			}
		}
	})
	authChecks = uniqueLocations(authChecks)
	e.statementGuardWeakAuthMu.Lock()
	e.statementGuardWeakAuthCache[c.Key] = locationCacheEntry{
		Locations: append([]Location(nil), authChecks...),
		Computed:  true,
	}
	e.statementGuardWeakAuthMu.Unlock()
	return authChecks
}

func (e *engine) mergeNegativeHelperGuardContext(helper FlowContext, ctx *FlowContext) {
	if len(helper.CapabilityChecks) == 0 &&
		len(helper.NonceChecks) == 0 &&
		len(helper.ValidationChecks) == 0 &&
		len(helper.AuthChecks) == 0 &&
		len(helper.AdminChecks) == 0 &&
		len(helper.AjaxChecks) == 0 {
		return
	}
	ctx.CapabilityChecks = append(ctx.CapabilityChecks, helper.CapabilityChecks...)
	ctx.NonceChecks = append(ctx.NonceChecks, helper.NonceChecks...)
	ctx.ValidationChecks = append(ctx.ValidationChecks, helper.ValidationChecks...)
	ctx.AdminChecks = append(ctx.AdminChecks, helper.AdminChecks...)
	ctx.AjaxChecks = append(ctx.AjaxChecks, helper.AjaxChecks...)
	if len(helper.AuthChecks) > 0 && len(helper.CapabilityChecks) == 0 {
		ctx.UnauthChecks = append(ctx.UnauthChecks, helper.AuthChecks...)
	}
}

func (e *engine) inspectNegativeGuardCondition(node ast.Node, current callable, ctx *FlowContext) {
	e.inspectNegativeGuardConditionWithSeen(node, current, ctx, map[string]struct{}{})
}

func (e *engine) inspectNegativeGuardConditionWithSeen(node ast.Node, current callable, ctx *FlowContext, seenVars map[string]struct{}) {
	switch typed := node.(type) {
	case *ast.ExprFuncCall:
		if e.recordNegativeGuardCall(typed, current, ctx) {
			return
		}
		helper := e.guardHelperContextForFuncCall(typed, current)
		if hasGuardSignals(helper) {
			e.mergeNegativeHelperGuardContext(helper, ctx)
			return
		}
		if isGuardPassthroughFunc(identifierText(typed.Name)) {
			for _, arg := range typed.Args[1:] {
				e.inspectNegativeGuardConditionWithSeen(argValue(arg), current, ctx, seenVars)
			}
		}
	case *ast.ExprMethodCall:
		if !e.recordNegativeGuardMethodCall(typed, current, ctx) {
			e.mergeNegativeHelperGuardContext(e.guardHelperContextForMethodCall(typed, current), ctx)
		}
	case *ast.ExprStaticCall:
		if !e.recordNegativeGuardStaticCall(typed, current, ctx) {
			e.mergeNegativeHelperGuardContext(e.guardHelperContextForStaticCall(typed, current), ctx)
		}
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			e.mergeNegativeHelperGuardContext(e.guardLocalVariableContext(current, name, seenVars), ctx)
		}
	case *ast.ExprBooleanNot:
		e.inspectGuardConditionWithSeen(typed.Expr, current, ctx, seenVars)
	case *ast.ExprBinaryOpBooleanAnd:
		e.inspectNegativeGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectNegativeGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpLogicalAnd:
		e.inspectNegativeGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectNegativeGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpBooleanOr:
		e.inspectNegativeGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectNegativeGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpLogicalOr:
		e.inspectNegativeGuardConditionWithSeen(typed.Left, current, ctx, seenVars)
		e.inspectNegativeGuardConditionWithSeen(typed.Right, current, ctx, seenVars)
	case *ast.ExprBinaryOpIdentical:
		e.inspectBooleanComparison(typed.Left, typed.Right, false, current, ctx)
	case *ast.ExprBinaryOpEqual:
		e.inspectBooleanComparison(typed.Left, typed.Right, false, current, ctx)
	case *ast.ExprBinaryOpNotIdentical:
		e.inspectBooleanComparison(typed.Left, typed.Right, true, current, ctx)
	case *ast.ExprBinaryOpNotEqual:
		e.inspectBooleanComparison(typed.Left, typed.Right, true, current, ctx)
	case *ast.ExprTernary:
		e.inspectNegativeGuardConditionWithSeen(typed.Cond, current, ctx, seenVars)
	}
}

func hasGuardSignals(ctx FlowContext) bool {
	return len(ctx.CapabilityChecks) > 0 ||
		len(ctx.NonceChecks) > 0 ||
		len(ctx.ValidationChecks) > 0 ||
		len(ctx.AuthChecks) > 0 ||
		len(ctx.UnauthChecks) > 0 ||
		len(ctx.AdminChecks) > 0 ||
		len(ctx.AjaxChecks) > 0
}

func isGuardPassthroughFunc(name string) bool {
	switch normalizeName(name) {
	case "apply_filters", "apply_filters_ref_array":
		return true
	default:
		return false
	}
}

func (e *engine) guardHelperContextForFuncCall(call *ast.ExprFuncCall, current callable) FlowContext {
	if key := e.resolveGuardFunctionKey(call.Name, current); key != "" {
		return e.contexts[key]
	}
	return FlowContext{}
}

func (e *engine) guardHelperContextForMethodCall(call *ast.ExprMethodCall, current callable) FlowContext {
	className := e.resolveCallbackClassRef(call.Var, current)
	if className == "" {
		className = e.resolveMethodCallClass(call, current)
	}
	if className == "" {
		return FlowContext{}
	}
	if key := e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name))); key != "" {
		return e.contexts[key]
	}
	return FlowContext{}
}

func (e *engine) guardHelperContextForStaticCall(call *ast.ExprStaticCall, current callable) FlowContext {
	className := resolveClassName(call.Class, current.Class, e.classParents)
	if className == "" {
		return FlowContext{}
	}
	if key := e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name))); key != "" {
		return e.contexts[key]
	}
	return FlowContext{}
}

func (e *engine) resolveGuardFunctionKey(node ast.Node, current callable) string {
	name := normalizeName(identifierText(node))
	if name == "" {
		return ""
	}
	if key, ok := e.functions[name]; ok {
		return key
	}
	if strings.HasPrefix(name, `\`) {
		short := strings.TrimPrefix(name, `\`)
		if key, ok := e.functions[strings.ToLower(short)]; ok {
			return key
		}
	} else if key, ok := e.functions[`\\`+name]; ok {
		return key
	}
	if current.Namespace != "" {
		qualified := normalizeName(current.Namespace + `\` + name)
		if key, ok := e.functions[qualified]; ok {
			return key
		}
	}
	return ""
}

func (e *engine) resolveMethodCallClass(call *ast.ExprMethodCall, current callable) string {
	switch typed := call.Var.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			if name == "this" {
				return current.Class
			}
			if current.ParamTypes != nil {
				if className := strings.TrimSpace(current.ParamTypes[strings.TrimSpace(name)]); className != "" {
					return className
				}
			}
		}
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, current.Class); ok {
			return e.receiverPropertyReturnClassHint(current.Class, path)
		}
	}
	return ""
}

func (e *engine) inspectBooleanComparison(left ast.Node, right ast.Node, equals bool, current callable, ctx *FlowContext) {
	if truthy, ok := booleanLiteral(right); ok {
		e.recordGuardCallWithTruth(left, truthy == equals, current, ctx)
		return
	}
	if truthy, ok := booleanLiteral(left); ok {
		e.recordGuardCallWithTruth(right, truthy == equals, current, ctx)
		return
	}
	if number, ok := numericLiteral(right); ok {
		e.recordGuardCallWithNumber(left, number, equals, current, ctx)
		return
	}
	if number, ok := numericLiteral(left); ok {
		e.recordGuardCallWithNumber(right, number, equals, current, ctx)
	}
}

func (e *engine) inspectPositiveNumericComparison(left ast.Node, right ast.Node, current callable, ctx *FlowContext) {
	number, ok := numericLiteral(right)
	if !ok || number <= 0 {
		return
	}
	call, ok := left.(*ast.ExprFuncCall)
	if !ok {
		return
	}
	switch normalizeName(identifierText(call.Name)) {
	case "get_current_user_id":
		ctx.AuthChecks = append(ctx.AuthChecks, locationForCallableNode(e, current, call))
	}
}

func (e *engine) recordGuardCallWithTruth(node ast.Node, truthy bool, current callable, ctx *FlowContext) {
	switch typed := node.(type) {
	case *ast.ExprFuncCall:
		if truthy {
			e.recordGuardCall(typed, current, ctx)
			return
		}
		e.recordNegativeGuardCall(typed, current, ctx)
	case *ast.ExprMethodCall:
		if truthy {
			e.recordGuardMethodCall(typed, current, ctx)
			return
		}
		e.recordNegativeGuardMethodCall(typed, current, ctx)
	case *ast.ExprStaticCall:
		if truthy {
			e.recordGuardStaticCall(typed, current, ctx)
			return
		}
		e.recordNegativeGuardStaticCall(typed, current, ctx)
	}
}

func (e *engine) recordGuardCallWithNumber(node ast.Node, number int, equals bool, current callable, ctx *FlowContext) {
	call, ok := node.(*ast.ExprFuncCall)
	if !ok {
		return
	}
	switch normalizeName(identifierText(call.Name)) {
	case "get_current_user_id":
		if equals && number == 0 {
			ctx.UnauthChecks = append(ctx.UnauthChecks, locationForCallableNode(e, current, call))
		}
		if !equals && number == 0 {
			ctx.AuthChecks = append(ctx.AuthChecks, locationForCallableNode(e, current, call))
		}
		if equals && number != 0 {
			ctx.AuthChecks = append(ctx.AuthChecks, locationForCallableNode(e, current, call))
		}
	}
}

func (e *engine) recordGuardCall(call *ast.ExprFuncCall, current callable, ctx *FlowContext) bool {
	location := locationForCallableNode(e, current, call)
	switch normalizeName(identifierText(call.Name)) {
	case "current_user_can", "user_can":
		if !e.isDefiniteCapabilityGuardCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "wp_verify_nonce":
		ctx.NonceChecks = append(ctx.NonceChecks, location)
		return true
	case "is_user_logged_in", "get_current_user_id":
		ctx.AuthChecks = append(ctx.AuthChecks, location)
		return true
	case "hash_equals":
		if !e.hashEqualsLooksLikeStrongAuth(call, current, map[string]struct{}{}, map[string]struct{}{}) {
			return true
		}
		ctx.AuthChecks = append(ctx.AuthChecks, location)
		return true
	case "is_admin":
		ctx.AdminChecks = append(ctx.AdminChecks, location)
		return true
	case "wp_doing_ajax":
		ctx.AjaxChecks = append(ctx.AjaxChecks, location)
		return true
	}
	return false
}

func (e *engine) recordNegativeGuardCall(call *ast.ExprFuncCall, current callable, ctx *FlowContext) bool {
	location := locationForCallableNode(e, current, call)
	switch normalizeName(identifierText(call.Name)) {
	case "current_user_can", "user_can":
		if !e.isDefiniteCapabilityGuardCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "wp_verify_nonce":
		ctx.NonceChecks = append(ctx.NonceChecks, location)
		return true
	case "is_user_logged_in", "get_current_user_id":
		ctx.UnauthChecks = append(ctx.UnauthChecks, location)
		return true
	case "hash_equals":
		// A guard like `if ( ! hash_equals(...) ) { return false; }` means the
		// callable continues only on the authenticated token-matched path.
		if !e.hashEqualsLooksLikeStrongAuth(call, current, map[string]struct{}{}, map[string]struct{}{}) {
			return true
		}
		ctx.AuthChecks = append(ctx.AuthChecks, location)
		return true
	}
	return false
}

func (e *engine) hashEqualsLooksLikeStrongAuth(call *ast.ExprFuncCall, current callable, seenVars map[string]struct{}, seenExprs map[string]struct{}) bool {
	if call == nil || len(call.Args) < 2 {
		return true
	}
	for _, arg := range call.Args[:2] {
		if e.exprUsesPredictablePublicAuthSeed(argValue(arg), current, seenVars, seenExprs) {
			return false
		}
	}
	return true
}

func (e *engine) exprUsesPredictablePublicAuthSeed(node ast.Node, current callable, seenVars map[string]struct{}, seenExprs map[string]struct{}) bool {
	if node == nil {
		return false
	}
	if seenExprs == nil {
		seenExprs = map[string]struct{}{}
	}
	exprKey := current.Key + ":" + strconv.Itoa(node.StartLine()) + ":" + strings.TrimSpace(identifierText(node))
	if exprKey != ":" {
		if _, ok := seenExprs[exprKey]; ok {
			return false
		}
		seenExprs[exprKey] = struct{}{}
		defer delete(seenExprs, exprKey)
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return false
		}
		return e.localVariableUsesPredictablePublicAuthSeed(current, name, node.StartLine(), seenVars, seenExprs)
	case *ast.ExprFuncCall:
		switch normalizeName(identifierText(typed.Name)) {
		case "hash_hmac":
			if len(typed.Args) >= 3 && e.predictablePublicAuthSeedExpr(argValue(typed.Args[2]), current, seenVars, seenExprs) {
				return true
			}
		}
		for _, arg := range typed.Args {
			if e.exprUsesPredictablePublicAuthSeed(argValue(arg), current, seenVars, seenExprs) {
				return true
			}
		}
	case *ast.ExprMethodCall:
		switch normalizeName(identifierText(typed.Name)) {
		case "generate_token", "generatetoken", "get_secret_key", "getsecretkey":
			if e.methodReceiverUsesPredictablePublicAuthSeed(typed, current, seenVars, seenExprs) {
				return true
			}
		}
		for _, arg := range typed.Args {
			if e.exprUsesPredictablePublicAuthSeed(argValue(arg), current, seenVars, seenExprs) {
				return true
			}
		}
	case *ast.ExprStaticCall:
		for _, arg := range typed.Args {
			if e.exprUsesPredictablePublicAuthSeed(argValue(arg), current, seenVars, seenExprs) {
				return true
			}
		}
	}
	return false
}

func (e *engine) localVariableUsesPredictablePublicAuthSeed(current callable, name string, beforeLine int, seenVars map[string]struct{}, seenExprs map[string]struct{}) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if seenVars == nil {
		seenVars = map[string]struct{}{}
	}
	if _, ok := seenVars[name]; ok {
		return false
	}
	seenVars[name] = struct{}{}
	defer delete(seenVars, name)

	bestLine := -1
	var bestExpr ast.Node
	walkNodes(current.Stmts, func(node ast.Node) {
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
		line := assign.StartLine()
		if beforeLine > 0 && line >= beforeLine {
			return
		}
		if line >= bestLine {
			bestLine = line
			bestExpr = assign.Expr
		}
	})
	if bestExpr == nil {
		return false
	}
	if newExpr, ok := bestExpr.(*ast.ExprNew); ok {
		return e.newExprUsesPredictablePublicAuthSeed(newExpr, current, seenVars, seenExprs)
	}
	return e.exprUsesPredictablePublicAuthSeed(bestExpr, current, seenVars, seenExprs)
}

func (e *engine) methodReceiverUsesPredictablePublicAuthSeed(call *ast.ExprMethodCall, current callable, seenVars map[string]struct{}, seenExprs map[string]struct{}) bool {
	if call == nil {
		return false
	}
	switch receiver := call.Var.(type) {
	case *ast.ExprVariable:
		name, ok := receiver.Name.(string)
		if !ok {
			return false
		}
		return e.localVariableUsesPredictablePublicAuthSeed(current, name, call.StartLine(), seenVars, seenExprs)
	case *ast.ExprNew:
		return e.newExprUsesPredictablePublicAuthSeed(receiver, current, seenVars, seenExprs)
	default:
		return e.predictablePublicAuthSeedExpr(receiver, current, seenVars, seenExprs)
	}
}

func (e *engine) newExprUsesPredictablePublicAuthSeed(expr *ast.ExprNew, current callable, seenVars map[string]struct{}, seenExprs map[string]struct{}) bool {
	if expr == nil {
		return false
	}
	for _, arg := range expr.Args {
		if e.predictablePublicAuthSeedExpr(argValue(arg), current, seenVars, seenExprs) {
			return true
		}
	}
	return false
}

func (e *engine) predictablePublicAuthSeedExpr(node ast.Node, current callable, seenVars map[string]struct{}, seenExprs map[string]struct{}) bool {
	switch typed := node.(type) {
	case nil:
		return false
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return false
		}
		return e.localVariableUsesPredictablePublicAuthSeed(current, name, node.StartLine(), seenVars, seenExprs)
	case *ast.ExprConstFetch:
		name := normalizeGlobalConstName(identifierText(typed.Name))
		value := e.literalGlobalConstValue(name)
		if looksLikePublicPathOrURL(value) {
			return true
		}
		return strings.Contains(name, "base_file") || strings.Contains(name, "abspath") || strings.Contains(name, "plugin_file")
	case *ast.ScalarMagicConstFile, *ast.ScalarMagicConstDir:
		return true
	case *ast.ExprBinaryOpConcat:
		return e.predictablePublicAuthSeedExpr(typed.Left, current, seenVars, seenExprs) &&
			e.predictablePublicAuthSeedExpr(typed.Right, current, seenVars, seenExprs)
	case *ast.ExprFuncCall:
		switch normalizeName(identifierText(typed.Name)) {
		case "plugin_dir_path", "plugin_basename", "plugins_url", "site_url", "home_url", "realpath", "dirname", "trailingslashit", "wp_normalize_path":
			for _, arg := range typed.Args {
				if e.predictablePublicAuthSeedExpr(argValue(arg), current, seenVars, seenExprs) {
					return true
				}
			}
		}
	}
	return looksLikePublicPathOrURL(literalStringForCallableWithSeen(node, current, e, nil))
}

func looksLikePublicPathOrURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	return strings.Contains(value, "/") ||
		strings.Contains(value, "\\") ||
		strings.Contains(lower, ".php") ||
		strings.Contains(lower, "http://") ||
		strings.Contains(lower, "https://")
}

func (e *engine) recordGuardMethodCall(call *ast.ExprMethodCall, current callable, ctx *FlowContext) bool {
	location := locationForCallableNode(e, current, call)
	switch normalizeName(identifierText(call.Name)) {
	case "current_user_can", "user_can":
		if !e.isDefiniteCapabilityGuardMethodCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatepermission":
		if !e.isDefiniteCapabilityGuardMethodCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatetoken":
		ctx.NonceChecks = append(ctx.NonceChecks, location)
		return true
	}
	return false
}

func (e *engine) recordGuardStaticCall(call *ast.ExprStaticCall, current callable, ctx *FlowContext) bool {
	location := locationForCallableNode(e, current, call)
	switch normalizeName(identifierText(call.Name)) {
	case "current_user_can", "user_can":
		if !e.isDefiniteCapabilityGuardStaticCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatepermission":
		if !e.isDefiniteCapabilityGuardStaticCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatetoken":
		ctx.NonceChecks = append(ctx.NonceChecks, location)
		return true
	}
	return false
}

func (e *engine) recordNegativeGuardMethodCall(call *ast.ExprMethodCall, current callable, ctx *FlowContext) bool {
	location := locationForCallableNode(e, current, call)
	switch normalizeName(identifierText(call.Name)) {
	case "current_user_can", "user_can":
		if !e.isDefiniteCapabilityGuardMethodCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatepermission":
		if !e.isDefiniteCapabilityGuardMethodCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatetoken":
		ctx.NonceChecks = append(ctx.NonceChecks, location)
		return true
	}
	return false
}

func (e *engine) recordNegativeGuardStaticCall(call *ast.ExprStaticCall, current callable, ctx *FlowContext) bool {
	location := locationForCallableNode(e, current, call)
	switch normalizeName(identifierText(call.Name)) {
	case "current_user_can", "user_can":
		if !e.isDefiniteCapabilityGuardStaticCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatepermission":
		if !e.isDefiniteCapabilityGuardStaticCall(call, current) {
			return true
		}
		ctx.CapabilityChecks = append(ctx.CapabilityChecks, location)
		return true
	case "validatetoken":
		ctx.NonceChecks = append(ctx.NonceChecks, location)
		return true
	}
	return false
}

func (e *engine) isDefiniteCapabilityGuardCall(call *ast.ExprFuncCall, current callable) bool {
	if len(call.Args) == 0 {
		return true
	}
	return !e.isWeakCapabilityExpr(argValue(call.Args[0]), current, map[string]struct{}{})
}

func (e *engine) isDefiniteCapabilityGuardMethodCall(call *ast.ExprMethodCall, current callable) bool {
	if len(call.Args) == 0 {
		return true
	}
	return !e.isWeakCapabilityExpr(argValue(call.Args[0]), current, map[string]struct{}{})
}

func (e *engine) isDefiniteCapabilityGuardStaticCall(call *ast.ExprStaticCall, current callable) bool {
	if len(call.Args) == 0 {
		return true
	}
	return !e.isWeakCapabilityExpr(argValue(call.Args[0]), current, map[string]struct{}{})
}

func (e *engine) isWeakCapabilityExpr(node ast.Node, current callable, seenVars map[string]struct{}) bool {
	switch typed := node.(type) {
	case nil:
		return false
	case *ast.ScalarString, *ast.ScalarInt, *ast.ScalarFloat, *ast.ExprConstFetch:
		return false
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return true
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return true
		}
		if _, ok := seenVars[name]; ok {
			return true
		}
		seenVars[name] = struct{}{}
		return e.callableVariableAssignedWeakCapability(current, name, seenVars)
	case *ast.ExprFuncCall:
		switch normalizeName(identifierText(typed.Name)) {
		case "apply_filters", "apply_filters_ref_array":
			if len(typed.Args) == 0 {
				return true
			}
			hook := hookDispatchKeyForCallable(argValue(typed.Args[0]), current, e)
			if hook == "" || strings.Contains(hook, "{") {
				return true
			}
			for _, arg := range typed.Args[1:] {
				if e.exprContainsDirectRequestSyntax(argValue(arg), current) {
					return true
				}
			}
			return false
		default:
			return true
		}
	case *ast.ExprMethodCall:
		return isRequestGetterMethodCall(typed)
	case *ast.ExprStaticCall:
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		return isRequestGetterStaticCall(className, identifierText(typed.Name)) || isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name))
	default:
		return true
	}
}

func (e *engine) callableVariableAssignedWeakCapability(current callable, name string, seenVars map[string]struct{}) bool {
	weak := false
	assigned := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if weak || node == nil {
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
		assigned = true
		if e.isWeakCapabilityExpr(assign.Expr, current, seenVars) {
			weak = true
			return
		}
	})
	if !assigned {
		for _, param := range current.Params {
			if strings.TrimSpace(param) == name {
				return false
			}
		}
	}
	return weak
}

func (e *engine) guardLocalVariableContext(current callable, name string, seenVars map[string]struct{}) FlowContext {
	name = strings.TrimSpace(name)
	if name == "" {
		return FlowContext{}
	}
	if _, ok := seenVars[name]; ok {
		return FlowContext{}
	}
	seenVars[name] = struct{}{}
	ctx := FlowContext{}
	walkNodes(current.Stmts, func(node ast.Node) {
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
		e.inspectGuardConditionWithSeen(assign.Expr, current, &ctx, seenVars)
	})
	delete(seenVars, name)
	return normalizeFlowContext(ctx)
}

func (e *engine) exprContainsDirectRequestSyntax(node ast.Node, current callable) bool {
	found := false
	walkNodes([]ast.Node{node}, func(item ast.Node) {
		if found || item == nil {
			return
		}
		switch typed := item.(type) {
		case *ast.ExprVariable:
			if name, ok := typed.Name.(string); ok {
				switch strings.ToUpper(strings.TrimSpace(name)) {
				case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES":
					found = true
				}
			}
		case *ast.ExprArrayDimFetch:
			if name, ok := superglobalArrayRootName(typed.Var); ok {
				switch strings.ToUpper(strings.TrimSpace(name)) {
				case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES":
					found = true
				}
			}
		case *ast.ExprFuncCall:
			if isDirectRequestSourceFunc(identifierText(typed.Name)) {
				found = true
			}
			if len(typed.Args) > 0 && isPHPInputLiteral(argValue(typed.Args[0])) {
				found = true
			}
		case *ast.ExprMethodCall:
			if isRequestGetterMethodCall(typed) {
				found = true
			}
		case *ast.ExprStaticCall:
			className := resolveClassName(typed.Class, current.Class, e.classParents)
			if isRequestGetterStaticCall(className, identifierText(typed.Name)) || isRequestGetterStaticCall(identifierText(typed.Class), identifierText(typed.Name)) {
				found = true
			}
		}
	})
	return found
}

func booleanLiteral(node ast.Node) (bool, bool) {
	switch typed := node.(type) {
	case *ast.ExprConstFetch:
		switch normalizeName(identifierText(typed.Name)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func numericLiteral(node ast.Node) (int, bool) {
	switch typed := node.(type) {
	case *ast.ScalarInt:
		return typed.Value, true
	}
	return 0, false
}

func (e *engine) collectCallbackRegistrations(c callable) []callbackRegistration {
	return e.collectCallbackRegistrationsWithSeen(c, map[string]struct{}{})
}

func (e *engine) collectCallbackRegistrationsWithSeen(c callable, seen map[string]struct{}) []callbackRegistration {
	if c.Key == "" {
		return nil
	}
	if _, ok := seen[c.Key]; ok {
		return nil
	}
	seen[c.Key] = struct{}{}
	defer delete(seen, c.Key)
	return e.collectCallbackRegistrationsInNodes(c.Stmts, c, seen)
}

func (e *engine) collectCallbackRegistrationsInNodes(nodes []ast.Node, current callable, seen map[string]struct{}) []callbackRegistration {
	regs := make([]callbackRegistration, 0)
	for _, node := range nodes {
		regs = append(regs, e.collectCallbackRegistrationsInNode(node, current, seen)...)
	}
	return regs
}

func (e *engine) collectCallbackRegistrationsInNode(node ast.Node, current callable, seen map[string]struct{}) []callbackRegistration {
	switch typed := node.(type) {
	case nil:
		return nil
	case *ast.StmtExpression:
		return e.collectCallbackRegistrationsInExpr(typed.Expr, current, seen)
	case *ast.ExprFuncCall, *ast.ExprMethodCall, *ast.ExprStaticCall:
		return e.collectCallbackRegistrationsInExpr(node, current, seen)
	case *ast.StmtIf:
		if truth, ok := e.literalConditionTruthForCallable(typed.Cond, current, map[string]struct{}{}); ok {
			if truth {
				return e.collectCallbackRegistrationsInNodes(typed.Stmts, current, seen)
			}
			regs := make([]callbackRegistration, 0)
			matchedElseif := false
			for _, rawElseIf := range typed.Elseifs {
				elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
				if !ok {
					continue
				}
				elseifTruth, elseifKnown := e.literalConditionTruthForCallable(elseifStmt.Cond, current, map[string]struct{}{})
				if elseifKnown {
					if elseifTruth {
						regs = append(regs, e.collectCallbackRegistrationsInNodes(elseifStmt.Stmts, current, seen)...)
						matchedElseif = true
						break
					}
					continue
				}
				regs = append(regs, e.collectCallbackRegistrationsInNodes(elseifStmt.Stmts, current, seen)...)
			}
			if !matchedElseif && typed.Else != nil {
				if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
					regs = append(regs, e.collectCallbackRegistrationsInNodes(elseStmt.Stmts, current, seen)...)
				}
			}
			return regs
		}
		regs := make([]callbackRegistration, 0)
		regs = append(regs, e.collectCallbackRegistrationsInNodes(typed.Stmts, current, seen)...)
		for _, rawElseIf := range typed.Elseifs {
			elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
			if !ok {
				continue
			}
			regs = append(regs, e.collectCallbackRegistrationsInNodes(elseifStmt.Stmts, current, seen)...)
		}
		if typed.Else != nil {
			if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
				regs = append(regs, e.collectCallbackRegistrationsInNodes(elseStmt.Stmts, current, seen)...)
			}
		}
		return regs
	default:
		regs := make([]callbackRegistration, 0)
		for _, block := range childStatementBlocks(node) {
			regs = append(regs, e.collectCallbackRegistrationsInNodes(block, current, seen)...)
		}
		return regs
	}
}

func (e *engine) collectCallbackRegistrationsInExpr(node ast.Node, current callable, seen map[string]struct{}) []callbackRegistration {
	regs := make([]callbackRegistration, 0)
	switch typed := node.(type) {
	case *ast.ExprFuncCall:
		name := normalizeName(identifierText(typed.Name))
		switch name {
		case "add_action", "add_filter":
			regs = append(regs, e.collectHookRegistrations(name, typed, current)...)
		case "add_menu_page", "add_submenu_page",
			"add_dashboard_page", "add_posts_page", "add_media_page", "add_links_page",
			"add_pages_page", "add_comments_page", "add_theme_page", "add_plugins_page",
			"add_users_page", "add_management_page", "add_options_page":
			regs = append(regs, e.collectAdminPageRegistrations(name, typed, current)...)
		case "add_meta_box":
			regs = append(regs, e.collectMetaBoxRegistrations(typed, current)...)
		case "add_shortcode":
			regs = append(regs, e.collectShortcodeRegistrations(typed, current)...)
		case "register_rest_route":
			regs = append(regs, e.collectRestRouteRegistrations(typed, current)...)
		case "register_block_type", "register_block_type_from_metadata":
			regs = append(regs, e.collectBlockRegistrations(typed, current)...)
		}
		for _, key := range e.registrationWrapperFunctionKeys(typed, current) {
			regs = append(regs, e.collectCallbackRegistrationsWithSeen(e.callables[key], seen)...)
		}
		for _, key := range e.registrationFactoryConstructorKeys(typed, current) {
			regs = append(regs, e.collectCallbackRegistrationsWithSeen(e.callables[key], seen)...)
		}
	case *ast.ExprMethodCall:
		regs = append(regs, e.collectWPFluentRouterRegistrations(typed, current)...)
		for _, key := range e.registrationWrapperMethodKeys(typed, current) {
			regs = append(regs, e.collectCallbackRegistrationsWithSeen(e.callables[key], seen)...)
		}
		for _, key := range e.registrationFactoryConstructorKeys(typed, current) {
			regs = append(regs, e.collectCallbackRegistrationsWithSeen(e.callables[key], seen)...)
		}
	case *ast.ExprStaticCall:
		for _, key := range e.registrationWrapperStaticKeys(typed, current) {
			regs = append(regs, e.collectCallbackRegistrationsWithSeen(e.callables[key], seen)...)
		}
		for _, key := range e.registrationFactoryConstructorKeys(typed, current) {
			regs = append(regs, e.collectCallbackRegistrationsWithSeen(e.callables[key], seen)...)
		}
	}
	return regs
}

type wpFluentRouteGroupContext struct {
	Prefixes []string
	Policy   string
}

func mergeWPFluentRouteGroupContext(parent wpFluentRouteGroupContext, child wpFluentRouteGroupContext) wpFluentRouteGroupContext {
	merged := wpFluentRouteGroupContext{
		Prefixes: append([]string(nil), parent.Prefixes...),
		Policy:   parent.Policy,
	}
	for _, prefix := range child.Prefixes {
		prefix = strings.Trim(prefix, "/")
		if prefix == "" {
			continue
		}
		merged.Prefixes = append(merged.Prefixes, prefix)
	}
	if child.Policy != "" {
		merged.Policy = child.Policy
	}
	return merged
}

func wpFluentRouteMethod(name string) string {
	switch normalizeName(name) {
	case "get":
		return "GET"
	case "post":
		return "POST"
	case "put":
		return "PUT"
	case "patch":
		return "PATCH"
	case "delete":
		return "DELETE"
	case "any":
		return "ANY"
	default:
		return ""
	}
}

func buildWPFluentRoutePath(prefixes []string, route string) string {
	parts := make([]string, 0, len(prefixes)+1)
	for _, prefix := range prefixes {
		prefix = strings.Trim(prefix, "/")
		if prefix == "" {
			continue
		}
		parts = append(parts, prefix)
	}
	route = strings.Trim(route, "/")
	if route != "" {
		parts = append(parts, route)
	}
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func appendUniqueCallbackRegistration(regs []callbackRegistration, reg callbackRegistration) []callbackRegistration {
	for _, existing := range regs {
		if existing.TargetKey != reg.TargetKey {
			continue
		}
		if existing.Entry.Kind != reg.Entry.Kind || existing.Entry.Route != reg.Entry.Route || existing.Entry.Methods != reg.Entry.Methods || existing.Entry.Access != reg.Entry.Access {
			continue
		}
		if existing.Entry.Location.Path != reg.Entry.Location.Path || existing.Entry.Location.Line != reg.Entry.Location.Line {
			continue
		}
		if len(existing.PermissionKeys) != len(reg.PermissionKeys) {
			continue
		}
		samePermissionKeys := true
		for idx := range existing.PermissionKeys {
			if existing.PermissionKeys[idx] != reg.PermissionKeys[idx] {
				samePermissionKeys = false
				break
			}
		}
		if samePermissionKeys {
			return regs
		}
	}
	return append(regs, reg)
}

func (e *engine) collectWPFluentRouterRegistrations(call *ast.ExprMethodCall, current callable) []callbackRegistration {
	if normalizeName(identifierText(call.Name)) != "group" {
		return nil
	}
	groupCtx, closure, ok := e.wpFluentRouteGroupContext(call, current)
	if !ok || closure == nil {
		return nil
	}
	return e.collectWPFluentRouteRegistrationsInNodes(closure.Stmts, current, groupCtx)
}

func (e *engine) collectWPFluentRouteRegistrationsInNodes(nodes []ast.Node, current callable, ctx wpFluentRouteGroupContext) []callbackRegistration {
	regs := make([]callbackRegistration, 0)
	for _, node := range nodes {
		regs = append(regs, e.collectWPFluentRouteRegistrationsInNode(node, current, ctx)...)
	}
	return regs
}

func (e *engine) collectWPFluentRouteRegistrationsInNode(node ast.Node, current callable, ctx wpFluentRouteGroupContext) []callbackRegistration {
	switch typed := node.(type) {
	case *ast.StmtExpression:
		return e.collectWPFluentRouteRegistrationsInExpr(typed.Expr, current, ctx)
	case *ast.StmtIf:
		regs := e.collectWPFluentRouteRegistrationsInNodes(typed.Stmts, current, ctx)
		for _, rawElseIf := range typed.Elseifs {
			elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
			if !ok {
				continue
			}
			regs = append(regs, e.collectWPFluentRouteRegistrationsInNodes(elseifStmt.Stmts, current, ctx)...)
		}
		if typed.Else != nil {
			if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
				regs = append(regs, e.collectWPFluentRouteRegistrationsInNodes(elseStmt.Stmts, current, ctx)...)
			}
		}
		return regs
	default:
		regs := make([]callbackRegistration, 0)
		for _, block := range childStatementBlocks(node) {
			regs = append(regs, e.collectWPFluentRouteRegistrationsInNodes(block, current, ctx)...)
		}
		return regs
	}
}

func (e *engine) collectWPFluentRouteRegistrationsInExpr(node ast.Node, current callable, ctx wpFluentRouteGroupContext) []callbackRegistration {
	call, ok := node.(*ast.ExprMethodCall)
	if !ok {
		return nil
	}
	switch normalizeName(identifierText(call.Name)) {
	case "group":
		childCtx, closure, ok := e.wpFluentRouteGroupContext(call, current)
		if !ok || closure == nil {
			return nil
		}
		return e.collectWPFluentRouteRegistrationsInNodes(closure.Stmts, current, mergeWPFluentRouteGroupContext(ctx, childCtx))
	default:
		methods := wpFluentRouteMethod(identifierText(call.Name))
		if methods == "" || len(call.Args) < 2 {
			return nil
		}
		route := strings.TrimSpace(literalStringForCallable(argValue(call.Args[0]), current, e))
		handler := strings.TrimSpace(literalStringForCallable(argValue(call.Args[1]), current, e))
		if handler == "" {
			return nil
		}
		keys, handlerMethod := e.resolveWPFluentStringHandlerKeys(handler, current)
		if len(keys) == 0 {
			return nil
		}
		permissionKeys, access := e.resolveWPFluentPolicyHandlerKeys(ctx.Policy, handlerMethod, current)
		entry := EntryPoint{
			Kind:     "rest",
			Name:     "wpfluent",
			Route:    buildWPFluentRoutePath(ctx.Prefixes, route),
			Methods:  methods,
			Access:   access,
			Location: locationForCallableNode(e, current, call),
		}
		regs := make([]callbackRegistration, 0, len(keys))
		for _, reg := range registrationsForKeysWithPermission(keys, entry, permissionKeys) {
			regs = appendUniqueCallbackRegistration(regs, reg)
		}
		return regs
	}
}

func (e *engine) wpFluentRouteGroupContext(call *ast.ExprMethodCall, current callable) (wpFluentRouteGroupContext, *ast.ExprClosure, bool) {
	ctx := wpFluentRouteGroupContext{}
	if !e.applyWPFluentRouteGroupChain(call.Var, current, &ctx) {
		return wpFluentRouteGroupContext{}, nil, false
	}
	var closure *ast.ExprClosure
	if len(call.Args) > 0 {
		if arrayNode, ok := argValue(call.Args[0]).(*ast.ExprArray); ok {
			if prefix := strings.TrimSpace(literalStringForCallable(arrayValueForStringKey(arrayNode, "prefix"), current, e)); prefix != "" {
				ctx.Prefixes = append(ctx.Prefixes, strings.Trim(prefix, "/"))
			}
			if policy := strings.TrimSpace(literalStringForCallable(arrayValueForStringKey(arrayNode, "policy"), current, e)); policy != "" {
				ctx.Policy = policy
			}
		}
	}
	for _, arg := range call.Args {
		if candidate, ok := argValue(arg).(*ast.ExprClosure); ok {
			closure = candidate
			break
		}
	}
	if closure == nil {
		return wpFluentRouteGroupContext{}, nil, false
	}
	return ctx, closure, true
}

func (e *engine) applyWPFluentRouteGroupChain(node ast.Node, current callable, ctx *wpFluentRouteGroupContext) bool {
	switch typed := node.(type) {
	case *ast.ExprMethodCall:
		ok := e.applyWPFluentRouteGroupChain(typed.Var, current, ctx)
		switch normalizeName(identifierText(typed.Name)) {
		case "prefix":
			if len(typed.Args) > 0 {
				if prefix := strings.TrimSpace(literalStringForCallable(argValue(typed.Args[0]), current, e)); prefix != "" {
					ctx.Prefixes = append(ctx.Prefixes, strings.Trim(prefix, "/"))
					return true
				}
			}
		case "withpolicy":
			if len(typed.Args) > 0 {
				if policy := strings.TrimSpace(literalStringForCallable(argValue(typed.Args[0]), current, e)); policy != "" {
					ctx.Policy = policy
					return true
				}
			}
		case "name":
			return true
		}
		return ok
	case *ast.ExprVariable, *ast.ExprPropertyFetch, *ast.ExprStaticPropertyFetch:
		return true
	default:
		return false
	}
}

func appendUniqueStringValue(items []string, value string) []string {
	for _, existing := range items {
		if existing == value {
			return items
		}
	}
	return append(items, value)
}

func (e *engine) resolveWPFluentShortClassCandidates(classRef string, current callable) []string {
	classRef = strings.TrimSpace(classRef)
	if classRef == "" {
		return nil
	}
	out := make([]string, 0, 4)
	if strings.Contains(classRef, `\`) {
		resolved := resolveCallbackClassRefString(classRef, current)
		if resolved != "" {
			out = appendUniqueStringValue(out, resolved)
		}
		return out
	}
	out = append(out, e.lookupClassesByPattern("", `\`+classRef)...)
	if _, ok := e.methods[classRef]; ok {
		out = appendUniqueStringValue(out, classRef)
	}
	return out
}

func (e *engine) resolveWPFluentStringHandlerKeys(handler string, current callable) ([]string, string) {
	handler = strings.TrimSpace(handler)
	if handler == "" {
		return nil, ""
	}
	if strings.Contains(handler, "@") {
		parts := strings.SplitN(handler, "@", 2)
		classCandidates := e.resolveWPFluentShortClassCandidates(parts[0], current)
		keys := make([]string, 0, len(classCandidates))
		for _, className := range classCandidates {
			if key := e.ensureRuntimeMethodCallable(className, parts[1]); key != "" {
				keys = appendUniqueStringValue(keys, key)
			}
		}
		return keys, strings.TrimSpace(parts[1])
	}
	if strings.Contains(handler, "::") {
		parts := strings.SplitN(handler, "::", 2)
		classCandidates := e.resolveWPFluentShortClassCandidates(parts[0], current)
		keys := make([]string, 0, len(classCandidates))
		for _, className := range classCandidates {
			if key := e.ensureRuntimeMethodCallable(className, parts[1]); key != "" {
				keys = appendUniqueStringValue(keys, key)
			}
		}
		return keys, strings.TrimSpace(parts[1])
	}
	if key := e.lookupFunctionKey(current.Namespace, handler); key != "" {
		return []string{key}, ""
	}
	return nil, ""
}

func (e *engine) resolveWPFluentPolicyHandlerKeys(policy string, handlerMethod string, current callable) ([]string, string) {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return nil, "unauthenticated"
	}
	classRef := policy
	methodName := strings.TrimSpace(handlerMethod)
	if strings.Contains(policy, "@") {
		parts := strings.SplitN(policy, "@", 2)
		classRef = strings.TrimSpace(parts[0])
		methodName = strings.TrimSpace(parts[1])
	} else if strings.Contains(policy, "::") {
		parts := strings.SplitN(policy, "::", 2)
		classRef = strings.TrimSpace(parts[0])
		methodName = strings.TrimSpace(parts[1])
	}
	classCandidates := e.resolveWPFluentShortClassCandidates(classRef, current)
	permissionKeys := make([]string, 0, len(classCandidates))
	fallbackKeys := make([]string, 0, len(classCandidates))
	for _, className := range classCandidates {
		if methodName != "" {
			if key := e.ensureRuntimeMethodCallable(className, methodName); key != "" {
				permissionKeys = appendUniqueStringValue(permissionKeys, key)
				continue
			}
		}
		if key := e.ensureRuntimeMethodCallable(className, "verifyRequest"); key != "" {
			permissionKeys = appendUniqueStringValue(permissionKeys, key)
			continue
		}
		if key := e.ensureRuntimeMethodCallable(className, "__returnTrue"); key != "" {
			fallbackKeys = appendUniqueStringValue(fallbackKeys, key)
		}
	}
	if len(permissionKeys) != 0 {
		return permissionKeys, "permission_callback"
	}
	if len(fallbackKeys) != 0 {
		return fallbackKeys, "unauthenticated"
	}
	return nil, "permission_callback"
}

func (e *engine) literalConditionTruthForCallable(node ast.Node, current callable, seen map[string]struct{}) (bool, bool) {
	switch typed := node.(type) {
	case nil:
		return false, false
	case *ast.ExprBooleanNot:
		if value, ok := e.literalConditionTruthForCallable(typed.Expr, current, seen); ok {
			return !value, true
		}
		return false, false
	case *ast.ExprBinaryOpBooleanAnd:
		return e.literalBooleanAndTruth(typed.Left, typed.Right, current, seen)
	case *ast.ExprBinaryOpLogicalAnd:
		return e.literalBooleanAndTruth(typed.Left, typed.Right, current, seen)
	case *ast.ExprBinaryOpBooleanOr:
		return e.literalBooleanOrTruth(typed.Left, typed.Right, current, seen)
	case *ast.ExprBinaryOpLogicalOr:
		return e.literalBooleanOrTruth(typed.Left, typed.Right, current, seen)
	case *ast.ExprBinaryOpIdentical:
		if value, ok := e.literalScalarComparisonTruth(typed.Left, typed.Right, true, current, seen); ok {
			return value, true
		}
		return e.literalBooleanComparisonTruth(typed.Left, typed.Right, true, current, seen)
	case *ast.ExprBinaryOpEqual:
		if value, ok := e.literalScalarComparisonTruth(typed.Left, typed.Right, true, current, seen); ok {
			return value, true
		}
		return e.literalBooleanComparisonTruth(typed.Left, typed.Right, true, current, seen)
	case *ast.ExprBinaryOpNotIdentical:
		if value, ok := e.literalScalarComparisonTruth(typed.Left, typed.Right, false, current, seen); ok {
			return value, true
		}
		return e.literalBooleanComparisonTruth(typed.Left, typed.Right, false, current, seen)
	case *ast.ExprBinaryOpNotEqual:
		if value, ok := e.literalScalarComparisonTruth(typed.Left, typed.Right, false, current, seen); ok {
			return value, true
		}
		return e.literalBooleanComparisonTruth(typed.Left, typed.Right, false, current, seen)
	}
	return e.literalBooleanValueForCallable(node, current, seen)
}

func (e *engine) literalScalarComparisonTruth(left ast.Node, right ast.Node, equals bool, current callable, seen map[string]struct{}) (bool, bool) {
	leftValue, leftKnown := literalScalarValueForCallable(left, current, e, seen)
	rightValue, rightKnown := literalScalarValueForCallable(right, current, e, seen)
	if !leftKnown || !rightKnown {
		return false, false
	}
	if equals {
		return leftValue == rightValue, true
	}
	return leftValue != rightValue, true
}

func literalScalarValueForCallable(node ast.Node, current callable, e *engine, seen map[string]struct{}) (string, bool) {
	if truth, ok := booleanLiteral(node); ok {
		if truth {
			return "bool:true", true
		}
		return "bool:false", true
	}
	if number, ok := numericLiteral(node); ok {
		return "num:" + strconv.Itoa(number), true
	}
	if value := literalStringForCallableWithSeen(node, current, e, seen); value != "" {
		return "str:" + value, true
	}
	switch typed := node.(type) {
	case *ast.ScalarString, *ast.ScalarInterpolatedString:
		return "str:" + literalStringForCallableWithSeen(typed, current, e, seen), true
	case *ast.ExprConstFetch:
		if strings.EqualFold(identifierText(typed.Name), "null") {
			return "null", true
		}
	}
	return "", false
}

func (e *engine) literalBooleanAndTruth(left ast.Node, right ast.Node, current callable, seen map[string]struct{}) (bool, bool) {
	leftValue, leftKnown := e.literalConditionTruthForCallable(left, current, seen)
	rightValue, rightKnown := e.literalConditionTruthForCallable(right, current, seen)
	if leftKnown && !leftValue {
		return false, true
	}
	if rightKnown && !rightValue {
		return false, true
	}
	if leftKnown && rightKnown {
		return leftValue && rightValue, true
	}
	return false, false
}

func (e *engine) literalBooleanOrTruth(left ast.Node, right ast.Node, current callable, seen map[string]struct{}) (bool, bool) {
	leftValue, leftKnown := e.literalConditionTruthForCallable(left, current, seen)
	rightValue, rightKnown := e.literalConditionTruthForCallable(right, current, seen)
	if leftKnown && leftValue {
		return true, true
	}
	if rightKnown && rightValue {
		return true, true
	}
	if leftKnown && rightKnown {
		return leftValue || rightValue, true
	}
	return false, false
}

func (e *engine) literalBooleanComparisonTruth(left ast.Node, right ast.Node, equals bool, current callable, seen map[string]struct{}) (bool, bool) {
	leftValue, leftKnown := e.literalBooleanValueForCallable(left, current, seen)
	rightValue, rightKnown := e.literalBooleanValueForCallable(right, current, seen)
	if !leftKnown || !rightKnown {
		return false, false
	}
	if equals {
		return leftValue == rightValue, true
	}
	return leftValue != rightValue, true
}

func (e *engine) literalBooleanValueForCallable(node ast.Node, current callable, seen map[string]struct{}) (bool, bool) {
	if truth, ok := booleanLiteral(node); ok {
		return truth, true
	}
	switch typed := node.(type) {
	case *ast.ExprFuncCall:
		if len(typed.Args) == 0 {
			switch normalizeName(identifierText(typed.Name)) {
			case "__return_true":
				return true, true
			case "__return_false":
				return false, true
			}
			if key := e.lookupFunctionKey(current.Namespace, identifierText(typed.Name)); key != "" {
				return e.literalCallableReturnBool(key, seen)
			}
		}
	case *ast.ExprMethodCall:
		if len(typed.Args) == 0 {
			className := e.resolveCallbackClassRef(typed.Var, current)
			if className == "" {
				className = e.resolveMethodCallClass(typed, current)
			}
			if className != "" {
				if key := e.ensureRuntimeMethodCallable(className, identifierText(typed.Name)); key != "" {
					return e.literalCallableReturnBool(key, seen)
				}
			}
		}
	case *ast.ExprStaticCall:
		if len(typed.Args) == 0 {
			className := resolveClassName(typed.Class, current.Class, e.classParents)
			if key := e.ensureRuntimeMethodCallable(className, identifierText(typed.Name)); key != "" {
				return e.literalCallableReturnBool(key, seen)
			}
		}
	}
	value := strings.ToLower(strings.TrimSpace(strings.Trim(literalStringForCallableWithSeen(node, current, e, seen), `"'`)))
	switch value {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func (e *engine) literalCallableReturnBool(key string, seen map[string]struct{}) (bool, bool) {
	if key == "" {
		return false, false
	}
	if _, ok := seen[key]; ok {
		return false, false
	}
	c, ok := e.callables[key]
	if !ok {
		return false, false
	}
	seen[key] = struct{}{}
	defer delete(seen, key)
	var ret ast.Node
	for _, stmt := range c.Stmts {
		switch typed := stmt.(type) {
		case *ast.StmtReturn:
			if ret != nil {
				return false, false
			}
			ret = typed.Expr
		case *ast.StmtNop:
			continue
		default:
			return false, false
		}
	}
	if ret == nil {
		return false, false
	}
	return e.literalConditionTruthForCallable(ret, c, seen)
}

func isRegistrationWrapperName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "init", "register", "boot", "hooks", "registerhooks", "register_hooks", "routes", "registerroutes", "register_routes":
		return true
	default:
		return false
	}
}

func (e *engine) registrationWrapperFunctionKeys(call *ast.ExprFuncCall, current callable) []string {
	if len(call.Args) != 0 || !isRegistrationWrapperName(identifierText(call.Name)) {
		return nil
	}
	if key := e.lookupFunctionKey(current.Namespace, identifierText(call.Name)); key != "" {
		return []string{key}
	}
	return nil
}

func (e *engine) registrationWrapperMethodKeys(call *ast.ExprMethodCall, current callable) []string {
	if len(call.Args) != 0 || !isRegistrationWrapperName(identifierText(call.Name)) {
		return nil
	}
	className := e.resolveCallbackClassRef(call.Var, current)
	if className == "" {
		className = e.resolveMethodCallClass(call, current)
	}
	if className == "" {
		return nil
	}
	if key := e.ensureRuntimeMethodCallable(className, identifierText(call.Name)); key != "" {
		return []string{key}
	}
	return nil
}

func (e *engine) registrationWrapperStaticKeys(call *ast.ExprStaticCall, current callable) []string {
	if len(call.Args) != 0 || !isRegistrationWrapperName(identifierText(call.Name)) {
		return nil
	}
	className := resolveClassName(call.Class, current.Class, e.classParents)
	if className == "" {
		return nil
	}
	if key := e.ensureRuntimeMethodCallable(className, identifierText(call.Name)); key != "" {
		return []string{key}
	}
	return nil
}

func (e *engine) directFileEntryPoint(c callable) (EntryPoint, bool) {
	if !strings.HasPrefix(c.Key, "file::") {
		return EntryPoint{}, false
	}
	if e.fileHasWordPressBootstrapGuard(c) {
		return EntryPoint{}, false
	}
	var location Location
	found := false
	walkNodes(c.Stmts, func(node ast.Node) {
		if found {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprVariable:
			name, ok := typed.Name.(string)
			if !ok || !isDirectFileSourceVariable(name, nil) {
				return
			}
			location = locationForCallableNode(e, c, typed)
			found = true
		case *ast.ExprArrayDimFetch:
			variable, ok := typed.Var.(*ast.ExprVariable)
			if !ok {
				return
			}
			name, ok := variable.Name.(string)
			if !ok || !isDirectFileSourceVariable(name, typed.Dim) {
				return
			}
			location = locationForCallableNode(e, c, typed)
			found = true
		case *ast.ExprFuncCall:
			if !isDirectRequestSourceFunc(identifierText(typed.Name)) {
				return
			}
			location = locationForCallableNode(e, c, typed)
			found = true
		}
	})
	if !found {
		return EntryPoint{}, false
	}
	return EntryPoint{
		Kind:     "file",
		Name:     c.SourcePath,
		Access:   "unknown",
		Location: location,
	}, true
}

func (e *engine) fileHasWordPressBootstrapGuard(c callable) bool {
	file, ok := e.fileIndex[c.SourcePath]
	if !ok || c.StartLine < 1 || c.StartLine > len(file.Lines) {
		return false
	}
	start := c.StartLine - 1
	end := start + 24
	if end > len(file.Lines) {
		end = len(file.Lines)
	}
	meaningful := make([]string, 0, 8)
	for idx := start; idx < end && len(meaningful) < 8; idx++ {
		line := strings.TrimSpace(file.Lines[idx])
		switch {
		case line == "",
			line == "<?php",
			strings.HasPrefix(line, "//"),
			strings.HasPrefix(line, "#"),
			strings.HasPrefix(line, "/*"),
			strings.HasPrefix(line, "*"),
			strings.HasPrefix(line, "*/"),
			strings.HasPrefix(line, "use "),
			strings.HasPrefix(line, "namespace "):
			continue
		default:
			meaningful = append(meaningful, line)
		}
	}
	if len(meaningful) == 0 {
		return false
	}
	joined := strings.ToLower(strings.Join(meaningful, ""))
	replacer := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", `"`, `'`)
	normalized := replacer.Replace(joined)
	return strings.Contains(normalized, "defined('abspath')||exit") ||
		strings.Contains(normalized, "defined('abspath')ordie") ||
		strings.Contains(normalized, "if(!defined('abspath'))exit") ||
		strings.Contains(normalized, "if(!defined('abspath')){exit") ||
		strings.Contains(normalized, "if(!defined('abspath'))die") ||
		strings.Contains(normalized, "if(!defined('abspath')){die")
}

func isDirectFileSourceVariable(name string, dim ast.Node) bool {
	switch name {
	case "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES":
		return true
	case "_SERVER":
		if dim == nil {
			return true
		}
		key := strings.ToUpper(literalString(dim))
		switch key {
		case "REQUEST_URI", "PATH_INFO", "REDIRECT_URL", "DOCUMENT_URI", "HTTP_HOST":
			return true
		default:
			return strings.HasPrefix(key, "HTTP_")
		}
	default:
		return false
	}
}

func appendUniqueString(items []string, value string) []string {
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

func isActionRegistrationKind(kind string) bool {
	switch kind {
	case "hook", "ajax", "admin_post", "front_hook", "rest_init":
		return true
	default:
		return false
	}
}

func (e *engine) shouldAttachRegistrationEntryPoint(entry EntryPoint) bool {
	switch entry.Kind {
	case "hook", "filter":
		if entry.Kind == "filter" {
			if e.allowsSinkOp("sql") {
				if _, ok := sqlClauseFilterModelForHook(entry.Name); ok {
					return true
				}
			}
			if e.allowsSinkOp("surface") {
				if _, ok := uploadValidationFilterModelForHook(entry.Name); ok {
					return true
				}
			}
			return false
		}
		return false
	default:
		return true
	}
}

func (e *engine) indexCallbackRegistration(reg callbackRegistration) {
	if reg.TargetKey == "" || reg.Entry.Name == "" {
		return
	}
	if reg.Entry.Kind == "filter" {
		e.filterCallbacks[reg.Entry.Name] = appendUniqueString(e.filterCallbacks[reg.Entry.Name], reg.TargetKey)
		return
	}
	if isActionRegistrationKind(reg.Entry.Kind) {
		e.actionCallbacks[reg.Entry.Name] = appendUniqueString(e.actionCallbacks[reg.Entry.Name], reg.TargetKey)
	}
}

func (e *engine) indexAllCallbackRegistrations() {
	for idx := 0; idx < len(e.callOrder); idx++ {
		key := e.callOrder[idx]
		for _, reg := range e.collectCallbackRegistrations(e.callables[key]) {
			e.indexCallbackRegistration(reg)
		}
	}
}

func (e *engine) dispatchCallbackKeys(kind string, hook string) []string {
	hook = strings.TrimSpace(hook)
	if hook == "" {
		return nil
	}
	switch kind {
	case "do_action", "do_action_ref_array":
		return dispatchCallbackKeysForHook(e.actionCallbacks, hook)
	case "apply_filters", "apply_filters_ref_array":
		return dispatchCallbackKeysForHook(e.filterCallbacks, hook)
	default:
		return nil
	}
}

func (e *engine) dispatchRelevantCallbackKeys(kind string, hook string) []string {
	keys := e.dispatchCallbackKeys(kind, hook)
	return e.batchRelevantCallbackKeys(keys)
}

func (e *engine) batchRelevantCallbackKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	if e.currentBatchName == "" || len(e.relevantCallables) == 0 {
		return keys
	}
	filtered := make([]string, 0, len(keys))
	for _, key := range keys {
		if _, ok := e.relevantCallables[key]; ok {
			filtered = append(filtered, key)
		}
	}
	return filtered
}

func dispatchCallbackKeysForHook(index map[string][]string, hook string) []string {
	if !strings.Contains(hook, "{") {
		return append([]string(nil), index[hook]...)
	}
	if !hookPatternHasLiteral(hook) {
		return nil
	}
	out := make([]string, 0)
	for registeredHook, keys := range index {
		if !hookPatternMatches(hook, registeredHook) {
			continue
		}
		for _, key := range keys {
			out = appendUniqueString(out, key)
		}
	}
	return out
}

func hookPatternHasLiteral(pattern string) bool {
	for {
		start := strings.Index(pattern, "{")
		if start == -1 {
			return strings.TrimSpace(pattern) != ""
		}
		if strings.TrimSpace(pattern[:start]) != "" {
			return true
		}
		end := strings.Index(pattern[start:], "}")
		if end == -1 {
			return strings.TrimSpace(pattern) != ""
		}
		pattern = pattern[start+end+1:]
	}
}

func hookPatternMatches(pattern string, value string) bool {
	if !strings.Contains(pattern, "{") {
		return pattern == value
	}
	originalPattern := pattern
	segments := make([]string, 0, 4)
	for len(pattern) > 0 {
		start := strings.Index(pattern, "{")
		if start == -1 {
			segments = append(segments, pattern)
			break
		}
		segments = append(segments, pattern[:start])
		end := strings.Index(pattern[start:], "}")
		if end == -1 {
			return false
		}
		pattern = pattern[start+end+1:]
	}
	pos := 0
	anchoredPrefix := !strings.HasPrefix(originalPattern, "{")
	anchoredSuffix := !strings.HasSuffix(originalPattern, "}")
	for idx, segment := range segments {
		if segment == "" {
			continue
		}
		if idx == 0 && anchoredPrefix {
			if !strings.HasPrefix(value, segment) {
				return false
			}
			pos = len(segment)
			continue
		}
		next := strings.Index(value[pos:], segment)
		if next == -1 {
			return false
		}
		pos += next + len(segment)
	}
	if anchoredSuffix && len(segments) > 0 {
		last := segments[len(segments)-1]
		if last != "" && !strings.HasSuffix(value, last) {
			return false
		}
	}
	return true
}

func (e *engine) collectHookRegistrations(kind string, call *ast.ExprFuncCall, current callable) []callbackRegistration {
	if len(call.Args) < 2 {
		return nil
	}
	hook := hookDispatchKeyForCallable(argValue(call.Args[0]), current, e)
	if hook == "" {
		return nil
	}
	entry := classifyHookEntryPoint(hook, locationForCallableNode(e, current, call))
	if kind == "add_filter" {
		entry.Kind = "filter"
		entry.Access = "unknown"
	}
	keys := e.resolveCallbackKeys(argValue(call.Args[1]), current)
	return registrationsForKeys(keys, entry)
}

func (e *engine) collectAdminPageRegistrations(kind string, call *ast.ExprFuncCall, current callable) []callbackRegistration {
	var capabilityIdx, slugIdx, callbackIdx int
	switch kind {
	case "add_submenu_page":
		if len(call.Args) < 6 {
			return nil
		}
		capabilityIdx = 3
		slugIdx = 4
		callbackIdx = 5
	default:
		if len(call.Args) < 5 {
			return nil
		}
		capabilityIdx = 2
		slugIdx = 3
		callbackIdx = 4
	}
	entry := EntryPoint{
		Kind:     "admin_page",
		Name:     literalStringForCallable(argValue(call.Args[slugIdx]), current, e),
		Access:   "authenticated",
		Location: locationForCallableNode(e, current, call),
	}
	keys := e.resolveCallbackKeys(argValue(call.Args[callbackIdx]), current)
	if len(keys) == 0 {
		return nil
	}
	capability := strings.TrimSpace(strings.Trim(literalStringForCallable(argValue(call.Args[capabilityIdx]), current, e), `"'`))
	if capability != "" {
		entry.Methods = capability
	}
	return registrationsForKeys(keys, entry)
}

func (e *engine) collectMetaBoxRegistrations(call *ast.ExprFuncCall, current callable) []callbackRegistration {
	if len(call.Args) < 3 {
		return nil
	}
	name := strings.TrimSpace(literalStringForCallable(argValue(call.Args[3]), current, e))
	if name == "" {
		name = strings.TrimSpace(literalStringForCallable(argValue(call.Args[0]), current, e))
	}
	if name == "" {
		name = "meta_box"
	}
	entry := EntryPoint{
		Kind:     "admin_page",
		Name:     name,
		Access:   "authenticated",
		Location: locationForCallableNode(e, current, call),
	}
	keys := e.resolveCallbackKeys(argValue(call.Args[2]), current)
	return registrationsForKeys(keys, entry)
}

func (e *engine) collectShortcodeRegistrations(call *ast.ExprFuncCall, current callable) []callbackRegistration {
	if len(call.Args) < 2 {
		return nil
	}
	tag := literalStringForCallable(argValue(call.Args[0]), current, e)
	if tag == "" {
		return nil
	}
	entry := EntryPoint{
		Kind:     "shortcode",
		Name:     tag,
		Access:   "unauthenticated",
		Location: locationForCallableNode(e, current, call),
	}
	keys := e.resolveCallbackKeys(argValue(call.Args[1]), current)
	return registrationsForKeys(keys, entry)
}

func (e *engine) collectRestRouteRegistrations(call *ast.ExprFuncCall, current callable) []callbackRegistration {
	if len(call.Args) < 3 {
		return nil
	}
	namespace := literalStringForCallable(argValue(call.Args[0]), current, e)
	route := literalStringForCallable(argValue(call.Args[1]), current, e)
	location := locationForCallableNode(e, current, call)
	return e.expandRestRouteRegistrations(argValue(call.Args[2]), current, location, namespace, route)
}

func (e *engine) collectBlockRegistrations(call *ast.ExprFuncCall, current callable) []callbackRegistration {
	if len(call.Args) == 0 {
		return nil
	}
	var settings ast.Node
	switch normalizeName(identifierText(call.Name)) {
	case "register_block_type":
		if len(call.Args) < 2 {
			return nil
		}
		settings = argValue(call.Args[1])
	case "register_block_type_from_metadata":
		if len(call.Args) < 2 {
			return nil
		}
		settings = argValue(call.Args[1])
	default:
		return nil
	}
	arrayNode, ok := settings.(*ast.ExprArray)
	if !ok {
		return nil
	}
	callbackNode := arrayValueForStringKey(arrayNode, "render_callback")
	if callbackNode == nil {
		return nil
	}
	entry := EntryPoint{
		Kind:     "block",
		Name:     literalStringForCallable(argValue(call.Args[0]), current, e),
		Access:   "unauthenticated",
		Location: locationForCallableNode(e, current, call),
	}
	keys := e.resolveCallbackKeys(callbackNode, current)
	return registrationsForKeys(keys, entry)
}

func (e *engine) expandRestRouteRegistrations(node ast.Node, current callable, location Location, namespace string, route string) []callbackRegistration {
	arrayNode, ok := node.(*ast.ExprArray)
	if !ok {
		return nil
	}
	regs := make([]callbackRegistration, 0)
	if callbackNode := arrayValueForStringKey(arrayNode, "callback"); callbackNode != nil {
		permissionNode := arrayValueForStringKey(arrayNode, "permission_callback")
		entry := EntryPoint{
			Kind:     "rest",
			Name:     strings.Trim(strings.TrimSpace(namespace), "/"),
			Route:    joinRestRoute(namespace, route),
			Methods:  literalString(arrayValueForStringKey(arrayNode, "methods")),
			Access:   restPermissionAccess(permissionNode),
			Location: location,
		}
		keys := e.resolveCallbackKeys(callbackNode, current)
		permissionKeys := e.resolveCallbackKeys(permissionNode, current)
		regs = append(regs, registrationsForKeysWithPermission(keys, entry, permissionKeys)...)
	}
	for _, itemNode := range arrayNode.Items {
		item, ok := itemNode.(*ast.ArrayItem)
		if !ok || item.Key != nil {
			continue
		}
		regs = append(regs, e.expandRestRouteRegistrations(item.Value, current, location, namespace, route)...)
	}
	return regs
}

func (e *engine) resolveCallbackKeys(node ast.Node, current callable) []string {
	return e.resolveCallbackKeysWithEnv(node, current, nil)
}

func closureCallableKey(current callable, closure *ast.ExprClosure) string {
	if closure == nil {
		return ""
	}
	return "closure::" + current.SourcePath + "::" + current.Key + "::" + strconv.Itoa(closure.StartLine())
}

func appendUniqueLowerString(items []string, value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
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

func exactCallbackMethodValuesFromIterable(expr ast.Node, current callable, e *engine, stringEnv map[string]string, resolver *localArrayLiteralResolver, beforeLine int, state *dispatchResolutionState, seen map[string]struct{}) []string {
	switch typed := expr.(type) {
	case nil:
		return nil
	case *ast.ExprArray:
		out := make([]string, 0)
		for _, item := range arrayItems(typed) {
			value := strings.TrimSpace(dynamicDispatchStringForCallableWithState(item, current, e, stringEnv, state))
			if value == "" || strings.Contains(value, "{") {
				return nil
			}
			out = appendUniqueLowerString(out, value)
		}
		return out
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return nil
		}
		seenKey := "callback-iterable::" + current.Key + "::" + name
		if _, ok := seen[seenKey]; ok {
			return nil
		}
		seen[seenKey] = struct{}{}
		defer delete(seen, seenKey)
		if stringEnv != nil {
			if value := strings.TrimSpace(stringEnv[name]); value != "" && value != conflictingLiteralArgHint && !strings.Contains(value, "{") {
				return []string{strings.ToLower(value)}
			}
		}
		if resolver == nil {
			resolver = newLocalArrayLiteralResolver(current)
		}
		if arrayNode, _ := resolver.latest(name, beforeLine); arrayNode != nil {
			return exactCallbackMethodValuesFromIterable(arrayNode, current, e, stringEnv, resolver, beforeLine, state, seen)
		}
		if latestExpr, _ := resolver.latestExpr(name, beforeLine); latestExpr != nil {
			return exactCallbackMethodValuesFromIterable(latestExpr, current, e, stringEnv, resolver, beforeLine, state, seen)
		}
	default:
		value := strings.TrimSpace(dynamicDispatchStringForCallableWithState(expr, current, e, stringEnv, state))
		if value != "" && !strings.Contains(value, "{") {
			return []string{strings.ToLower(value)}
		}
	}
	return nil
}

func (e *engine) localExactCallbackMethodValues(current callable, name string, stringEnv map[string]string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	out := make([]string, 0)
	add := func(value string) {
		out = appendUniqueLowerString(out, value)
	}
	if stringEnv != nil {
		if value := strings.TrimSpace(stringEnv[name]); value != "" && value != conflictingLiteralArgHint && !strings.Contains(value, "{") {
			add(value)
		}
	}
	state := newDispatchResolutionState()
	resolver := e.localArrayLiteralResolver(current)
	walkNodes(current.Stmts, func(node ast.Node) {
		switch typed := node.(type) {
		case *ast.ExprAssign:
			variable, ok := typed.Var.(*ast.ExprVariable)
			if !ok {
				return
			}
			varName, ok := variable.Name.(string)
			if !ok || strings.TrimSpace(varName) != name {
				return
			}
			if value := strings.TrimSpace(dynamicDispatchStringForCallableWithState(typed.Expr, current, e, stringEnv, state)); value != "" && !strings.Contains(value, "{") {
				add(value)
			}
		case *ast.StmtForeach:
			valueVar, ok := typed.ValueVar.(*ast.ExprVariable)
			if !ok {
				return
			}
			varName, ok := valueVar.Name.(string)
			if !ok || strings.TrimSpace(varName) != name {
				return
			}
			for _, value := range exactCallbackMethodValuesFromIterable(typed.Expr, current, e, stringEnv, resolver, typed.StartLine(), state, map[string]struct{}{}) {
				add(value)
			}
		}
	})
	return out
}

func (e *engine) exactCallbackMethodNames(node ast.Node, current callable, stringEnv map[string]string) []string {
	if value := strings.TrimSpace(dynamicDispatchStringForCallable(node, current, e, stringEnv)); value != "" && !strings.Contains(value, "{") {
		return []string{strings.ToLower(value)}
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return nil
		}
		return e.localExactCallbackMethodValues(current, name, stringEnv)
	}
	return nil
}

func (e *engine) resolveCallbackKeysWithEnv(node ast.Node, current callable, stringEnv map[string]string) []string {
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
			add(e.ensureRuntimeMethodCallable(resolveCallbackClassRefString(parts[0], current), parts[1]))
			return keys
		}
		add(e.lookupFunctionKey(current.Namespace, name))
		add(e.ensureRuntimeMethodCallable(current.Class, name))
	case *ast.ExprClosure:
		key := closureCallableKey(current, typed)
		if key == "" {
			return keys
		}
		if _, ok := e.callables[key]; ok {
			add(key)
			return keys
		}
		if e.currentBatchName == "" {
			add(e.ensureClosureCallable(current, typed))
		}
	case *ast.ExprArray:
		items := arrayItems(typed)
		if len(items) < 2 {
			return keys
		}
		exactMethodNames := e.exactCallbackMethodNames(items[1], current, stringEnv)
		if len(exactMethodNames) != 0 {
			for _, className := range e.resolveCallbackClassRefsWithSeen(items[0], current, map[string]struct{}{}) {
				if className == "" {
					continue
				}
				for _, methodName := range exactMethodNames {
					add(e.ensureRuntimeMethodCallable(className, methodName))
				}
			}
			if len(keys) != 0 {
				return keys
			}
		}
		methodName := strings.ToLower(strings.TrimSpace(dynamicDispatchStringForCallable(items[1], current, e, stringEnv)))
		if methodName == "" {
			methodName = strings.ToLower(strings.TrimSpace(callbackMethodName(items[1])))
		}
		for _, className := range e.resolveCallbackClassRefsWithSeen(items[0], current, map[string]struct{}{}) {
			if className == "" || methodName == "" {
				continue
			}
			if !strings.Contains(methodName, "{") {
				add(e.ensureRuntimeMethodCallable(className, methodName))
				continue
			}
			prefixEnd := strings.Index(methodName, "{")
			suffixStart := strings.LastIndex(methodName, "}")
			if prefixEnd < 0 || suffixStart < prefixEnd {
				continue
			}
			for _, key := range e.lookupMethodKeysByPattern(className, methodName[:prefixEnd], methodName[suffixStart+1:]) {
				add(key)
			}
		}
	}
	return keys
}

func (e *engine) ensureClosureCallable(current callable, closure *ast.ExprClosure) string {
	if closure == nil {
		return ""
	}
	key := closureCallableKey(current, closure)
	if _, ok := e.callables[key]; ok {
		return key
	}
	e.addCallable(callable{
		Key:        key,
		Display:    key,
		SourcePath: current.SourcePath,
		StartLine:  closure.StartLine(),
		Class:      current.Class,
		Namespace:  current.Namespace,
		UseAliases: cloneStringMap(current.UseAliases),
		Static:     current.Static,
		Params:     extractParams(closure.Params),
		ParamTypes: extractParamTypes(closure.Params, current.Namespace, current.Class, current.UseAliases),
		Stmts:      closure.Stmts,
	})
	return key
}

func (e *engine) constructorCallableKeyForClass(className string) string {
	className = strings.TrimSpace(className)
	if className == "" {
		return ""
	}
	return e.lookupMethodKey(className, "__construct")
}

func (e *engine) registrationFactoryConstructorKeys(node ast.Node, current callable) []string {
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
	case *ast.ExprFuncCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(e.constructorCallableKeyForClass(className))
			return keys
		}
		if len(typed.Args) == 0 {
			if key := e.lookupFunctionKey(current.Namespace, identifierText(typed.Name)); key != "" {
				for _, className := range e.callableReturnClassCandidates(key) {
					add(e.constructorCallableKeyForClass(className))
				}
			}
		}
	case *ast.ExprMethodCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(e.constructorCallableKeyForClass(className))
			return keys
		}
		if len(typed.Args) == 0 {
			methodName := identifierText(typed.Name)
			for _, receiverClass := range e.resolveCallbackClassRefsWithSeen(typed.Var, current, map[string]struct{}{}) {
				if singletonClass := singletonFactoryReturnClass(methodName, receiverClass); singletonClass != "" {
					add(e.constructorCallableKeyForClass(singletonClass))
				}
				if key := e.existingRuntimeMethodCallable(receiverClass, methodName); key != "" {
					for _, className := range e.callableReturnClassCandidates(key) {
						add(e.constructorCallableKeyForClass(className))
					}
				}
			}
		}
	case *ast.ExprStaticCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(e.constructorCallableKeyForClass(className))
			return keys
		}
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		if len(typed.Args) == 0 {
			methodName := identifierText(typed.Name)
			if singletonClass := singletonFactoryReturnClass(methodName, className); singletonClass != "" {
				add(e.constructorCallableKeyForClass(singletonClass))
			}
			if key := e.existingRuntimeMethodCallable(className, methodName); key != "" {
				for _, candidate := range e.callableReturnClassCandidates(key) {
					add(e.constructorCallableKeyForClass(candidate))
				}
			}
		}
	}
	return keys
}

func (e *engine) resolveCallbackClassRef(node ast.Node, current callable) string {
	refs := e.resolveCallbackClassRefs(node, current)
	if len(refs) == 0 {
		return ""
	}
	return refs[0]
}

func (e *engine) resolveCallbackClassRefs(node ast.Node, current callable) []string {
	return e.resolveCallbackClassRefsWithSeen(node, current, map[string]struct{}{})
}

func (e *engine) resolveCallbackClassRefsWithSeen(node ast.Node, current callable, seen map[string]struct{}) []string {
	if seen == nil {
		seen = map[string]struct{}{}
	}
	resolveKey := "callback-node::" + dispatchResolutionKey("callback-class", current.Key, node)
	if _, ok := seen[resolveKey]; ok {
		return nil
	}
	seen[resolveKey] = struct{}{}
	defer delete(seen, resolveKey)

	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			if name == "this" {
				for _, className := range e.runtimeCallbackClassRefs(current.Class) {
					add(className)
				}
				return out
			}
			for _, className := range e.localCallbackVariableClassRefs(current, name, seen) {
				add(className)
			}
		}
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, current.Class); ok {
			for _, className := range e.receiverPropertyReturnClassCandidates(current.Class, path) {
				add(className)
			}
			if len(out) != 0 {
				return out
			}
		}
	case *ast.ExprFuncCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(className)
			return out
		}
		if key := e.lookupFunctionKey(current.Namespace, identifierText(typed.Name)); key != "" {
			for _, className := range e.callableReturnClassCandidates(key) {
				add(className)
			}
			return out
		}
	case *ast.ExprMethodCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(className)
			return out
		}
		methodName := strings.ToLower(identifierText(typed.Name))
		for _, receiverClass := range e.resolveCallbackClassRefsWithSeen(typed.Var, current, seen) {
			if key := e.existingRuntimeMethodCallable(receiverClass, methodName); key != "" {
				for _, className := range e.callableReturnClassCandidates(key) {
					add(className)
				}
			}
		}
		if len(out) != 0 {
			return out
		}
	case *ast.ExprStaticCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(className)
			return out
		}
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		if singletonClass := singletonFactoryReturnClass(identifierText(typed.Name), className); singletonClass != "" {
			add(singletonClass)
			return out
		}
		if key := e.existingRuntimeMethodCallable(className, strings.ToLower(identifierText(typed.Name))); key != "" {
			for _, candidate := range e.callableReturnClassCandidates(key) {
				add(candidate)
			}
		}
		if len(out) != 0 {
			return out
		}
	case *ast.ScalarMagicConstClass:
		add(current.Class)
	case *ast.ExprClassConstFetch:
		if strings.EqualFold(identifierText(typed.Name), "class") {
			if strings.EqualFold(identifierText(typed.Class), "static") {
				for _, className := range e.runtimeCallbackClassRefs(current.Class) {
					add(className)
				}
				return out
			}
			add(resolveClassName(typed.Class, current.Class, e.classParents))
		}
	case *ast.ExprBinaryOpConcat:
		if dynamic := strings.TrimSpace(dynamicDispatchStringForCallableWithState(typed, current, e, nil, newDispatchResolutionState())); dynamic != "" {
			if strings.Contains(dynamic, "{") {
				prefixEnd := strings.Index(dynamic, "{")
				suffixStart := strings.LastIndex(dynamic, "}")
				if prefixEnd >= 0 && suffixStart >= prefixEnd {
					prefix := resolveCallbackClassPatternPrefix(dynamic[:prefixEnd], current)
					suffix := dynamic[suffixStart+1:]
					for _, className := range e.lookupClassesByPattern(prefix, suffix) {
						add(className)
					}
					if len(out) != 0 {
						return out
					}
				}
			} else {
				add(resolveCallbackClassRefString(dynamic, current))
				return out
			}
		}
		if literal := strings.TrimSpace(literalStringForCallableWithSeen(typed, current, e, seen)); literal != "" {
			add(resolveCallbackClassRefString(literal, current))
		}
	case *ast.Name, *ast.NameFullyQualified, *ast.NameRelative, *ast.Identifier:
		add(resolveClassName(node, current.Class, e.classParents))
	case *ast.ScalarString:
		add(resolveCallbackClassRefString(typed.Value, current))
	}
	return out
}

func (e *engine) localCallbackVariableClassRefs(current callable, name string, seen map[string]struct{}) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	seenKey := "callback-var::" + current.Key + "::" + name
	if _, ok := seen[seenKey]; ok {
		return nil
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	walkNodes(current.Stmts, func(node ast.Node) {
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
		for _, className := range e.callbackAssignmentClassRefs(assign.Expr, current, seen) {
			add(className)
		}
	})
	return out
}

func (e *engine) callbackAssignmentClassRefs(node ast.Node, current callable, seen map[string]struct{}) []string {
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			for _, className := range e.localCallbackVariableClassRefs(current, name, seen) {
				add(className)
			}
		}
	case *ast.ExprNew:
		if className := resolveClassName(typed.Class, current.Class, e.classParents); className != "" {
			add(className)
			break
		}
		for _, className := range e.dynamicClassNodeRefs(typed.Class, current) {
			add(className)
		}
	case *ast.ExprArrayDimFetch:
		for _, className := range e.arrayLookupCallbackClassRefs(typed, current, seen) {
			add(className)
		}
	case *ast.ExprFuncCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(className)
			return out
		}
		if key := e.lookupFunctionKey(current.Namespace, identifierText(typed.Name)); key != "" {
			key = e.specializeCallableKeyForIntrospection(key, literalArgHintsForArgsWithEnvAndSeen(typed.Args, current, e, nil, seen))
			for _, className := range e.callableReturnClassCandidates(key) {
				add(className)
			}
			for _, className := range e.callableReturnArrayEntryClassRefs(key, seen) {
				add(className)
			}
		}
	case *ast.ExprMethodCall:
		methodName := strings.ToLower(identifierText(typed.Name))
		for _, receiverClass := range e.resolveCallbackClassRefsWithSeen(typed.Var, current, seen) {
			if key := e.existingRuntimeMethodCallable(receiverClass, methodName); key != "" {
				key = e.specializeCallableKeyForIntrospection(key, literalArgHintsForArgsWithEnvAndSeen(typed.Args, current, e, nil, seen))
				for _, className := range e.callableReturnClassCandidates(key) {
					add(className)
				}
				for _, className := range e.callableReturnArrayEntryClassRefs(key, seen) {
					add(className)
				}
			}
		}
	case *ast.ExprStaticCall:
		if className := e.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			add(className)
			return out
		}
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		if singletonClass := singletonFactoryReturnClass(identifierText(typed.Name), className); singletonClass != "" {
			add(singletonClass)
			return out
		}
		if key := e.existingRuntimeMethodCallable(className, strings.ToLower(identifierText(typed.Name))); key != "" {
			key = e.specializeCallableKeyForIntrospection(key, literalArgHintsForArgsWithEnvAndSeen(typed.Args, current, e, nil, seen))
			for _, candidate := range e.callableReturnClassCandidates(key) {
				add(candidate)
			}
			for _, candidate := range e.callableReturnArrayEntryClassRefs(key, seen) {
				add(candidate)
			}
		}
	}
	return out
}

func (e *engine) specializeCallableKeyForIntrospection(baseKey string, hints map[int]string) string {
	if baseKey == "" || len(hints) == 0 {
		return baseKey
	}
	savedBatch := e.currentBatchName
	if savedBatch != "" {
		// Introspection runs during parallel batch analysis must stay read-only.
		// Reuse any existing literal specialization, but do not create new callables here.
		return e.existingSpecializedCallableForLiteralArgs(baseKey, hints)
	}
	e.currentBatchName = "call"
	defer func() {
		e.currentBatchName = savedBatch
	}()
	return e.maybeSpecializeCallableForLiteralArgs(baseKey, hints)
}

func (e *engine) dynamicClassNodeRefs(node ast.Node, current callable) []string {
	value := strings.TrimSpace(dynamicDispatchStringForCallable(node, current, e, nil))
	if value == "" {
		return nil
	}
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	if !strings.Contains(value, "{") {
		add(resolveCallbackClassRefString(value, current))
		return out
	}
	prefixEnd := strings.Index(value, "{")
	suffixStart := strings.LastIndex(value, "}")
	if prefixEnd < 0 || suffixStart < prefixEnd {
		return nil
	}
	prefix := resolveCallbackClassPatternPrefix(value[:prefixEnd], current)
	suffix := value[suffixStart+1:]
	for _, className := range e.lookupClassesByPattern(prefix, suffix) {
		add(className)
	}
	return out
}

func arrayRootVariableName(node ast.Node) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			return strings.TrimSpace(name)
		}
	case *ast.ExprArrayDimFetch:
		return arrayRootVariableName(typed.Var)
	}
	return ""
}

func (e *engine) exprArrayEntryClassRefs(node ast.Node, current callable, seen map[string]struct{}) []string {
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	switch typed := node.(type) {
	case nil:
		return nil
	case *ast.ExprAssign:
		return e.exprArrayEntryClassRefs(typed.Expr, current, seen)
	case *ast.ExprAssignRef:
		return e.exprArrayEntryClassRefs(typed.Expr, current, seen)
	case *ast.ExprArray:
		for _, rawItem := range typed.Items {
			item, ok := rawItem.(*ast.ArrayItem)
			if !ok || item.Value == nil {
				continue
			}
			for _, className := range e.callbackAssignmentClassRefs(item.Value, current, seen) {
				add(className)
			}
			for _, className := range e.exprArrayEntryClassRefs(item.Value, current, seen) {
				add(className)
			}
		}
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return nil
		}
		seenKey := "arrayvar::" + current.Key + "::" + strings.TrimSpace(name)
		if _, ok := seen[seenKey]; ok {
			return nil
		}
		seen[seenKey] = struct{}{}
		defer delete(seen, seenKey)
		walkNodes(current.Stmts, func(candidate ast.Node) {
			assign, ok := candidate.(*ast.ExprAssign)
			if !ok {
				return
			}
			targetRoot := arrayRootVariableName(assign.Var)
			if targetRoot != strings.TrimSpace(name) {
				return
			}
			for _, className := range e.callbackAssignmentClassRefs(assign.Expr, current, seen) {
				add(className)
			}
			for _, className := range e.exprArrayEntryClassRefs(assign.Expr, current, seen) {
				add(className)
			}
		})
	case *ast.ExprFuncCall:
		if isGuardPassthroughFunc(identifierText(typed.Name)) && len(typed.Args) > 1 {
			return e.exprArrayEntryClassRefs(argValue(typed.Args[1]), current, seen)
		}
		if key := e.lookupFunctionKey(current.Namespace, identifierText(typed.Name)); key != "" {
			key = e.specializeCallableKeyForIntrospection(key, literalArgHintsForArgsWithEnvAndSeen(typed.Args, current, e, nil, seen))
			for _, className := range e.callableReturnArrayEntryClassRefs(key, seen) {
				add(className)
			}
		}
	case *ast.ExprMethodCall:
		methodName := strings.ToLower(identifierText(typed.Name))
		for _, receiverClass := range e.resolveCallbackClassRefsWithSeen(typed.Var, current, seen) {
			if key := e.existingRuntimeMethodCallable(receiverClass, methodName); key != "" {
				key = e.specializeCallableKeyForIntrospection(key, literalArgHintsForArgsWithEnvAndSeen(typed.Args, current, e, nil, seen))
				for _, className := range e.callableReturnArrayEntryClassRefs(key, seen) {
					add(className)
				}
			}
		}
	case *ast.ExprStaticCall:
		className := resolveClassName(typed.Class, current.Class, e.classParents)
		if key := e.existingRuntimeMethodCallable(className, strings.ToLower(identifierText(typed.Name))); key != "" {
			key = e.specializeCallableKeyForIntrospection(key, literalArgHintsForArgsWithEnvAndSeen(typed.Args, current, e, nil, seen))
			for _, candidate := range e.callableReturnArrayEntryClassRefs(key, seen) {
				add(candidate)
			}
		}
	}
	return out
}

func (e *engine) callableReturnArrayEntryClassRefs(key string, seen map[string]struct{}) []string {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if cached := e.getCallableArrayEntryClassHints(key); len(cached) != 0 {
		return cached
	}
	seenKey := "arrayret::" + key
	if _, ok := seen[seenKey]; ok {
		return nil
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)
	current, ok := e.callables[key]
	if !ok {
		return nil
	}
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	for _, stmt := range current.Stmts {
		ret, ok := stmt.(*ast.StmtReturn)
		if !ok {
			continue
		}
		for _, className := range e.exprArrayEntryClassRefs(ret.Expr, current, seen) {
			add(className)
		}
	}
	e.mergeCallableArrayEntryClassHints(key, out)
	return out
}

func (e *engine) receiverPropertyAssignmentMatches(target ast.Node, ownerClass string, propertyName string, current callable) bool {
	prop, ok := target.(*ast.ExprPropertyFetch)
	if !ok {
		return false
	}
	if !strings.EqualFold(identifierText(prop.Name), propertyName) {
		return false
	}
	switch receiver := prop.Var.(type) {
	case *ast.ExprVariable:
		if name, ok := receiver.Name.(string); ok && name == "this" {
			return current.Class == ownerClass
		}
	case *ast.ExprStaticPropertyFetch:
		className := resolveClassName(receiver.Class, current.Class, e.classParents)
		property := strings.ToLower(strings.TrimSpace(identifierText(receiver.Name)))
		className = e.resolveStaticPropertyOwner(className, property)
		return className == ownerClass
	}
	return false
}

func (e *engine) receiverPropertyArrayEntryClassRefs(className string, propertyName string, seen map[string]struct{}) []string {
	className = strings.TrimSpace(className)
	propertyName = strings.ToLower(strings.TrimSpace(propertyName))
	if className == "" || propertyName == "" {
		return nil
	}
	cacheKey := receiverPropertyClassHintKey(className, propertyName)
	if cached := e.getReceiverPropertyEntryClassHints(cacheKey); len(cached) != 0 {
		return cached
	}
	out := make([]string, 0, 2)
	add := func(candidate string) {
		if candidate == "" {
			return
		}
		for _, existing := range out {
			if existing == candidate {
				return
			}
		}
		out = append(out, candidate)
	}
	for _, owner := range classHierarchyForPropertyHints(className, e.classParents) {
		for _, key := range e.callOrder {
			current := e.callables[key]
			if current.Class != owner {
				continue
			}
			walkNodes(current.Stmts, func(node ast.Node) {
				assign, ok := node.(*ast.ExprAssign)
				if !ok {
					return
				}
				if !e.receiverPropertyAssignmentMatches(assign.Var, owner, propertyName, current) {
					return
				}
				for _, candidate := range e.callbackAssignmentClassRefs(assign.Expr, current, seen) {
					add(candidate)
				}
				for _, candidate := range e.exprArrayEntryClassRefs(assign.Expr, current, seen) {
					add(candidate)
				}
			})
		}
	}
	e.mergeReceiverPropertyEntryClassHints(cacheKey, out)
	return out
}

func (e *engine) getCallableArrayEntryClassHints(key string) []string {
	e.callbackClassHintMu.RLock()
	defer e.callbackClassHintMu.RUnlock()
	if cached := e.callableArrayEntryClassHints[key]; len(cached) != 0 {
		return append([]string(nil), cached...)
	}
	return nil
}

func (e *engine) mergeCallableArrayEntryClassHints(key string, values []string) {
	if key == "" || len(values) == 0 {
		return
	}
	e.callbackClassHintMu.Lock()
	defer e.callbackClassHintMu.Unlock()
	merged := append([]string(nil), e.callableArrayEntryClassHints[key]...)
	for _, value := range values {
		merged = appendUniqueClassHint(merged, value)
	}
	if len(merged) != 0 {
		e.callableArrayEntryClassHints[key] = merged
	}
}

func (e *engine) getReceiverPropertyEntryClassHints(cacheKey string) []string {
	e.callbackClassHintMu.RLock()
	defer e.callbackClassHintMu.RUnlock()
	if cached := e.receiverPropertyEntryClassHints[cacheKey]; len(cached) != 0 {
		return append([]string(nil), cached...)
	}
	return nil
}

func (e *engine) mergeReceiverPropertyEntryClassHints(cacheKey string, values []string) {
	if cacheKey == "" || len(values) == 0 {
		return
	}
	e.callbackClassHintMu.Lock()
	defer e.callbackClassHintMu.Unlock()
	merged := append([]string(nil), e.receiverPropertyEntryClassHints[cacheKey]...)
	for _, value := range values {
		merged = appendUniqueClassHint(merged, value)
	}
	if len(merged) != 0 {
		e.receiverPropertyEntryClassHints[cacheKey] = merged
	}
}

func (e *engine) arrayLookupCallbackClassRefs(node *ast.ExprArrayDimFetch, current callable, seen map[string]struct{}) []string {
	if node == nil {
		return nil
	}
	out := make([]string, 0, 2)
	add := func(className string) {
		if className == "" {
			return
		}
		for _, existing := range out {
			if existing == className {
				return
			}
		}
		out = append(out, className)
	}
	switch base := node.Var.(type) {
	case *ast.ExprPropertyFetch:
		propertyName := identifierText(base.Name)
		for _, receiverClass := range e.resolveCallbackClassRefsWithSeen(base.Var, current, seen) {
			for _, candidate := range e.receiverPropertyArrayEntryClassRefs(receiverClass, propertyName, seen) {
				add(candidate)
			}
		}
	default:
		for _, candidate := range e.exprArrayEntryClassRefs(node.Var, current, seen) {
			add(candidate)
		}
	}
	return out
}

func (e *engine) runtimeCallbackClassRefs(className string) []string {
	if className == "" {
		return nil
	}
	out := []string{className}
	seen := map[string]struct{}{className: {}}
	queue := []string{className}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for child, parent := range e.classParents {
			if parent != current {
				continue
			}
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			out = append(out, child)
			queue = append(queue, child)
		}
	}
	return out
}
