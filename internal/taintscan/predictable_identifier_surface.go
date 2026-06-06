package taintscan

import (
	"math"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

const predictableIdentifierWeakBitsThreshold = 40

type weakIdentifierHint struct {
	Bits   int
	Source Location
}

func (h weakIdentifierHint) weakerThan(other weakIdentifierHint) bool {
	if h.Bits == 0 {
		return false
	}
	if other.Bits == 0 {
		return true
	}
	return h.Bits < other.Bits
}

func mergeWeakIdentifierHint(existing weakIdentifierHint, next weakIdentifierHint) weakIdentifierHint {
	if existing.Bits == 0 {
		return next
	}
	if next.Bits == 0 {
		return existing
	}
	if next.Bits < existing.Bits {
		return next
	}
	if next.Bits == existing.Bits && !hasConcreteLocation(existing.Source) && hasConcreteLocation(next.Source) {
		return next
	}
	return existing
}

func (s *analysisState) assignWeakIdentifierHint(target ast.Node, expr ast.Node) {
	variable, ok := target.(*ast.ExprVariable)
	if !ok {
		return
	}
	name, ok := variable.Name.(string)
	if !ok || name == "" {
		return
	}
	if hint, ok := s.weakIdentifierHintForExpr(expr); ok {
		s.weakIdentifierEnv[name] = hint
		return
	}
	delete(s.weakIdentifierEnv, name)
}

func (s *analysisState) addPredictableIdentifierSurfaceFindingForReturn(stmt *ast.StmtReturn) {
	if stmt == nil || !s.engine.allowsSinkOp("surface") {
		return
	}
	if !callableLooksLikeArtifactSurface(s.current) || !exprLooksLikeArtifactName(stmt.Expr) {
		return
	}
	hint, ok := s.weakIdentifierHintForExpr(stmt.Expr)
	if !ok || hint.Bits >= predictableIdentifierWeakBitsThreshold {
		return
	}
	s.addSinkFindings(
		"predictable-security-identifier-surface",
		predictableIdentifierSurfaceMessage,
		makeOriginSet(origin{kind: originSource, source: hint.Source}),
		s.locationForNode(stmt.Expr),
		s.currentContext(),
	)
}

func (e *engine) callableHasPredictableIdentifierSurfaceSink(c callable) bool {
	if !callableLooksLikeArtifactSurface(c) {
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
		if exprLooksLikeArtifactName(ret.Expr) {
			found = true
		}
	})
	return found
}

func callableLooksLikeArtifactSurface(c callable) bool {
	name := strings.ToLower(c.Display)
	return strings.Contains(name, "export") || strings.Contains(name, "download") || strings.Contains(name, "snapshot")
}

func exprLooksLikeArtifactName(expr ast.Node) bool {
	found := false
	walkNode(expr, func(node ast.Node) {
		if found {
			return
		}
		text := strings.ToLower(strings.TrimSpace(literalString(node)))
		if text == "" {
			return
		}
		if strings.Contains(text, "snapshot") || strings.Contains(text, "download") || strings.Contains(text, "export") {
			found = true
			return
		}
		if strings.Contains(text, ".sql") || strings.Contains(text, ".gz") || strings.Contains(text, ".zip") || strings.Contains(text, "/") {
			found = true
		}
	})
	return found
}

func (s *analysisState) weakIdentifierHintForExpr(expr ast.Node) (weakIdentifierHint, bool) {
	switch typed := expr.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || name == "" {
			return weakIdentifierHint{}, false
		}
		if hint, ok := s.weakIdentifierEnv[name]; ok && hint.Bits > 0 {
			return hint, true
		}
		if hint, ok := s.engine.weakIdentifierHintForClassVariable(s.current.Class, name); ok {
			return hint, true
		}
	case *ast.ExprBinaryOpConcat:
		leftHint, leftOK := s.weakIdentifierHintForExpr(typed.Left)
		rightHint, rightOK := s.weakIdentifierHintForExpr(typed.Right)
		return weakerWeakIdentifierHint(leftHint, leftOK, rightHint, rightOK)
	case *ast.ExprFuncCall:
		name := normalizeName(identifierText(typed.Name))
		switch name {
		case "md5", "sha1", "hash":
			if len(typed.Args) == 0 {
				return weakIdentifierHint{}, false
			}
			return s.weakIdentifierHintForExpr(argValue(typed.Args[0]))
		}
	case *ast.ExprMethodCall:
		name := strings.ToLower(identifierText(typed.Name))
		if key := s.resolveMethodKeyWithArgs(s.resolveClassExpr(typed.Var), name, typed.Args); key != "" {
			if hint, ok := s.engine.weakIdentifierHintForGeneratorCall(key, sliceArgValues(typed.Args)); ok {
				return hint, true
			}
		}
	case *ast.ExprStaticCall:
		name := strings.ToLower(identifierText(typed.Name))
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if key := s.resolveMethodKeyWithArgs(className, name, typed.Args); key != "" {
			if hint, ok := s.engine.weakIdentifierHintForGeneratorCall(key, sliceArgValues(typed.Args)); ok {
				return hint, true
			}
		}
	}
	return weakIdentifierHint{}, false
}

func weakerWeakIdentifierHint(a weakIdentifierHint, okA bool, b weakIdentifierHint, okB bool) (weakIdentifierHint, bool) {
	switch {
	case okA && okB:
		return mergeWeakIdentifierHint(a, b), true
	case okA:
		return a, true
	case okB:
		return b, true
	default:
		return weakIdentifierHint{}, false
	}
}

func (e *engine) weakIdentifierHintForClassVariable(className, varName string) (weakIdentifierHint, bool) {
	if className == "" || !isSecurityIdentifierName(varName) {
		return weakIdentifierHint{}, false
	}
	methods := e.methods[className]
	if len(methods) == 0 {
		return weakIdentifierHint{}, false
	}
	best := weakIdentifierHint{}
	found := false
	for methodName, key := range methods {
		if !weakIdentifierGeneratorNameMatches(methodName, varName) {
			continue
		}
		if hint, ok := e.weakIdentifierHintForGeneratorCall(key, nil); ok {
			if !found || hint.weakerThan(best) {
				best = hint
				found = true
			}
		}
	}
	return best, found
}

func weakIdentifierGeneratorNameMatches(methodName, varName string) bool {
	methodName = strings.ToLower(methodName)
	varName = strings.ToLower(varName)
	if !strings.Contains(methodName, "generate") && !strings.Contains(methodName, "create") {
		return false
	}
	if strings.Contains(methodName, varName) {
		return true
	}
	return isSecurityIdentifierName(methodName) && isSecurityIdentifierName(varName)
}

func isSecurityIdentifierName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	return strings.Contains(name, "token") ||
		strings.Contains(name, "nonce") ||
		strings.Contains(name, "secret") ||
		strings.Contains(name, "uid") ||
		strings.Contains(name, "key") ||
		strings.Contains(name, "snapshot")
}

func (e *engine) weakIdentifierHintForGeneratorCall(key string, args []ast.Node) (weakIdentifierHint, bool) {
	c, ok := e.callables[key]
	if !ok || !isSecurityIdentifierName(lastSegment(c.Display)) {
		return weakIdentifierHint{}, false
	}
	best := weakIdentifierHint{}
	found := false
	walkCallableExecutableNodes(c, func(node ast.Node) {
		if found && best.Bits <= 1 {
			return
		}
		ret, ok := node.(*ast.StmtReturn)
		if !ok {
			return
		}
		if hint, ok := weakIdentifierHintForGeneratorReturnExpr(e, c, ret.Expr, c.Stmts, args); ok {
			best = mergeWeakIdentifierHint(best, hint)
			found = true
		}
	})
	return best, found
}

func weakIdentifierHintForGeneratorReturnExpr(e *engine, c callable, expr ast.Node, stmts []ast.Node, args []ast.Node) (weakIdentifierHint, bool) {
	if variable, ok := expr.(*ast.ExprVariable); ok {
		if name, ok := variable.Name.(string); ok && name != "" {
			if hint, ok := weakIdentifierHintForAssignedVariable(e, c, name, stmts, args); ok {
				return hint, true
			}
		}
	}
	substrCall, ok := expr.(*ast.ExprFuncCall)
	if !ok || normalizeName(identifierText(substrCall.Name)) != "substr" || len(substrCall.Args) < 3 {
		return weakIdentifierHint{}, false
	}
	shuffleCall, ok := argValue(substrCall.Args[0]).(*ast.ExprFuncCall)
	if !ok || normalizeName(identifierText(shuffleCall.Name)) != "str_shuffle" || len(shuffleCall.Args) == 0 {
		return weakIdentifierHint{}, false
	}
	repeatCall, ok := argValue(shuffleCall.Args[0]).(*ast.ExprFuncCall)
	if !ok || normalizeName(identifierText(repeatCall.Name)) != "str_repeat" || len(repeatCall.Args) < 2 {
		return weakIdentifierHint{}, false
	}
	alphabet := literalString(argValue(repeatCall.Args[0]))
	if alphabet == "" {
		return weakIdentifierHint{}, false
	}
	repeatCount, ok := weakIdentifierLengthValue(argValue(repeatCall.Args[1]), c, args)
	if !ok {
		return weakIdentifierHint{}, false
	}
	takeCount, ok := weakIdentifierLengthValue(argValue(substrCall.Args[2]), c, args)
	if !ok {
		return weakIdentifierHint{}, false
	}
	length := repeatCount
	if takeCount < length {
		length = takeCount
	}
	if length <= 0 {
		return weakIdentifierHint{}, false
	}
	uniqueChars := uniqueRuneCount(alphabet)
	if uniqueChars <= 1 {
		return weakIdentifierHint{}, false
	}
	alphabetBits := int(math.Ceil(math.Log2(float64(uniqueChars))))
	if alphabetBits <= 0 {
		return weakIdentifierHint{}, false
	}
	return weakIdentifierHint{
		Bits:   length * alphabetBits,
		Source: locationForCallableNode(e, c, expr),
	}, true
}

func weakIdentifierHintForAssignedVariable(e *engine, c callable, name string, stmts []ast.Node, args []ast.Node) (weakIdentifierHint, bool) {
	best := weakIdentifierHint{}
	found := false
	walkNodes(stmts, func(node ast.Node) {
		var expr ast.Node
		switch typed := node.(type) {
		case *ast.ExprAssign:
			variable, ok := typed.Var.(*ast.ExprVariable)
			if !ok {
				return
			}
			target, ok := variable.Name.(string)
			if !ok || target != name {
				return
			}
			expr = typed.Expr
		case *ast.ExprAssignRef:
			variable, ok := typed.Var.(*ast.ExprVariable)
			if !ok {
				return
			}
			target, ok := variable.Name.(string)
			if !ok || target != name {
				return
			}
			expr = typed.Expr
		default:
			return
		}
		if hint, ok := weakIdentifierHintForGeneratorReturnExpr(e, c, expr, nil, args); ok {
			best = mergeWeakIdentifierHint(best, hint)
			found = true
		}
	})
	return best, found
}

func weakIdentifierLengthValue(node ast.Node, c callable, args []ast.Node) (int, bool) {
	if value := literalInt(node); value > 0 {
		return value, true
	}
	variable, ok := node.(*ast.ExprVariable)
	if !ok {
		return 0, false
	}
	name, ok := variable.Name.(string)
	if !ok || name == "" {
		return 0, false
	}
	for idx, param := range c.Params {
		if param != name || idx >= len(args) {
			continue
		}
		if value := literalInt(args[idx]); value > 0 {
			return value, true
		}
	}
	return 0, false
}

func literalInt(node ast.Node) int {
	switch typed := node.(type) {
	case *ast.ScalarInt:
		return typed.Value
	}
	return 0
}

func uniqueRuneCount(text string) int {
	seen := map[rune]struct{}{}
	for _, r := range text {
		seen[r] = struct{}{}
	}
	return len(seen)
}
