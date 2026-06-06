package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (s *analysisState) evalExpr(node ast.Node) originSet {
	switch typed := node.(type) {
	case nil:
		return originSet{}
	case *ast.ExprAssign:
		origins := s.evalAssignedExpr(typed.Expr)
		s.assignToNode(typed.Var, origins, s.resolveClassExpr(typed.Expr))
		s.assignStringHint(typed.Var, typed.Expr)
		s.assignWeakIdentifierHint(typed.Var, typed.Expr)
		s.trackPathExprAssignment(typed.Var, typed.Expr)
		s.applyPostAssignEffects(typed.Var, typed.Expr)
		return origins
	case *ast.ExprAssignRef:
		origins := s.evalAssignedExpr(typed.Expr)
		s.assignToNode(typed.Var, origins, s.resolveClassExpr(typed.Expr))
		s.assignStringHint(typed.Var, typed.Expr)
		s.assignWeakIdentifierHint(typed.Var, typed.Expr)
		s.trackPathExprAssignment(typed.Var, typed.Expr)
		s.applyPostAssignEffects(typed.Var, typed.Expr)
		return origins
	case *ast.ExprAssignOpConcat:
		current := s.evalConcatTargetOrigins(typed.Var)
		exprOrigins := s.evalExpr(typed.Expr)
		combined := current.union(exprOrigins)
		s.assignToNode(typed.Var, combined, s.resolveClassExpr(typed.Var))
		s.appendStringHint(typed.Var, typed.Expr)
		s.assignWeakIdentifierHint(typed.Var, typed.Expr)
		s.clearPathSafetyForAssignmentTarget(typed.Var)
		return combined
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return s.evalChildren(node)
		}
		if name == "this" && s.current.Class != "" {
			return makeOriginSet(origin{kind: originReceiver})
		}
		if source, ok := s.superglobalSource(name, nil, typed); ok {
			return makeOriginSet(source)
		}
		origins := s.varTaint[name]
		if len(origins) == 0 {
			origins = s.resolveExtractedVariableOrigins(name)
			if len(origins) != 0 {
				s.varTaint[name] = origins
			}
		}
		out := origins.clone()
		out = collectPropertyOriginsInto(out, s.propTaint, name+".")
		out = collectPropertyOriginsInto(out, s.propTaint, name+"[")
		return out
	case *ast.ExprArrayDimFetch:
		if name, ok := superglobalArrayRootName(typed.Var); ok {
			if source, ok := s.superglobalSource(name, typed.Dim, typed); ok {
				return makeOriginSet(source)
			}
		}
		if path, ok := storagePathKey(typed); ok {
			origins := s.storageSelfOrigins(path)
			origins = origins.union(s.storageChildOrigins(path))
			if len(origins) != 0 {
				return origins
			}
		}
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			origins := originSet{}
			origins = origins.union(lookupStructuralPathOrigins(s.engine.staticProps, path))
			origins = origins.union(lookupStructuralPathOrigins(s.staticPropTaint, path))
			if len(origins) != 0 {
				return origins
			}
		}
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			origins := lookupStructuralPathOrigins(s.propTaint, path)
			if len(origins) != 0 {
				return origins
			}
			if structuralPathTracked(s.propTaint, path) {
				return originSet{}
			}
		}
		if typed.Dim != nil {
			if root, ok := s.structuralRoot(typed.Var); ok {
				if structuralContainerDefinitelyLacksSegment(s.destinationStructuralStore(root), root.key, rootlessArrayPath(typed.Dim)) {
					return originSet{}
				}
			}
		}
		origins := s.evalContainerBase(typed.Var)
		if typed.Dim == nil {
			return appendIteratedOrigins(origins)
		}
		if key, ok := stableArrayDimKey(typed.Dim); ok {
			return appendIndexedOrigins(origins, key, s.locationForNode(typed))
		}
		return appendIndexedOrigins(origins, "*", s.locationForNode(typed))
	case *ast.ExprPropertyFetch:
		origins := originSet{}
		if name := strings.ToLower(identifierText(typed.Name)); name != "" {
			origins = origins.union(storageOriginsForFamily(name, s))
		}
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			origins = unionInto(origins, lookupStructuralPathOrigins(s.propTaint, path))
			origins = collectPropertyOriginsInto(origins, s.propTaint, path+".")
			origins = collectPropertyOriginsInto(origins, s.propTaint, path+"[")
			if len(origins) == 0 && structuralPathTracked(s.propTaint, path) {
				return originSet{}
			}
		}
		if root, ok := s.structuralRoot(typed.Var); ok {
			if structuralContainerDefinitelyLacksSegment(s.destinationStructuralStore(root), root.key, "."+identifierText(typed.Name)) {
				return originSet{}
			}
		}
		if len(origins) != 0 {
			return origins
		}
		return appendPropertyOrigins(s.evalDirectBaseOrigins(typed.Var), identifierText(typed.Name))
	case *ast.ExprStaticPropertyFetch:
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			origins := lookupStructuralPathOrigins(s.engine.staticProps, path)
				origins = unionInto(origins, lookupStructuralPathOrigins(s.staticPropTaint, path))
				origins = collectPropertyOriginsInto(origins, s.engine.staticProps, path+".")
				origins = collectPropertyOriginsInto(origins, s.engine.staticProps, path+"[")
				origins = collectPropertyOriginsInto(origins, s.staticPropTaint, path+".")
				origins = collectPropertyOriginsInto(origins, s.staticPropTaint, path+"[")
			if len(origins) != 0 {
				return origins
			}
		}
		return originSet{}
	case *ast.ExprNew:
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if className == "" {
			// new $_GET['class'](...) — attacker-chosen class instantiation
			// (object-injection / gadget construction primitive).
			s.emitDynamicCallNameFinding(typed.Class, s.locationForNode(typed))
		}
		if sinkIndex, ruleID, message, ok := sqlTemplateConstructorArgIndex(className); ok && s.engine.allowsSinkOp("sql") {
			if sinkIndex >= 0 && sinkIndex < len(typed.Args) {
				s.addSinkFindings(ruleID, message, s.sqlExecutionOrigins(argValue(typed.Args[sinkIndex])), s.locationForNode(argValue(typed.Args[sinkIndex])), s.currentContext())
			}
			return originSet{}
		}
		origins := unionAll(s.evalArgs(typed.Args))
		if key := s.resolveMethodKey(className, "__construct"); key != "" {
			origins = origins.union(s.instantiateSummaryReturn(key, s.evalArgs(typed.Args), typed.Args, "", true))
		}
		return origins
	case *ast.ExprClosure:
		// Stored closures should behave like opaque callback values here.
		// Walking their bodies as normal expressions causes unrelated
		// callback-heavy import helpers to pollute call-sink analysis.
		return originSet{}
	case *ast.ExprArrowFunction:
		return originSet{}
	case *ast.ExprCastInt, *ast.ExprCastDouble, *ast.ExprCastBool:
		// Numeric/boolean coercion makes a value injection-safe (it cannot carry
		// HTML, SQL, or path metacharacters), so mark the result HTML-output-safe
		// AND numeric-safe. numericSafe lets the SQL sink drop the value even
		// when the cast result is stored in a local and later interpolated into
		// a query string (the canonical $id=(int)$_GET['id']; "... '$id' ..."
		// idiom), where sqlExecutionOrigins cannot see the inline cast node.
		// The taint is NOT dropped: a coerced value is still attacker-controlled
		// for resource-selection sinks (delete/action/disclosure), where it
		// expresses IDOR / missing-authorization bugs.
		return markNumericSafeOrigins(markHTMLOutputSafeOrigins(s.evalExpr(castOperand(typed))))
	case *ast.ExprIsset, *ast.ExprEmpty:
		// isset()/empty() are boolean predicates: their RESULT is always a
		// true/false value and can never carry attacker-controlled string
		// content, even when the operand reads a superglobal. Returning the
		// children's taint (the default behaviour) mis-attributes the operand's
		// taint to the boolean, producing false positives such as
		//   $cfg['x'] = isset($_POST['x']);  echo $cfg['y'];
		// where the assigned value is a bare boolean.
		return originSet{}
	case *ast.ExprBinaryOpConcat:
		return s.evalExpr(typed.Left).union(s.evalExpr(typed.Right))
	case *ast.ScalarInterpolatedString:
		origins := originSet{}
		for _, rawPart := range typed.Parts {
			child, ok := rawPart.(ast.Node)
			if !ok {
				continue
			}
			origins = origins.union(s.evalExpr(child))
		}
		return origins
	case *ast.ExprTernary:
		// Value-flow: a ternary's RESULT is its If or Else branch, never the
		// condition. Including the condition's taint over-approximates output
		// value taint and produces false positives such as
		//   echo ($req == 'x') ? ' class="current"' : '';
		// where both arms are constant string literals and the request value
		// only steers branch selection (never reaches the output).
		// For the short ternary "$a ?: $b" (typed.If == nil) PHP yields the
		// condition value when truthy, so the condition IS part of the result.
		if typed.If == nil {
			return s.evalExpr(typed.Cond).union(s.evalExpr(typed.Else))
		}
		return s.evalExpr(typed.If).union(s.evalExpr(typed.Else))
	case *ast.ExprBooleanNot:
		return s.evalChildren(node)
	case *ast.ExprArray:
		origins := originSet{}
		for _, item := range typed.Items {
			origins = origins.union(s.evalExpr(item))
		}
		return origins
	case *ast.ArrayItem:
		return s.evalExpr(typed.Value).union(s.evalExpr(typed.Key))
	case *ast.ExprPrint:
		origins := s.evalExpr(typed.Expr)
		s.addRecordDisclosureFinding(origins, s.locationForNode(typed.Expr))
		s.addPersistentOutputFinding(origins, s.locationForNode(typed.Expr))
		s.addReflectedRequestOutputFinding(origins, s.locationForNode(typed.Expr))
		if s.engine.allowsSinkOp("action") &&
			(s.engine.callableHasRecordRead(s.current.Key) || callableHasDownloadDataSource(s.current)) &&
			callableHasAttachmentDispositionHeaderBefore(s.engine, s.current, typed.StartLine()) {
			actionOrigins := s.currentActionRequestOrigins()
			if len(actionOrigins) != 0 {
				s.addUnauthorizedActionFinding("wp-request-sensitive-action-without-cap-check", requestSensitiveActionMessage, actionOrigins, s.locationForNode(typed.Expr))
			}
		}
		return originSet{}
	case *ast.ExprEval:
		origins := s.evalExpr(typed.Expr)
		if s.engine.allowsSinkOp("call") {
			s.addSinkFindings("unsafe-use", unsafeUseMessage, origins, s.locationForNode(typed.Expr), s.currentContext())
		}
		return originSet{}
	case *ast.ExprShellExec:
		origins := shellExecOrigins(s, typed)
		if s.engine.allowsSinkOp("call") {
			s.addSinkFindings("unsafe-use", unsafeUseMessage, origins, s.locationForNode(typed), s.currentContext())
		}
		return originSet{}
	case *ast.ExprInclude:
		origins := s.evalExpr(typed.Expr)
		if returned := s.evalStaticIncludedFile(typed.Expr); len(returned) != 0 {
			origins = origins.union(returned)
		}
		if s.engine.allowsSinkOp("include") {
			origins = s.filterPathSinkOrigins(typed.Expr, origins)
			s.addSinkFindings("path-transversal", pathTransversalMessage, origins, s.locationForNode(typed.Expr), s.currentContext())
		}
		return origins
	case *ast.ExprFuncCall:
		return s.evalFuncCall(typed)
	case *ast.ExprMethodCall:
		return s.evalMethodCall(typed)
	case *ast.ExprStaticCall:
		return s.evalStaticCall(typed)
	default:
		return s.evalChildren(node)
	}
}

// castOperand returns the operand expression of a numeric/boolean cast node.
func castOperand(node ast.Node) ast.Node {
	switch typed := node.(type) {
	case *ast.ExprCastInt:
		return typed.Expr
	case *ast.ExprCastDouble:
		return typed.Expr
	case *ast.ExprCastBool:
		return typed.Expr
	default:
		return nil
	}
}

func (s *analysisState) resolveExtractedVariableOrigins(name string) originSet {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return originSet{}
	}
	if s.activeExtractResolves == nil {
		s.activeExtractResolves = map[string]struct{}{}
	}
	if _, active := s.activeExtractResolves[name]; active {
		return originSet{}
	}
	s.activeExtractResolves[name] = struct{}{}
	defer delete(s.activeExtractResolves, name)
	path := "[" + name + "]"
	for i := len(s.extractContainers) - 1; i >= 0; i-- {
		if origins := s.resolveArgumentPathOrigins(s.extractContainers[i], path); len(origins) != 0 {
			return origins
		}
	}
	return originSet{}
}

func shellExecOrigins(s *analysisState, node *ast.ExprShellExec) originSet {
	if node == nil {
		return originSet{}
	}
	origins := originSet{}
	for _, rawPart := range node.Parts {
		part, ok := rawPart.(ast.Node)
		if !ok {
			continue
		}
		origins = origins.union(s.evalExpr(part))
	}
	return origins
}

func (s *analysisState) evalConcatTargetOrigins(node ast.Node) originSet {
	if path, ok := staticPropertyPathKey(node, s.current.Class, s.engine); ok {
		return lookupStructuralPathOrigins(s.staticPropTaint, path)
	}
	return s.evalExpr(node)
}

func (s *analysisState) evalContainerBase(node ast.Node) originSet {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return originSet{}
		}
		if name == "this" && s.current.Class != "" {
			return makeOriginSet(origin{kind: originReceiver})
		}
		return s.varTaint[name]
	case *ast.ExprPropertyFetch:
		origins := originSet{}
		if name := strings.ToLower(identifierText(typed.Name)); name != "" {
			origins = origins.union(storageOriginsForFamily(name, s))
		}
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			if propOrigins, ok := s.propTaint[path]; ok {
				origins = origins.union(propOrigins)
			}
		}
		if len(origins) != 0 {
			return origins
		}
		return appendPropertyOrigins(s.evalExpr(typed.Var), identifierText(typed.Name))
	case *ast.ExprStaticPropertyFetch:
		origins := originSet{}
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			structural := collectStructuralChildren(s.engine.staticProps, path)
			structural = structural.union(collectStructuralChildren(s.staticPropTaint, path))
			if len(structural) != 0 {
				origins = origins.union(structural)
			} else {
				origins = origins.union(lookupStructuralSelfOrigins(s.engine.staticProps, path))
				origins = origins.union(lookupStructuralSelfOrigins(s.staticPropTaint, path))
			}
		}
		return origins
	case *ast.ExprArrayDimFetch:
		origins := originSet{}
		if path, ok := storagePathKey(typed); ok {
			origins = origins.union(s.storageSelfOrigins(path))
		}
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			origins = origins.union(lookupStructuralSelfOrigins(s.engine.staticProps, path))
			origins = origins.union(lookupStructuralSelfOrigins(s.staticPropTaint, path))
		}
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			if localOrigins, ok := s.propTaint[path]; ok {
				origins = origins.union(localOrigins)
			}
		}
		if len(origins) != 0 {
			return origins
		}
		base := s.evalContainerBase(typed.Var)
		if typed.Dim == nil {
			return appendIteratedOrigins(base)
		}
		if key, ok := stableArrayDimKey(typed.Dim); ok {
			return appendIndexedOrigins(base, key, s.locationForNode(typed))
		}
		return appendIndexedOrigins(base, "*", s.locationForNode(typed))
	default:
		return originSet{}
	}
}

func (s *analysisState) evalAssignedExpr(node ast.Node) originSet {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return s.evalExpr(node)
		}
		if name == "this" && s.current.Class != "" {
			return makeOriginSet(origin{kind: originReceiver})
		}
		if source, ok := s.superglobalSource(name, nil, typed); ok {
			return makeOriginSet(source)
		}
		return s.varTaint[name]
	case *ast.ExprPropertyFetch, *ast.ExprStaticPropertyFetch:
		return s.evalDirectBaseOrigins(node)
	default:
		return s.evalExpr(node)
	}
}

func (s *analysisState) evalDirectBaseOrigins(node ast.Node) originSet {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return originSet{}
		}
		if name == "this" && s.current.Class != "" {
			return makeOriginSet(origin{kind: originReceiver})
		}
		if source, ok := s.superglobalSource(name, nil, typed); ok {
			return makeOriginSet(source)
		}
		return s.varTaint[name]
	case *ast.ExprArrayDimFetch:
		return s.evalExpr(typed)
	case *ast.ExprPropertyFetch:
		origins := originSet{}
		if name := strings.ToLower(identifierText(typed.Name)); name != "" {
			if familyOrigins, ok := s.engine.storage[name]; ok {
				origins = origins.union(familyOrigins)
			}
		}
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			if propOrigins, ok := s.propTaint[path]; ok {
				origins = origins.union(propOrigins)
			}
		}
		return origins
	case *ast.ExprStaticPropertyFetch:
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			origins := lookupStructuralSelfOrigins(s.engine.staticProps, path)
			origins = origins.union(lookupStructuralSelfOrigins(s.staticPropTaint, path))
			return origins
		}
	}
	return originSet{}
}
