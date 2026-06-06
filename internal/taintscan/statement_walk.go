package taintscan

import (
	"strconv"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (s *analysisState) returnParamIndex(expr ast.Node) (int, bool) {
	variable, ok := expr.(*ast.ExprVariable)
	if !ok {
		return 0, false
	}
	name, ok := variable.Name.(string)
	if !ok {
		return 0, false
	}
	for idx, param := range s.current.Params {
		if param == name {
			return idx, true
		}
	}
	return 0, false
}

func (s *analysisState) walkStatements(stmts []ast.Node) {
	for i := 0; i < len(stmts); i++ {
		if s.aborted {
			return
		}
		// Mid-analysis memory circuit-breaker: under heap pressure, abort this
		// callable's walk (its growing transient state becomes garbage), so a
		// single pathological callable on a mega-plugin cannot OOM the process.
		// Polled cheaply (atomic gauge) every 32 statements.
		if s.engine.heapHardLimit > 0 {
			s.stmtCounter++
			if s.stmtCounter&0x1F == 0 && s.engine.underMemoryPressure() {
				s.aborted = true
				return
			}
		}
		if handled, next := s.walkMutuallyExclusiveLiteralIfChain(stmts, i); handled {
			i = next - 1
			continue
		}
		stmt := stmts[i]
		s.walkStatement(stmt)
		if statementEndsCurrentCallable(stmt) {
			break
		}
		if outcome := s.engine.statementFlowOutcome(stmt, s.current, map[string]struct{}{}); !outcome.canContinue && !outcome.canReturn && outcome.canAbort {
			break
		}
	}
}

func statementEndsCurrentCallable(node ast.Node) bool {
	switch typed := node.(type) {
	case *ast.StmtReturn, *ast.ExprThrow:
		return true
	case *ast.StmtExpression:
		switch typed.Expr.(type) {
		case *ast.ExprExit, *ast.ExprThrow:
			return true
		}
	}
	return false
}

type statementFlow struct {
	canContinue bool
	canReturn   bool
	canAbort    bool
}

func (e *engine) statementFlowOutcome(node ast.Node, current callable, seen map[string]struct{}) statementFlow {
	switch typed := node.(type) {
	case nil, *ast.StmtNop:
		return statementFlow{canContinue: true}
	case *ast.ExprThrow:
		return statementFlow{canAbort: true}
	case *ast.StmtReturn:
		return statementFlow{canReturn: true}
	case *ast.StmtExpression:
		return e.exprFlowOutcome(typed.Expr, current, seen)
	case *ast.StmtIf:
		if truth, ok := e.literalConditionTruthForCallable(typed.Cond, current, map[string]struct{}{}); ok {
			if truth {
				return e.statementsFlowOutcome(typed.Stmts, current, seen)
			}
			for _, rawElseIf := range typed.Elseifs {
				elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
				if !ok {
					continue
				}
				elseifTruth, elseifKnown := e.literalConditionTruthForCallable(elseifStmt.Cond, current, map[string]struct{}{})
				if !elseifKnown {
					return statementFlow{canContinue: true}
				}
				if elseifTruth {
					return e.statementsFlowOutcome(elseifStmt.Stmts, current, seen)
				}
			}
			if typed.Else == nil {
				return statementFlow{canContinue: true}
			}
			elseStmt, ok := typed.Else.(*ast.StmtElse)
			if !ok {
				return statementFlow{canContinue: true}
			}
			return e.statementsFlowOutcome(elseStmt.Stmts, current, seen)
		}
		outcome := e.statementsFlowOutcome(typed.Stmts, current, seen)
		for _, rawElseIf := range typed.Elseifs {
			elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
			if !ok {
				outcome.canContinue = true
				continue
			}
			outcome = mergeStatementFlow(outcome, e.statementsFlowOutcome(elseifStmt.Stmts, current, seen))
		}
		if typed.Else == nil {
			outcome.canContinue = true
			return outcome
		}
		elseStmt, ok := typed.Else.(*ast.StmtElse)
		if !ok {
			outcome.canContinue = true
			return outcome
		}
		return mergeStatementFlow(outcome, e.statementsFlowOutcome(elseStmt.Stmts, current, seen))
	default:
		return statementFlow{canContinue: true}
	}
}

func mergeStatementFlow(base, other statementFlow) statementFlow {
	return statementFlow{
		canContinue: base.canContinue || other.canContinue,
		canReturn:   base.canReturn || other.canReturn,
		canAbort:    base.canAbort || other.canAbort,
	}
}

func (e *engine) exprFlowOutcome(node ast.Node, current callable, seen map[string]struct{}) statementFlow {
	switch typed := node.(type) {
	case nil:
		return statementFlow{canContinue: true}
	case *ast.ExprExit, *ast.ExprThrow:
		return statementFlow{canAbort: true}
	case *ast.ExprFuncCall:
		return e.funcCallFlowOutcome(typed, current, seen)
	case *ast.ExprMethodCall:
		return e.methodCallFlowOutcome(typed, current, seen)
	case *ast.ExprStaticCall:
		return e.staticCallFlowOutcome(typed, current, seen)
	default:
		return statementFlow{canContinue: true}
	}
}

func (e *engine) statementsFlowOutcome(stmts []ast.Node, current callable, seen map[string]struct{}) statementFlow {
	outcome := statementFlow{canContinue: true}
	for _, stmt := range stmts {
		if !outcome.canContinue {
			break
		}
		step := e.statementFlowOutcome(stmt, current, seen)
		outcome.canReturn = outcome.canReturn || step.canReturn
		outcome.canAbort = outcome.canAbort || step.canAbort
		outcome.canContinue = step.canContinue
	}
	return outcome
}

func (e *engine) funcCallFlowOutcome(call *ast.ExprFuncCall, current callable, seen map[string]struct{}) statementFlow {
	if call == nil {
		return statementFlow{canContinue: true}
	}
	if key := e.resolveGuardFunctionKey(call.Name, current); key != "" {
		return e.callableFlowOutcome(key, seen)
	}
	return statementFlow{canContinue: true}
}

func (e *engine) methodCallFlowOutcome(call *ast.ExprMethodCall, current callable, seen map[string]struct{}) statementFlow {
	if call == nil {
		return statementFlow{canContinue: true}
	}
	className := e.resolveCallbackClassRef(call.Var, current)
	if className == "" {
		className = e.resolveMethodCallClass(call, current)
	}
	if className == "" {
		return statementFlow{canContinue: true}
	}
	key := e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name)))
	if key == "" {
		return statementFlow{canContinue: true}
	}
	return e.callableFlowOutcome(key, seen)
}

func (e *engine) staticCallFlowOutcome(call *ast.ExprStaticCall, current callable, seen map[string]struct{}) statementFlow {
	if call == nil {
		return statementFlow{canContinue: true}
	}
	className := resolveClassName(call.Class, current.Class, e.classParents)
	if className == "" {
		return statementFlow{canContinue: true}
	}
	key := e.lookupMethodKey(className, strings.ToLower(identifierText(call.Name)))
	if key == "" {
		return statementFlow{canContinue: true}
	}
	return e.callableFlowOutcome(key, seen)
}

func (e *engine) callableFlowOutcome(key string, seen map[string]struct{}) statementFlow {
	if key == "" {
		return statementFlow{canContinue: true}
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	if _, ok := seen[key]; ok {
		return statementFlow{canContinue: true}
	}
	callable, ok := e.callables[key]
	if !ok {
		return statementFlow{canContinue: true}
	}
	seen[key] = struct{}{}
	defer delete(seen, key)
	return e.statementsFlowOutcome(callable.Stmts, callable, seen)
}

func (s *analysisState) walkMutuallyExclusiveLiteralIfChain(stmts []ast.Node, start int) (bool, int) {
	if s == nil || start < 0 || start >= len(stmts) {
		return false, start
	}
	first, ok := stmts[start].(*ast.StmtIf)
	if !ok || len(first.Elseifs) != 0 || first.Else != nil {
		return false, start
	}
	varName, literalKey, literalString, ok := s.literalEqualityGuardVariableAndValue(first.Cond)
	if !ok || varName == "" || literalKey == "" {
		return false, start
	}
	if _, known := s.literalScalarValue(&ast.ExprVariable{Name: varName}); known {
		return false, start
	}

	type guardedIf struct {
		stmt          *ast.StmtIf
		literalKey    string
		literalString string
	}
	chain := []guardedIf{{stmt: first, literalKey: literalKey, literalString: literalString}}
	seen := map[string]struct{}{literalKey: {}}
	next := start + 1
	for next < len(stmts) {
		current, ok := stmts[next].(*ast.StmtIf)
		if !ok || len(current.Elseifs) != 0 || current.Else != nil {
			break
		}
		name, key, rawString, ok := s.literalEqualityGuardVariableAndValue(current.Cond)
		if !ok || name != varName || key == "" {
			break
		}
		if _, exists := seen[key]; exists {
			break
		}
		seen[key] = struct{}{}
		chain = append(chain, guardedIf{stmt: current, literalKey: key, literalString: rawString})
		next++
	}
	if len(chain) < 2 {
		return false, start
	}

	baseVars := cloneVarMap(s.varTaint)
	baseProps := cloneVarMap(s.propTaint)
	baseStaticProps := cloneVarMap(s.staticPropTaint)
	baseClasses := cloneStringMap(s.classEnv)
	baseStrings := cloneStringMap(s.stringEnv)
	baseExtractContainers := append([]ast.Node(nil), s.extractContainers...)

	mergedVars := cloneVarMap(baseVars)
	mergedProps := cloneVarMap(baseProps)
	mergedStaticProps := cloneVarMap(baseStaticProps)
	mergedReceiverWrites := cloneVarMap(s.receiverWrites)
	mergedReceiverStorageLinks := cloneStringMap(s.receiverStorageLinks)
	mergedStructuralStorageLinks := cloneStringMap(s.structuralStorageLinks)
	mergedStorageWrites := cloneVarMap(s.storageWrites)
	mergedStoragePathWrites := cloneVarMap(s.storagePathWrites)
	mergedClasses := cloneStringMap(baseClasses)
	mergedStrings := cloneStringMap(baseStrings)
	mergedExtractContainers := append([]ast.Node(nil), baseExtractContainers...)
	mergedReturns := s.returnValue
	mergedReturnPathWrites := cloneVarMap(s.returnPathWrites)
	mergedReturnClasses := cloneStringSet(s.returnClasses)

	for _, item := range chain {
		branch := s.cloneWith(cloneVarMap(baseVars), cloneVarMap(baseProps), cloneVarMap(baseStaticProps), cloneStringMap(baseClasses), cloneStringMap(baseStrings))
		if item.literalString != "" {
			branch.stringEnv[varName] = item.literalString
		}
		branch.walkStatements(item.stmt.Stmts)
		mergedVars = mergeVarMaps(mergedVars, branch.varTaint)
		mergedProps = mergeVarMaps(mergedProps, branch.propTaint)
		mergedStaticProps = mergeVarMaps(mergedStaticProps, branch.staticPropTaint)
		mergedReceiverWrites = mergeVarMaps(mergedReceiverWrites, branch.receiverWrites)
		mergedReceiverStorageLinks = mergeStringMaps(mergedReceiverStorageLinks, branch.receiverStorageLinks)
		mergedStructuralStorageLinks = mergeStringMaps(mergedStructuralStorageLinks, branch.structuralStorageLinks)
		mergedStorageWrites = mergeVarMaps(mergedStorageWrites, branch.storageWrites)
		mergedStoragePathWrites = mergeVarMaps(mergedStoragePathWrites, branch.storagePathWrites)
		mergedClasses = mergeStringMaps(mergedClasses, branch.classEnv)
		mergedStrings = mergeStringMaps(mergedStrings, branch.stringEnv)
		mergedExtractContainers = mergeNodeSlices(mergedExtractContainers, branch.extractContainers)
		mergedReturns = mergedReturns.union(branch.returnValue)
		mergedReturnPathWrites = mergeVarMaps(mergedReturnPathWrites, branch.returnPathWrites)
		mergedReturnClasses = mergeStringSets(mergedReturnClasses, branch.returnClasses)
		s.mergeFindingsFrom(branch)
	}

	s.varTaint = mergedVars
	s.propTaint = mergedProps
	s.staticPropTaint = mergedStaticProps
	s.receiverWrites = mergedReceiverWrites
	s.receiverStorageLinks = mergedReceiverStorageLinks
	s.structuralStorageLinks = mergedStructuralStorageLinks
	s.storageWrites = mergedStorageWrites
	s.storagePathWrites = mergedStoragePathWrites
	s.classEnv = mergedClasses
	s.stringEnv = mergedStrings
	s.extractContainers = mergedExtractContainers
	s.returnValue = mergedReturns
	s.returnPathWrites = mergedReturnPathWrites
	s.returnClasses = mergedReturnClasses
	return true, next
}

func literalSwitchCasesForCallable(stmt *ast.StmtSwitch, current callable, e *engine) ([]*ast.StmtCase, bool) {
	if stmt == nil || e == nil {
		return nil, false
	}
	switchValue := strings.TrimSpace(literalStringForCallable(stmt.Cond, current, e))
	if switchValue == "" || strings.ContainsAny(switchValue, "{}") {
		return nil, false
	}
	start := -1
	defaultIndex := -1
	cases := make([]*ast.StmtCase, 0, len(stmt.Cases))
	for _, rawCase := range stmt.Cases {
		caseStmt, ok := rawCase.(*ast.StmtCase)
		if !ok {
			continue
		}
		cases = append(cases, caseStmt)
		idx := len(cases) - 1
		if caseStmt.Cond == nil {
			if defaultIndex < 0 {
				defaultIndex = idx
			}
			continue
		}
		caseValue := strings.TrimSpace(literalStringForCallable(caseStmt.Cond, current, e))
		if caseValue != "" && !strings.ContainsAny(caseValue, "{}") && caseValue == switchValue && start < 0 {
			start = idx
		}
	}
	if start < 0 {
		start = defaultIndex
	}
	if start < 0 {
		return nil, true
	}
	return cases[start:], true
}

func (s *analysisState) literalSwitchCases(stmt *ast.StmtSwitch) ([]*ast.StmtCase, bool) {
	if stmt == nil {
		return nil, false
	}
	switchValue, ok := s.literalScalarValue(stmt.Cond)
	if !ok || strings.HasPrefix(switchValue, "str:") && strings.ContainsAny(strings.TrimPrefix(switchValue, "str:"), "{}") {
		return literalSwitchCasesForCallable(stmt, s.current, s.engine)
	}
	start := -1
	defaultIndex := -1
	cases := make([]*ast.StmtCase, 0, len(stmt.Cases))
	for _, rawCase := range stmt.Cases {
		caseStmt, ok := rawCase.(*ast.StmtCase)
		if !ok {
			continue
		}
		cases = append(cases, caseStmt)
		idx := len(cases) - 1
		if caseStmt.Cond == nil {
			if defaultIndex < 0 {
				defaultIndex = idx
			}
			continue
		}
		caseValue, caseKnown := s.literalScalarValue(caseStmt.Cond)
		if caseKnown && (!strings.HasPrefix(caseValue, "str:") || !strings.ContainsAny(strings.TrimPrefix(caseValue, "str:"), "{}")) && caseValue == switchValue && start < 0 {
			start = idx
		}
	}
	if start < 0 {
		start = defaultIndex
	}
	if start < 0 {
		return nil, true
	}
	return cases[start:], true
}

func (s *analysisState) literalConditionTruth(node ast.Node) (bool, bool) {
	if value, ok := s.engine.literalConditionTruthForCallable(node, s.current, map[string]struct{}{}); ok {
		return value, true
	}
	switch typed := node.(type) {
	case nil:
		return false, false
	case *ast.ExprBooleanNot:
		if value, ok := s.literalConditionTruth(typed.Expr); ok {
			return !value, true
		}
		return false, false
	case *ast.ExprBinaryOpBooleanAnd:
		return s.literalBooleanAndTruth(typed.Left, typed.Right)
	case *ast.ExprBinaryOpLogicalAnd:
		return s.literalBooleanAndTruth(typed.Left, typed.Right)
	case *ast.ExprBinaryOpBooleanOr:
		return s.literalBooleanOrTruth(typed.Left, typed.Right)
	case *ast.ExprBinaryOpLogicalOr:
		return s.literalBooleanOrTruth(typed.Left, typed.Right)
	case *ast.ExprBinaryOpIdentical:
		return s.literalScalarComparisonTruth(typed.Left, typed.Right, true)
	case *ast.ExprBinaryOpEqual:
		return s.literalScalarComparisonTruth(typed.Left, typed.Right, true)
	case *ast.ExprBinaryOpNotIdentical:
		return s.literalScalarComparisonTruth(typed.Left, typed.Right, false)
	case *ast.ExprBinaryOpNotEqual:
		return s.literalScalarComparisonTruth(typed.Left, typed.Right, false)
	default:
		return booleanLiteralForCallable(node, s.current, s.engine, s.stringEnv)
	}
}

func (s *analysisState) literalBooleanAndTruth(left, right ast.Node) (bool, bool) {
	leftValue, leftKnown := s.literalConditionTruth(left)
	rightValue, rightKnown := s.literalConditionTruth(right)
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

func (s *analysisState) literalBooleanOrTruth(left, right ast.Node) (bool, bool) {
	leftValue, leftKnown := s.literalConditionTruth(left)
	rightValue, rightKnown := s.literalConditionTruth(right)
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

func (s *analysisState) literalScalarComparisonTruth(left, right ast.Node, equals bool) (bool, bool) {
	leftValue, leftKnown := s.literalScalarValue(left)
	rightValue, rightKnown := s.literalScalarValue(right)
	if !leftKnown || !rightKnown {
		leftBool, leftBoolKnown := s.literalConditionTruth(left)
		rightBool, rightBoolKnown := s.literalConditionTruth(right)
		if leftBoolKnown && rightBoolKnown {
			if equals {
				return leftBool == rightBool, true
			}
			return leftBool != rightBool, true
		}
		return false, false
	}
	if equals {
		return leftValue == rightValue, true
	}
	return leftValue != rightValue, true
}

func (s *analysisState) literalScalarValue(node ast.Node) (string, bool) {
	if truth, ok := booleanLiteral(node); ok {
		if truth {
			return "bool:true", true
		}
		return "bool:false", true
	}
	if number, ok := numericLiteral(node); ok {
		return "num:" + strconv.Itoa(number), true
	}
	if value, ok := s.literalStringValue(node); ok {
		return "str:" + value, true
	}
	switch typed := node.(type) {
	case *ast.ExprFuncCall:
		return s.literalFuncScalarValue(typed)
	case *ast.ExprConstFetch:
		if strings.EqualFold(identifierText(typed.Name), "null") {
			return "null", true
		}
	}
	return "", false
}

func (s *analysisState) literalStringValue(node ast.Node) (string, bool) {
	switch typed := node.(type) {
	case *ast.ScalarString:
		return typed.Value, true
	case *ast.ScalarInterpolatedString:
		if value := dynamicDispatchStringForCallable(node, s.current, s.engine, s.stringEnv); value != "" {
			return value, true
		}
		if value := literalStringForCallableWithSeen(node, s.current, s.engine, map[string]struct{}{}); value != "" {
			return value, true
		}
		return "", len(typed.Parts) == 0
	default:
		if value := dynamicDispatchStringForCallable(node, s.current, s.engine, s.stringEnv); value != "" {
			return value, true
		}
		if value := literalStringForCallableWithSeen(node, s.current, s.engine, map[string]struct{}{}); value != "" {
			return value, true
		}
		return "", false
	}
}

func (s *analysisState) literalEqualityGuardVariableAndValue(node ast.Node) (string, string, string, bool) {
	switch typed := node.(type) {
	case *ast.ExprBinaryOpIdentical:
		return s.literalEqualityGuardPair(typed.Left, typed.Right)
	case *ast.ExprBinaryOpEqual:
		return s.literalEqualityGuardPair(typed.Left, typed.Right)
	default:
		return "", "", "", false
	}
}

func (s *analysisState) literalEqualityGuardPair(left, right ast.Node) (string, string, string, bool) {
	variable, ok := left.(*ast.ExprVariable)
	if !ok {
		return "", "", "", false
	}
	name, ok := variable.Name.(string)
	if !ok || name == "" {
		return "", "", "", false
	}
	value, ok := s.literalScalarValue(right)
	if !ok || value == "" {
		return "", "", "", false
	}
	rawString, _ := s.literalStringValue(right)
	return name, value, rawString, true
}

func (s *analysisState) literalFuncScalarValue(call *ast.ExprFuncCall) (string, bool) {
	name := normalizeName(identifierText(call.Name))
	switch name {
	case "strpos", "stripos":
		if len(call.Args) < 2 {
			return "", false
		}
		haystack, haystackKnown := s.literalStringValue(argValue(call.Args[0]))
		needle, needleKnown := s.literalStringValue(argValue(call.Args[1]))
		if !haystackKnown || !needleKnown {
			return "", false
		}
		if name == "stripos" {
			haystack = strings.ToLower(haystack)
			needle = strings.ToLower(needle)
		}
		idx := strings.Index(haystack, needle)
		if idx < 0 {
			return "bool:false", true
		}
		return "num:" + strconv.Itoa(idx), true
	case "str_contains":
		if len(call.Args) < 2 {
			return "", false
		}
		haystack, haystackKnown := s.literalStringValue(argValue(call.Args[0]))
		needle, needleKnown := s.literalStringValue(argValue(call.Args[1]))
		if !haystackKnown || !needleKnown {
			return "", false
		}
		if strings.Contains(haystack, needle) {
			return "bool:true", true
		}
		return "bool:false", true
	default:
		return "", false
	}
}

func (s *analysisState) refineStringEnvForTruthyCondition(node ast.Node) {
	switch typed := node.(type) {
	case *ast.ExprBinaryOpBooleanAnd:
		s.refineStringEnvForTruthyCondition(typed.Left)
		s.refineStringEnvForTruthyCondition(typed.Right)
	case *ast.ExprBinaryOpLogicalAnd:
		s.refineStringEnvForTruthyCondition(typed.Left)
		s.refineStringEnvForTruthyCondition(typed.Right)
	case *ast.ExprBinaryOpIdentical:
		s.applyTruthyStringPrefixGuard(typed.Left, typed.Right)
	case *ast.ExprBinaryOpEqual:
		s.applyTruthyStringPrefixGuard(typed.Left, typed.Right)
	}
}

func (s *analysisState) applyTruthyStringPrefixGuard(left, right ast.Node) {
	name, pattern, ok := s.truthyStringPrefixGuard(left, right)
	if !ok {
		name, pattern, ok = s.truthyStringPrefixGuard(right, left)
	}
	if !ok || name == "" || pattern == "" {
		return
	}
	current := strings.TrimSpace(s.stringEnv[name])
	switch {
	case current == "", current == conflictingLiteralArgHint:
		s.stringEnv[name] = pattern
	case !strings.Contains(current, "{"):
		return
	case strings.HasPrefix(current, strings.TrimSuffix(pattern, "{suffix}")):
		return
	default:
		s.stringEnv[name] = pattern
	}
}

func (s *analysisState) seedSelectorConditionAssignments(branch analysisState, cond ast.Node, stmts []ast.Node) analysisState {
	candidate, origins, ok := s.selectorConditionCandidateOrigins(cond)
	if !ok || candidate == "" || len(origins) == 0 {
		return branch
	}
	for _, node := range stmts {
		exprStmt, ok := node.(*ast.StmtExpression)
		if !ok {
			continue
		}
		var target ast.Node
		switch typed := exprStmt.Expr.(type) {
		case *ast.ExprAssign:
			if !selectorAssignedFromVariable(typed.Expr, candidate) {
				continue
			}
			target = typed.Var
		case *ast.ExprAssignRef:
			if !selectorAssignedFromVariable(typed.Expr, candidate) {
				continue
			}
			target = typed.Var
		default:
			continue
		}
		branch.assignToNode(target, origins, "")
	}
	return branch
}

func selectorAssignedFromVariable(node ast.Node, candidate string) bool {
	variable, ok := node.(*ast.ExprVariable)
	if !ok {
		return false
	}
	name, ok := variable.Name.(string)
	return ok && name == candidate
}

func (s *analysisState) selectorConditionCandidateOrigins(node ast.Node) (string, originSet, bool) {
	switch typed := node.(type) {
	case *ast.ExprBinaryOpNotIdentical:
		if isFalseLiteralNode(typed.Left) {
			return s.selectorCallCandidateOrigins(typed.Right)
		}
		if isFalseLiteralNode(typed.Right) {
			return s.selectorCallCandidateOrigins(typed.Left)
		}
	case *ast.ExprBinaryOpNotEqual:
		if isFalseLiteralNode(typed.Left) {
			return s.selectorCallCandidateOrigins(typed.Right)
		}
		if isFalseLiteralNode(typed.Right) {
			return s.selectorCallCandidateOrigins(typed.Left)
		}
	case *ast.ExprFuncCall:
		return s.selectorCallCandidateOrigins(typed)
	case *ast.ExprBinaryOpBooleanAnd:
		if candidate, origins, ok := s.selectorConditionCandidateOrigins(typed.Left); ok {
			return candidate, origins, true
		}
		return s.selectorConditionCandidateOrigins(typed.Right)
	case *ast.ExprBinaryOpLogicalAnd:
		if candidate, origins, ok := s.selectorConditionCandidateOrigins(typed.Left); ok {
			return candidate, origins, true
		}
		return s.selectorConditionCandidateOrigins(typed.Right)
	}
	return "", nil, false
}

func (s *analysisState) selectorCallCandidateOrigins(node ast.Node) (string, originSet, bool) {
	call, ok := node.(*ast.ExprFuncCall)
	if !ok {
		return "", nil, false
	}
	name := normalizeName(identifierText(call.Name))
	if name != "strpos" && name != "stripos" && name != "str_contains" {
		return "", nil, false
	}
	if len(call.Args) < 2 {
		return "", nil, false
	}
	variable, ok := argValue(call.Args[0]).(*ast.ExprVariable)
	if !ok {
		return "", nil, false
	}
	candidate, ok := variable.Name.(string)
	if !ok || candidate == "" {
		return "", nil, false
	}
	origins := s.evalExpr(argValue(call.Args[1]))
	if len(origins) == 0 {
		return "", nil, false
	}
	return candidate, origins, true
}

func isFalseLiteralNode(node ast.Node) bool {
	if truth, ok := booleanLiteral(node); ok {
		return !truth
	}
	fetch, ok := node.(*ast.ExprConstFetch)
	return ok && strings.EqualFold(identifierText(fetch.Name), "false")
}

func (s *analysisState) truthyStringPrefixGuard(left, right ast.Node) (string, string, bool) {
	number, ok := numericLiteral(left)
	if !ok || number != 0 {
		return "", "", false
	}
	call, ok := right.(*ast.ExprFuncCall)
	if !ok {
		return "", "", false
	}
	name := normalizeName(identifierText(call.Name))
	if name != "strpos" && name != "stripos" {
		return "", "", false
	}
	if len(call.Args) < 2 {
		return "", "", false
	}
	variable, ok := argValue(call.Args[0]).(*ast.ExprVariable)
	if !ok {
		return "", "", false
	}
	varName, ok := variable.Name.(string)
	if !ok {
		return "", "", false
	}
	prefix, ok := s.literalStringValue(argValue(call.Args[1]))
	if !ok || prefix == "" {
		return "", "", false
	}
	return strings.TrimSpace(varName), prefix + "{suffix}", true
}

func (s *analysisState) walkStatement(node ast.Node) {
	switch typed := node.(type) {
	case *ast.StmtExpression:
		s.evalExpr(typed.Expr)
	case *ast.StmtEcho:
		for _, expr := range typed.Exprs {
			origins := s.evalExpr(expr)
			s.addRecordDisclosureFinding(origins, s.locationForNode(expr))
			s.addPersistentOutputFinding(origins, s.locationForNode(expr))
			s.addReflectedRequestOutputFinding(origins, s.locationForNode(expr))
			if s.engine.allowsSinkOp("action") &&
				(s.engine.callableHasRecordRead(s.current.Key) || callableHasDownloadDataSource(s.current)) &&
				callableHasAttachmentDispositionHeaderBefore(s.engine, s.current, typed.StartLine()) {
				actionOrigins := s.currentActionRequestOrigins()
				if len(actionOrigins) != 0 {
					s.addUnauthorizedActionFinding("wp-request-sensitive-action-without-cap-check", requestSensitiveActionMessage, actionOrigins, s.locationForNode(expr))
				}
			}
		}
	case *ast.StmtReturn:
		s.addPublicTokenIssuanceSurfaceFindingForReturn(typed)
		s.addPredictableIdentifierSurfaceFindingForReturn(typed)
		returnPaths := s.returnStructuralPaths(typed.Expr)
		returnOrigins := originSet{}
		if paramIdx, ok := s.returnParamIndex(typed.Expr); ok && len(returnPaths) != 0 {
			returnOrigins = makeOriginSet(origin{kind: originParam, paramIdx: paramIdx})
		} else {
			returnOrigins = s.evalExpr(typed.Expr)
			if collapsed, ok := collapseOriginsToSingleParamRoot(returnOrigins); ok {
				returnOrigins = collapsed
			}
		}
		if collapsed, ok := collapseOriginsToSingleParamRoot(returnOrigins); ok {
			returnOrigins = collapsed
		}
		if s.pathExprIsCanonical(typed.Expr) {
			returnOrigins = markPathSafeOrigins(returnOrigins)
		}
		if paramIdx, ok := s.engine.pathSanitizingReturnParamIndex(s.current.Key); ok {
			if returnedParamIdx, returned := s.returnParamIndex(typed.Expr); returned && returnedParamIdx == paramIdx {
				returnOrigins = markPathSafeOrigins(returnOrigins)
			}
		}
		s.returnValue = s.returnValue.union(returnOrigins)
		if ruleID, message, ok := s.engine.sqlClauseFilterReturnSinkForCallable(s.current.Key); ok {
			s.addSinkFindings(ruleID, message, s.sqlExecutionOrigins(typed.Expr), s.locationForNode(typed.Expr), s.currentContext())
		}
		if s.currentCallableReturnsPublicMarkup() {
			s.addPersistentOutputFinding(returnOrigins, s.locationForNode(typed.Expr))
		}
		if len(returnPaths) != 0 {
			for relPath, origins := range returnPaths {
				unionMapEntry(s.returnPathWrites, relPath, origins)
			}
		} else {
			s.captureReturnStructure(typed.Expr)
		}
		if className := s.resolveClassExpr(typed.Expr); className != "" {
			s.returnClasses[className] = struct{}{}
		}
	case *ast.StmtIf:
		s.addUploadValidationSurfaceFindingsForIf(typed)
		if truth, ok := s.engine.literalConditionTruthForCallable(typed.Cond, s.current, map[string]struct{}{}); ok {
			s.evalExpr(typed.Cond)
			if truth {
				s.walkStatements(typed.Stmts)
				return
			}
			allElseifsKnown := true
			for _, elseifNode := range typed.Elseifs {
				elseifStmt, ok := elseifNode.(*ast.StmtElseIf)
				if !ok {
					continue
				}
				elseifTruth, elseifKnown := s.engine.literalConditionTruthForCallable(elseifStmt.Cond, s.current, map[string]struct{}{})
				if !elseifKnown {
					allElseifsKnown = false
					break
				}
				s.evalExpr(elseifStmt.Cond)
				if elseifTruth {
					s.walkStatements(elseifStmt.Stmts)
					return
				}
			}
			if allElseifsKnown {
				if typed.Else != nil {
					if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
						s.walkStatements(elseStmt.Stmts)
					}
				}
				return
			}
		}
		s.evalExpr(typed.Cond)
		baseVars := cloneVarMap(s.varTaint)
		baseProps := cloneVarMap(s.propTaint)
		baseStaticProps := cloneVarMap(s.staticPropTaint)
		baseClasses := cloneStringMap(s.classEnv)
		baseStrings := cloneStringMap(s.stringEnv)
		baseExtractContainers := append([]ast.Node(nil), s.extractContainers...)
		thenState := s.cloneWith(cloneVarMap(baseVars), cloneVarMap(baseProps), cloneVarMap(baseStaticProps), cloneStringMap(baseClasses), cloneStringMap(baseStrings))
		for name := range s.canonicalPathVariablesForTrueBranch(typed.Cond) {
			thenState.markCanonicalPathVariable(name)
		}
		thenState.walkStatements(typed.Stmts)
		thenState = s.seedSelectorConditionAssignments(thenState, typed.Cond, typed.Stmts)
		mergedVars := cloneVarMap(thenState.varTaint)
		mergedProps := cloneVarMap(thenState.propTaint)
		mergedStaticProps := cloneVarMap(thenState.staticPropTaint)
		mergedReceiverWrites := cloneVarMap(thenState.receiverWrites)
		mergedReceiverStorageLinks := cloneStringMap(thenState.receiverStorageLinks)
		mergedStructuralStorageLinks := cloneStringMap(thenState.structuralStorageLinks)
		mergedStorageWrites := cloneVarMap(thenState.storageWrites)
		mergedStoragePathWrites := cloneVarMap(thenState.storagePathWrites)
		mergedClasses := cloneStringMap(thenState.classEnv)
		mergedStrings := cloneStringMap(thenState.stringEnv)
		mergedExtractContainers := append([]ast.Node(nil), thenState.extractContainers...)
		mergedReturns := thenState.returnValue
		mergedReturnPathWrites := cloneVarMap(thenState.returnPathWrites)
		mergedReturnClasses := cloneStringSet(thenState.returnClasses)
		s.mergeFindingsFrom(thenState)
		for _, elseifNode := range typed.Elseifs {
			elseifStmt, ok := elseifNode.(*ast.StmtElseIf)
			if !ok {
				continue
			}
			elseifState := s.cloneWith(cloneVarMap(baseVars), cloneVarMap(baseProps), cloneVarMap(baseStaticProps), cloneStringMap(baseClasses), cloneStringMap(baseStrings))
			elseifState.evalExpr(elseifStmt.Cond)
			for name := range s.canonicalPathVariablesForTrueBranch(elseifStmt.Cond) {
				elseifState.markCanonicalPathVariable(name)
			}
			elseifState.walkStatements(elseifStmt.Stmts)
			elseifState = s.seedSelectorConditionAssignments(elseifState, elseifStmt.Cond, elseifStmt.Stmts)
			mergedVars = mergeVarMaps(mergedVars, elseifState.varTaint)
			mergedProps = mergeVarMaps(mergedProps, elseifState.propTaint)
			mergedStaticProps = mergeVarMaps(mergedStaticProps, elseifState.staticPropTaint)
			mergedReceiverWrites = mergeVarMaps(mergedReceiverWrites, elseifState.receiverWrites)
			mergedReceiverStorageLinks = mergeStringMaps(mergedReceiverStorageLinks, elseifState.receiverStorageLinks)
			mergedStructuralStorageLinks = mergeStringMaps(mergedStructuralStorageLinks, elseifState.structuralStorageLinks)
			mergedStorageWrites = mergeVarMaps(mergedStorageWrites, elseifState.storageWrites)
			mergedStoragePathWrites = mergeVarMaps(mergedStoragePathWrites, elseifState.storagePathWrites)
			mergedClasses = mergeStringMaps(mergedClasses, elseifState.classEnv)
			mergedStrings = mergeStringMaps(mergedStrings, elseifState.stringEnv)
			mergedExtractContainers = mergeNodeSlices(mergedExtractContainers, elseifState.extractContainers)
			mergedReturns = mergedReturns.union(elseifState.returnValue)
			mergedReturnPathWrites = mergeVarMaps(mergedReturnPathWrites, elseifState.returnPathWrites)
			mergedReturnClasses = mergeStringSets(mergedReturnClasses, elseifState.returnClasses)
			s.mergeFindingsFrom(elseifState)
		}
		if typed.Else != nil {
			if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
				elseState := s.cloneWith(cloneVarMap(baseVars), cloneVarMap(baseProps), cloneVarMap(baseStaticProps), cloneStringMap(baseClasses), cloneStringMap(baseStrings))
				elseState.walkStatements(elseStmt.Stmts)
				mergedVars = mergeVarMaps(mergedVars, elseState.varTaint)
				mergedProps = mergeVarMaps(mergedProps, elseState.propTaint)
				mergedStaticProps = mergeVarMaps(mergedStaticProps, elseState.staticPropTaint)
				mergedReceiverWrites = mergeVarMaps(mergedReceiverWrites, elseState.receiverWrites)
				mergedReceiverStorageLinks = mergeStringMaps(mergedReceiverStorageLinks, elseState.receiverStorageLinks)
				mergedStructuralStorageLinks = mergeStringMaps(mergedStructuralStorageLinks, elseState.structuralStorageLinks)
				mergedStorageWrites = mergeVarMaps(mergedStorageWrites, elseState.storageWrites)
				mergedStoragePathWrites = mergeVarMaps(mergedStoragePathWrites, elseState.storagePathWrites)
				mergedClasses = mergeStringMaps(mergedClasses, elseState.classEnv)
				mergedStrings = mergeStringMaps(mergedStrings, elseState.stringEnv)
				mergedExtractContainers = mergeNodeSlices(mergedExtractContainers, elseState.extractContainers)
				mergedReturns = mergedReturns.union(elseState.returnValue)
				mergedReturnPathWrites = mergeVarMaps(mergedReturnPathWrites, elseState.returnPathWrites)
				mergedReturnClasses = mergeStringSets(mergedReturnClasses, elseState.returnClasses)
				s.mergeFindingsFrom(elseState)
			}
		} else {
			mergedVars = mergeVarMaps(mergedVars, baseVars)
			mergedProps = mergeVarMaps(mergedProps, baseProps)
			mergedStaticProps = mergeVarMaps(mergedStaticProps, baseStaticProps)
			mergedClasses = mergeStringMaps(mergedClasses, baseClasses)
			mergedStrings = mergeStringMaps(mergedStrings, baseStrings)
			mergedExtractContainers = mergeNodeSlices(mergedExtractContainers, baseExtractContainers)
		}
		s.varTaint = mergedVars
		s.propTaint = mergedProps
		s.staticPropTaint = mergedStaticProps
		s.receiverWrites = mergedReceiverWrites
		s.receiverStorageLinks = mergedReceiverStorageLinks
		s.structuralStorageLinks = mergedStructuralStorageLinks
		s.storageWrites = mergedStorageWrites
		s.storagePathWrites = mergedStoragePathWrites
		s.classEnv = mergedClasses
		s.stringEnv = mergedStrings
		s.extractContainers = mergedExtractContainers
		s.returnValue = s.returnValue.union(mergedReturns)
		s.returnPathWrites = mergeVarMaps(s.returnPathWrites, mergedReturnPathWrites)
		s.returnClasses = mergeStringSets(s.returnClasses, mergedReturnClasses)
		if typed.Else == nil && branchDefinitelyAborts(typed.Stmts) {
			if guardedVar, ok := canonicalRealpathGuardVariable(typed.Cond); ok {
				s.markCanonicalPathVariable(guardedVar)
			}
		}
	case *ast.StmtForeach:
		origins := s.evalExpr(typed.Expr)
		branch := s.clone()
		branch.assignToNode(typed.ValueVar, appendIteratedOrigins(origins), "")
		branch.copyForeachValueStructure(typed.ValueVar, typed.Expr)
		if typed.KeyVar != nil {
			branch.assignToNode(typed.KeyVar, origins, "")
			branch.assignForeachKeyHint(typed.KeyVar, typed.Expr)
		}
		branch.walkStatements(typed.Stmts)
		s.varTaint = mergeVarMaps(s.varTaint, branch.varTaint)
		s.propTaint = mergeVarMaps(s.propTaint, branch.propTaint)
		s.staticPropTaint = mergeVarMaps(s.staticPropTaint, branch.staticPropTaint)
		s.receiverWrites = mergeVarMaps(s.receiverWrites, branch.receiverWrites)
		s.receiverStorageLinks = mergeStringMaps(s.receiverStorageLinks, branch.receiverStorageLinks)
		s.structuralStorageLinks = mergeStringMaps(s.structuralStorageLinks, branch.structuralStorageLinks)
		s.storageWrites = mergeVarMaps(s.storageWrites, branch.storageWrites)
		s.storagePathWrites = mergeVarMaps(s.storagePathWrites, branch.storagePathWrites)
		s.classEnv = mergeStringMaps(s.classEnv, branch.classEnv)
		s.stringEnv = mergeStringMaps(s.stringEnv, branch.stringEnv)
		s.extractContainers = mergeNodeSlices(s.extractContainers, branch.extractContainers)
		s.returnValue = s.returnValue.union(branch.returnValue)
		s.returnPathWrites = mergeVarMaps(s.returnPathWrites, branch.returnPathWrites)
		s.returnClasses = mergeStringSets(s.returnClasses, branch.returnClasses)
		s.mergeFindingsFrom(branch)
	case *ast.StmtSwitch:
		s.evalExpr(typed.Cond)
		if cases, ok := s.literalSwitchCases(typed); ok {
			for _, caseStmt := range cases {
				if caseStmt.Cond != nil {
					s.evalExpr(caseStmt.Cond)
				}
				s.walkStatements(caseStmt.Stmts)
				if branchDefinitelyAborts(caseStmt.Stmts) {
					break
				}
			}
			return
		}
		baseVars := cloneVarMap(s.varTaint)
		baseProps := cloneVarMap(s.propTaint)
		baseStaticProps := cloneVarMap(s.staticPropTaint)
		baseClasses := cloneStringMap(s.classEnv)
		baseStrings := cloneStringMap(s.stringEnv)
		baseExtractContainers := append([]ast.Node(nil), s.extractContainers...)
		mergedVars := cloneVarMap(baseVars)
		mergedProps := cloneVarMap(baseProps)
		mergedStaticProps := cloneVarMap(baseStaticProps)
		mergedClasses := cloneStringMap(baseClasses)
		mergedStrings := cloneStringMap(baseStrings)
		mergedExtractContainers := append([]ast.Node(nil), baseExtractContainers...)
		for _, caseNode := range typed.Cases {
			caseStmt, ok := caseNode.(*ast.StmtCase)
			if !ok {
				continue
			}
			branch := s.cloneWith(cloneVarMap(baseVars), cloneVarMap(baseProps), cloneVarMap(baseStaticProps), cloneStringMap(baseClasses), cloneStringMap(baseStrings))
			branch.evalExpr(caseStmt.Cond)
			branch.walkStatements(caseStmt.Stmts)
			mergedVars = mergeVarMaps(mergedVars, branch.varTaint)
			mergedProps = mergeVarMaps(mergedProps, branch.propTaint)
			mergedStaticProps = mergeVarMaps(mergedStaticProps, branch.staticPropTaint)
			s.receiverWrites = mergeVarMaps(s.receiverWrites, branch.receiverWrites)
			s.receiverStorageLinks = mergeStringMaps(s.receiverStorageLinks, branch.receiverStorageLinks)
			s.structuralStorageLinks = mergeStringMaps(s.structuralStorageLinks, branch.structuralStorageLinks)
			s.storageWrites = mergeVarMaps(s.storageWrites, branch.storageWrites)
			s.storagePathWrites = mergeVarMaps(s.storagePathWrites, branch.storagePathWrites)
			mergedClasses = mergeStringMaps(mergedClasses, branch.classEnv)
			mergedStrings = mergeStringMaps(mergedStrings, branch.stringEnv)
			mergedExtractContainers = mergeNodeSlices(mergedExtractContainers, branch.extractContainers)
			s.returnValue = s.returnValue.union(branch.returnValue)
			s.returnPathWrites = mergeVarMaps(s.returnPathWrites, branch.returnPathWrites)
			s.returnClasses = mergeStringSets(s.returnClasses, branch.returnClasses)
			s.mergeFindingsFrom(branch)
		}
		s.varTaint = mergedVars
		s.propTaint = mergedProps
		s.staticPropTaint = mergedStaticProps
		s.classEnv = mergedClasses
		s.stringEnv = mergedStrings
		s.extractContainers = mergedExtractContainers
	default:
		if skipNestedDeclarationBodies(s.current, node) {
			return
		}
		for _, nested := range childStatementBlocks(node) {
			s.walkStatements(nested)
		}
	}
}
