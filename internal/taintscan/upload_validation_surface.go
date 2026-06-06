package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func uploadValidationFilterModelForEntryPoints(entries []EntryPoint) (uploadValidationFilterModel, bool) {
	for _, entry := range entries {
		if entry.Kind != "filter" {
			continue
		}
		if model, ok := uploadValidationFilterModelForHook(entry.Name); ok {
			return model, true
		}
	}
	return uploadValidationFilterModel{}, false
}

func (e *engine) callableHasUploadValidationSurfaceSink(c callable) bool {
	model, ok := uploadValidationFilterModelForEntryPoints(e.contexts[c.Key].EntryPoints)
	if !ok {
		model, ok = uploadValidationFilterModelForEntryPoints(e.directEntryPointsByCallable[c.Key])
		if !ok {
			return false
		}
	}
	return callableHasUploadValidationSurfaceInNodes(c.Stmts, c, model)
}

func callableHasUploadValidationSurfaceInNodes(nodes []ast.Node, current callable, model uploadValidationFilterModel) bool {
	filenameVars := uploadValidationConditionFilenameVarsInNodes(nodes)
	if len(filenameVars) == 0 {
		filenameVars = map[string]struct{}{}
	}
	extensionVars := callableFilenameExtensionVars(current, filenameVars)
	for _, node := range nodes {
		switch typed := node.(type) {
		case *ast.StmtIf:
			if uploadValidationConditionIsUnsafe(typed.Cond, current, filenameVars, extensionVars) &&
				len(collectUploadValidationSurfaceWriteLocations(typed.Stmts, current, model)) != 0 {
				return true
			}
			for _, rawElseIf := range typed.Elseifs {
				elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
				if !ok {
					continue
				}
				if uploadValidationConditionIsUnsafe(elseifStmt.Cond, current, filenameVars, extensionVars) &&
					len(collectUploadValidationSurfaceWriteLocations(elseifStmt.Stmts, current, model)) != 0 {
					return true
				}
			}
			if callableHasUploadValidationSurfaceInNodes(typed.Stmts, current, model) {
				return true
			}
			for _, rawElseIf := range typed.Elseifs {
				elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
				if ok && callableHasUploadValidationSurfaceInNodes(elseifStmt.Stmts, current, model) {
					return true
				}
			}
			if elseStmt, ok := typed.Else.(*ast.StmtElse); ok && callableHasUploadValidationSurfaceInNodes(elseStmt.Stmts, current, model) {
				return true
			}
		default:
			for _, nested := range childStatementBlocks(node) {
				if callableHasUploadValidationSurfaceInNodes(nested, current, model) {
					return true
				}
			}
		}
	}
	return false
}

func (s *analysisState) addUploadValidationSurfaceFindingsForIf(stmt *ast.StmtIf) {
	if stmt == nil || !s.engine.allowsSinkOp("surface") {
		return
	}
	model, ok := uploadValidationFilterModelForEntryPoints(s.currentContext().EntryPoints)
	if !ok {
		return
	}
	s.addUploadValidationSurfaceFindingsForBranch(stmt.Cond, stmt.Stmts, model)
	for _, rawElseIf := range stmt.Elseifs {
		elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
		if !ok {
			continue
		}
		s.addUploadValidationSurfaceFindingsForBranch(elseifStmt.Cond, elseifStmt.Stmts, model)
	}
}

func (s *analysisState) addUploadValidationSurfaceFindingsForBranch(cond ast.Node, nodes []ast.Node, model uploadValidationFilterModel) {
	origins := s.uploadValidationConditionOrigins(cond)
	if len(origins) == 0 {
		return
	}
	for _, sink := range collectUploadValidationSurfaceWriteLocations(nodes, s.current, model) {
		s.addSinkFindings(model.RuleID, model.Message, origins, sink, s.currentContext())
	}
}

func (s *analysisState) uploadValidationConditionOrigins(cond ast.Node) originSet {
	filenameVars := uploadValidationConditionFilenameVars(cond)
	if len(filenameVars) == 0 {
		return originSet{}
	}
	extensionVars := callableFilenameExtensionVars(s.current, filenameVars)
	if !uploadValidationConditionIsUnsafe(cond, s.current, filenameVars, extensionVars) {
		return originSet{}
	}
	origins := originSet{}
	walkNode(cond, func(node ast.Node) {
		if call, ok := node.(*ast.ExprFuncCall); ok && uploadValidationFilenameSubstringCheck(call, filenameVars) {
			origins = origins.union(s.evalExpr(argValue(call.Args[0])))
		}
	})
	return origins
}

func collectUploadValidationSurfaceWriteLocations(nodes []ast.Node, current callable, model uploadValidationFilterModel) []Location {
	defaultsParam := ""
	if len(current.Params) > 0 {
		defaultsParam = current.Params[0]
	}
	if defaultsParam == "" {
		return nil
	}
	out := make([]Location, 0)
	for _, node := range nodes {
		switch typed := node.(type) {
		case *ast.StmtExpression:
			if loc, ok := uploadValidationSurfaceWriteLocationForExpr(typed.Expr, current, defaultsParam); ok {
				out = append(out, loc)
			}
		case *ast.StmtIf, *ast.StmtSwitch:
			continue
		default:
			for _, nested := range childStatementBlocks(node) {
				out = append(out, collectUploadValidationSurfaceWriteLocations(nested, current, model)...)
			}
		}
	}
	return out
}

func uploadValidationSurfaceWriteLocationForExpr(expr ast.Node, current callable, defaultsParam string) (Location, bool) {
	switch typed := expr.(type) {
	case *ast.ExprAssign:
		if isUploadValidationDefaultsWrite(typed.Var, defaultsParam) {
			return locationForCallableNode(nil, current, typed.Var), true
		}
	case *ast.ExprAssignRef:
		if isUploadValidationDefaultsWrite(typed.Var, defaultsParam) {
			return locationForCallableNode(nil, current, typed.Var), true
		}
	}
	return Location{}, false
}

func isUploadValidationDefaultsWrite(target ast.Node, defaultsParam string) bool {
	arrayDim, ok := target.(*ast.ExprArrayDimFetch)
	if !ok {
		return false
	}
	if root := arrayDimRootVariableName(arrayDim); root != defaultsParam {
		return false
	}
	key := strings.ToLower(strings.TrimSpace(literalString(arrayDim.Dim)))
	return key == "ext" || key == "type"
}

func arrayDimRootVariableName(node *ast.ExprArrayDimFetch) string {
	if node == nil {
		return ""
	}
	switch typed := node.Var.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		return strings.TrimSpace(name)
	case *ast.ExprArrayDimFetch:
		return arrayDimRootVariableName(typed)
	default:
		return ""
	}
}

func uploadValidationConditionIsUnsafe(cond ast.Node, current callable, filenameVars map[string]struct{}, extensionVars map[string]struct{}) bool {
	if len(filenameVars) == 0 {
		return false
	}
	if !uploadValidationConditionHasFilenameSubstringCheck(cond, filenameVars) {
		return false
	}
	return !uploadValidationConditionHasExactExtensionGuard(cond, filenameVars, extensionVars)
}

func uploadValidationConditionFilenameVarsInNodes(nodes []ast.Node) map[string]struct{} {
	out := map[string]struct{}{}
	for _, node := range nodes {
		switch typed := node.(type) {
		case *ast.StmtIf:
			for name := range uploadValidationConditionFilenameVars(typed.Cond) {
				out[name] = struct{}{}
			}
			for _, rawElseIf := range typed.Elseifs {
				elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
				if !ok {
					continue
				}
				for name := range uploadValidationConditionFilenameVars(elseifStmt.Cond) {
					out[name] = struct{}{}
				}
			}
			for name := range uploadValidationConditionFilenameVarsInNodes(typed.Stmts) {
				out[name] = struct{}{}
			}
			for _, rawElseIf := range typed.Elseifs {
				elseifStmt, ok := rawElseIf.(*ast.StmtElseIf)
				if ok {
					for name := range uploadValidationConditionFilenameVarsInNodes(elseifStmt.Stmts) {
						out[name] = struct{}{}
					}
				}
			}
			if elseStmt, ok := typed.Else.(*ast.StmtElse); ok {
				for name := range uploadValidationConditionFilenameVarsInNodes(elseStmt.Stmts) {
					out[name] = struct{}{}
				}
			}
		default:
			for _, nested := range childStatementBlocks(node) {
				for name := range uploadValidationConditionFilenameVarsInNodes(nested) {
					out[name] = struct{}{}
				}
			}
		}
	}
	return out
}

func uploadValidationConditionFilenameVars(cond ast.Node) map[string]struct{} {
	out := map[string]struct{}{}
	walkNode(cond, func(node ast.Node) {
		call, ok := node.(*ast.ExprFuncCall)
		if !ok || !uploadValidationFilenameSubstringCheck(call, nil) {
			return
		}
		variable, ok := argValue(call.Args[0]).(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := variable.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return
		}
		out[strings.TrimSpace(name)] = struct{}{}
	})
	return out
}

func callableFilenameExtensionVars(current callable, filenameVars map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	if len(filenameVars) == 0 {
		return out
	}
	walkNodes(current.Stmts, func(node ast.Node) {
		assign, ok := node.(*ast.ExprAssign)
		if !ok {
			return
		}
		target, ok := assign.Var.(*ast.ExprVariable)
		if !ok {
			return
		}
		name, ok := target.Name.(string)
		if !ok || strings.TrimSpace(name) == "" {
			return
		}
		if isFilenameExtensionExpr(assign.Expr, filenameVars, nil) {
			out[strings.TrimSpace(name)] = struct{}{}
		}
	})
	return out
}

func uploadValidationConditionHasFilenameSubstringCheck(cond ast.Node, filenameVars map[string]struct{}) bool {
	found := false
	walkNode(cond, func(node ast.Node) {
		if found {
			return
		}
		call, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		found = uploadValidationFilenameSubstringCheck(call, filenameVars)
	})
	return found
}

func uploadValidationFilenameSubstringCheck(call *ast.ExprFuncCall, filenameVars map[string]struct{}) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}
	switch normalizeName(identifierText(call.Name)) {
	case "strpos", "stripos", "str_contains":
	default:
		return false
	}
	if len(filenameVars) == 0 {
		return true
	}
	variable, ok := argValue(call.Args[0]).(*ast.ExprVariable)
	if !ok {
		return false
	}
	name, ok := variable.Name.(string)
	if !ok {
		return false
	}
	_, ok = filenameVars[strings.TrimSpace(name)]
	return ok
}

func uploadValidationConditionHasExactExtensionGuard(cond ast.Node, filenameVars map[string]struct{}, extensionVars map[string]struct{}) bool {
	found := false
	walkNode(cond, func(node ast.Node) {
		if found {
			return
		}
		switch typed := node.(type) {
		case *ast.ExprBinaryOpIdentical:
			found = uploadValidationExactExtensionComparison(typed.Left, typed.Right, filenameVars, extensionVars) ||
				uploadValidationExactExtensionComparison(typed.Right, typed.Left, filenameVars, extensionVars)
		case *ast.ExprBinaryOpEqual:
			found = uploadValidationExactExtensionComparison(typed.Left, typed.Right, filenameVars, extensionVars) ||
				uploadValidationExactExtensionComparison(typed.Right, typed.Left, filenameVars, extensionVars)
		}
	})
	return found
}

func uploadValidationExactExtensionComparison(left ast.Node, right ast.Node, filenameVars map[string]struct{}, extensionVars map[string]struct{}) bool {
	if !isNonEmptyStringLiteral(left) {
		return false
	}
	return isFilenameExtensionExpr(right, filenameVars, extensionVars)
}

func isNonEmptyStringLiteral(node ast.Node) bool {
	switch typed := node.(type) {
	case *ast.ScalarString:
		return strings.TrimSpace(typed.Value) != ""
	default:
		return false
	}
}

func isFilenameExtensionExpr(node ast.Node, filenameVars map[string]struct{}, extensionVars map[string]struct{}) bool {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return false
		}
		_, ok = extensionVars[strings.TrimSpace(name)]
		return ok
	case *ast.ExprFuncCall:
		if normalizeName(identifierText(typed.Name)) != "pathinfo" || len(typed.Args) == 0 {
			return false
		}
		variable, ok := argValue(typed.Args[0]).(*ast.ExprVariable)
		if !ok {
			return false
		}
		filenameName, ok := variable.Name.(string)
		if !ok {
			return false
		}
		if _, ok := filenameVars[strings.TrimSpace(filenameName)]; !ok {
			return false
		}
		return true
	default:
		return false
	}
}

func isPathinfoExtensionConst(node ast.Node) bool {
	name := strings.ToLower(strings.TrimSpace(strings.Trim(literalString(node), `"'`)))
	if name == "pathinfo_extension" {
		return true
	}
	return normalizeName(identifierText(node)) == "pathinfo_extension"
}
