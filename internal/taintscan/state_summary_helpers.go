package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

type storageFuncSpec struct {
	family    string
	familyArg int
	keyArgs   []int
	valueArg  int
}

type sqlSelectColumn struct {
	Field        string
	StorageField string
	Family       string
}

func originsFromTaintSummary(item taintSummary) originSet {
	out := make(originSet, len(item.Sources)+len(item.SourceOrigins)+len(item.ReceiverPaths))
	for _, loc := range item.Sources {
		entry := origin{kind: originSource, source: loc}
		out[originKey(entry)] = entry
	}
	for _, ref := range item.SourceOrigins {
		entry := origin{
			kind:               originSource,
			source:             ref.Location,
			persistentRead:     ref.PersistentRead,
			pathSafe:           ref.PathSafe,
			outputSafeHTML:     ref.OutputSafeHTML,
			outputUnsafeHTML:   ref.OutputUnsafeHTML,
			storedWriteContext: ref.StoredWriteContext,
		}
		key := originKey(entry)
		if existing, ok := out[key]; ok {
			entry = mergeOrigins(existing, entry)
		}
		out[key] = entry
	}
	for _, ref := range item.ReceiverPaths {
		entry := origin{
			kind:               originReceiver,
			receiverPath:       ref.Path,
			persistentRead:     ref.PersistentRead,
			pathSafe:           ref.PathSafe,
			outputSafeHTML:     ref.OutputSafeHTML,
			outputUnsafeHTML:   ref.OutputUnsafeHTML,
			storedWriteContext: ref.StoredWriteContext,
		}
		key := originKey(entry)
		if existing, ok := out[key]; ok {
			entry = mergeOrigins(existing, entry)
		}
		out[key] = entry
	}
	return out
}

func storageWritesForMethodCall(call *ast.ExprMethodCall, s *analysisState) map[string]originSet {
	name := strings.ToLower(identifierText(call.Name))
	if name == "query" && len(call.Args) > 0 {
		families := parseSQLWriteFamilies(sqlQueryString(argValue(call.Args[0])))
		if len(families) == 0 {
			return nil
		}
		origins := s.evalExpr(argValue(call.Args[0]))
		out := map[string]originSet{}
		for _, family := range families {
			out[family] = out[family].union(origins)
		}
		return out
	}
	if name != "insert" && name != "update" && name != "replace" {
		return nil
	}
	if len(call.Args) < 2 {
		return nil
	}
	out := map[string]originSet{}
	if writes := databaseTableStorageWritesForMethodCall(call, s); len(writes) != 0 {
		for family, origins := range writes {
			out[family] = out[family].union(origins)
		}
	}
	pathWrites := extractStoragePathFamilies(argValue(call.Args[1]), s)
	writes := extractStorageFamilies(argValue(call.Args[1]), s)
	if len(writes) != 0 {
		if len(out) == 0 {
			for family := range writes {
				if hasExactStoragePathWriteForFamily(pathWrites, family) {
					delete(writes, family)
				}
			}
		}
		if len(writes) == 0 {
			if len(out) != 0 {
				return out
			}
			return nil
		}
		for family, origins := range writes {
			out[family] = out[family].union(origins)
		}
		return out
	}
	if len(out) != 0 {
		return out
	}
	return schemaStorageWritesForPreparedArg(argValue(call.Args[1]), s)
}

func storageWritesForFuncCall(call *ast.ExprFuncCall, s *analysisState) map[string]originSet {
	out := map[string]originSet{}
	for family, origins := range postRecordWritesForFuncCall(call, s) {
		out[family] = out[family].union(origins)
	}
	spec, ok := storageWriteSpecForFunc(normalizeName(identifierText(call.Name)))
	if !ok || spec.valueArg < 0 || spec.valueArg >= len(call.Args) {
		if len(out) == 0 {
			return nil
		}
		return out
	}
	family := storageFamilyForSpec(spec, call.Args)
	if family == "" {
		if len(out) == 0 {
			return nil
		}
		return out
	}
	if _, ok := storageRootForArgsWithState(spec, call.Args, s); ok {
		if len(out) == 0 {
			return nil
		}
		return out
	}
	out[family] = out[family].union(s.evalExpr(argValue(call.Args[spec.valueArg])))
	return out
}

func storagePathWritesForMethodCall(call *ast.ExprMethodCall, s *analysisState) map[string]originSet {
	name := strings.ToLower(identifierText(call.Name))
	if name == "query" {
		return nil
	}
	if name != "insert" && name != "update" && name != "replace" {
		return nil
	}
	if len(call.Args) < 2 {
		return nil
	}
	if writes := databaseTableStoragePathWritesForMethodCall(call, s); len(writes) != 0 {
		return writes
	}
	return extractStoragePathFamilies(argValue(call.Args[1]), s)
}

func storagePathWritesForFuncCall(call *ast.ExprFuncCall, s *analysisState) map[string]originSet {
	out := map[string]originSet{}
	for path, origins := range postRecordPathWritesForFuncCall(call, s) {
		out[path] = out[path].union(origins)
	}
	spec, ok := storageWriteSpecForFunc(normalizeName(identifierText(call.Name)))
	if !ok || spec.valueArg < 0 || spec.valueArg >= len(call.Args) {
		if len(out) == 0 {
			return nil
		}
		return out
	}
	root, ok := storageRootForArgsWithState(spec, call.Args, s)
	if !ok {
		if len(out) == 0 {
			return nil
		}
		return out
	}
	valueNode := argValue(call.Args[spec.valueArg])
	copyExprStructureToStorage(out, root, valueNode, s)
	if len(out) == 0 {
		if origins := s.evalExpr(valueNode); len(origins) != 0 {
			out[root] = origins
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hasExactStoragePathWriteForFamily(pathWrites map[string]originSet, family string) bool {
	if family == "" || len(pathWrites) == 0 {
		return false
	}
	for path := range pathWrites {
		if structuralPathRoot(path) == family && path != family {
			return true
		}
	}
	return false
}

func storageReadOriginsForMethodCall(call *ast.ExprMethodCall, s *analysisState) (originSet, bool) {
	if tableRoot := sqlSelectTableStorageRootForMethodCall(call, s); tableRoot != "" {
		origins := originSet{}
		if columns, _, ok := sqlSelectColumnsForMethodCallWithContext(call, s.current, s.engine, call.StartLine()); ok && len(columns) != 0 {
			for _, column := range columns {
				if column.StorageField == "" {
					continue
				}
				for _, storagePath := range databaseTableColumnStorageRoots(tableRoot, column.StorageField) {
					origins = unionInto(origins, s.storageSelfOrigins(storagePath))
					origins = unionInto(origins, s.storageChildOrigins(storagePath))
				}
			}
		} else {
			origins = unionInto(origins, s.storageSelfOrigins(tableRoot))
			origins = unionInto(origins, s.storageChildOrigins(tableRoot))
		}
		if len(origins) == 0 && strings.EqualFold(identifierText(call.Name), "get_results") {
			origins = unionInto(origins, s.storageSelfOrigins(tableRoot))
			origins = unionInto(origins, s.storageChildOrigins(tableRoot))
		}
		if len(origins) == 0 {
			origins = unionInto(origins, sqlSelectSelectorOriginsForMethodCall(call, s))
		}
		if len(origins) != 0 {
			return markPersistentReadOrigins(origins), true
		}
	}
	columns, _, ok := sqlSelectColumnsForMethodCallWithContext(call, s.current, s.engine, call.StartLine())
	if !ok {
		return nil, false
	}
	origins := originSet{}
	for _, column := range columns {
		origins = unionInto(origins, storageOriginsForFamily(column.Family, s))
	}
	if len(origins) == 0 {
		origins = unionInto(origins, sqlSelectSelectorOriginsForMethodCall(call, s))
	}
	return markPersistentReadOrigins(origins), true
}

func storageReadOriginsForStaticCall(call *ast.ExprStaticCall, s *analysisState) (originSet, bool) {
	if tableRoot := sqlSelectTableStorageRootForStaticCall(call, s); tableRoot != "" {
		origins := originSet{}
		if columns, _, ok := sqlSelectColumnsForStaticCall(call); ok && len(columns) != 0 {
			for _, column := range columns {
				if column.StorageField == "" {
					continue
				}
				for _, storagePath := range databaseTableColumnStorageRoots(tableRoot, column.StorageField) {
					origins = unionInto(origins, s.storageSelfOrigins(storagePath))
					origins = unionInto(origins, s.storageChildOrigins(storagePath))
				}
			}
		} else {
			origins = unionInto(origins, s.storageSelfOrigins(tableRoot))
			origins = unionInto(origins, s.storageChildOrigins(tableRoot))
		}
		if len(origins) == 0 && strings.EqualFold(identifierText(call.Name), "queryall") {
			origins = unionInto(origins, s.storageSelfOrigins(tableRoot))
			origins = unionInto(origins, s.storageChildOrigins(tableRoot))
		}
		if len(origins) == 0 {
			origins = unionInto(origins, sqlSelectSelectorOriginsForStaticCall(call, s))
		}
		if len(origins) != 0 {
			return markPersistentReadOrigins(origins), true
		}
	}
	columns, _, ok := sqlSelectColumnsForStaticCall(call)
	if !ok {
		return nil, false
	}
	origins := originSet{}
	for _, column := range columns {
		origins = unionInto(origins, storageOriginsForFamily(column.Family, s))
	}
	if len(origins) == 0 {
		origins = unionInto(origins, sqlSelectSelectorOriginsForStaticCall(call, s))
	}
	return markPersistentReadOrigins(origins), true
}

func sqlSelectSelectorOriginsForMethodCall(call *ast.ExprMethodCall, s *analysisState) originSet {
	if !isSQLSelectReadMethodCallWithContext(call, s.current, s.engine, call.StartLine()) {
		return nil
	}
	origins := originSet{}
	if len(call.Args) > 0 {
		origins = unionInto(origins, sqlSelectSelectorOriginsForNode(argValue(call.Args[0]), s, call.StartLine(), map[string]struct{}{}))
	}
	if len(origins) == 0 && len(call.Args) > 1 {
		origins = unionInto(origins, sqlSelectSelectorOriginsForNode(argValue(call.Args[1]), s, call.StartLine(), map[string]struct{}{}))
	}
	return origins
}

func sqlSelectSelectorOriginsForStaticCall(call *ast.ExprStaticCall, s *analysisState) originSet {
	if !isSQLSelectReadStaticCall(call) {
		return nil
	}
	if len(call.Args) == 0 {
		return nil
	}
	return sqlSelectSelectorOriginsForNode(argValue(call.Args[0]), s, call.StartLine(), map[string]struct{}{})
}

func sqlSelectSelectorOriginsForNode(node ast.Node, s *analysisState, beforeLine int, seen map[string]struct{}) originSet {
	if node == nil || s == nil {
		return nil
	}
	switch typed := node.(type) {
	case *ast.ExprAssign:
		return sqlSelectSelectorOriginsForNode(typed.Expr, s, beforeLine, seen)
	case *ast.ExprAssignRef:
		return sqlSelectSelectorOriginsForNode(typed.Expr, s, beforeLine, seen)
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return nil
		}
		return s.localSQLSelectorOrigins(name, beforeLine, seen)
	case *ast.ExprMethodCall:
		name := strings.ToLower(identifierText(typed.Name))
		if name == "prepare" {
			out := originSet{}
			for _, arg := range typed.Args[1:] {
				out = unionInto(out, s.evalExpr(argValue(arg)))
			}
			return out
		}
	case *ast.ExprStaticCall:
		if strings.EqualFold(identifierText(typed.Name), "prepare") {
			out := originSet{}
			for _, arg := range typed.Args[1:] {
				out = unionInto(out, s.evalExpr(argValue(arg)))
			}
			return out
		}
	}
	return nil
}

func (s *analysisState) localSQLSelectorOrigins(name string, beforeLine int, seen map[string]struct{}) originSet {
	name = strings.TrimSpace(name)
	if name == "" || s == nil || s.engine == nil {
		return nil
	}
	seenKey := "sqlselector::" + s.current.Key + "::" + name
	if _, ok := seen[seenKey]; ok {
		return nil
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)

	var best originsWithLine
	ambiguous := false
	walkNodes(s.current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok || assign.StartLine() >= beforeLine {
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
		candidate := sqlSelectSelectorOriginsForNode(assign.Expr, s, assign.StartLine(), seen)
		if len(candidate) == 0 {
			return
		}
		if assign.StartLine() > best.line {
			best = originsWithLine{origins: candidate, line: assign.StartLine()}
			ambiguous = false
			return
		}
		if assign.StartLine() == best.line && !originsEqual(best.origins, candidate) {
			ambiguous = true
		}
	})
	if ambiguous {
		return nil
	}
	return best.origins
}

type originsWithLine struct {
	origins originSet
	line    int
}

func originsEqual(a, b originSet) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

func sqlSelectReturnPathsForMethodCall(call *ast.ExprMethodCall, s *analysisState) (map[string]originSet, bool) {
	tableRoot := sqlSelectTableStorageRootForMethodCall(call, s)
	columns, multipleRows, ok := sqlSelectColumnsForMethodCallWithContext(call, s.current, s.engine, call.StartLine())
	if ok && len(columns) != 0 {
		paths := returnPathsForSQLColumns(columns, multipleRows, tableRoot, s)
		if len(paths) != 0 {
			return paths, true
		}
	}
	if !strings.EqualFold(identifierText(call.Name), "get_results") || tableRoot == "" {
		return nil, false
	}
	paths := returnPathsForWholeSQLTable(true, tableRoot, s)
	if len(paths) == 0 {
		if fallback := sourceLikeReturnPathsForMethodCall(call, columns, true, s); len(fallback) != 0 {
			return fallback, true
		}
		return nil, false
	}
	return paths, true
}

func sqlSelectReturnPathsForStaticCall(call *ast.ExprStaticCall, s *analysisState) (map[string]originSet, bool) {
	tableRoot := sqlSelectTableStorageRootForStaticCall(call, s)
	columns, multipleRows, ok := sqlSelectColumnsForStaticCall(call)
	if ok && len(columns) != 0 {
		paths := returnPathsForSQLColumns(columns, multipleRows, tableRoot, s)
		if len(paths) != 0 {
			return paths, true
		}
	}
	if !strings.EqualFold(identifierText(call.Name), "queryall") || tableRoot == "" {
		return nil, false
	}
	paths := returnPathsForWholeSQLTable(true, tableRoot, s)
	if len(paths) == 0 {
		if fallback := sourceLikeReturnPathsForStaticCall(call, columns, true, s); len(fallback) != 0 {
			return fallback, true
		}
		return nil, false
	}
	return paths, true
}

func returnPathsForWholeSQLTable(multipleRows bool, tableRoot string, s *analysisState) map[string]originSet {
	if tableRoot == "" {
		return nil
	}
	out := map[string]originSet{}
	prefix := ""
	if multipleRows {
		prefix = "[]"
	}
	for rel, origins := range collectRelativeStructuralPathsFromStorage(s, tableRoot) {
		unionMapEntry(out, prefix+rel, origins)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sourceLikeReturnPathsForMethodCall(call *ast.ExprMethodCall, columns []sqlSelectColumn, multipleRows bool, s *analysisState) map[string]originSet {
	origins := sourceLikeSQLReadOriginsForMethodCall(call, s)
	if len(origins) == 0 {
		return nil
	}
	return sourceLikeReturnPathsForSQLRead(columns, multipleRows, origins)
}

func sourceLikeReturnPathsForStaticCall(call *ast.ExprStaticCall, columns []sqlSelectColumn, multipleRows bool, s *analysisState) map[string]originSet {
	origins := sourceLikeSQLReadOriginsForStaticCall(call, s)
	if len(origins) == 0 {
		return nil
	}
	return sourceLikeReturnPathsForSQLRead(columns, multipleRows, origins)
}

func sourceLikeReturnPathsForSQLRead(columns []sqlSelectColumn, multipleRows bool, origins originSet) map[string]originSet {
	if len(origins) == 0 {
		return nil
	}
	out := map[string]originSet{}
	if len(columns) != 0 {
		for _, column := range columns {
			if column.Field == "" {
				continue
			}
			for _, relPath := range sqlColumnResultRelativePaths(column.Field, multipleRows) {
				unionMapEntry(out, relPath, origins)
			}
		}
	}
	if len(out) != 0 {
		return out
	}
	relPath := "[*]"
	if multipleRows {
		relPath = "[][*]"
	}
	unionMapEntry(out, relPath, origins)
	return out
}

func databaseTableStorageRootForMethodCall(call *ast.ExprMethodCall, s *analysisState) string {
	if len(call.Args) == 0 {
		return ""
	}
	tableKey := databaseTableKeyForNode(argValue(call.Args[0]), s, call.StartLine())
	if tableKey == "" {
		return ""
	}
	return "db_table_value[" + tableKey + "]"
}

func databaseTableStorageWritesForMethodCall(call *ast.ExprMethodCall, s *analysisState) map[string]originSet {
	root := databaseTableStorageRootForMethodCall(call, s)
	if root == "" || len(call.Args) < 2 {
		return nil
	}
	origins := s.evalExpr(argValue(call.Args[1]))
	if len(origins) == 0 {
		return nil
	}
	return map[string]originSet{root: origins}
}

func databaseTableStoragePathWritesForMethodCall(call *ast.ExprMethodCall, s *analysisState) map[string]originSet {
	root := databaseTableStorageRootForMethodCall(call, s)
	if root == "" || len(call.Args) < 2 {
		return nil
	}
	arrayNode, ok := argValue(call.Args[1]).(*ast.ExprArray)
	if ok {
		out := map[string]originSet{}
		for _, itemNode := range arrayNode.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			key := canonicalDBTableKey(literalString(item.Key))
			if key == "" {
				continue
			}
			copyExprStructureToStorage(out, root+"."+key, item.Value, s)
			if _, exists := out[root+"."+key]; !exists {
				unionMapEntry(out, root+"."+key, s.evalExpr(item.Value))
			}
		}
		if len(out) != 0 {
			return out
		}
	}
	if src, ok := s.structuralRoot(argValue(call.Args[1])); ok {
		out := map[string]originSet{}
		s.copyStructuralPathsToMap(out, root, src)
		if len(out) != 0 {
			return out
		}
	}
	if prepared := preparedSchemaSourceNode(argValue(call.Args[1]), s); prepared != nil {
		if writes := extractStoragePathFamilies(prepared, s); len(writes) != 0 {
			out := map[string]originSet{}
			for path, origins := range writes {
				unionMapEntry(out, root+"."+path, origins)
			}
			if len(out) != 0 {
				return out
			}
		}
	}
	if writes := schemaStoragePathWritesForPreparedArg(argValue(call.Args[1]), s); len(writes) != 0 {
		out := map[string]originSet{}
		for path, origins := range writes {
			unionMapEntry(out, root+"."+path, origins)
		}
		if len(out) != 0 {
			return out
		}
	}
	return nil
}

func sqlSelectTableStorageRootForMethodCall(call *ast.ExprMethodCall, s *analysisState) string {
	if !isSQLSelectReadMethodCallWithContext(call, s.current, s.engine, call.StartLine()) || len(call.Args) == 0 {
		return ""
	}
	queryNode := argValue(call.Args[0])
	if key := sqlSelectTableKeyForNode(queryNode, s, call.StartLine()); key != "" {
		return "db_table_value[" + key + "]"
	}
	if len(call.Args) > 1 {
		if key := sqlSelectTableKeyForNode(argValue(call.Args[1]), s, call.StartLine()); key != "" {
			return "db_table_value[" + key + "]"
		}
	}
	return ""
}

func sqlSelectTableStorageRootForStaticCall(call *ast.ExprStaticCall, s *analysisState) string {
	if !isSQLSelectReadStaticCall(call) || len(call.Args) == 0 {
		return ""
	}
	queryNode := argValue(call.Args[0])
	if key := sqlSelectTableKeyForNode(queryNode, s, call.StartLine()); key != "" {
		return "db_table_value[" + key + "]"
	}
	return ""
}

func isSQLSelectReadMethodCall(call *ast.ExprMethodCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "get_var" && name != "get_row" && name != "get_results" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	if isSQLSelectQueryString(sqlQueryString(argValue(call.Args[0]))) {
		return true
	}
	if len(call.Args) > 1 && isSQLSelectQueryString(sqlQueryString(argValue(call.Args[1]))) {
		return true
	}
	return false
}

func isSQLSelectReadMethodCallWithContext(call *ast.ExprMethodCall, current callable, e *engine, beforeLine int) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "get_var" && name != "get_row" && name != "get_results" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	if isSQLSelectQueryString(sqlQueryStringWithContext(argValue(call.Args[0]), current, e, beforeLine, map[string]struct{}{})) {
		return true
	}
	if len(call.Args) > 1 && isSQLSelectQueryString(sqlQueryStringWithContext(argValue(call.Args[1]), current, e, beforeLine, map[string]struct{}{})) {
		return true
	}
	return false
}

func isSQLSelectReadStaticCall(call *ast.ExprStaticCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "queryrow" && name != "queryall" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	return isSQLSelectQueryString(sqlQueryString(argValue(call.Args[0])))
}

func isSQLAggregateScalarReadMethodCall(call *ast.ExprMethodCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "get_var" && name != "get_row" && name != "get_results" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	query := sqlQueryString(argValue(call.Args[0]))
	if query == "" && len(call.Args) > 1 {
		query = sqlQueryString(argValue(call.Args[1]))
	}
	return isSQLAggregateScalarQuery(query)
}

func isSQLAggregateScalarReadMethodCallWithContext(call *ast.ExprMethodCall, current callable, e *engine, beforeLine int) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "get_var" && name != "get_row" && name != "get_results" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	query := sqlQueryStringWithContext(argValue(call.Args[0]), current, e, beforeLine, map[string]struct{}{})
	if query == "" && len(call.Args) > 1 {
		query = sqlQueryStringWithContext(argValue(call.Args[1]), current, e, beforeLine, map[string]struct{}{})
	}
	return isSQLAggregateScalarQuery(query)
}

func isSQLAggregateScalarReadStaticCall(call *ast.ExprStaticCall) bool {
	name := strings.ToLower(identifierText(call.Name))
	if name != "queryrow" && name != "queryall" {
		return false
	}
	if len(call.Args) == 0 {
		return false
	}
	return isSQLAggregateScalarQuery(sqlQueryString(argValue(call.Args[0])))
}

func isSQLAggregateScalarQuery(query string) bool {
	query = strings.TrimSpace(strings.ToLower(query))
	if !strings.HasPrefix(query, "select ") {
		return false
	}
	fromIdx := strings.Index(query, " from ")
	if fromIdx == -1 {
		return false
	}
	selectList := strings.TrimSpace(query[len("select "):fromIdx])
	if selectList == "" || selectList == "*" {
		return false
	}
	if strings.HasPrefix(selectList, "distinct ") {
		selectList = strings.TrimSpace(selectList[len("distinct "):])
	}
	items := splitSQLSelectList(selectList)
	if len(items) != 1 {
		return false
	}
	item := strings.TrimSpace(items[0])
	return strings.HasPrefix(item, "count(") ||
		strings.HasPrefix(item, "sum(") ||
		strings.HasPrefix(item, "avg(") ||
		strings.HasPrefix(item, "min(") ||
		strings.HasPrefix(item, "max(")
}

func storageReadOriginsForFuncCall(call *ast.ExprFuncCall, s *analysisState) (originSet, bool) {
	spec, ok := storageReadSpecForFunc(normalizeName(identifierText(call.Name)))
	if !ok {
		return nil, false
	}
	family := storageFamilyForSpec(spec, call.Args)
	if family == "" {
		return nil, false
	}
	origins := originSet{}
	if root, ok := storageRootForArgsWithState(spec, call.Args, s); ok {
		origins = unionInto(origins, s.storageSelfOrigins(root))
		origins = unionInto(origins, s.storageChildOrigins(root))
		if root == family || len(origins) == 0 {
			origins = unionInto(origins, s.storageFamilySelfOrigins(family))
		}
		return markPersistentReadOrigins(origins), true
	}
	origins = unionInto(origins, storageOriginsForFamily(family, s))
	return markPersistentReadOrigins(origins), true
}

func storageOriginsForFamily(family string, s *analysisState) originSet {
	if family == "" {
		return originSet{}
	}
	origins := originSet{}
	origins = unionInto(origins, s.storageChildOrigins(family))
	origins = unionInto(origins, s.storageFamilySelfOrigins(family))
	origins = unionInto(origins, databaseTableColumnOrigins(family, s))
	return origins
}

func databaseTableColumnOrigins(field string, s *analysisState) originSet {
	field = strings.ToLower(strings.TrimSpace(field))
	if field == "" {
		return originSet{}
	}
	origins := originSet{}
	origins = unionInto(origins, collectDatabaseTableColumnOrigins(s.engine.storagePaths, field))
	origins = unionInto(origins, collectDatabaseTableColumnOrigins(s.storagePathWrites, field))
	return origins
}

func collectDatabaseTableColumnOrigins(store map[string]originSet, field string) originSet {
	if len(store) == 0 || field == "" {
		return originSet{}
	}
	origins := originSet{}
	dotSegment := "." + field
	bracketSegment := "[" + canonicalDBTableKey(field) + "]"
	for path, pathOrigins := range store {
		if !strings.HasPrefix(path, "db_table_value[") {
			continue
		}
		end := strings.Index(path, "]")
		if end == -1 || end+1 >= len(path) {
			continue
		}
		rest := path[end+1:]
		if !databaseTablePathHasColumnPrefix(rest, dotSegment, bracketSegment) {
			continue
		}
		origins = unionInto(origins, pathOrigins)
	}
	return origins
}

func databaseTableColumnFieldForPath(path string) string {
	if !strings.HasPrefix(path, "db_table_value[") {
		return ""
	}
	end := strings.Index(path, "]")
	if end == -1 || end+1 >= len(path) {
		return ""
	}
	rest := path[end+1:]
	if rest == "" {
		return ""
	}
	switch rest[0] {
	case '.':
		rest = rest[1:]
		if rest == "" {
			return ""
		}
		stop := len(rest)
		if idx := strings.IndexAny(rest, ".["); idx != -1 {
			stop = idx
		}
		return strings.ToLower(strings.TrimSpace(rest[:stop]))
	case '[':
		close := strings.Index(rest, "]")
		if close <= 1 {
			return ""
		}
		return canonicalDBTableKey(rest[1:close])
	default:
		return ""
	}
}

func databaseTableColumnStorageRoots(tableRoot string, storageField string) []string {
	if tableRoot == "" || storageField == "" {
		return nil
	}
	out := []string{tableRoot + "." + storageField}
	if key := canonicalDBTableKey(storageField); key != "" {
		bracket := tableRoot + "[" + key + "]"
		if bracket != out[0] {
			out = append(out, bracket)
		}
	}
	return out
}

func databaseTablePathHasColumnPrefix(rest string, dotSegment string, bracketSegment string) bool {
	for _, segment := range []string{dotSegment, bracketSegment} {
		if segment == "" {
			continue
		}
		if rest == segment || strings.HasPrefix(rest, segment+".") || strings.HasPrefix(rest, segment+"[") {
			return true
		}
	}
	return false
}

func (s *analysisState) storageFamilySelfOrigins(family string) originSet {
	if family == "" {
		return originSet{}
	}
	origins := originSet{}
	if familyOrigins, ok := s.engine.storage[family]; ok {
		origins = unionInto(origins, familyOrigins)
	}
	origins = unionInto(origins, s.storageWrites[family])
	return origins
}

func (s *analysisState) enrichStorageOriginsWithFamilyContext(origins originSet, path string) originSet {
	family := structuralPathRoot(path)
	if family == "" {
		return origins
	}
	return mergeStoredWriteContextByLocation(origins, s.storageFamilySelfOrigins(family))
}

func (s *analysisState) storageSelfOrigins(path string) originSet {
	origins := originSet{}
	origins = unionInto(origins, lookupStructuralSelfOrigins(s.engine.storagePaths, path))
	origins = unionInto(origins, lookupStructuralSelfOrigins(s.storagePathWrites, path))
	return s.enrichStorageOriginsWithFamilyContext(origins, path)
}

func (s *analysisState) storageChildOrigins(path string) originSet {
	origins := originSet{}
	origins = unionInto(origins, collectStructuralChildren(s.engine.storagePaths, path))
	origins = unionInto(origins, collectStructuralChildren(s.storagePathWrites, path))
	return s.enrichStorageOriginsWithFamilyContext(origins, path)
}

func storageReadRootForFuncCall(call *ast.ExprFuncCall) (string, bool) {
	spec, ok := storageReadSpecForFunc(normalizeName(identifierText(call.Name)))
	if !ok {
		return "", false
	}
	return storageRootForArgs(spec, call.Args)
}

func storageReadSpecForFunc(name string) (storageFuncSpec, bool) {
	switch normalizeName(name) {
	case "get_option":
		return storageFuncSpec{family: "option_value", keyArgs: []int{0}, valueArg: -1}, true
	case "get_site_option":
		return storageFuncSpec{family: "site_option_value", keyArgs: []int{0}, valueArg: -1}, true
	case "get_transient":
		return storageFuncSpec{family: "transient_value", keyArgs: []int{0}, valueArg: -1}, true
	case "get_site_transient":
		return storageFuncSpec{family: "site_transient_value", keyArgs: []int{0}, valueArg: -1}, true
	case "get_metadata":
		return storageFuncSpec{familyArg: 0, keyArgs: []int{1, 2}, valueArg: -1}, true
	case "get_post_meta":
		return storageFuncSpec{family: "post_meta_value", keyArgs: []int{0, 1}, valueArg: -1}, true
	case "get_user_meta":
		return storageFuncSpec{family: "user_meta_value", keyArgs: []int{0, 1}, valueArg: -1}, true
	case "get_term_meta":
		return storageFuncSpec{family: "term_meta_value", keyArgs: []int{0, 1}, valueArg: -1}, true
	case "get_post":
		return storageFuncSpec{family: "post_record", keyArgs: []int{0}, valueArg: -1}, true
	default:
		return storageFuncSpec{}, false
	}
}

func storageWriteSpecForFunc(name string) (storageFuncSpec, bool) {
	switch normalizeName(name) {
	case "add_option", "update_option":
		return storageFuncSpec{family: "option_value", keyArgs: []int{0}, valueArg: 1}, true
	case "add_site_option", "update_site_option":
		return storageFuncSpec{family: "site_option_value", keyArgs: []int{0}, valueArg: 1}, true
	case "set_transient":
		return storageFuncSpec{family: "transient_value", keyArgs: []int{0}, valueArg: 1}, true
	case "set_site_transient":
		return storageFuncSpec{family: "site_transient_value", keyArgs: []int{0}, valueArg: 1}, true
	case "add_metadata", "update_metadata":
		return storageFuncSpec{familyArg: 0, keyArgs: []int{1, 2}, valueArg: 3}, true
	case "add_post_meta", "update_post_meta":
		return storageFuncSpec{family: "post_meta_value", keyArgs: []int{0, 1}, valueArg: 2}, true
	case "add_user_meta", "update_user_meta":
		return storageFuncSpec{family: "user_meta_value", keyArgs: []int{0, 1}, valueArg: 2}, true
	case "add_term_meta", "update_term_meta":
		return storageFuncSpec{family: "term_meta_value", keyArgs: []int{0, 1}, valueArg: 2}, true
	default:
		return storageFuncSpec{}, false
	}
}

func storageRootForNode(family string, node ast.Node) (string, bool) {
	if family == "" || node == nil {
		return "", false
	}
	if stableStorageKey(node) {
		return appendArrayPath(family, node), true
	}
	return family + "[*]", true
}

func storageRootForArgsWithState(spec storageFuncSpec, args []ast.Node, s *analysisState) (string, bool) {
	family := storageFamilyForSpec(spec, args)
	if family == "" {
		return "", false
	}
	if len(spec.keyArgs) == 0 {
		return family, true
	}
	root := family
	sawStable := false
	sawDynamic := false
	for _, idx := range spec.keyArgs {
		if idx < 0 || idx >= len(args) {
			return "", false
		}
		node := argValue(args[idx])
		if key, ok := s.stableStorageKeyValue(node); ok {
			root = appendArrayPathWithKey(root, key)
			sawStable = true
			continue
		}
		if stableStorageKey(node) {
			root = appendArrayPath(root, node)
			sawStable = true
			continue
		}
		sawDynamic = true
		root += "[*]"
	}
	if sawDynamic && !sawStable && len(spec.keyArgs) == 1 && family != "post_record" {
		return "", false
	}
	return root, true
}

func storageRootForArgs(spec storageFuncSpec, args []ast.Node) (string, bool) {
	family := storageFamilyForSpec(spec, args)
	if family == "" {
		return "", false
	}
	if len(spec.keyArgs) == 0 {
		return family, true
	}
	root := family
	sawStable := false
	sawDynamic := false
	for _, idx := range spec.keyArgs {
		if idx < 0 || idx >= len(args) {
			return "", false
		}
		node := argValue(args[idx])
		if stableStorageKey(node) {
			root = appendArrayPath(root, node)
			sawStable = true
			continue
		}
		sawDynamic = true
		root += "[*]"
	}
	if sawDynamic && !sawStable && len(spec.keyArgs) == 1 && family != "post_record" {
		return "", false
	}
	return root, true
}

func storageFamilyForSpec(spec storageFuncSpec, args []ast.Node) string {
	if spec.family != "" {
		return spec.family
	}
	if spec.familyArg < 0 || spec.familyArg >= len(args) {
		return ""
	}
	return metadataFamilyName(argValue(args[spec.familyArg]))
}

func metadataFamilyName(node ast.Node) string {
	switch strings.ToLower(strings.TrimSpace(literalString(node))) {
	case "post":
		return "post_meta_value"
	case "user":
		return "user_meta_value"
	case "term":
		return "term_meta_value"
	case "comment":
		return "comment_meta_value"
	default:
		return "meta_value"
	}
}

func sqlSelectColumnsForMethodCall(call *ast.ExprMethodCall) ([]sqlSelectColumn, bool, bool) {
	name := strings.ToLower(identifierText(call.Name))
	if name != "get_var" && name != "get_row" && name != "get_results" {
		return nil, false, false
	}
	if len(call.Args) == 0 {
		return nil, false, false
	}
	columns := parseSQLSelectColumns(sqlQueryString(argValue(call.Args[0])))
	if len(columns) == 0 && len(call.Args) > 1 {
		columns = parseSQLSelectColumnList(sqlQueryString(argValue(call.Args[1])))
	}
	if len(columns) == 0 {
		return nil, false, false
	}
	return columns, name == "get_results", true
}

func sqlSelectColumnsForMethodCallWithContext(call *ast.ExprMethodCall, current callable, e *engine, beforeLine int) ([]sqlSelectColumn, bool, bool) {
	name := strings.ToLower(identifierText(call.Name))
	if name != "get_var" && name != "get_row" && name != "get_results" {
		return nil, false, false
	}
	if len(call.Args) == 0 {
		return nil, false, false
	}
	columns := parseSQLSelectColumns(sqlQueryStringWithContext(argValue(call.Args[0]), current, e, beforeLine, map[string]struct{}{}))
	if len(columns) == 0 && len(call.Args) > 1 {
		columns = parseSQLSelectColumnList(sqlQueryStringWithContext(argValue(call.Args[1]), current, e, beforeLine, map[string]struct{}{}))
	}
	if len(columns) == 0 {
		return nil, false, false
	}
	return columns, name == "get_results", true
}

func sqlSelectColumnsForStaticCall(call *ast.ExprStaticCall) ([]sqlSelectColumn, bool, bool) {
	name := strings.ToLower(identifierText(call.Name))
	if name != "queryrow" && name != "queryall" {
		return nil, false, false
	}
	if len(call.Args) == 0 {
		return nil, false, false
	}
	columns := parseSQLSelectColumns(sqlQueryString(argValue(call.Args[0])))
	if len(columns) == 0 {
		return nil, false, false
	}
	return columns, name == "queryall", true
}

func sqlQueryString(node ast.Node) string {
	switch typed := node.(type) {
	case *ast.ScalarString:
		return typed.Value
	case *ast.ExprBinaryOpConcat:
		return sqlQueryString(typed.Left) + sqlQueryString(typed.Right)
	case *ast.ExprMethodCall:
		if strings.EqualFold(identifierText(typed.Name), "prepare") && len(typed.Args) > 0 {
			return sqlQueryString(argValue(typed.Args[0]))
		}
	case *ast.ExprStaticCall:
		if strings.EqualFold(identifierText(typed.Name), "prepare") && len(typed.Args) > 0 {
			return sqlQueryString(argValue(typed.Args[0]))
		}
	case *ast.ExprNew:
		className := strings.ToLower(strings.TrimPrefix(normalizeName(resolveClassName(typed.Class, "", nil)), `\`))
		if className == "rawsql" && len(typed.Args) > 0 {
			return sqlQueryString(argValue(typed.Args[0]))
		}
	case *ast.ExprFuncCall:
		if strings.EqualFold(normalizeName(identifierText(typed.Name)), "sprintf") && len(typed.Args) > 0 {
			return sqlQueryString(argValue(typed.Args[0]))
		}
	}
	return literalString(node)
}

func sqlQueryStringWithContext(node ast.Node, current callable, e *engine, beforeLine int, seen map[string]struct{}) string {
	if e == nil {
		return sqlQueryString(node)
	}
	switch typed := node.(type) {
	case *ast.ScalarString:
		return typed.Value
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		return e.localSQLQueryVariableValue(current, name, beforeLine, seen)
	case *ast.ExprBinaryOpConcat:
		return sqlQueryStringWithContext(typed.Left, current, e, beforeLine, seen) + sqlQueryStringWithContext(typed.Right, current, e, beforeLine, seen)
	case *ast.ExprMethodCall:
		name := strings.ToLower(identifierText(typed.Name))
		if strings.EqualFold(name, "prepare") && len(typed.Args) > 0 {
			return sqlQueryStringWithContext(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 1 && strings.Contains(name, "table") {
			return sqlQueryStringWithContext(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 0 && strings.Contains(name, "table") {
			return databaseTableKeyForZeroArgMethodCall(typed, current, e, seen)
		}
	case *ast.ExprStaticCall:
		name := strings.ToLower(identifierText(typed.Name))
		if strings.EqualFold(name, "prepare") && len(typed.Args) > 0 {
			return sqlQueryStringWithContext(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 1 && strings.Contains(name, "table") {
			return sqlQueryStringWithContext(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 0 && strings.Contains(name, "table") {
			return databaseTableKeyForZeroArgStaticCall(typed, current, e, seen)
		}
	case *ast.ExprNew:
		className := strings.ToLower(strings.TrimPrefix(normalizeName(resolveClassName(typed.Class, "", nil)), `\`))
		if className == "rawsql" && len(typed.Args) > 0 {
			return sqlQueryStringWithContext(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
	case *ast.ExprFuncCall:
		name := strings.ToLower(normalizeName(identifierText(typed.Name)))
		if name == "sprintf" && len(typed.Args) > 0 {
			return sqlQueryStringWithContext(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 1 && strings.Contains(name, "table") {
			return sqlQueryStringWithContext(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 0 && strings.Contains(name, "table") {
			return databaseTableKeyForZeroArgFuncCall(typed, current, e, seen)
		}
	}
	if literal := literalStringForCallableWithSeen(node, current, e, seen); literal != "" {
		return literal
	}
	return literalString(node)
}

func isSQLSelectQueryString(query string) bool {
	query = strings.TrimSpace(strings.ToLower(query))
	return strings.HasPrefix(query, "select ")
}

func parseSQLSelectColumns(query string) []sqlSelectColumn {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	lower := strings.ToLower(query)
	if !strings.HasPrefix(lower, "select ") {
		return nil
	}
	fromIdx := strings.Index(lower, " from ")
	if fromIdx == -1 {
		return nil
	}
	selectList := strings.TrimSpace(query[len("select "):fromIdx])
	return parseSQLSelectColumnList(selectList)
}

func parseSQLSelectColumnList(selectList string) []sqlSelectColumn {
	if selectList == "" {
		return nil
	}
	items := splitSQLSelectList(selectList)
	out := make([]sqlSelectColumn, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		column, ok := parseSQLSelectItem(item)
		if !ok {
			continue
		}
		key := column.Field + ":" + column.Family
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, column)
	}
	return out
}

func splitSQLSelectList(value string) []string {
	out := []string{}
	depth := 0
	start := 0
	inSingle := false
	inDouble := false
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				depth++
			}
		case ')':
			if !inSingle && !inDouble && depth > 0 {
				depth--
			}
		case ',':
			if !inSingle && !inDouble && depth == 0 {
				out = append(out, strings.TrimSpace(value[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(value[start:]))
	return out
}

func parseSQLSelectItem(item string) (sqlSelectColumn, bool) {
	item = strings.TrimSpace(item)
	if item == "" || item == "*" {
		return sqlSelectColumn{}, false
	}
	if strings.HasPrefix(strings.ToLower(item), "distinct ") {
		item = strings.TrimSpace(item[len("distinct "):])
	}
	lower := strings.ToLower(item)
	alias := ""
	source := item
	if idx := strings.LastIndex(lower, " as "); idx != -1 {
		alias = normalizeSQLIdentifier(item[idx+4:])
		source = item[:idx]
	} else {
		fields := strings.Fields(item)
		if len(fields) == 2 {
			alias = normalizeSQLIdentifier(fields[1])
			source = fields[0]
		}
	}
	sourceIdent := normalizeSQLIdentifier(source)
	if sourceIdent == "" {
		return sqlSelectColumn{}, false
	}
	family := storageFamilyForSQLColumn(sourceIdent)
	if family == "" {
		return sqlSelectColumn{}, false
	}
	if alias == "" {
		alias = sourceIdent
	}
	return sqlSelectColumn{Field: alias, StorageField: sourceIdent, Family: family}, true
}

func normalizeSQLIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.Trim(value, "`\"' ")
	if idx := strings.LastIndex(value, "."); idx != -1 {
		value = value[idx+1:]
	}
	value = strings.Trim(value, "`\"' ")
	return strings.ToLower(value)
}

func canonicalDBTableKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var b strings.Builder
	lastUnderscore := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			b.WriteByte(ch)
			lastUnderscore = false
		case ch == '_' || ch == '-':
			b.WriteByte(ch)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func databaseTableKeyForNode(node ast.Node, s *analysisState, beforeLine int) string {
	return databaseTableKeyForNodeWithSeen(node, s.current, s.engine, beforeLine, map[string]struct{}{})
}

func databaseTableKeyForNodeWithSeen(node ast.Node, current callable, e *engine, beforeLine int, seen map[string]struct{}) string {
	switch typed := node.(type) {
	case *ast.ScalarString:
		return canonicalDBTableKey(typed.Value)
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		return e.localTableKeyVariableValue(current, name, beforeLine, seen)
	case *ast.ExprMethodCall:
		name := strings.ToLower(identifierText(typed.Name))
		if len(typed.Args) == 1 && strings.Contains(name, "table") {
			return databaseTableKeyForNodeWithSeen(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 0 && strings.Contains(name, "table") {
			return databaseTableKeyForZeroArgMethodCall(typed, current, e, seen)
		}
	case *ast.ExprStaticCall:
		name := strings.ToLower(identifierText(typed.Name))
		if len(typed.Args) == 1 && strings.Contains(name, "table") {
			return databaseTableKeyForNodeWithSeen(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 0 && strings.Contains(name, "table") {
			return databaseTableKeyForZeroArgStaticCall(typed, current, e, seen)
		}
	case *ast.ExprFuncCall:
		name := strings.ToLower(normalizeName(identifierText(typed.Name)))
		if len(typed.Args) == 1 && strings.Contains(name, "table") {
			return databaseTableKeyForNodeWithSeen(argValue(typed.Args[0]), current, e, beforeLine, seen)
		}
		if len(typed.Args) == 0 && strings.Contains(name, "table") {
			return databaseTableKeyForZeroArgFuncCall(typed, current, e, seen)
		}
	}
	if literal := strings.TrimSpace(literalString(node)); literal != "" {
		return canonicalDBTableKey(literal)
	}
	return ""
}

func databaseTableKeyForZeroArgMethodCall(call *ast.ExprMethodCall, current callable, e *engine, seen map[string]struct{}) string {
	if call == nil || e == nil || len(call.Args) != 0 {
		return ""
	}
	if literal := strings.TrimSpace(literalStringForCallableWithSeen(call, current, e, seen)); literal != "" {
		return canonicalDBTableKey(literal)
	}
	className := ""
	if refs := e.resolveCallbackClassRefsWithSeen(call.Var, current, seen); len(refs) != 0 {
		className = refs[0]
	}
	if className == "" {
		className = e.resolveMethodCallClass(call, current)
	}
	if className == "" {
		return ""
	}
	return databaseTableKeyForZeroArgCallableReturn(e.ensureRuntimeMethodCallable(className, identifierText(call.Name)), e, seen)
}

func databaseTableKeyForZeroArgStaticCall(call *ast.ExprStaticCall, current callable, e *engine, seen map[string]struct{}) string {
	if call == nil || e == nil || len(call.Args) != 0 {
		return ""
	}
	if literal := strings.TrimSpace(literalStringForCallableWithSeen(call, current, e, seen)); literal != "" {
		return canonicalDBTableKey(literal)
	}
	className := resolveClassName(call.Class, current.Class, e.classParents)
	if className == "" {
		return ""
	}
	return databaseTableKeyForZeroArgCallableReturn(e.ensureRuntimeMethodCallable(className, identifierText(call.Name)), e, seen)
}

func databaseTableKeyForZeroArgFuncCall(call *ast.ExprFuncCall, current callable, e *engine, seen map[string]struct{}) string {
	if call == nil || e == nil || len(call.Args) != 0 {
		return ""
	}
	if literal := strings.TrimSpace(literalStringForCallableWithSeen(call, current, e, seen)); literal != "" {
		return canonicalDBTableKey(literal)
	}
	key := e.lookupFunctionKey(current.Namespace, identifierText(call.Name))
	if key == "" {
		return ""
	}
	return databaseTableKeyForZeroArgCallableReturn(key, e, seen)
}

func databaseTableKeyForZeroArgCallableReturn(key string, e *engine, seen map[string]struct{}) string {
	if key == "" || e == nil {
		return ""
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	seenKey := "tablecall::" + key
	if _, ok := seen[seenKey]; ok {
		return ""
	}
	c, ok := e.callables[key]
	if !ok {
		return ""
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)

	var ret ast.Node
	for _, stmt := range c.Stmts {
		switch typed := stmt.(type) {
		case *ast.StmtReturn:
			if ret != nil {
				return ""
			}
			ret = typed.Expr
		case *ast.StmtNop:
			continue
		default:
			return ""
		}
	}
	if ret == nil {
		return ""
	}
	if literal := strings.TrimSpace(literalStringForCallableWithSeen(ret, c, e, seen)); literal != "" {
		return canonicalDBTableKey(literal)
	}
	if path, ok := propertyPathKey(ret, c.Class); ok {
		path = strings.TrimSpace(path)
		if strings.HasPrefix(path, "this.") {
			return canonicalDBTableKey(strings.TrimPrefix(path, "this."))
		}
		if last := lastPropertyPathSegment(path); last != "" {
			return canonicalDBTableKey(last)
		}
	}
	if path, ok := staticPropertyPathKey(ret, c.Class, e); ok {
		if idx := strings.LastIndex(path, ".$"); idx >= 0 {
			return canonicalDBTableKey(path[idx+2:])
		}
	}
	switch typed := ret.(type) {
	case *ast.ExprVariable:
		if name, ok := typed.Name.(string); ok {
			return canonicalDBTableKey(name)
		}
	case *ast.Identifier:
		return canonicalDBTableKey(typed.Name)
	}
	return ""
}

func lastPropertyPathSegment(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		return strings.TrimSpace(path[idx+1:])
	}
	return path
}

func (e *engine) localTableKeyVariableValue(current callable, name string, beforeLine int, seen map[string]struct{}) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	seenKey := "tablevar::" + current.Key + "::" + name
	if _, ok := seen[seenKey]; ok {
		return ""
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)

	bestValue := ""
	bestLine := -1
	ambiguous := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok || assign.StartLine() >= beforeLine {
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
		candidate := databaseTableKeyForNodeWithSeen(assign.Expr, current, e, assign.StartLine(), seen)
		if candidate == "" {
			return
		}
		if assign.StartLine() > bestLine {
			bestValue = candidate
			bestLine = assign.StartLine()
			ambiguous = false
			return
		}
		if assign.StartLine() == bestLine && bestValue != candidate {
			ambiguous = true
		}
	})
	if ambiguous || bestValue == "" {
		return ""
	}
	return bestValue
}

func (e *engine) localSQLQueryVariableValue(current callable, name string, beforeLine int, seen map[string]struct{}) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	seenKey := "sqlvar::" + current.Key + "::" + name
	if _, ok := seen[seenKey]; ok {
		return ""
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)

	bestValue := ""
	bestLine := -1
	ambiguous := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok || assign.StartLine() >= beforeLine {
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
		candidate := sqlQueryStringWithContext(assign.Expr, current, e, assign.StartLine(), seen)
		if candidate == "" {
			return
		}
		if assign.StartLine() > bestLine {
			bestValue = candidate
			bestLine = assign.StartLine()
			ambiguous = false
			return
		}
		if assign.StartLine() == bestLine && bestValue != candidate {
			ambiguous = true
		}
	})
	if ambiguous || bestValue == "" {
		return ""
	}
	return bestValue
}

func sqlSelectTableKeyForNode(node ast.Node, s *analysisState, beforeLine int) string {
	return sqlSelectTableKeyForNodeWithContext(node, s.current, s.engine, beforeLine)
}

func sqlSelectTableKeyForNodeWithContext(node ast.Node, current callable, e *engine, beforeLine int) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		return e.localSQLTableKeyVariableValue(current, name, beforeLine, map[string]struct{}{})
	case *ast.ExprMethodCall:
		if !strings.EqualFold(identifierText(typed.Name), "prepare") || len(typed.Args) == 0 {
			return ""
		}
		return sqlSelectPreparedTableKeyWithContext(sqlQueryString(argValue(typed.Args[0])), typed.Args[1:], current, e, beforeLine)
	case *ast.ExprStaticCall:
		if !strings.EqualFold(identifierText(typed.Name), "prepare") || len(typed.Args) == 0 {
			return ""
		}
		return sqlSelectPreparedTableKeyWithContext(sqlQueryString(argValue(typed.Args[0])), typed.Args[1:], current, e, beforeLine)
	case *ast.ExprFuncCall:
		if !strings.EqualFold(normalizeName(identifierText(typed.Name)), "sprintf") || len(typed.Args) == 0 {
			return ""
		}
		return sqlLiteralTableKey(sqlQueryString(argValue(typed.Args[0])))
	default:
		return sqlLiteralTableKey(sqlQueryStringWithContext(node, current, e, beforeLine, map[string]struct{}{}))
	}
}

func (e *engine) localSQLTableKeyVariableValue(current callable, name string, beforeLine int, seen map[string]struct{}) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	seenKey := "sqltablevar::" + current.Key + "::" + name
	if _, ok := seen[seenKey]; ok {
		return ""
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)

	bestValue := ""
	bestLine := -1
	ambiguous := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok || assign.StartLine() >= beforeLine {
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
		candidate := sqlSelectTableKeyForNodeWithContext(assign.Expr, current, e, assign.StartLine())
		if candidate == "" {
			return
		}
		if assign.StartLine() > bestLine {
			bestValue = candidate
			bestLine = assign.StartLine()
			ambiguous = false
			return
		}
		if assign.StartLine() == bestLine && bestValue != candidate {
			ambiguous = true
		}
	})
	if ambiguous || bestValue == "" {
		return ""
	}
	return bestValue
}

func sqlSelectPreparedTableKey(query string, args []ast.Node, s *analysisState, beforeLine int) string {
	return sqlSelectPreparedTableKeyWithContext(query, args, s.current, s.engine, beforeLine)
}

func sqlSelectPreparedTableKeyWithContext(query string, args []ast.Node, current callable, e *engine, beforeLine int) string {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return ""
	}
	fromIdx := strings.Index(query, " from ")
	if fromIdx == -1 {
		return ""
	}
	placeholderOrdinal := sqlIdentifierPlaceholderOrdinal(query, fromIdx)
	if placeholderOrdinal < 0 || placeholderOrdinal >= len(args) {
		return ""
	}
	return databaseTableKeyForNodeWithSeen(argValue(args[placeholderOrdinal]), current, e, beforeLine, map[string]struct{}{})
}

func sqlIdentifierPlaceholderOrdinal(query string, beforeIdx int) int {
	count := 0
	for i := 0; i < len(query)-1 && i < beforeIdx+len(" from %i"); i++ {
		if query[i] != '%' {
			continue
		}
		spec := query[i+1]
		switch spec {
		case 'i':
			if i >= beforeIdx && strings.HasPrefix(query[i:], "%i") {
				return count
			}
			count++
		case 'd', 'f', 's':
			count++
		case '%':
		default:
		}
	}
	return -1
}

func sqlLiteralTableKey(query string) string {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return ""
	}
	fromIdx := strings.Index(query, " from ")
	if fromIdx == -1 {
		return ""
	}
	remainder := strings.TrimSpace(query[fromIdx+len(" from "):])
	if remainder == "" {
		return ""
	}
	for i := 0; i < len(remainder); i++ {
		switch remainder[i] {
		case ' ', '\t', '\n', '\r', ',', ')':
			remainder = remainder[:i]
			return canonicalDBTableKey(remainder)
		}
	}
	return canonicalDBTableKey(remainder)
}

func storageFamilyForSQLColumn(column string) string {
	column = normalizeSQLIdentifier(column)
	if _, ok := storageFamilies[column]; ok {
		return column
	}
	return ""
}

func parseSQLWriteFamilies(query string) []string {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	lower := strings.ToLower(query)
	switch {
	case strings.HasPrefix(lower, "insert "):
		return parseSQLInsertLikeFamilies(query)
	case strings.HasPrefix(lower, "replace "):
		return parseSQLInsertLikeFamilies(query)
	case strings.HasPrefix(lower, "update "):
		return parseSQLUpdateFamilies(query)
	default:
		return nil
	}
}

func parseSQLInsertLikeFamilies(query string) []string {
	openIdx := strings.Index(query, "(")
	if openIdx == -1 {
		return nil
	}
	closeIdx := strings.Index(query[openIdx:], ")")
	if closeIdx == -1 {
		return nil
	}
	columnsPart := query[openIdx+1 : openIdx+closeIdx]
	return parseSQLColumnList(columnsPart)
}

func parseSQLUpdateFamilies(query string) []string {
	lower := strings.ToLower(query)
	setIdx := strings.Index(lower, " set ")
	if setIdx == -1 {
		return nil
	}
	assignments := query[setIdx+5:]
	if whereIdx := strings.Index(strings.ToLower(assignments), " where "); whereIdx != -1 {
		assignments = assignments[:whereIdx]
	}
	items := splitSQLSelectList(assignments)
	out := []string{}
	seen := map[string]struct{}{}
	for _, item := range items {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		family := storageFamilyForSQLColumn(parts[0])
		if family == "" {
			continue
		}
		if _, ok := seen[family]; ok {
			continue
		}
		seen[family] = struct{}{}
		out = append(out, family)
	}
	return out
}

func parseSQLColumnList(columns string) []string {
	items := splitSQLSelectList(columns)
	out := []string{}
	seen := map[string]struct{}{}
	for _, item := range items {
		family := storageFamilyForSQLColumn(item)
		if family == "" {
			continue
		}
		if _, ok := seen[family]; ok {
			continue
		}
		seen[family] = struct{}{}
		out = append(out, family)
	}
	return out
}

func postRecordWritesForFuncCall(call *ast.ExprFuncCall, s *analysisState) map[string]originSet {
	fields, _ := postRecordFieldValues(call)
	if len(fields) == 0 {
		return nil
	}
	out := map[string]originSet{}
	for field, valueNode := range fields {
		origins := s.evalExpr(valueNode)
		if len(origins) == 0 {
			continue
		}
		unionMapEntry(out, field, origins)
		unionMapEntry(out, "post_record", origins)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func postRecordPathWritesForFuncCall(call *ast.ExprFuncCall, s *analysisState) map[string]originSet {
	fields, root := postRecordFieldValues(call)
	if len(fields) == 0 || root == "" {
		return nil
	}
	out := map[string]originSet{}
	for field, valueNode := range fields {
		path := root + "." + field
		copyExprStructureToStorage(out, path, valueNode, s)
		if len(lookupStructuralSelfOrigins(out, path)) != 0 || hasStructuralChildren(out, path) {
			continue
		}
		origins := s.evalExpr(valueNode)
		if len(origins) == 0 {
			continue
		}
		unionMapEntry(out, path, origins)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func postRecordFieldValues(call *ast.ExprFuncCall) (map[string]ast.Node, string) {
	name := normalizeName(identifierText(call.Name))
	if name != "wp_insert_post" && name != "wp_update_post" {
		return nil, ""
	}
	if len(call.Args) == 0 {
		return nil, ""
	}
	arrayNode, ok := argValue(call.Args[0]).(*ast.ExprArray)
	if !ok {
		return nil, ""
	}
	root, _ := postRecordRootForArray(arrayNode)
	out := map[string]ast.Node{}
	for _, field := range []string{"post_content", "post_excerpt"} {
		if valueNode := arrayValueForStringKey(arrayNode, field); valueNode != nil {
			out[field] = valueNode
		}
	}
	return out, root
}

func postRecordRootForArray(node *ast.ExprArray) (string, bool) {
	if node == nil {
		return "", false
	}
	idNode := arrayValueForStringKey(node, "ID")
	if idNode == nil {
		idNode = arrayValueForStringKey(node, "id")
	}
	if idNode == nil {
		return "", false
	}
	if !stableStorageKey(idNode) {
		return "post_record[*]", true
	}
	return appendArrayPath("post_record", idNode), true
}

func stableStorageKey(node ast.Node) bool {
	_, ok := stableArrayDimKey(node)
	return ok
}

func (s *analysisState) stableStorageKeyValue(node ast.Node) (string, bool) {
	if key, ok := stableArrayDimKey(node); ok {
		return strings.ToLower(strings.TrimSpace(key)), true
	}
	if node == nil {
		return "", false
	}
	if literal := sanitizeStableStorageKeyLiteral(dynamicDispatchStringForCallable(node, s.current, s.engine, s.stringEnv)); literal != "" {
		return literal, true
	}
	return "", false
}

func sanitizeStableStorageKeyLiteral(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	if value == "" || strings.Contains(value, "{") {
		return ""
	}
	return value
}

func appendArrayPathWithKey(base string, key string) string {
	if base == "" {
		return ""
	}
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return base + "[*]"
	}
	return base + "[" + key + "]"
}

func (s *analysisState) assignForeachKeyHint(target ast.Node, expr ast.Node) {
	variable, ok := target.(*ast.ExprVariable)
	if !ok {
		return
	}
	name, ok := variable.Name.(string)
	if !ok || name == "" {
		return
	}
	if key := s.stableForeachKeyForExpr(expr); key != "" {
		s.stringEnv[name] = key
		return
	}
	delete(s.stringEnv, name)
}

func (s *analysisState) stableForeachKeyForExpr(expr ast.Node) string {
	keys := map[string]struct{}{}
	add := func(key string) {
		key = sanitizeStableStorageKeyLiteral(key)
		if key == "" {
			return
		}
		keys[key] = struct{}{}
	}
	if arrayNode, ok := expr.(*ast.ExprArray); ok {
		for _, itemNode := range arrayNode.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			if item.Key == nil {
				return ""
			}
			if key, ok := stableArrayDimKey(item.Key); ok {
				add(key)
				continue
			}
			return ""
		}
	}
	for relPath := range s.collectExprStructuralPaths(expr) {
		segment, _, ok := nextPathSegment(relPath)
		if !ok || segment == "" || segment == "[]" || segment == "*" || strings.HasPrefix(segment, ".") {
			continue
		}
		add(segment)
	}
	if len(keys) != 1 {
		return ""
	}
	for key := range keys {
		return key
	}
	return ""
}

func extractStorageFamilies(node ast.Node, s *analysisState) map[string]originSet {
	arrayNode, ok := node.(*ast.ExprArray)
	if ok {
		out := map[string]originSet{}
		for _, itemNode := range arrayNode.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			key := strings.ToLower(literalString(item.Key))
			if _, ok := storageFamilies[key]; !ok {
				continue
			}
			unionMapEntry(out, key, s.evalExpr(item.Value))
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	src, ok := s.structuralRoot(node)
	if !ok {
		return nil
	}
	return extractStorageFamiliesFromStructuralRoot(src, s)
}

func extractStoragePathFamilies(node ast.Node, s *analysisState) map[string]originSet {
	arrayNode, ok := node.(*ast.ExprArray)
	if ok {
		out := map[string]originSet{}
		for _, itemNode := range arrayNode.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			family := strings.ToLower(literalString(item.Key))
			if _, ok := storageFamilies[family]; !ok {
				continue
			}
			copyExprStructureToStorage(out, family, item.Value, s)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	src, ok := s.structuralRoot(node)
	if !ok {
		return nil
	}
	return extractStoragePathFamiliesFromStructuralRoot(src, s)
}

func copyExprStructureToStorage(dst map[string]originSet, family string, expr ast.Node, s *analysisState) {
	resolver := s.engine.localArrayLiteralResolver(s.current)
	copyExprStructureToStorageWithResolver(dst, family, expr, s, resolver, map[string]struct{}{})
}

func copyExprStructureToStorageWithResolver(dst map[string]originSet, family string, expr ast.Node, s *analysisState, resolver *localArrayLiteralResolver, seen map[string]struct{}) {
	if family == "" {
		return
	}
	if resolved := resolveLocalStructuredExpr(expr, resolver, seen); resolved != nil && resolved != expr {
		copyExprStructureToStorageWithResolver(dst, family, resolved, s, resolver, seen)
		return
	}
	if src, ok := s.structuralRoot(expr); ok {
		s.copyStructuralPathsToMap(dst, family, src)
		return
	}
	if nestedFamily, ok := storageFamilyExpr(expr); ok {
		copyStructuralPathMap(dst, s.engine.storagePaths, family, nestedFamily)
		copyStructuralPathMap(dst, s.storagePathWrites, family, nestedFamily)
		return
	}
	switch typed := expr.(type) {
	case *ast.ExprArray:
		for _, itemNode := range typed.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			childKey := appendArrayPath(family, item.Key)
			copyExprStructureToStorageWithResolver(dst, childKey, item.Value, s, resolver, seen)
			if hasStructuralChildren(dst, childKey) {
				continue
			}
			unionMapEntry(dst, childKey, s.evalExpr(item.Value))
		}
	case *ast.ExprFuncCall:
		if isPropagatingFunc(normalizeName(identifierText(typed.Name))) && len(typed.Args) > 0 {
			copyExprStructureToStorageWithResolver(dst, family, argValue(typed.Args[0]), s, resolver, seen)
		}
	}
}

func resolveLocalStructuredExpr(expr ast.Node, resolver *localArrayLiteralResolver, seen map[string]struct{}) ast.Node {
	if expr == nil || resolver == nil {
		return nil
	}
	switch typed := expr.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok || name == "" {
			return nil
		}
		key := "var:" + name
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		defer delete(seen, key)
		resolved, _ := resolver.latestExpr(name, typed.StartLine())
		return resolved
	case *ast.ExprArrayDimFetch:
		base := resolveLocalStructuredExpr(typed.Var, resolver, seen)
		arrayExpr, ok := base.(*ast.ExprArray)
		if !ok {
			return nil
		}
		for _, itemNode := range arrayExpr.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			if literalString(item.Key) != literalString(typed.Dim) {
				continue
			}
			return item.Value
		}
	case *ast.ExprFuncCall:
		if isPropagatingFunc(normalizeName(identifierText(typed.Name))) && len(typed.Args) > 0 {
			return resolveLocalStructuredExpr(argValue(typed.Args[0]), resolver, seen)
		}
	}
	return nil
}

func schemaStorageWritesForPreparedArg(node ast.Node, s *analysisState) map[string]originSet {
	families := schemaStorageFamiliesForCurrentClass(s)
	if len(families) == 0 {
		return nil
	}
	baseOrigins := s.evalExpr(node)
	if len(baseOrigins) == 0 {
		if prepared := preparedSchemaSourceNode(node, s); prepared != nil {
			baseOrigins = s.evalExpr(prepared)
		}
	}
	if len(baseOrigins) == 0 {
		return nil
	}
	loc := s.locationForNode(node)
	out := map[string]originSet{}
	for _, family := range families {
		path := "[" + family + "]"
		unionMapEntry(out, family, applyPathStringToOrigins(baseOrigins, path, loc))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func schemaStoragePathWritesForPreparedArg(node ast.Node, s *analysisState) map[string]originSet {
	families := schemaStorageFamiliesForCurrentClass(s)
	if len(families) == 0 {
		return nil
	}
	baseOrigins := s.evalExpr(node)
	if len(baseOrigins) == 0 {
		if prepared := preparedSchemaSourceNode(node, s); prepared != nil {
			baseOrigins = s.evalExpr(prepared)
		}
	}
	if len(baseOrigins) == 0 {
		return nil
	}
	loc := s.locationForNode(node)
	out := map[string]originSet{}
	for _, family := range families {
		unionMapEntry(out, family, applyPathStringToOrigins(baseOrigins, "["+family+"]", loc))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func preparedSchemaSourceNode(node ast.Node, s *analysisState) ast.Node {
	if s == nil || s.engine == nil || node == nil {
		return nil
	}
	dimFetch, ok := node.(*ast.ExprArrayDimFetch)
	if !ok {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(literalString(dimFetch.Dim)))
	if key != "data" {
		return nil
	}
	variable, ok := dimFetch.Var.(*ast.ExprVariable)
	if !ok {
		return nil
	}
	name, ok := variable.Name.(string)
	if !ok {
		return nil
	}
	return s.engine.localPreparedSchemaArgValue(s.current, name, dimFetch.StartLine(), map[string]struct{}{})
}

func (e *engine) localPreparedSchemaArgValue(current callable, name string, beforeLine int, seen map[string]struct{}) ast.Node {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if seen == nil {
		seen = map[string]struct{}{}
	}
	seenKey := "preparedvar::" + current.Key + "::" + name
	if _, ok := seen[seenKey]; ok {
		return nil
	}
	seen[seenKey] = struct{}{}
	defer delete(seen, seenKey)

	var best ast.Node
	bestLine := -1
	ambiguous := false
	walkNodes(current.Stmts, func(node ast.Node) {
		if ambiguous {
			return
		}
		assign, ok := node.(*ast.ExprAssign)
		if !ok || assign.StartLine() >= beforeLine {
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
		candidate := preparedSchemaArgFromCall(assign.Expr)
		if candidate == nil {
			return
		}
		if assign.StartLine() > bestLine {
			best = candidate
			bestLine = assign.StartLine()
			ambiguous = false
			return
		}
		if assign.StartLine() == bestLine && best != candidate {
			ambiguous = true
		}
	})
	if ambiguous {
		return nil
	}
	return best
}

func preparedSchemaArgFromCall(node ast.Node) ast.Node {
	switch typed := node.(type) {
	case *ast.ExprMethodCall:
		if len(typed.Args) == 0 {
			return nil
		}
		name := normalizeName(identifierText(typed.Name))
		if name == "prepare_data" || name == "preparedata" {
			return argValue(typed.Args[0])
		}
	case *ast.ExprStaticCall:
		if len(typed.Args) == 0 {
			return nil
		}
		name := normalizeName(identifierText(typed.Name))
		if name == "prepare_data" || name == "preparedata" {
			return argValue(typed.Args[0])
		}
	case *ast.ExprFuncCall:
		if len(typed.Args) == 0 {
			return nil
		}
		name := normalizeName(identifierText(typed.Name))
		if name == "prepare_data" || name == "preparedata" {
			return argValue(typed.Args[0])
		}
	}
	return nil
}

func schemaStorageFamiliesForCurrentClass(s *analysisState) []string {
	candidates := []string{}
	seen := map[string]struct{}{}
	for className := s.current.Class; className != ""; className = s.engine.classParents[className] {
		if _, ok := seen[className]; ok {
			continue
		}
		seen[className] = struct{}{}
		candidates = append(candidates, className)
	}
	for className := range s.engine.classParents {
		if !classDescendsFrom(className, s.current.Class, s.engine.classParents) {
			continue
		}
		if _, ok := seen[className]; ok {
			continue
		}
		seen[className] = struct{}{}
		candidates = append(candidates, className)
	}
	families := map[string]struct{}{}
	for _, className := range candidates {
		if key := s.engine.lookupMethodKey(className, "get_schema"); key != "" {
			for _, family := range schemaStorageFamiliesForCallable(s.engine.callables[key]) {
				families[family] = struct{}{}
			}
		}
	}
	if len(families) == 0 {
		return nil
	}
	out := make([]string, 0, len(families))
	for family := range families {
		out = append(out, family)
	}
	return out
}

func classDescendsFrom(className string, ancestor string, parents map[string]string) bool {
	if className == "" || ancestor == "" || className == ancestor {
		return false
	}
	for current := parents[className]; current != ""; current = parents[current] {
		if current == ancestor {
			return true
		}
	}
	return false
}

func schemaStorageFamiliesForCallable(c callable) []string {
	families := map[string]struct{}{}
	walkNodes(c.Stmts, func(node ast.Node) {
		returnStmt, ok := node.(*ast.StmtReturn)
		if !ok {
			return
		}
		arrayNode, ok := returnStmt.Expr.(*ast.ExprArray)
		if !ok {
			return
		}
		for _, itemNode := range arrayNode.Items {
			item, ok := itemNode.(*ast.ArrayItem)
			if !ok {
				continue
			}
			key := strings.ToLower(literalString(item.Key))
			if _, ok := storageFamilies[key]; ok {
				families[key] = struct{}{}
			}
		}
	})
	if len(families) == 0 {
		return nil
	}
	out := make([]string, 0, len(families))
	for family := range families {
		out = append(out, family)
	}
	return out
}

func extractStorageFamiliesFromStructuralRoot(src structuralRoot, s *analysisState) map[string]originSet {
	out := map[string]originSet{}
	for rel, origins := range collectRelativePathsFromStructuralRoot(src, s) {
		segment, _, ok := nextPathSegment(rel)
		if !ok {
			continue
		}
		if strings.HasPrefix(segment, ".") {
			segment = segment[1:]
		}
		if _, ok := storageFamilies[segment]; !ok {
			continue
		}
		unionMapEntry(out, segment, origins)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func extractStoragePathFamiliesFromStructuralRoot(src structuralRoot, s *analysisState) map[string]originSet {
	out := map[string]originSet{}
	for rel, origins := range collectRelativePathsFromStructuralRoot(src, s) {
		segment, rest, ok := nextPathSegment(rel)
		if !ok {
			continue
		}
		if strings.HasPrefix(segment, ".") {
			segment = segment[1:]
		}
		if _, ok := storageFamilies[segment]; !ok {
			continue
		}
		path := segment + rest
		unionMapEntry(out, path, origins)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectRelativePathsFromStructuralRoot(src structuralRoot, s *analysisState) map[string]originSet {
	out := map[string]originSet{}
	if src.key == "" {
		return nil
	}
	var stores []map[string]originSet
	if src.isStatic {
		stores = append(stores, s.engine.staticProps, s.staticPropTaint)
	} else {
		stores = append(stores, s.propTaint)
	}
	for _, store := range stores {
		for rel, origins := range collectRelativeStructuralPaths(store, src.key) {
			unionMapEntry(out, rel, origins)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func callbackMethodName(node ast.Node) string {
	value := ""
	switch typed := node.(type) {
	case *ast.ScalarString:
		value = typed.Value
	case *ast.Identifier:
		value = typed.Name
	default:
		value = literalString(node)
	}
	value = strings.TrimSpace(value)
	if parts := strings.Split(value, "::"); len(parts) == 2 {
		value = strings.TrimSpace(parts[1])
	}
	return value
}

func resolveCallbackClassRefString(value string, current callable) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "", "self", "static":
		return current.Class
	case "parent":
		return ""
	default:
		return qualifiedName(current.Namespace, value)
	}
}

func resolveCallbackClassPatternPrefix(value string, current callable) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return resolveCallbackClassRefString(value, current)
}

func registrationsForKeys(keys []string, entry EntryPoint) []callbackRegistration {
	return registrationsForKeysWithPermission(keys, entry, nil)
}

func registrationsForKeysWithPermission(keys []string, entry EntryPoint, permissionKeys []string) []callbackRegistration {
	out := make([]callbackRegistration, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		out = append(out, callbackRegistration{
			TargetKey:      key,
			Entry:          entry,
			PermissionKeys: append([]string(nil), permissionKeys...),
		})
	}
	return out
}

func classifyHookEntryPoint(hook string, location Location) EntryPoint {
	entry := EntryPoint{
		Kind:     "hook",
		Name:     hook,
		Access:   "unknown",
		Location: location,
	}
	switch {
	case strings.HasPrefix(hook, "wp_ajax_nopriv_"):
		entry.Kind = "ajax"
		entry.Access = "unauthenticated"
	case strings.HasPrefix(hook, "wp_ajax_"):
		entry.Kind = "ajax"
		entry.Access = "authenticated"
	case strings.HasPrefix(hook, "admin_post_nopriv_"):
		entry.Kind = "admin_post"
		entry.Access = "unauthenticated"
	case strings.HasPrefix(hook, "admin_post_"):
		entry.Kind = "admin_post"
		entry.Access = "authenticated"
	case isCoreAuthenticatedAdminHookEntryPoint(hook):
		entry.Kind = "front_hook"
		entry.Access = "authenticated"
	case isCoreFrontHookEntryPoint(hook):
		entry.Kind = "front_hook"
		// init/wp_loaded/template_redirect/parse_request/wp run on every public
		// front-end request, so callbacks hooked here are reachable unauthenticated.
		entry.Access = "unauthenticated"
	case hook == "rest_api_init":
		entry.Kind = "rest_init"
	}
	return entry
}

func isCoreFrontHookEntryPoint(hook string) bool {
	switch hook {
	case "muplugins_loaded", "plugins_loaded", "init", "wp_loaded", "parse_request", "template_redirect", "wp":
		return true
	default:
		return false
	}
}

func isCoreAuthenticatedAdminHookEntryPoint(hook string) bool {
	switch hook {
	case "admin_init":
		return true
	default:
		return false
	}
}

func joinRestRoute(namespace string, route string) string {
	namespace = strings.Trim(namespace, "/")
	route = strings.TrimSpace(route)
	if namespace == "" {
		return route
	}
	if route == "" {
		return "/" + namespace
	}
	if strings.HasPrefix(route, "/") {
		return "/" + namespace + route
	}
	return "/" + namespace + "/" + route
}

func restPermissionAccess(node ast.Node) string {
	if node == nil {
		// A REST route registered without a permission_callback is served to
		// everyone (WordPress only warns), so treat it as unauthenticated rather
		// than unknown. This lets the auth-aware rules fire and scores it as the
		// public surface it is.
		return "unauthenticated"
	}
	switch typed := node.(type) {
	case *ast.ScalarString:
		if strings.EqualFold(typed.Value, "__return_true") {
			return "unauthenticated"
		}
	case *ast.ExprConstFetch:
		if strings.EqualFold(identifierText(typed.Name), "true") {
			return "unauthenticated"
		}
	}
	return "permission_callback"
}
