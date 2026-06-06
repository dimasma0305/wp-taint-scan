package taintscan

import (
	"sort"
	"strconv"
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func makeOriginSet(items ...origin) originSet {
	out := originSet{}
	for _, item := range items {
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func (s originSet) clone() originSet {
	if len(s) == 0 {
		return originSet{}
	}
	out := make(originSet, len(s))
	for key, value := range s {
		out[key] = value
	}
	return out
}

func (s originSet) union(other originSet) originSet {
	if len(s) == 0 {
		return other.clone()
	}
	if len(other) == 0 {
		return s.clone()
	}
	out := make(originSet, len(s)+len(other))
	for key, value := range s {
		if len(out) >= maxOriginSetSize {
			break
		}
		out[key] = value
	}
	for key, value := range other {
		if len(out) >= maxOriginSetSize {
			break
		}
		if existing, ok := out[key]; ok {
			value = mergeOrigins(existing, value)
		}
		out[key] = value
	}
	return out
}

// maxOriginSetSize caps origin set growth to prevent OOM on large codebases.
// An origin set with more entries than this is unlikely to produce useful
// findings — it indicates an over-approximation that should be pruned.
const maxOriginSetSize = 48

func unionInto(dst originSet, src originSet) originSet {
	if len(src) == 0 {
		if dst == nil {
			return originSet{}
		}
		return dst
	}
	if dst == nil {
		dst = make(originSet, len(src))
	}
	for key, value := range src {
		if len(dst) >= maxOriginSetSize {
			break
		}
		if existing, ok := dst[key]; ok {
			value = mergeOrigins(existing, value)
		}
		dst[key] = value
	}
	return dst
}

func originSetCoveredBy(need originSet, have originSet) bool {
	if len(need) == 0 {
		return true
	}
	if len(have) == 0 {
		return false
	}
	for key, item := range need {
		existing, ok := have[key]
		if !ok {
			return false
		}
		merged := mergeOrigins(existing, item)
		if !flowContextsEquivalent(merged.storedWriteContext, existing.storedWriteContext) {
			return false
		}
	}
	return true
}

func originSetsEquivalent(a originSet, b originSet) bool {
	return originSetCoveredBy(a, b) && originSetCoveredBy(b, a)
}

func (s originSet) sorted() []origin {
	out := make([]origin, 0, len(s))
	for _, item := range s {
		out = append(out, item)
	}
	sort.Slice(out, func(i int, j int) bool {
		if out[i].kind != out[j].kind {
			return out[i].kind < out[j].kind
		}
		if out[i].paramIdx != out[j].paramIdx {
			return out[i].paramIdx < out[j].paramIdx
		}
		if out[i].paramPath != out[j].paramPath {
			return out[i].paramPath < out[j].paramPath
		}
		if out[i].receiverPath != out[j].receiverPath {
			return out[i].receiverPath < out[j].receiverPath
		}
		if out[i].source.Path != out[j].source.Path {
			return out[i].source.Path < out[j].source.Path
		}
		return out[i].source.Line < out[j].source.Line
	})
	return out
}

func originKey(item origin) string {
	if item.kind == originParam {
		return "param:" + strconv.Itoa(item.paramIdx) + ":" + item.paramPath
	}
	if item.kind == originReceiver {
		return "receiver:" + item.receiverPath
	}
	return item.kind + ":" + locationKey(item.source)
}

func mergeOrigins(existing origin, next origin) origin {
	existing.persistentRead = existing.persistentRead || next.persistentRead
	existing.pathSafe = existing.pathSafe || next.pathSafe
	existing.outputSafeHTML = existing.outputSafeHTML || next.outputSafeHTML
	existing.outputUnsafeHTML = existing.outputUnsafeHTML || next.outputUnsafeHTML
	existing.numericSafe = existing.numericSafe || next.numericSafe
	existing.storedWriteContext = mergeOptionalFlowContext(existing.storedWriteContext, next.storedWriteContext)
	return existing
}

func collapseOriginsToSingleParamRoot(origins originSet) (originSet, bool) {
	if len(origins) == 0 {
		return nil, false
	}
	paramIdx := -1
	for _, item := range origins {
		if item.kind != originParam {
			return nil, false
		}
		if item.persistentRead || item.pathSafe || item.outputSafeHTML || item.outputUnsafeHTML || hasMeaningfulFlowContext(item.storedWriteContext) {
			return nil, false
		}
		if paramIdx == -1 {
			paramIdx = item.paramIdx
			continue
		}
		if item.paramIdx != paramIdx {
			return nil, false
		}
	}
	if paramIdx < 0 {
		return nil, false
	}
	return makeOriginSet(origin{kind: originParam, paramIdx: paramIdx}), true
}

func markPersistentReadOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		item.persistentRead = true
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func markPathSafeOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		item.pathSafe = true
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func markNumericSafeOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		item.numericSafe = true
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func markHTMLOutputSafeOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		item.outputSafeHTML = true
		item.outputUnsafeHTML = false
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func markHTMLOutputUnsafeOrigins(origins originSet) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		item.outputUnsafeHTML = true
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func mergeStoredWriteContextByLocation(origins originSet, contextOrigins originSet) originSet {
	if len(origins) == 0 || len(contextOrigins) == 0 {
		return origins
	}
	contextByLocation := map[string]FlowContext{}
	for _, item := range contextOrigins {
		if !hasMeaningfulFlowContext(item.storedWriteContext) || item.source.Path == "" {
			continue
		}
		key := locationKey(item.source)
		contextByLocation[key] = mergeOptionalFlowContext(contextByLocation[key], item.storedWriteContext)
	}
	if len(contextByLocation) == 0 {
		return origins
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		if item.source.Path != "" {
			if ctx, ok := contextByLocation[locationKey(item.source)]; ok {
				item.storedWriteContext = mergeOptionalFlowContext(item.storedWriteContext, ctx)
			}
		}
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func appendIteratedOrigins(origins originSet) originSet {
	return appendPathOrigins(origins, "[]", Location{})
}

func appendIndexedOrigins(origins originSet, key string, loc Location) originSet {
	if key == "" {
		return appendPathOrigins(origins, "", loc)
	}
	return appendPathOrigins(origins, "["+strings.ToLower(key)+"]", loc)
}

func appendPropertyOrigins(origins originSet, name string) originSet {
	if name == "" {
		return origins
	}
	return appendPathOrigins(origins, "."+name, Location{})
}

func appendPathOrigins(origins originSet, segment string, loc Location) originSet {
	if len(origins) == 0 {
		return originSet{}
	}
	out := make(originSet, len(origins))
	for _, item := range origins {
		switch item.kind {
		case originParam:
			item.paramPath += segment
			item.paramPath = compactRelativeOriginPath(item.paramPath)
		case originReceiver:
			switch {
			case item.receiverPath == "" && strings.HasPrefix(segment, "."):
				item.receiverPath = segment[1:]
			default:
				item.receiverPath += segment
			}
			item.receiverPath = compactRelativeOriginPath(item.receiverPath)
		case originContainer:
			item.kind = originSource
			if loc.Path != "" {
				item.source = loc
			}
		}
		key := originKey(item)
		if existing, ok := out[key]; ok {
			item = mergeOrigins(existing, item)
		}
		out[key] = item
	}
	return out
}

func compactRelativeOriginPath(path string) string {
	if maxRelativeOriginPathSegments <= 0 || path == "" {
		return path
	}
	var b strings.Builder
	remainder := path
	segments := 0
	for remainder != "" {
		segment, rest, ok := nextPathSegment(remainder)
		if !ok {
			return path
		}
		if segments >= maxRelativeOriginPathSegments {
			break
		}
		switch {
		case segment == "[]":
			b.WriteString("[]")
		case segment == "*":
			b.WriteString("[*]")
		case strings.HasPrefix(segment, "."):
			b.WriteString(segment)
		default:
			b.WriteString("[")
			b.WriteString(segment)
			b.WriteString("]")
		}
		segments++
		remainder = rest
	}
	return b.String()
}

func rootlessArrayPath(dim ast.Node) string {
	if key, ok := stableArrayDimKey(dim); ok {
		return "[" + strings.ToLower(key) + "]"
	}
	if dim == nil {
		return "[]"
	}
	return "[*]"
}

func nextPathSegment(path string) (string, string, bool) {
	if path == "" {
		return "", "", false
	}
	if path[0] == '.' {
		rest := path[1:]
		end := len(rest)
		for i := 0; i < len(rest); i++ {
			if rest[i] == '[' || rest[i] == '.' {
				end = i
				break
			}
		}
		if end == 0 {
			return "", "", false
		}
		return "." + rest[:end], rest[end:], true
	}
	if path[0] != '[' {
		return "", "", false
	}
	end := strings.IndexByte(path, ']')
	if end < 0 {
		return "", "", false
	}
	raw := path[1:end]
	if raw == "" {
		return "[]", path[end+1:], true
	}
	return raw, path[end+1:], true
}

func applyPathStringToOrigins(origins originSet, path string, loc Location) originSet {
	out := origins
	for path != "" {
		segment, rest, ok := nextPathSegment(path)
		if !ok {
			break
		}
		switch {
		case segment == "[]":
			out = appendIteratedOrigins(out)
		case strings.HasPrefix(segment, "."):
			out = appendPropertyOrigins(out, segment[1:])
		default:
			out = appendIndexedOrigins(out, segment, loc)
		}
		path = rest
	}
	return out
}
