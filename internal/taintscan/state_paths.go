package taintscan

import (
	"fmt"
	"strings"
	"sync"
)

var structuralPathVariantsCache sync.Map

func structuralPathRoot(path string) string {
	if path == "" {
		return ""
	}
	if idx := strings.Index(path, "["); idx >= 0 {
		return path[:idx]
	}
	if strings.Contains(path, ".$") {
		return path
	}
	if idx := strings.Index(path, "."); idx >= 0 {
		return path[:idx]
	}
	return path
}

func structuralCollapseBucket(path string) string {
	root := structuralPathRoot(path)
	if root == "" || len(path) <= len(root) {
		return root
	}
	remainder := path[len(root):]
	bucket := root
	sawStable := false
	sawWildcardPrefix := false
	for len(remainder) > 0 && remainder[0] == '[' {
		end, ok := matchingBracketIndex(remainder, 0)
		if !ok {
			return root
		}
		content := remainder[1:end]
		segment := remainder[:end+1]
		switch {
		case content == "":
			if sawStable {
				return bucket
			}
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
				remainder = remainder[end+1:]
				continue
			}
			remainder = remainder[end+1:]
		case content == "*":
			if sawStable {
				return bucket
			}
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
				remainder = remainder[end+1:]
				continue
			}
			if sawStable {
				return bucket
			}
			return root
		case isStableArraySegment(content):
			bucket += segment
			sawStable = true
			remainder = remainder[end+1:]
		default:
			if sawStable {
				return bucket
			}
			if sawWildcardPrefix {
				remainder = remainder[end+1:]
				continue
			}
			return root
		}
	}
	if sawStable || sawWildcardPrefix {
		return bucket
	}
	return root
}

func structuralStablePathBucket(path string) string {
	root := structuralPathRoot(path)
	if root == "" || len(path) <= len(root) {
		return root
	}
	remainder := path[len(root):]
	bucket := root
	sawStable := false
	for len(remainder) > 0 && remainder[0] == '[' {
		end, ok := matchingBracketIndex(remainder, 0)
		if !ok {
			return bucket
		}
		content := remainder[1:end]
		segment := remainder[:end+1]
		switch {
		case content == "*":
			if sawStable {
				return bucket
			}
			return root
		case isStableArraySegment(content):
			bucket += segment
			sawStable = true
			remainder = remainder[end+1:]
		default:
			if sawStable {
				return bucket
			}
			return root
		}
	}
	if bucket != "" {
		return bucket
	}
	return root
}

func firstStructuralCompactionBucket(path string) string {
	root := structuralPathRoot(path)
	if root != "" && len(path) > len(root) && path[len(root)] == '.' {
		return collapseFirstArraySegment(path)
	}
	if bucket := structuralCollapseBucket(path); bucket != "" && bucket != path {
		if len(bucket) < len(path) && strings.HasSuffix(bucket, "[*]") && strings.HasPrefix(path[len(bucket):], ".") {
			return collapseFirstArraySegment(path)
		}
		return bucket
	}
	return collapseFirstArraySegment(path)
}

func storageStablePathBucket(path string) string {
	root := structuralPathRoot(path)
	if root == "" || len(path) <= len(root) {
		return root
	}
	remainder := path[len(root):]
	bucket := root
	sawWildcardPrefix := false
	sawStableAfterWildcard := false
	wildcardFromInput := false
	for len(remainder) > 0 && remainder[0] == '[' {
		end, ok := matchingBracketIndex(remainder, 0)
		if !ok {
			return root
		}
		content := remainder[1:end]
		segment := remainder[:end+1]
		switch {
		case content == "":
			if sawStableAfterWildcard {
				return bucket
			}
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
				wildcardFromInput = true
			}
			remainder = remainder[end+1:]
		case content == "*":
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
				wildcardFromInput = true
			} else if sawStableAfterWildcard {
				return bucket
			}
			remainder = remainder[end+1:]
		case isStableArraySegment(content):
			if sawStableAfterWildcard {
				return bucket
			}
			bucket += segment
			if !sawWildcardPrefix {
				return bucket
			}
			if !wildcardFromInput {
				return bucket
			}
			sawStableAfterWildcard = true
			remainder = remainder[end+1:]
		default:
			if sawStableAfterWildcard {
				return bucket
			}
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
			}
			remainder = remainder[end+1:]
		}
	}
	if sawWildcardPrefix {
		return bucket
	}
	return root
}

func structuralPathWildcardVariants(path string) []string {
	if path == "" {
		return nil
	}
	if cached, ok := structuralPathVariantsCache.Load(path); ok {
		return cached.([]string)
	}
	variants := []string{path}
	seen := map[string]struct{}{path: {}}
	if collapsed := collapseFirstDynamicArraySegment(path); collapsed != "" && collapsed != path {
		variants = append(variants, collapsed)
		seen[collapsed] = struct{}{}
	}
	if collapsed := collapseFirstArraySegment(path); collapsed != "" && collapsed != path {
		if _, ok := seen[collapsed]; !ok {
			variants = append(variants, collapsed)
			seen[collapsed] = struct{}{}
		}
	}
	if collapsed := collapseAllArraySegments(path); collapsed != "" {
		if _, ok := seen[collapsed]; !ok {
			variants = append(variants, collapsed)
		}
	}
	structuralPathVariantsCache.Store(path, variants)
	return variants
}

func staticPathInvalidationBucket(path string) string {
	if path == "" {
		return ""
	}
	if collapsed := collapseFirstDynamicArraySegment(path); collapsed != "" && collapsed != path {
		return collapsed
	}
	if collapsed := collapseFirstArraySegment(path); collapsed != "" {
		return collapsed
	}
	return path
}

func trimTrailingPathSegment(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if path[len(path)-1] == ']' {
		depth := 0
		for i := len(path) - 1; i >= 0; i-- {
			switch path[i] {
			case ']':
				depth++
			case '[':
				depth--
				if depth == 0 {
					return path[:i], true
				}
			}
		}
		return "", false
	}
	idx := strings.LastIndexByte(path, '.')
	if idx < 0 {
		return "", false
	}
	return path[:idx], true
}

func collapseFirstDynamicArraySegment(path string) string {
	for i := 0; i < len(path); i++ {
		if path[i] != '[' {
			continue
		}
		end, ok := matchingBracketIndex(path, i)
		if !ok {
			return path
		}
		content := path[i+1 : end]
		if isStableArraySegment(content) {
			i = end
			continue
		}
		return path[:i] + "[*]" + path[end+1:]
	}
	return path
}

func collapseFirstArraySegment(path string) string {
	start := strings.IndexByte(path, '[')
	if start < 0 {
		return path
	}
	end, ok := matchingBracketIndex(path, start)
	if !ok {
		return path
	}
	if path[start:end+1] == "[*]" {
		return path
	}
	return path[:start] + "[*]" + path[end+1:]
}

func isStableArraySegment(content string) bool {
	if content == "" || content == "*" {
		return true
	}
	for _, r := range content {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func collapseAllArraySegments(path string) string {
	if !strings.Contains(path, "[") {
		return path
	}
	var b strings.Builder
	for i := 0; i < len(path); {
		if path[i] != '[' {
			b.WriteByte(path[i])
			i++
			continue
		}
		end, ok := matchingBracketIndex(path, i)
		if !ok {
			return path
		}
		b.WriteString("[*]")
		i = end + 1
	}
	return b.String()
}

func matchingBracketIndex(path string, start int) (int, bool) {
	if start < 0 || start >= len(path) || path[start] != '[' {
		return -1, false
	}
	depth := 0
	for i := start; i < len(path); i++ {
		switch path[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return -1, false
}

func compactStaticPropsByRoot(raw map[string]originSet) map[string]originSet {
	if maxNestedStaticPathsPerRoot <= 0 || len(raw) == 0 {
		return raw
	}
	grouped := map[string]int{}
	for path := range raw {
		root := structuralPathRoot(path)
		if root == "" || root == path {
			continue
		}
		grouped[root]++
	}
	stageOne := map[string]originSet{}
	for path, origins := range raw {
		target := path
		root := structuralPathRoot(path)
		if root != "" && root != path && grouped[root] > maxNestedStaticPathsPerRoot {
			target = collapseFirstDynamicArraySegment(path)
		}
		stageOne[target] = stageOne[target].union(origins)
	}
	grouped = map[string]int{}
	for path := range stageOne {
		bucket := firstStructuralCompactionBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	stageTwo := map[string]originSet{}
	for path, origins := range stageOne {
		target := path
		bucket := firstStructuralCompactionBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedStaticPathsPerRoot {
			target = bucket
		}
		stageTwo[target] = stageTwo[target].union(origins)
	}
	grouped = map[string]int{}
	for path := range stageTwo {
		bucket := structuralStablePathBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	out := map[string]originSet{}
	for path, origins := range stageTwo {
		target := path
		root := structuralPathRoot(path)
		bucket := structuralStablePathBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedStaticPathsPerRoot {
			if bucket == root {
				target = collapseAllArraySegments(path)
			} else {
				target = bucket
			}
		}
		out[target] = out[target].union(origins)
	}
	return pruneStructuralPathsCoveredByChildren(out)
}

func compactStoragePathsByRoot(raw map[string]originSet) map[string]originSet {
	if maxNestedStoragePathsPerRoot <= 0 || len(raw) == 0 {
		return raw
	}
	grouped := map[string]int{}
	for path := range raw {
		root := structuralPathRoot(path)
		if root == "" || root == path {
			continue
		}
		grouped[root]++
	}
	stageOne := map[string]originSet{}
	for path, origins := range raw {
		target := path
		root := structuralPathRoot(path)
		if root != "" && root != path && grouped[root] > maxNestedStoragePathsPerRoot {
			target = collapseFirstDynamicArraySegment(path)
		}
		stageOne[target] = stageOne[target].union(origins)
	}
	grouped = map[string]int{}
	for path := range stageOne {
		bucket := firstStructuralCompactionBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	stageTwo := map[string]originSet{}
	for path, origins := range stageOne {
		target := path
		bucket := firstStructuralCompactionBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedStoragePathsPerRoot {
			target = bucket
		}
		stageTwo[target] = stageTwo[target].union(origins)
	}
	grouped = map[string]int{}
	for path := range stageTwo {
		bucket := storageStablePathBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	out := map[string]originSet{}
	for path, origins := range stageTwo {
		target := path
		root := structuralPathRoot(path)
		bucket := storageStablePathBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedStoragePathsPerRoot {
			stableBucket := storageStablePathBucket(path)
			if stableBucket == "" || stableBucket == root {
				target = collapseAllArraySegments(path)
			} else {
				target = stableBucket
			}
		}
		out[target] = out[target].union(origins)
	}
	return pruneStructuralPathsCoveredByChildren(out)
}

func compactRelativeStructuralPathsByRoot(raw map[string]originSet) map[string]originSet {
	if maxNestedParamPathsPerRoot <= 0 || len(raw) == 0 {
		return raw
	}
	const prefix = "__value"
	prefixed := map[string]originSet{}
	for path, origins := range raw {
		prefixed[prefix+path] = prefixed[prefix+path].union(origins)
	}
	compacted := compactStructuralPathsByRootWithLimit(prefixed, maxNestedParamPathsPerRoot)
	out := map[string]originSet{}
	for path, origins := range compacted {
		trimmed := strings.TrimPrefix(path, prefix)
		out[trimmed] = out[trimmed].union(origins)
	}
	return out
}

func compactParamPathRefsByRoot(raw map[string]paramPathRef) map[string]paramPathRef {
	if maxNestedParamPathsPerRoot <= 0 || len(raw) == 0 {
		return raw
	}
	grouped := map[string]int{}
	for path := range raw {
		root := structuralPathRoot(path)
		if root == "" || root == path {
			continue
		}
		grouped[root]++
	}
	stageOne := map[string]paramPathRef{}
	for path, ref := range raw {
		target := path
		root := structuralPathRoot(path)
		if root != "" && root != path && grouped[root] > maxNestedParamPathsPerRoot {
			target = collapseFirstDynamicArraySegment(path)
		}
		ref.Path = strings.TrimPrefix(target, paramPathSyntheticPrefix(ref.Index))
		unionParamPathRefEntry(stageOne, target, ref)
	}
	grouped = map[string]int{}
	for path := range stageOne {
		bucket := firstStructuralCompactionBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	stageTwo := map[string]paramPathRef{}
	for path, ref := range stageOne {
		target := path
		bucket := firstStructuralCompactionBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedParamPathsPerRoot {
			target = bucket
		}
		ref.Path = strings.TrimPrefix(target, paramPathSyntheticPrefix(ref.Index))
		unionParamPathRefEntry(stageTwo, target, ref)
	}
	grouped = map[string]int{}
	for path := range stageTwo {
		bucket := paramStablePathBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	out := map[string]paramPathRef{}
	for path, ref := range stageTwo {
		target := path
		root := structuralPathRoot(path)
		bucket := paramStablePathBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedParamPathsPerRoot {
			stableBucket := paramStablePathBucket(path)
			if stableBucket == "" || stableBucket == root {
				target = collapseAllArraySegments(path)
				if target == path && strings.HasPrefix(path[len(root):], ".") {
					target = root
				}
			} else {
				target = stableBucket
			}
		}
		ref.Path = strings.TrimPrefix(target, paramPathSyntheticPrefix(ref.Index))
		unionParamPathRefEntry(out, target, ref)
	}
	return out
}

func compactReceiverPathRefsByRoot(raw map[string]receiverPathRef) map[string]receiverPathRef {
	if maxNestedParamPathsPerRoot <= 0 || len(raw) == 0 {
		return raw
	}
	const prefix = "__receiver"
	prefixed := map[string]receiverPathRef{}
	for path, ref := range raw {
		key := prefix + path
		ref.Path = key
		unionReceiverPathRefEntry(prefixed, key, ref)
	}
	grouped := map[string]int{}
	for path := range prefixed {
		root := structuralPathRoot(path)
		if root == "" || root == path {
			continue
		}
		grouped[root]++
	}
	stageOne := map[string]receiverPathRef{}
	for path, ref := range prefixed {
		target := path
		root := structuralPathRoot(path)
		if root != "" && root != path && grouped[root] > maxNestedParamPathsPerRoot {
			target = collapseFirstDynamicArraySegment(path)
		}
		ref.Path = target
		unionReceiverPathRefEntry(stageOne, target, ref)
	}
	grouped = map[string]int{}
	for path := range stageOne {
		bucket := firstStructuralCompactionBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	stageTwo := map[string]receiverPathRef{}
	for path, ref := range stageOne {
		target := path
		bucket := firstStructuralCompactionBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedParamPathsPerRoot {
			target = bucket
		}
		ref.Path = target
		unionReceiverPathRefEntry(stageTwo, target, ref)
	}
	grouped = map[string]int{}
	for path := range stageTwo {
		bucket := paramStablePathBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	out := map[string]receiverPathRef{}
	for path, ref := range stageTwo {
		target := path
		root := structuralPathRoot(path)
		bucket := paramStablePathBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > maxNestedParamPathsPerRoot {
			stableBucket := paramStablePathBucket(path)
			if stableBucket == "" || stableBucket == root {
				target = collapseAllArraySegments(path)
				if target == path && strings.HasPrefix(path[len(root):], ".") {
					target = root
				}
			} else {
				target = stableBucket
			}
		}
		ref.Path = strings.TrimPrefix(target, prefix)
		unionReceiverPathRefEntry(out, target, ref)
	}
	return out
}

func paramStablePathBucket(path string) string {
	root := structuralPathRoot(path)
	if root == "" || len(path) <= len(root) {
		return root
	}
	remainder := path[len(root):]
	bucket := root
	sawWildcardPrefix := false
	sawStableAfterWildcard := false
	wildcardFromInput := false
	for remainder != "" {
		segment, rest, ok := nextPathSegment(remainder)
		if !ok {
			return root
		}
		switch {
		case segment == "[]":
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
				wildcardFromInput = true
			} else if sawStableAfterWildcard {
				return bucket
			}
			remainder = rest
		case segment == "*":
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
				wildcardFromInput = true
			} else if sawStableAfterWildcard {
				return bucket
			}
			remainder = rest
		case strings.HasPrefix(segment, "."):
			if len(segment) <= 1 {
				return root
			}
			if sawStableAfterWildcard {
				return bucket
			}
			bucket += segment
			if !sawWildcardPrefix {
				return bucket
			}
			if !wildcardFromInput {
				return bucket
			}
			sawStableAfterWildcard = true
			remainder = rest
		case isStableArraySegment(segment):
			if sawStableAfterWildcard {
				return bucket
			}
			bucket += "[" + segment + "]"
			if !sawWildcardPrefix {
				return bucket
			}
			if !wildcardFromInput {
				return bucket
			}
			sawStableAfterWildcard = true
			remainder = rest
		default:
			if sawStableAfterWildcard {
				return bucket
			}
			if !sawWildcardPrefix {
				bucket += "[*]"
				sawWildcardPrefix = true
			}
			remainder = rest
		}
	}
	if sawWildcardPrefix {
		return bucket
	}
	return root
}

func compactStructuralPathsByRootWithLimit(raw map[string]originSet, limit int) map[string]originSet {
	if limit <= 0 || len(raw) == 0 {
		return raw
	}
	grouped := map[string]int{}
	for path := range raw {
		root := structuralPathRoot(path)
		if root == "" || root == path {
			continue
		}
		grouped[root]++
	}
	stageOne := map[string]originSet{}
	for path, origins := range raw {
		target := path
		root := structuralPathRoot(path)
		if root != "" && root != path && grouped[root] > limit {
			target = collapseFirstDynamicArraySegment(path)
		}
		stageOne[target] = stageOne[target].union(origins)
	}
	grouped = map[string]int{}
	for path := range stageOne {
		bucket := firstStructuralCompactionBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	stageTwo := map[string]originSet{}
	for path, origins := range stageOne {
		target := path
		bucket := firstStructuralCompactionBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > limit {
			target = bucket
		}
		stageTwo[target] = stageTwo[target].union(origins)
	}
	grouped = map[string]int{}
	for path := range stageTwo {
		bucket := storageStablePathBucket(path)
		if bucket == "" || bucket == path {
			continue
		}
		grouped[bucket]++
	}
	out := map[string]originSet{}
	for path, origins := range stageTwo {
		target := path
		root := structuralPathRoot(path)
		bucket := storageStablePathBucket(path)
		if bucket != "" && bucket != path && grouped[bucket] > limit {
			stableBucket := storageStablePathBucket(path)
			if stableBucket == "" || stableBucket == root {
				target = collapseAllArraySegments(path)
			} else {
				target = stableBucket
			}
		}
		out[target] = out[target].union(origins)
	}
	return pruneStructuralPathsCoveredByChildren(out)
}

func paramPathSyntheticPrefix(index int) string {
	return fmt.Sprintf("__param%d", index)
}

func unionParamPathRefEntry(dst map[string]paramPathRef, key string, ref paramPathRef) {
	if existing, ok := dst[key]; ok {
		existing.PersistentRead = existing.PersistentRead || ref.PersistentRead
		existing.PathSafe = existing.PathSafe || ref.PathSafe
		existing.OutputSafeHTML = existing.OutputSafeHTML || ref.OutputSafeHTML
		existing.OutputUnsafeHTML = existing.OutputUnsafeHTML || ref.OutputUnsafeHTML
		existing.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, ref.StoredWriteContext)
		dst[key] = existing
		return
	}
	dst[key] = ref
}

func unionReceiverPathRefEntry(dst map[string]receiverPathRef, key string, ref receiverPathRef) {
	if existing, ok := dst[key]; ok {
		existing.PersistentRead = existing.PersistentRead || ref.PersistentRead
		existing.PathSafe = existing.PathSafe || ref.PathSafe
		existing.OutputSafeHTML = existing.OutputSafeHTML || ref.OutputSafeHTML
		existing.OutputUnsafeHTML = existing.OutputUnsafeHTML || ref.OutputUnsafeHTML
		existing.StoredWriteContext = mergeOptionalFlowContext(existing.StoredWriteContext, ref.StoredWriteContext)
		dst[key] = existing
		return
	}
	dst[key] = ref
}

func pruneStructuralPathsCoveredByChildren(paths map[string]originSet) map[string]originSet {
	if len(paths) == 0 {
		return paths
	}
	out := make(map[string]originSet, len(paths))
	for path, origins := range paths {
		if len(origins) == 0 {
			continue
		}
		if children := collectStructuralCoveredChildren(paths, path); originSetCoveredBy(origins, children) {
			continue
		}
		out[path] = origins
	}
	return out
}

func collectStructuralCoveredChildren(items map[string]originSet, path string) originSet {
	out := originSet{}
	for candidate, origins := range items {
		if candidate == path {
			continue
		}
		if structuralPathCoveredByChild(path, candidate) {
			out = unionInto(out, origins)
		}
	}
	return out
}

func structuralPathCoveredByChild(parent, child string) bool {
	root := structuralPathRoot(parent)
	if root == "" || root != structuralPathRoot(child) {
		return false
	}
	parentRemainder := parent[len(root):]
	childRemainder := child[len(root):]
	if parentRemainder == "" || childRemainder == "" {
		return false
	}
	matchedSpecificChild := false
	for parentRemainder != "" {
		parentSeg, nextParent, ok := nextPathSegment(parentRemainder)
		if !ok {
			return false
		}
		childSeg, nextChild, ok := nextPathSegment(childRemainder)
		if !ok {
			return false
		}
		if !structuralSegmentMatches(parentSeg, childSeg) {
			return false
		}
		if parentSeg != childSeg {
			matchedSpecificChild = true
		}
		parentRemainder = nextParent
		childRemainder = nextChild
	}
	return matchedSpecificChild || childRemainder != ""
}

func structuralSegmentMatches(parentSeg, childSeg string) bool {
	if parentSeg == childSeg {
		return true
	}
	if strings.HasPrefix(parentSeg, ".") || strings.HasPrefix(childSeg, ".") {
		return false
	}
	return parentSeg == "*" || parentSeg == "[]"
}
