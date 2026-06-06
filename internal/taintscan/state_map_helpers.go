package taintscan

import (
	"sort"
	"strings"
)

func unionAll(items []originSet) originSet {
	var out originSet
	for _, item := range items {
		out = unionInto(out, item)
	}
	return out
}

func cloneVarMap(src map[string]originSet) map[string]originSet {
	out := make(map[string]originSet, len(src))
	for key, value := range src {
		// originSet updates are modeled functionally: callers replace map entries
		// with union()/clone()-style results instead of mutating a shared set
		// in place. A shallow copy avoids cloning every originSet during branch
		// state snapshots while mergeVarMaps still deep-copies where mutation via
		// unionInto can occur.
		out[key] = value
	}
	return out
}

func mergeVarMaps(a map[string]originSet, b map[string]originSet) map[string]originSet {
	out := make(map[string]originSet, len(a)+len(b))
	for key, value := range a {
		out[key] = value
	}
	for key, value := range b {
		if existing, ok := out[key]; ok {
			out[key] = unionInto(existing.clone(), value)
			continue
		}
		out[key] = value
	}
	return out
}

func unionMapEntry(dst map[string]originSet, key string, src originSet) {
	if len(src) == 0 {
		return
	}
	if existing, ok := dst[key]; ok {
		dst[key] = unionInto(existing.clone(), src)
		return
	}
	// Cap map growth to prevent OOM on large plugins with deep property chains.
	if len(dst) >= maxStateMapEntries {
		return
	}
	dst[key] = src
}

func collectPropertyOrigins(items map[string]originSet, prefix string) originSet {
	var out originSet
	for key, origins := range items {
		if strings.HasPrefix(key, prefix) {
			out = unionInto(out, origins)
		}
	}
	return out
}

func collectPropertyOriginsInto(dst originSet, items map[string]originSet, prefix string) originSet {
	for key, origins := range items {
		if strings.HasPrefix(key, prefix) {
			dst = unionInto(dst, origins)
		}
	}
	return dst
}

func collectStructuralChildren(items map[string]originSet, path string) originSet {
	out := collectPropertyOriginsInto(nil, items, path+"[")
	out = collectPropertyOriginsInto(out, items, path+".")
	for _, variant := range structuralPathWildcardVariants(path) {
		if variant == path {
			continue
		}
		out = collectPropertyOriginsInto(out, items, variant+"[")
		out = collectPropertyOriginsInto(out, items, variant+".")
	}
	return out
}

func lookupStructuralSelfOrigins(items map[string]originSet, path string) originSet {
	var out originSet
	for _, variant := range structuralPathWildcardVariants(path) {
		if origins, ok := items[variant]; ok {
			out = unionInto(out, origins)
		}
	}
	return out
}

func structuralPathTracked(items map[string]originSet, path string) bool {
	for _, variant := range structuralPathWildcardVariants(path) {
		if _, ok := items[variant]; ok {
			return true
		}
	}
	return false
}

func structuralContainerDefinitelyLacksSegment(items map[string]originSet, containerPath string, wantedPath string) bool {
	if len(items) == 0 || containerPath == "" || wantedPath == "" {
		return false
	}
	wantedSeg, _, ok := nextPathSegment(wantedPath)
	if !ok {
		return false
	}
	knownChild := false
	persistentStructuredChild := false
	for _, variant := range structuralPathWildcardVariants(containerPath) {
		prefixArray := variant + "["
		prefixProp := variant + "."
		for key := range items {
			if !strings.HasPrefix(key, prefixArray) && !strings.HasPrefix(key, prefixProp) {
				continue
			}
			remainder := strings.TrimPrefix(key, variant)
			gotSeg, _, ok := nextPathSegment(remainder)
			if !ok {
				continue
			}
			knownChild = true
			if origins := items[key]; originsHavePersistentStructuredOrigin(origins) {
				persistentStructuredChild = true
			}
			if structuralPathSegmentMatches(wantedSeg, gotSeg) {
				return false
			}
			if gotSeg == "*" || gotSeg == "[]" {
				return false
			}
		}
	}
	return knownChild && persistentStructuredChild
}

func originsHavePersistentStructuredOrigin(origins originSet) bool {
	for _, item := range origins {
		if item.persistentRead || hasMeaningfulFlowContext(item.storedWriteContext) {
			return true
		}
	}
	return false
}

func lookupStructuralPathOrigins(items map[string]originSet, path string) originSet {
	out := lookupStructuralSelfOrigins(items, path)
	for _, variant := range structuralPathWildcardVariants(path) {
		out = collectPropertyOriginsInto(out, items, variant+"[")
		out = collectPropertyOriginsInto(out, items, variant+".")
	}
	return out
}

func cloneStringMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func cloneStringSet(src map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(src))
	for key := range src {
		out[key] = struct{}{}
	}
	return out
}

func mergeStringMaps(a map[string]string, b map[string]string) map[string]string {
	out := cloneStringMap(a)
	for key, value := range b {
		if value != "" {
			out[key] = value
		}
	}
	return out
}

func mergeStringSets(a map[string]struct{}, b map[string]struct{}) map[string]struct{} {
	out := cloneStringSet(a)
	for key := range b {
		out[key] = struct{}{}
	}
	return out
}

func sortedStringSet(items map[string]struct{}) []string {
	out := make([]string, 0, len(items))
	for key := range items {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func summaryReturnClass(item summary) string {
	if len(item.ReturnClasses) != 1 {
		return ""
	}
	return item.ReturnClasses[0]
}
