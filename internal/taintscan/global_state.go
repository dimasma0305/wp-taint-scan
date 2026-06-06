package taintscan

func (e *engine) recomputeGlobalStorage() {
	next := map[string]originSet{}
	nextPaths := map[string]originSet{}
	for _, item := range e.summaries {
		for family, effect := range item.StorageWrites {
			unionMapEntry(next, family, originsFromTaintSummary(effect))
		}
		for path, effect := range item.StoragePathWrites {
			unionMapEntry(nextPaths, path, originsFromTaintSummary(effect))
		}
	}
	e.storagePaths = compactStoragePathsByRoot(nextPaths)
	e.storage = pruneStructuralRootOriginsCoveredByChildren(next, e.storagePaths)
}

func (e *engine) recomputeGlobalStaticProps() {
	next := map[string]originSet{}
	for _, item := range e.summaries {
		for path, effect := range item.StaticWrites {
			unionMapEntry(next, path, originsFromTaintSummary(effect))
		}
	}
	e.staticProps = compactStaticPropsByRoot(next)
	e.staticProps = pruneStructuralRootOriginsCoveredByChildren(e.staticProps, e.staticProps)
}

func pruneStructuralRootOriginsCoveredByChildren(roots map[string]originSet, paths map[string]originSet) map[string]originSet {
	if len(roots) == 0 {
		return roots
	}
	out := make(map[string]originSet, len(roots))
	for root, origins := range roots {
		if len(origins) == 0 {
			continue
		}
		if children := collectStructuralChildren(paths, root); originSetCoveredBy(origins, children) {
			continue
		}
		out[root] = origins
	}
	return out
}
