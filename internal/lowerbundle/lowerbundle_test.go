package lowerbundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildForRootLowersInstanceAndStaticCalls(t *testing.T) {
	root := t.TempDir()
	writePHPFile(t, filepath.Join(root, "demo.php"), `<?php
function top_level($value) {
    return $value;
}

class Demo {
    public function run($value) {
        return $this->sink(self::helper($value));
    }

    public function sink($value) {
        return $value;
    }

    public static function helper($value) {
        return $value;
    }
}
`)

	bundlePath := filepath.Join(root, "out", "lowered-bundle.php")
	mapPath := filepath.Join(root, "out", "lowered-mapping.json")
	result, err := BuildForRoot(root, nil, bundlePath, mapPath, 1)
	if err != nil {
		t.Fatalf("BuildForRoot(): %v", err)
	}
	if len(result.Files) != 1 {
		t.Fatalf("parsed files = %d, want 1", len(result.Files))
	}

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("ReadFile(bundle): %v", err)
	}
	bundle := string(bundleBytes)
	for _, want := range []string{
		"function top_level($value)",
		"function __semgrep_lowered__Demo__run($_semgrep_this, $value)",
		"return __semgrep_lowered__Demo__sink($_semgrep_this, __semgrep_lowered__Demo__helper($value));",
		"function __semgrep_lowered__Demo__sink($_semgrep_this, $value)",
		"function __semgrep_lowered__Demo__helper($value)",
	} {
		if !strings.Contains(bundle, want) {
			t.Fatalf("bundle missing %q\n%s", want, bundle)
		}
	}

	mappingBytes, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatalf("ReadFile(mapping): %v", err)
	}
	var mapping Mapping
	if err := json.Unmarshal(mappingBytes, &mapping); err != nil {
		t.Fatalf("Unmarshal(mapping): %v", err)
	}
	if len(mapping.Segments) != 4 {
		t.Fatalf("segment count = %d, want 4", len(mapping.Segments))
	}
	if mapping.Segments[0].Kind != "function" {
		t.Fatalf("first segment kind = %q, want function", mapping.Segments[0].Kind)
	}
}

func TestBuildForRootResolvesParentMethodOwner(t *testing.T) {
	root := t.TempDir()
	writePHPFile(t, filepath.Join(root, "demo.php"), `<?php
class ParentDemo {
    public function sink($value) {
        return $value;
    }
}

class ChildDemo extends ParentDemo {
    public function run($value) {
        return $this->sink($value);
    }
}
`)

	bundlePath := filepath.Join(root, "out", "lowered-bundle.php")
	mapPath := filepath.Join(root, "out", "lowered-mapping.json")
	if _, err := BuildForRoot(root, nil, bundlePath, mapPath, 1); err != nil {
		t.Fatalf("BuildForRoot(): %v", err)
	}

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("ReadFile(bundle): %v", err)
	}
	bundle := string(bundleBytes)
	if !strings.Contains(bundle, "__semgrep_lowered__ParentDemo__sink($_semgrep_this, $value)") {
		t.Fatalf("bundle did not lower parent-owner call:\n%s", bundle)
	}
}

func writePHPFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
