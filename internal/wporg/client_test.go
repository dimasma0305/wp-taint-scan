package wporg

import (
	"encoding/json"
	"testing"
)

func TestValidSlug(t *testing.T) {
	ok := []string{"contact-form-7", "woocommerce", "a", "wp_super_cache", "akismet.2"}
	bad := []string{"", "../etc", "Foo", "a/b", "x..y", "-leading"}
	for _, s := range ok {
		if !ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = true, want false", s)
		}
	}
}

func TestValidVersion(t *testing.T) {
	ok := []string{"1.0", "6.1.6", "1.10.0.1", "2.0-beta1", "trunk"}
	bad := []string{"", "../1.0", "1/2", "1..2", "a b"}
	for _, v := range ok {
		if !ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = false, want true", v)
		}
	}
	for _, v := range bad {
		if ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = true, want false", v)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign
	}{
		{"1.10", "1.9", 1},   // numeric, not lexical
		{"1.9", "1.10", -1},
		{"2.0", "2.0", 0},
		{"1.10.0.1", "1.10", 1},
		{"6.1.6", "6.1.5", 1},
		{"1.0", "1.0.0", 0},        // missing trailing components treated equal
		{"6.0", "6.0-beta1", 1},    // release outranks pre-release
		{"6.0-beta2", "6.0-beta1", 1},
		{"2.0-rc1", "2.0", -1},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("compareVersions(%q,%q) sign = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSortedVersionsExcludesTrunkNewestFirst(t *testing.T) {
	info := &Info{Versions: map[string]string{
		"1.1": "u", "1.10": "u", "1.2": "u", "trunk": "u", "1.10.0.1": "u",
	}}
	got := info.SortedVersions()
	want := []string{"1.10.0.1", "1.10", "1.2", "1.1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestDownloadURL(t *testing.T) {
	u, err := DownloadURL("contact-form-7", "5.9.8")
	if err != nil {
		t.Fatal(err)
	}
	if u != "https://downloads.wordpress.org/plugin/contact-form-7.5.9.8.zip" {
		t.Errorf("unexpected url: %s", u)
	}
	if _, err := DownloadURL("../evil", "1.0"); err == nil {
		t.Error("expected error for traversal slug")
	}
}

// The WordPress.org API returns `false` for unset string fields; flexString must
// tolerate that instead of failing the whole decode.
func TestFlexStringToleratesBool(t *testing.T) {
	var p Plugin
	raw := `{"slug":"x","name":"X","requires_php":false,"tested":"6.7","requires":false}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.RequiresPHP != "" || p.Requires != "" {
		t.Errorf("bool fields should decode to empty string, got php=%q requires=%q", p.RequiresPHP, p.Requires)
	}
	if p.Tested != "6.7" {
		t.Errorf("tested = %q, want 6.7", p.Tested)
	}
}
