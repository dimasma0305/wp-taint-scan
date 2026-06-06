package main

import (
	"testing"

	"github.com/dimasma0305/wp-taint-scan/internal/wporg"
)

func sample() []wporg.Plugin {
	return []wporg.Plugin{
		{Slug: "a", Name: "Zeta", ActiveInstalls: 5_000, Rating: 90, LastUpdated: "2026-01-01 1:00am"},
		{Slug: "b", Name: "alpha", ActiveInstalls: 1_000_000, Rating: 70, LastUpdated: "2026-05-01 1:00am"},
		{Slug: "c", Name: "Mid", ActiveInstalls: 80_000, Rating: 60, LastUpdated: "2026-03-01 1:00am"},
	}
}

func TestFilterPlugins_InstallRange(t *testing.T) {
	in := sample()
	out := filterPlugins(in, 10_000, 200_000, 0) // 10k–200k
	if len(out) != 1 || out[0].Slug != "c" {
		t.Fatalf("expected only c, got %+v", out)
	}
	if len(in) != 3 {
		t.Fatalf("input slice was mutated: %+v", in)
	}
}

func TestFilterPlugins_MinRating(t *testing.T) {
	out := filterPlugins(sample(), 0, 0, 80)
	if len(out) != 1 || out[0].Slug != "a" {
		t.Fatalf("expected only a (rating>=80), got %+v", out)
	}
}

func TestFilterPlugins_MinInstallsUnbounded(t *testing.T) {
	out := filterPlugins(sample(), 50_000, 0, 0)
	if len(out) != 2 {
		t.Fatalf("expected b and c, got %+v", out)
	}
}

func TestSortPlugins(t *testing.T) {
	p := sample()
	sortPlugins(p, "installs")
	if p[0].Slug != "b" || p[2].Slug != "a" {
		t.Errorf("installs sort wrong: %s,%s,%s", p[0].Slug, p[1].Slug, p[2].Slug)
	}
	p = sample()
	sortPlugins(p, "rating")
	if p[0].Slug != "a" {
		t.Errorf("rating sort wrong, top=%s", p[0].Slug)
	}
	p = sample()
	sortPlugins(p, "updated")
	if p[0].Slug != "b" {
		t.Errorf("updated sort wrong, top=%s", p[0].Slug)
	}
	p = sample()
	sortPlugins(p, "name")
	if p[0].Slug != "b" { // "alpha" < "Mid" < "Zeta" case-insensitively
		t.Errorf("name sort wrong, top=%s", p[0].Name)
	}
}

func TestBrowseForSort(t *testing.T) {
	cases := map[string]string{"": "popular", "installs": "popular", "rating": "popular", "updated": "updated", "new": "new"}
	for in, want := range cases {
		if got := browseForSort(in); got != want {
			t.Errorf("browseForSort(%q)=%q want %q", in, got, want)
		}
	}
}
