package taintscan

import (
	"os"
	"testing"
)

func requireRealPluginFixtureTest(t *testing.T) {
	t.Helper()
	if os.Getenv("PHARSER_ENABLE_REAL_PLUGIN_TESTS") == "1" {
		return
	}
	t.Skip("set PHARSER_ENABLE_REAL_PLUGIN_TESTS=1 to run real-plugin taintscan regressions")
}
