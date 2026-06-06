#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from run_bundle_corpus import evaluate_coverage
from corpus_lib import CORPUS_ARTIFACTS_DIR, REPO_ROOT


class EvaluateCoverageTests(unittest.TestCase):
    def test_default_artifact_root_is_outside_repo_test_tree(self) -> None:
        self.assertFalse(str(CORPUS_ARTIFACTS_DIR).startswith(str(REPO_ROOT / "test")))
        self.assertFalse(str(CORPUS_ARTIFACTS_DIR).startswith(str(REPO_ROOT / "artifacts")))

    def test_coverage_passes_when_path_and_bundle_string_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            plugin_dir = output_dir / "plugin"
            plugin_dir.mkdir()
            (output_dir / "lowered-mapping.json").write_text(
                json.dumps({"segments": [{"source_path": "includes/vuln.php"}]}),
                encoding="utf-8",
            )
            (output_dir / "lowered-bundle.php").write_text(
                "<?php\nfunction vulnerable_feature() {}\n",
                encoding="utf-8",
            )

            report = evaluate_coverage(
                {
                    "coverage": {
                        "paths_any": ["includes/vuln.php"],
                        "bundle_strings_any": ["function vulnerable_feature("],
                    }
                },
                output_dir,
                plugin_dir,
            )

            self.assertEqual(report["status"], "passed")

    def test_coverage_fails_when_expected_path_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            plugin_dir = output_dir / "plugin"
            plugin_dir.mkdir()
            (output_dir / "lowered-mapping.json").write_text(
                json.dumps({"segments": [{"source_path": "includes/other.php"}]}),
                encoding="utf-8",
            )
            (output_dir / "lowered-bundle.php").write_text(
                "<?php\nfunction vulnerable_feature() {}\n",
                encoding="utf-8",
            )

            report = evaluate_coverage(
                {
                    "coverage": {
                        "paths_any": ["includes/vuln.php"],
                        "bundle_strings_any": ["function vulnerable_feature("],
                    }
                },
                output_dir,
                plugin_dir,
            )

            self.assertEqual(report["status"], "failed")

    def test_coverage_passes_when_source_string_only_exists_in_plugin_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            plugin_dir = output_dir / "plugin"
            plugin_dir.mkdir()
            (output_dir / "lowered-mapping.json").write_text(
                json.dumps({"segments": [{"source_path": "includes/vuln.php"}]}),
                encoding="utf-8",
            )
            (output_dir / "lowered-bundle.php").write_text(
                "<?php\nfunction vulnerable_feature() {}\n",
                encoding="utf-8",
            )
            (plugin_dir / "top-level.php").write_text(
                "<?php\nif ( ! function_exists( 'wp_handle_upload' ) ) {}\n",
                encoding="utf-8",
            )

            report = evaluate_coverage(
                {
                    "coverage": {
                        "paths_any": ["includes/vuln.php"],
                        "bundle_strings_any": ["function vulnerable_feature("],
                        "source_strings_any": ["function_exists( 'wp_handle_upload' )"],
                    }
                },
                output_dir,
                plugin_dir,
            )

            self.assertEqual(report["status"], "passed")

    def test_coverage_passes_when_expected_finding_path_and_rule_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            plugin_dir = output_dir / "plugin"
            plugin_dir.mkdir()
            (output_dir / "semgrep-results.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "bugbounty-note.semgrep.raw-sql-clause-builder-surface",
                                "path": "src/Events/Custom_Tables/V1/Models/Builder.php",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = evaluate_coverage(
                {
                    "coverage": {
                        "finding_paths_any": ["src/Events/Custom_Tables/V1/Models/Builder.php"],
                        "finding_rule_ids_any": ["bugbounty-note.semgrep.raw-sql-clause-builder-surface"],
                    }
                },
                output_dir,
                plugin_dir,
            )

            self.assertEqual(report["status"], "passed")

    def test_coverage_fails_when_expected_finding_rule_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            plugin_dir = output_dir / "plugin"
            plugin_dir.mkdir()
            (output_dir / "semgrep-results.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "bugbounty-note.semgrep.unrelated-rule",
                                "path": "src/Events/Custom_Tables/V1/Models/Builder.php",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = evaluate_coverage(
                {
                    "coverage": {
                        "finding_paths_any": ["src/Events/Custom_Tables/V1/Models/Builder.php"],
                        "finding_rule_ids_any": ["bugbounty-note.semgrep.raw-sql-clause-builder-surface"],
                    }
                },
                output_dir,
                plugin_dir,
            )

            self.assertEqual(report["status"], "failed")


if __name__ == "__main__":
    unittest.main()
