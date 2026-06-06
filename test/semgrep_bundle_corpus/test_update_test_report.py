#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from update_test_report import build_report, derive_real_sink_status, summarize_rule_counts


class UpdateTestReportTests(unittest.TestCase):
    def test_derive_real_sink_status_requires_explicit_sink_contract(self) -> None:
        case = {
            "coverage": {
                "finding_rule_ids_any": ["render-callback-execution"],
            }
        }
        row = {
            "status": "passed",
        }

        status, reason, trace_fact = derive_real_sink_status(case, row, [])

        self.assertEqual(status, "not_found")
        self.assertIn("coverage contract", reason)
        self.assertIsNone(trace_fact)

    def test_derive_real_sink_status_marks_nearby_only_without_trace_contract(self) -> None:
        case = {
            "coverage": {
                "finding_rule_ids_any": ["render-callback-execution"],
                "finding_paths_any": ["includes/modules/form/module-form-front-render.php"],
            }
        }
        row = {
            "status": "passed",
        }
        results = [
            {
                "check_id": "render-callback-execution",
                "path": "includes/modules/form/module-form-front-render.php",
                "start": {"line": 151},
            }
        ]

        status, reason, trace_fact = derive_real_sink_status(case, row, results)

        self.assertEqual(status, "nearby_only")
        self.assertIn("does not yet require", reason)
        self.assertIsNone(trace_fact)

    def test_derive_real_sink_status_marks_found_when_trace_contract_matches(self) -> None:
        case = {
            "coverage": {
                "finding_rule_ids_any": ["path-transversal"],
                "trace_source_strings_any": ["$_GET['template']"],
                "trace_sink_locations_any": ["geo-query.php:128"],
                "trace_sink_strings_any": ["GeoMashup::locate_template("],
            }
        }
        row = {"status": "passed"}
        results = [
            {
                "check_id": "path-transversal",
                "path": "geo-query.php",
                "start": {"line": 128},
                "extra": {
                    "dataflow_trace": {
                        "taint_source": [
                            "CliLoc",
                            [
                                {"path": "geo-query.php", "start": {"line": 84}},
                                "$_GET['template']",
                            ],
                        ],
                        "taint_sink": [
                            "CliLoc",
                            [
                                {"path": "geo-query.php", "start": {"line": 128}},
                                "GeoMashup::locate_template( $template_base )",
                            ],
                        ],
                    }
                },
            }
        ]

        status, reason, trace_fact = derive_real_sink_status(case, row, results)

        self.assertEqual(status, "found")
        self.assertIn("matching request-source to sink trace", reason)
        self.assertIsNotNone(trace_fact)

    def test_derive_real_sink_status_marks_not_found_when_trace_contract_does_not_match(self) -> None:
        case = {
            "coverage": {
                "finding_rule_ids_any": ["path-transversal"],
                "trace_source_strings_any": ["$_GET['template']"],
                "trace_sink_locations_any": ["geo-query.php:128"],
            }
        }
        row = {"status": "passed"}
        results = [
            {
                "check_id": "path-transversal",
                "path": "other.php",
                "start": {"line": 55},
                "extra": {
                    "dataflow_trace": {
                        "taint_source": [
                            "CliLoc",
                            [
                                {"path": "other.php", "start": {"line": 10}},
                                "$_GET['template']",
                            ],
                        ],
                        "taint_sink": [
                            "CliLoc",
                            [
                                {"path": "other.php", "start": {"line": 55}},
                                "include $template",
                            ],
                        ],
                    }
                },
            }
        ]

        status, reason, trace_fact = derive_real_sink_status(case, row, results)

        self.assertEqual(status, "not_found")
        self.assertIn("no Semgrep dataflow trace matched", reason)
        self.assertIsNone(trace_fact)

    def test_summarize_rule_counts_formats_lowered_and_target_split(self) -> None:
        summary = summarize_rule_counts(
            {
                "render-callback-execution": {"total": 2, "lowered": 2, "target": 0},
                "unsafe-use": {"total": 1, "lowered": 0, "target": 1},
            }
        )

        self.assertIn("render-callback-execution: 2 [L2/T0]", summary)
        self.assertIn("unsafe-use: 1 [L0/T1]", summary)

    def test_build_report_includes_real_sink_and_rule_ping_columns(self) -> None:
        manifest = {
            "cases": [
                {
                    "case_id": "acf-extended-cve-2025-13486",
                    "rank": 5,
                    "plugin_name": "Advanced Custom Fields: Extended",
                    "install_version": "0.9.1.1",
                    "cve_id": "CVE-2025-13486",
                    "coverage": {
                        "finding_rule_ids_any": ["render-callback-execution"],
                        "finding_paths_any": ["includes/modules/form/module-form-front-render.php"],
                        "trace_source_strings_any": ["$_POST['render']"],
                        "trace_sink_strings_any": ["$_semgrep_flow_bridge_loaded"],
                    },
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest_path = root / "corpus.json"
            summary_path = root / "summary.json"
            case_output_dir = root / "acf-extended-cve-2025-13486"
            case_output_dir.mkdir()
            (case_output_dir / "semgrep-results.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "render-callback-execution",
                                "path": "lowered-bundle.php",
                                "start": {"line": 151},
                                "extra": {
                                    "dataflow_trace": {
                                        "taint_source": [
                                            "CliLoc",
                                            [
                                                {"path": "lowered-bundle.php", "start": {"line": 140}},
                                                "$_POST['render']",
                                            ],
                                        ],
                                        "taint_sink": [
                                            "CliLoc",
                                            [
                                                {"path": "lowered-bundle.php", "start": {"line": 151}},
                                                "$_semgrep_flow_bridge_loaded",
                                            ],
                                        ],
                                    }
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            summary_path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "case_id": "acf-extended-cve-2025-13486",
                                "status": "passed",
                                "output_dir": str(case_output_dir),
                                "config_paths": ["bugbounty-note/semgrep/unsafe-use.yaml"],
                                "coverage": {"status": "passed", "checks": []},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = build_report(manifest_path, summary_path)

        self.assertIn("Real sink found", report)
        self.assertIn("render-callback-execution: 1 [L1/T0]", report)
        self.assertIn("| 5 | CVE-2025-13486 |", report)
        self.assertIn("Trace proof: render-callback-execution:", report)


if __name__ == "__main__":
    unittest.main()
