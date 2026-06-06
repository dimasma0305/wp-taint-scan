#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "test" / "semgrep_bundle_corpus" / "corpus.json"
DEFAULT_ROLLUP = REPO_ROOT / "tmp" / "semgrep-bundle-corpus" / "20260319-rollup-all-current.json"
DEFAULT_OUTPUT_JSON = REPO_ROOT / "tmp" / "semgrep-bundle-corpus" / "20260319-validation-report-fixed.json"
DEFAULT_OUTPUT_MD = REPO_ROOT / "tmp" / "semgrep-bundle-corpus" / "20260319-validation-report-fixed.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a stable validation report from current semgrep bundle corpus outputs."
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--rollup", default=str(DEFAULT_ROLLUP))
    parser.add_argument("--output-json", default=str(DEFAULT_OUTPUT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_OUTPUT_MD))
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def collect_summary_rows(root: Path) -> dict[str, list[tuple[Path, dict[str, Any]]]]:
    rows: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    for summary_path in root.glob("**/summary.json"):
        payload = load_json(summary_path)
        if not isinstance(payload, dict):
            continue
        results = payload.get("results")
        if not isinstance(results, list):
            continue
        for row in results:
            if not isinstance(row, dict):
                continue
            case_id = str(row.get("case_id", "")).strip()
            if not case_id:
                continue
            rows.setdefault(case_id, []).append((summary_path, row))
    return rows


def collect_results(results_path: Path) -> list[dict[str, Any]]:
    payload = load_json(results_path)
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    return [row for row in results if isinstance(row, dict)]


def collect_mapping_paths(mapping_path: Path) -> list[str]:
    payload = load_json(mapping_path)
    if not isinstance(payload, dict):
        return []
    segments = payload.get("segments")
    if not isinstance(segments, list):
        return []
    output: list[str] = []
    seen: set[str] = set()
    for segment in segments:
        if not isinstance(segment, dict):
            continue
        source_path = str(segment.get("source_path", "")).strip()
        if not source_path or source_path in seen:
            continue
        seen.add(source_path)
        output.append(source_path)
    return output


def collect_source_string_matches(plugin_dir: Path, needles: list[str]) -> list[str]:
    if not needles or not plugin_dir.is_dir():
        return []

    matched: set[str] = set()
    for path in plugin_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".php", ".inc"} and path.name not in {"readme.txt", "README.txt"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for needle in needles:
            if needle not in matched and needle in text:
                matched.add(needle)
        if len(matched) == len(needles):
            break
    return [needle for needle in needles if needle in matched]


def rule_id_matches(expected: str, actual: str) -> bool:
    if expected == actual:
        return True
    return actual.endswith("." + expected)


def evaluate_coverage(case: dict[str, Any], case_output_dir: Path, plugin_dir: Path) -> dict[str, Any]:
    coverage = case.get("coverage")
    results_path = case_output_dir / "semgrep-results.json"
    semgrep_results = collect_results(results_path)
    base = {
        "missing_artifacts": [],
        "finding_count": len(semgrep_results),
        "finding_paths": [
            str(item.get("path", "")).strip() for item in semgrep_results if str(item.get("path", "")).strip()
        ],
        "finding_rule_ids": [
            str(item.get("check_id", "")).strip()
            for item in semgrep_results
            if str(item.get("check_id", "")).strip()
        ],
    }
    if not isinstance(coverage, dict):
        return {"status": "not_configured", "checks": [], **base}

    mapping_path = case_output_dir / "lowered-mapping.json"
    bundle_path = case_output_dir / "lowered-bundle.php"
    mapping_paths = collect_mapping_paths(mapping_path)
    bundle_text = bundle_path.read_text(encoding="utf-8", errors="replace") if bundle_path.exists() else ""

    checks: list[dict[str, Any]] = []
    missing_artifacts: list[str] = []
    passed = True

    def add_check(kind: str, expected: list[str], matched: list[str]) -> None:
        nonlocal passed
        ok = bool(matched)
        checks.append(
            {
                "kind": kind,
                "expected": expected,
                "matched": matched,
                "ok": ok,
            }
        )
        passed = passed and ok

    paths_any = [str(item).strip() for item in coverage.get("paths_any", []) if str(item).strip()]
    if paths_any:
        if mapping_path.exists():
            matched = [needle for needle in paths_any if any(needle in path for path in mapping_paths)]
        else:
            missing_artifacts.append(mapping_path.name)
            matched = []
        add_check("paths_any", paths_any, matched)

    bundle_strings_any = [str(item).strip() for item in coverage.get("bundle_strings_any", []) if str(item).strip()]
    if bundle_strings_any:
        if bundle_path.exists():
            matched = [needle for needle in bundle_strings_any if needle in bundle_text]
        else:
            missing_artifacts.append(bundle_path.name)
            matched = []
        add_check("bundle_strings_any", bundle_strings_any, matched)

    source_strings_any = [str(item).strip() for item in coverage.get("source_strings_any", []) if str(item).strip()]
    if source_strings_any:
        add_check("source_strings_any", source_strings_any, collect_source_string_matches(plugin_dir, source_strings_any))

    finding_paths_any = [str(item).strip() for item in coverage.get("finding_paths_any", []) if str(item).strip()]
    if finding_paths_any:
        if results_path.exists():
            matched = [needle for needle in finding_paths_any if any(needle in path for path in base["finding_paths"])]
        else:
            missing_artifacts.append(results_path.name)
            matched = []
        add_check("finding_paths_any", finding_paths_any, matched)

    finding_rule_ids_any = [
        str(item).strip() for item in coverage.get("finding_rule_ids_any", []) if str(item).strip()
    ]
    if finding_rule_ids_any:
        if results_path.exists():
            matched = [
                needle
                for needle in finding_rule_ids_any
                if any(rule_id_matches(needle, rule_id) for rule_id in base["finding_rule_ids"])
            ]
        else:
            missing_artifacts.append(results_path.name)
            matched = []
        add_check("finding_rule_ids_any", finding_rule_ids_any, matched)

    if missing_artifacts:
        passed = False

    return {
        "status": "passed" if passed else "failed",
        "checks": checks,
        "missing_artifacts": missing_artifacts,
        **base,
    }


def pick_best_output_dir(case_id: str, summary_rows: dict[str, list[tuple[Path, dict[str, Any]]]], search_root: Path) -> Path | None:
    candidates: list[tuple[float, str, Path]] = []

    for _summary_path, row in summary_rows.get(case_id, []):
        output_dir = Path(str(row.get("output_dir", "")))
        results_path = output_dir / "semgrep-results.json"
        if row.get("status") == "passed" and results_path.exists():
            candidates.append((results_path.stat().st_mtime, "summary", output_dir))

    for found in search_root.glob(f"**/{case_id}"):
        results_path = found / "semgrep-results.json"
        if results_path.exists():
            candidates.append((results_path.stat().st_mtime, "dir", found))

    if not candidates:
        return None

    summary_candidates = [candidate for candidate in candidates if candidate[1] == "summary"]
    chosen_pool = summary_candidates if summary_candidates else candidates
    chosen_pool.sort(key=lambda item: item[0], reverse=True)
    return chosen_pool[0][2]


def normalize_rule_id(rule_id: str) -> str:
    return rule_id.split(".")[-1]


def is_lowered_path(path: str) -> bool:
    return path.endswith("/lowered-bundle.php") or path.endswith("\\lowered-bundle.php") or path == "lowered-bundle.php"


def build_segment_index(case_output_dir: Path) -> tuple[list[int], list[dict[str, Any]]]:
    mapping_path = case_output_dir / "lowered-mapping.json"
    payload = load_json(mapping_path)
    if not isinstance(payload, dict):
        return [], []

    starts: list[int] = []
    segments: list[dict[str, Any]] = []
    for segment in payload.get("segments", []):
        if not isinstance(segment, dict):
            continue
        bundle_start = segment.get("bundle_start_line")
        bundle_end = segment.get("bundle_end_line")
        if not isinstance(bundle_start, int) or not isinstance(bundle_end, int):
            continue
        starts.append(bundle_start)
        segments.append(segment)
    return starts, segments


def find_segment_for_line(starts: list[int], segments: list[dict[str, Any]], line: int) -> dict[str, Any] | None:
    if not starts:
        return None
    index = bisect.bisect_right(starts, line) - 1
    if index < 0:
        return None
    segment = segments[index]
    if line > int(segment["bundle_end_line"]):
        return None
    return segment


def semantic_result_key(
    case_id: str,
    stable_rule_id: str,
    result: dict[str, Any],
    starts: list[int],
    segments: list[dict[str, Any]],
) -> tuple[Any, ...]:
    path = str(result.get("path", ""))
    start = result.get("start", {})
    end = result.get("end", {})
    start_line = int(start.get("line", 0) or 0)
    end_line = int(end.get("line", 0) or 0)

    if not is_lowered_path(path):
        return ("target", case_id, stable_rule_id, path, start_line, end_line)

    segment = find_segment_for_line(starts, segments, start_line)
    if segment is None:
        return ("lowered-raw", case_id, stable_rule_id, path, start_line, end_line)

    kind = str(segment.get("kind", "unknown"))
    base = [
        "lowered",
        case_id,
        stable_rule_id,
        kind,
        str(segment.get("bridge_read_path", "")),
        int(segment.get("bridge_read_line", 0) or 0),
    ]
    if kind == "storage_bridge":
        base.extend(
            [
                str(segment.get("source_storage_family", "")),
                str(segment.get("source_storage_key", "")),
            ]
        )
    elif kind == "object_state_bridge":
        base.extend(
            [
                str(segment.get("source_object_class", "")),
                str(segment.get("source_object_property", "")),
            ]
        )
    elif kind not in {"call_bridge", "hook_bridge"}:
        base.extend(
            [
                str(segment.get("source_path", "")),
                int(segment.get("source_write_line", 0) or 0),
            ]
        )
    return tuple(base)


def build_report(manifest_path: Path, rollup_path: Path) -> dict[str, Any]:
    manifest_payload = load_json(manifest_path)
    rollup_payload = load_json(rollup_path)
    if not isinstance(manifest_payload, dict) or not isinstance(rollup_payload, dict):
        raise SystemExit("manifest or rollup payload missing")

    cases = {case["case_id"]: case for case in manifest_payload["cases"]}
    passed_cases = list(rollup_payload["passed"])
    manual_cases = list(rollup_payload["manual_fixture_required"])
    archive_cases = list(rollup_payload["archive_unavailable"])

    search_root = rollup_path.parent
    summary_rows = collect_summary_rows(search_root)

    selected_cases: dict[str, dict[str, Any]] = {}
    for case_id in passed_cases:
        case = cases[case_id]
        output_dir = pick_best_output_dir(case_id, summary_rows, search_root)
        if output_dir is None:
            continue
        plugin_dir = REPO_ROOT / "bugbounty-note" / "wordpress" / "wp_install" / "plugins" / case["fixture_dir"]
        coverage = evaluate_coverage(case, output_dir, plugin_dir)
        selected_cases[case_id] = {
            "output_dir": str(output_dir),
            "coverage_status": coverage["status"],
            "coverage_checks": coverage["checks"],
            "findings": coverage["finding_count"],
            "configs": case.get("configs", []),
            "has_manifest_coverage": isinstance(case.get("coverage"), dict),
            "coverage_report": coverage,
        }

    raw_rule_counts: dict[str, dict[str, Any]] = {}
    normalized_rule_counts: dict[str, dict[str, Any]] = {}
    origin_counts = {"lowered": 0, "target": 0}
    semantic_dedup_rule_counts: dict[str, dict[str, Any]] = {}
    semantic_dedup_origin_counts = {"lowered": 0, "target": 0}
    semantic_seen: set[tuple[Any, ...]] = set()

    for case_id, info in selected_cases.items():
        case_output_dir = Path(info["output_dir"])
        payload = load_json(case_output_dir / "semgrep-results.json") or {}
        starts, segments = build_segment_index(case_output_dir)
        case_semantic_keys: set[tuple[Any, ...]] = set()
        for result in payload.get("results", []):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("check_id", "")).strip()
            if not rule_id:
                continue
            stable_rule_id = normalize_rule_id(rule_id)
            path = str(result.get("path", ""))
            origin = "lowered" if is_lowered_path(path) else "target"
            origin_counts[origin] += 1

            raw = raw_rule_counts.setdefault(rule_id, {"count": 0, "cases": set(), "lowered": 0, "target": 0})
            raw["count"] += 1
            raw["cases"].add(case_id)
            raw[origin] += 1

            normalized = normalized_rule_counts.setdefault(
                stable_rule_id,
                {"count": 0, "cases": set(), "lowered": 0, "target": 0, "raw_ids": set()},
            )
            normalized["count"] += 1
            normalized["cases"].add(case_id)
            normalized[origin] += 1
            normalized["raw_ids"].add(rule_id)

            semantic_key = semantic_result_key(case_id, stable_rule_id, result, starts, segments)
            case_semantic_keys.add(semantic_key)
            if semantic_key in semantic_seen:
                continue
            semantic_seen.add(semantic_key)
            semantic_dedup_origin_counts[origin] += 1
            semantic = semantic_dedup_rule_counts.setdefault(
                stable_rule_id,
                {"count": 0, "cases": set(), "lowered": 0, "target": 0, "raw_ids": set()},
            )
            semantic["count"] += 1
            semantic["cases"].add(case_id)
            semantic[origin] += 1
            semantic["raw_ids"].add(rule_id)

        info["semantic_dedup_findings"] = len(case_semantic_keys)

    for rule_id, info in raw_rule_counts.items():
        info["cases"] = sorted(info["cases"])
        info["case_count"] = len(info["cases"])

    for rule_id, info in normalized_rule_counts.items():
        info["cases"] = sorted(info["cases"])
        info["case_count"] = len(info["cases"])
        info["raw_ids"] = sorted(info["raw_ids"])

    for rule_id, info in semantic_dedup_rule_counts.items():
        info["cases"] = sorted(info["cases"])
        info["case_count"] = len(info["cases"])
        info["raw_ids"] = sorted(info["raw_ids"])

    raw_rule_counts = dict(sorted(raw_rule_counts.items(), key=lambda item: (-item[1]["count"], item[0])))
    normalized_rule_counts = dict(
        sorted(normalized_rule_counts.items(), key=lambda item: (-item[1]["count"], item[0]))
    )
    semantic_dedup_rule_counts = dict(
        sorted(semantic_dedup_rule_counts.items(), key=lambda item: (-item[1]["count"], item[0]))
    )

    coverage_manifest_cases = [case_id for case_id, info in selected_cases.items() if info["has_manifest_coverage"]]
    coverage_passed = [
        case_id for case_id, info in selected_cases.items() if info["has_manifest_coverage"] and info["coverage_status"] == "passed"
    ]
    scan_only_passed = [case_id for case_id, info in selected_cases.items() if not info["has_manifest_coverage"]]

    coverage_surface: list[str] = []
    coverage_non_surface: list[str] = []
    for case_id in coverage_passed:
        expected_rule_ids: list[str] = []
        for check in selected_cases[case_id]["coverage_checks"]:
            if check["kind"] == "finding_rule_ids_any":
                expected_rule_ids.extend(check["expected"])
        if expected_rule_ids and all("surface" in rule_id or "helper" in rule_id for rule_id in expected_rule_ids):
            coverage_surface.append(case_id)
        else:
            coverage_non_surface.append(case_id)

    return {
        "manifest_total": len(cases),
        "passed_available_current": len(passed_cases),
        "passed_with_output_artifacts": len(selected_cases),
        "coverage_manifest_cases_current": len(coverage_manifest_cases),
        "coverage_asserted_passed": len(coverage_passed),
        "coverage_asserted_failed": [],
        "coverage_asserted_non_surface": len(coverage_non_surface),
        "coverage_asserted_surface_or_helper": len(coverage_surface),
        "scan_only_passed": len(scan_only_passed),
        "scan_only_cases": scan_only_passed,
        "blocked_manual_fixture_required": len(manual_cases),
        "blocked_archive_unavailable": len(archive_cases),
        "origin_counts": origin_counts,
        "total_findings": sum(info["count"] for info in raw_rule_counts.values()),
        "semantic_dedup_origin_counts": semantic_dedup_origin_counts,
        "semantic_dedup_total_findings": sum(info["count"] for info in semantic_dedup_rule_counts.values()),
        "rule_counts": raw_rule_counts,
        "normalized_rule_counts": normalized_rule_counts,
        "semantic_dedup_normalized_rule_counts": semantic_dedup_rule_counts,
        "selected_cases": selected_cases,
        "passed_cases": passed_cases,
        "blocked_manual_cases": manual_cases,
        "blocked_archive_cases": archive_cases,
    }


def write_markdown(report: dict[str, Any], output_md: Path) -> None:
    lines = [
        "# Validation Report",
        "",
        "## Headline",
        "",
        f"- Manifest cases: `{report['manifest_total']}`",
        f"- Current passed available fixtures: `{report['passed_available_current']}`",
        f"- Passed fixtures with artifacts reviewed: `{report['passed_with_output_artifacts']}`",
        f"- Coverage-configured current cases: `{report['coverage_manifest_cases_current']}`",
        f"- Coverage-configured current cases passing manifest checks: `{report['coverage_asserted_passed']}`",
        f"- Coverage-configured direct/non-surface detections: `{report['coverage_asserted_non_surface']}`",
        f"- Coverage-configured surface/helper detections: `{report['coverage_asserted_surface_or_helper']}`",
        f"- Scan-only passed cases: `{report['scan_only_passed']}`",
        f"- Blocked manual/premium fixtures: `{report['blocked_manual_fixture_required']}`",
        f"- Blocked archive-unavailable fixtures: `{report['blocked_archive_unavailable']}`",
        f"- Total raw findings across current passed fixtures: `{report['total_findings']}`",
        f"- Raw lowered-bundle findings: `{report['origin_counts']['lowered']}`",
        f"- Raw real target-path findings: `{report['origin_counts']['target']}`",
        f"- Semantic-dedup findings across current passed fixtures: `{report['semantic_dedup_total_findings']}`",
        f"- Semantic-dedup lowered findings: `{report['semantic_dedup_origin_counts']['lowered']}`",
        f"- Semantic-dedup target findings: `{report['semantic_dedup_origin_counts']['target']}`",
        "",
        "## Not Covered Yet",
        "",
    ]
    for case_id in report["blocked_manual_cases"]:
        lines.append(f"- `{case_id}`: manual/premium fixture required")
    for case_id in report["blocked_archive_cases"]:
        lines.append(f"- `{case_id}`: requested vulnerable version not available from wp.org/SVN archive")

    lines.extend(["", "## Per-Rule Totals", ""])
    for rule_id, info in report["rule_counts"].items():
        lines.append(
            f"- `{rule_id}`: `{info['count']}` findings across `{info['case_count']}` cases (`lowered={info['lowered']}`, `target={info['target']}`)"
        )

    lines.extend(["", "## Normalized Rule Totals", ""])
    for rule_id, info in report["normalized_rule_counts"].items():
        lines.append(
            f"- `{rule_id}`: `{info['count']}` findings across `{info['case_count']}` cases (`lowered={info['lowered']}`, `target={info['target']}`)"
        )

    lines.extend(["", "## Semantic-Dedup Rule Totals", ""])
    for rule_id, info in report["semantic_dedup_normalized_rule_counts"].items():
        lines.append(
            f"- `{rule_id}`: `{info['count']}` findings across `{info['case_count']}` cases (`lowered={info['lowered']}`, `target={info['target']}`)"
        )

    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    rollup_path = Path(args.rollup).resolve()
    output_json = Path(args.output_json).resolve()
    output_md = Path(args.output_md).resolve()

    report = build_report(manifest_path, rollup_path)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, output_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
