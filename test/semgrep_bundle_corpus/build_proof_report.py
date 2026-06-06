#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from build_validation_report import (
    DEFAULT_MANIFEST,
    DEFAULT_OUTPUT_JSON,
    REPO_ROOT,
    build_segment_index,
    collect_results,
    find_segment_for_line,
    is_lowered_path,
    load_json,
    normalize_rule_id,
    rule_id_matches,
)


DEFAULT_OUTPUT_MD = REPO_ROOT / "tmp" / "semgrep-bundle-corpus" / "20260319-proof-report.md"
DEFAULT_OUTPUT_JSON = REPO_ROOT / "tmp" / "semgrep-bundle-corpus" / "20260319-proof-report.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a per-plugin proof report showing how Semgrep reached each vulnerable fixture."
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument(
        "--validation-report",
        default=str(REPO_ROOT / "tmp" / "semgrep-bundle-corpus" / "20260319-validation-report-fixed.json"),
    )
    parser.add_argument("--output-json", default=str(DEFAULT_OUTPUT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_OUTPUT_MD))
    return parser.parse_args()


def read_source_line(plugin_dir: Path, path_value: str, line_number: int) -> str | None:
    if not path_value or line_number <= 0:
        return None
    path = Path(path_value)
    if not path.is_absolute():
        path = plugin_dir / path
    if not path.exists() or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return None


def contains_any(haystack: str | None, needles: list[str]) -> bool:
    if not haystack:
        return False
    return any(needle and needle in haystack for needle in needles)


def result_entry(
    result: dict[str, Any],
    plugin_dir: Path,
    segment_starts: list[int],
    segment_index: list[dict[str, Any]],
) -> dict[str, Any]:
    path = str(result.get("path", "")).strip()
    start = result.get("start", {})
    start_line = int(start.get("line", 0) or 0)
    entry = {
        "rule_id": str(result.get("check_id", "")).strip(),
        "stable_rule_id": normalize_rule_id(str(result.get("check_id", "")).strip()),
        "path": path,
        "start_line": start_line,
        "origin": "lowered" if is_lowered_path(path) else "target",
        "source_line": read_source_line(plugin_dir, path, start_line),
    }
    if entry["origin"] == "lowered":
        segment = find_segment_for_line(segment_starts, segment_index, start_line)
        if segment is not None:
            entry["mapped_segment"] = {
                "kind": segment.get("kind"),
                "source_path": segment.get("source_path"),
                "source_write_line": segment.get("source_write_line"),
                "bridge_read_path": segment.get("bridge_read_path"),
                "bridge_read_line": segment.get("bridge_read_line"),
                "source_storage_family": segment.get("source_storage_family"),
                "source_storage_key": segment.get("source_storage_key"),
                "source_object_class": segment.get("source_object_class"),
                "source_object_property": segment.get("source_object_property"),
                "source_write_snippet": read_source_line(
                    plugin_dir,
                    str(segment.get("source_path", "")),
                    int(segment.get("source_write_line", 0) or 0),
                ),
                "bridge_read_snippet": read_source_line(
                    plugin_dir,
                    str(segment.get("bridge_read_path", "")),
                    int(segment.get("bridge_read_line", 0) or 0),
                ),
            }
    return entry


def proof_score(
    entry: dict[str, Any],
    expected_paths: list[str],
    expected_rule_ids: list[str],
    source_strings: list[str],
    advisory_paths: list[str],
) -> int:
    score = 0

    if any(rule_id_matches(expected, entry["rule_id"]) for expected in expected_rule_ids):
        score += 100

    if any(expected in entry["path"] for expected in expected_paths):
        score += 80

    if contains_any(entry.get("source_line"), source_strings):
        score += 70

    mapped = entry.get("mapped_segment")
    if isinstance(mapped, dict):
        mapped_paths = [
            str(mapped.get("source_path", "")),
            str(mapped.get("bridge_read_path", "")),
        ]
        mapped_snippets = [
            mapped.get("source_write_snippet"),
            mapped.get("bridge_read_snippet"),
        ]
        if any(any(path and path in mapped_path for path in advisory_paths) for mapped_path in mapped_paths):
            score += 90
        if any(any(path and path in mapped_path for path in expected_paths) for mapped_path in mapped_paths):
            score += 60
        if any(contains_any(snippet, source_strings) for snippet in mapped_snippets):
            score += 80

    return score


def covered_advisory_paths(entry: dict[str, Any], advisory_paths: list[str]) -> set[str]:
    covered: set[str] = set()
    if not advisory_paths:
        return covered
    candidate_paths = [entry["path"]]
    mapped = entry.get("mapped_segment")
    if isinstance(mapped, dict):
        candidate_paths.extend(
            [
                str(mapped.get("source_path", "")),
                str(mapped.get("bridge_read_path", "")),
            ]
        )
    for advisory_path in advisory_paths:
        if any(advisory_path and advisory_path in candidate_path for candidate_path in candidate_paths):
            covered.add(advisory_path)
    return covered


def choose_asserted_matches(
    results: list[dict[str, Any]],
    coverage: dict[str, Any],
    plugin_dir: Path,
    segment_starts: list[int],
    segment_index: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    expected_paths = [str(item) for item in coverage.get("finding_paths_any", [])]
    expected_rule_ids = [str(item) for item in coverage.get("finding_rule_ids_any", [])]
    source_strings = [str(item) for item in coverage.get("source_strings_any", [])]
    advisory_paths = [str(item) for item in coverage.get("advisory_paths_any", [])]
    ranked: list[tuple[int, dict[str, Any]]] = []

    for result in results:
        entry = result_entry(result, plugin_dir, segment_starts, segment_index)
        score = proof_score(entry, expected_paths, expected_rule_ids, source_strings, advisory_paths)
        if score > 0:
            ranked.append((score, entry))

    ranked.sort(
        key=lambda item: (
            -item[0],
            item[1]["origin"] != "target",
            item[1]["path"],
            item[1]["start_line"],
        )
    )

    selected: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    remaining = list(ranked)
    uncovered = set(advisory_paths)
    if advisory_paths:
        while remaining and uncovered and len(selected) < 3:
            best_index = None
            best_key = None
            for index, (score, entry) in enumerate(remaining):
                covered_now = covered_advisory_paths(entry, advisory_paths)
                newly_covered = covered_now & uncovered
                if not newly_covered:
                    continue
                ordering = (
                    len(newly_covered),
                    len(covered_now),
                    score,
                    entry["origin"] == "target",
                )
                if best_key is None or ordering > best_key:
                    best_key = ordering
                    best_index = index
            if best_index is None:
                break
            score, entry = remaining.pop(best_index)
            mapped = entry.get("mapped_segment")
            dedup_key = (
                entry["stable_rule_id"],
                entry["path"],
                entry["start_line"],
                mapped.get("source_path") if isinstance(mapped, dict) else None,
                mapped.get("bridge_read_path") if isinstance(mapped, dict) else None,
                mapped.get("bridge_read_line") if isinstance(mapped, dict) else None,
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            entry["proof_score"] = score
            selected.append(entry)
            uncovered -= covered_advisory_paths(entry, advisory_paths)

    for score, entry in remaining:
        mapped = entry.get("mapped_segment")
        dedup_key = (
            entry["stable_rule_id"],
            entry["path"],
            entry["start_line"],
            mapped.get("source_path") if isinstance(mapped, dict) else None,
            mapped.get("bridge_read_path") if isinstance(mapped, dict) else None,
            mapped.get("bridge_read_line") if isinstance(mapped, dict) else None,
        )
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        entry["proof_score"] = score
        selected.append(entry)
        if len(selected) >= 3:
            break

    return selected


def choose_scan_only_matches(
    results: list[dict[str, Any]],
    plugin_dir: Path,
    segment_starts: list[int],
    segment_index: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for result in results[:5]:
        ranked.append(result_entry(result, plugin_dir, segment_starts, segment_index))
    return ranked


def build_report(manifest_path: Path, validation_report_path: Path) -> dict[str, Any]:
    manifest_payload = load_json(manifest_path)
    validation_payload = load_json(validation_report_path)
    if not isinstance(manifest_payload, dict) or not isinstance(validation_payload, dict):
        raise SystemExit("missing manifest or validation report")

    cases = {case["case_id"]: case for case in manifest_payload["cases"]}
    selected_cases = validation_payload["selected_cases"]

    asserted: list[dict[str, Any]] = []
    scan_only: list[dict[str, Any]] = []
    for case_id in validation_payload["passed_cases"]:
        case = cases[case_id]
        selected = selected_cases[case_id]
        output_dir = Path(selected["output_dir"])
        plugin_dir = REPO_ROOT / "bugbounty-note" / "wordpress" / "wp_install" / "plugins" / case["fixture_dir"]
        results = collect_results(output_dir / "semgrep-results.json")
        segment_starts, segment_index = build_segment_index(output_dir)

        base = {
            "case_id": case_id,
            "plugin_name": case["plugin_name"],
            "fixture_dir": case["fixture_dir"],
            "cve_id": case["cve_id"],
            "description": case["description"],
            "output_dir": str(output_dir),
            "human_summary": str(output_dir / "human-summary.md"),
            "semgrep_results": str(output_dir / "semgrep-results.json"),
            "coverage_status": selected["coverage_status"],
            "semantic_dedup_findings": selected.get("semantic_dedup_findings"),
        }

        if selected["has_manifest_coverage"]:
            coverage = case.get("coverage", {})
            matched_source_strings = []
            for check in selected["coverage_checks"]:
                if check["kind"] == "source_strings_any":
                    matched_source_strings = check["matched"]
                    break
            entry = {
                **base,
                "proof_level": "coverage-asserted",
                "expected_paths": [str(item) for item in coverage.get("finding_paths_any", [])],
                "expected_rule_ids": [str(item) for item in coverage.get("finding_rule_ids_any", [])],
                "advisory_paths": [str(item) for item in coverage.get("advisory_paths_any", [])],
                "matched_source_strings": matched_source_strings,
                "proof_matches": choose_asserted_matches(
                    results,
                    coverage,
                    plugin_dir,
                    segment_starts,
                    segment_index,
                ),
            }
            asserted.append(entry)
        else:
            entry = {
                **base,
                "proof_level": "scan-only",
                "proof_matches": choose_scan_only_matches(results, plugin_dir, segment_starts, segment_index),
            }
            scan_only.append(entry)

    return {
        "asserted_cases": asserted,
        "scan_only_cases": scan_only,
        "blocked_manual_cases": validation_payload["blocked_manual_cases"],
        "blocked_archive_cases": validation_payload["blocked_archive_cases"],
    }


def write_markdown(report: dict[str, Any], output_path: Path) -> None:
    lines: list[str] = [
        "# Semgrep Proof Report",
        "",
        "## Coverage-Asserted Cases",
        "",
    ]

    for item in report["asserted_cases"]:
        lines.append(f"### {item['case_id']}")
        lines.append(f"- Plugin: `{item['plugin_name']}`")
        lines.append(f"- Fixture: `{item['fixture_dir']}`")
        lines.append(f"- CVE: `{item['cve_id']}`")
        lines.append(f"- Expected rules: `{', '.join(item['expected_rule_ids'])}`")
        lines.append(f"- Expected paths: `{', '.join(item['expected_paths'])}`")
        if item["advisory_paths"]:
            lines.append(f"- Advisory paths: `{', '.join(item['advisory_paths'])}`")
        lines.append(f"- Matched source strings: `{', '.join(item['matched_source_strings'])}`")
        lines.append(f"- Human summary: `{item['human_summary']}`")
        lines.append(f"- Semgrep results: `{item['semgrep_results']}`")
        lines.append(f"- Semantic-dedup findings in this case: `{item['semantic_dedup_findings']}`")
        for match in item["proof_matches"]:
            lines.append(
                f"- Match: rule `{match['stable_rule_id']}` at `{match['path']}:{match['start_line']}` (score `{match.get('proof_score', 0)}`)"
            )
            if match.get("source_line"):
                lines.append(f"  source: `{match['source_line']}`")
            mapped = match.get("mapped_segment")
            if isinstance(mapped, dict):
                lines.append(
                    f"  mapped: kind `{mapped.get('kind')}`, source `{mapped.get('source_path')}:{mapped.get('source_write_line')}`, bridge `{mapped.get('bridge_read_path')}:{mapped.get('bridge_read_line')}`"
                )
                if mapped.get("source_storage_key"):
                    lines.append(f"  storage-key: `{mapped.get('source_storage_key')}`")
                if mapped.get("source_object_property"):
                    lines.append(f"  object-property: `{mapped.get('source_object_property')}`")
                if mapped.get("source_write_snippet"):
                    lines.append(f"  source-snippet: `{mapped.get('source_write_snippet')}`")
                if mapped.get("bridge_read_snippet"):
                    lines.append(f"  bridge-snippet: `{mapped.get('bridge_read_snippet')}`")
        lines.append("")

    lines.extend(["## Scan-Only Cases", ""])
    for item in report["scan_only_cases"]:
        lines.append(f"### {item['case_id']}")
        lines.append(f"- Plugin: `{item['plugin_name']}`")
        lines.append(f"- Fixture: `{item['fixture_dir']}`")
        lines.append(f"- CVE: `{item['cve_id']}`")
        lines.append("- Proof level: `scan-only`")
        lines.append(f"- Human summary: `{item['human_summary']}`")
        lines.append(f"- Semgrep results: `{item['semgrep_results']}`")
        for match in item["proof_matches"]:
            lines.append(
                f"- Match: rule `{match['stable_rule_id']}` at `{match['path']}:{match['start_line']}`"
            )
            if match.get("source_line"):
                lines.append(f"  source: `{match['source_line']}`")
            mapped = match.get("mapped_segment")
            if isinstance(mapped, dict):
                lines.append(
                    f"  mapped: kind `{mapped.get('kind')}`, source `{mapped.get('source_path')}:{mapped.get('source_write_line')}`, bridge `{mapped.get('bridge_read_path')}:{mapped.get('bridge_read_line')}`"
                )
        lines.append("")

    lines.extend(["## Not Covered Yet", ""])
    for case_id in report["blocked_manual_cases"]:
        lines.append(f"- `{case_id}`: manual/premium fixture required")
    for case_id in report["blocked_archive_cases"]:
        lines.append(f"- `{case_id}`: archive-unavailable vulnerable version")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    report = build_report(Path(args.manifest).resolve(), Path(args.validation_report).resolve())
    output_json = Path(args.output_json).resolve()
    output_md = Path(args.output_md).resolve()
    output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, output_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
