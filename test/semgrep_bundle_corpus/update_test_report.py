#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from corpus_lib import MANIFEST_PATH, REPO_ROOT


DEFAULT_OUTPUT = REPO_ROOT / "test" / "report.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate test/report.md from a semgrep bundle corpus summary.json run."
    )
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--summary", default="")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def find_latest_summary() -> Path:
    tmp_root = REPO_ROOT / "tmp"
    candidates: list[tuple[float, Path]] = []
    for path in tmp_root.glob("**/summary.json"):
        try:
            payload = load_json(path)
        except Exception:
            continue
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            continue
        candidates.append((path.stat().st_mtime, path))
    if not candidates:
        raise FileNotFoundError("no summary.json found under tmp/")
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def normalize_rule_id(rule_id: str) -> str:
    return rule_id.split(".")[-1]


def is_lowered_path(path: str) -> bool:
    return path.endswith("/lowered-bundle.php") or path.endswith("\\lowered-bundle.php") or path == "lowered-bundle.php"


def read_case_results(case_output_dir: Path) -> list[dict[str, Any]]:
    results_path = case_output_dir / "semgrep-results.json"
    if not results_path.exists():
        return []
    payload = load_json(results_path)
    results = payload.get("results", [])
    if not isinstance(results, list):
        return []
    return [row for row in results if isinstance(row, dict)]


def rule_ping_summary(results: list[dict[str, Any]]) -> tuple[dict[str, dict[str, int]], list[str]]:
    counts: dict[str, dict[str, int]] = {}
    evidence_paths: list[str] = []
    seen_paths: set[str] = set()

    for result in results:
        rule_id = normalize_rule_id(str(result.get("check_id", "")).strip())
        if not rule_id:
            continue
        entry = counts.setdefault(rule_id, {"total": 0, "lowered": 0, "target": 0})
        entry["total"] += 1
        path = str(result.get("path", "")).strip()
        if is_lowered_path(path):
            entry["lowered"] += 1
        else:
            entry["target"] += 1

        start = result.get("start", {})
        line = int(start.get("line", 0) or 0)
        if path and len(evidence_paths) < 5:
            location = f"{path}:{line}" if line > 0 else path
            if location not in seen_paths:
                seen_paths.add(location)
                evidence_paths.append(location)

    return counts, evidence_paths


def summarize_rule_counts(rule_counts: dict[str, dict[str, int]]) -> str:
    if not rule_counts:
        return "none"
    parts = []
    for rule_id, counts in sorted(rule_counts.items(), key=lambda item: (-item[1]["total"], item[0])):
        parts.append(
            f"{rule_id}: {counts['total']} [L{counts['lowered']}/T{counts['target']}]"
        )
    return "; ".join(parts)


def summarize_expected_rules(case: dict[str, Any]) -> str:
    coverage = case.get("coverage", {})
    if not isinstance(coverage, dict):
        return "none"
    values = [str(item).strip() for item in coverage.get("finding_rule_ids_any", []) if str(item).strip()]
    return ", ".join(values) if values else "none"


def coverage_values(case: dict[str, Any], key: str) -> list[str]:
    coverage = case.get("coverage", {})
    if not isinstance(coverage, dict):
        return []
    raw = coverage.get(key, [])
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return []


def normalize_text_path(path: str) -> str:
    return path.replace("\\", "/").strip()


def display_path(path: str) -> str:
    normalized = normalize_text_path(path)
    repo_root = normalize_text_path(str(REPO_ROOT))
    prefix = repo_root.rstrip("/") + "/"
    if normalized.startswith(prefix):
        return normalized[len(prefix) :]
    return normalized


def format_location(path: str, line: int) -> str:
    shown_path = display_path(path)
    return f"{shown_path}:{line}" if line > 0 else shown_path


def location_matches(actual: str, expected: str) -> bool:
    actual_norm = normalize_text_path(actual)
    expected_norm = normalize_text_path(expected)
    return (
        actual_norm == expected_norm
        or actual_norm.endswith(expected_norm)
        or expected_norm in actual_norm
    )


def summary_check_matches(row: dict[str, Any] | None, kind: str, expected_values: list[str]) -> bool:
    if row is None:
        return False
    coverage = row.get("coverage", {})
    if not isinstance(coverage, dict):
        return False
    checks = coverage.get("checks", [])
    if not isinstance(checks, list):
        return False
    for check in checks:
        if not isinstance(check, dict):
            continue
        if str(check.get("kind", "")).strip() != kind or not check.get("ok"):
            continue
        matched = check.get("matched", [])
        if not isinstance(matched, list):
            continue
        matched_values = [str(item).strip() for item in matched if str(item).strip()]
        if not expected_values:
            return True
        if kind.endswith("_locations_any"):
            if all(
                any(location_matches(actual, expected) for actual in matched_values)
                for expected in expected_values
            ):
                return True
            continue
        if all(
            any(expected in actual for actual in matched_values)
            for expected in expected_values
        ):
            return True
    return False


def case_has_sink_contract(case: dict[str, Any]) -> bool:
    return any(
        bool(coverage_values(case, key))
        for key in (
            "finding_paths_any",
            "bridge_read_locations_any",
            "paths_any",
            "advisory_paths_any",
            "trace_sink_locations_any",
            "trace_sink_strings_any",
        )
    )


def case_has_trace_contract(case: dict[str, Any]) -> bool:
    return bool(coverage_values(case, "trace_source_strings_any")) and (
        bool(coverage_values(case, "trace_sink_strings_any"))
        or bool(coverage_values(case, "trace_sink_locations_any"))
        or bool(coverage_values(case, "bridge_read_locations_any"))
    )


def extract_trace_endpoint(trace: dict[str, Any], key: str) -> dict[str, Any] | None:
    raw = trace.get(key)
    if not isinstance(raw, list) or len(raw) < 2:
        return None
    payload = raw[1]
    if not isinstance(payload, list) or len(payload) != 2:
        return None
    location, content = payload
    if not isinstance(location, dict):
        return None
    start = location.get("start", {})
    line = int(start.get("line", 0) or 0) if isinstance(start, dict) else 0
    return {
        "path": str(location.get("path", "")).strip(),
        "line": line,
        "content": str(content).strip(),
    }


def extract_trace_fact(result: dict[str, Any]) -> dict[str, Any] | None:
    extra = result.get("extra", {})
    if not isinstance(extra, dict):
        return None
    trace = extra.get("dataflow_trace")
    if not isinstance(trace, dict):
        return None
    source = extract_trace_endpoint(trace, "taint_source")
    sink = extract_trace_endpoint(trace, "taint_sink")
    if source is None or sink is None:
        return None
    start = result.get("start", {})
    finding_line = int(start.get("line", 0) or 0) if isinstance(start, dict) else 0
    return {
        "rule_id": normalize_rule_id(str(result.get("check_id", "")).strip()),
        "finding_path": str(result.get("path", "")).strip(),
        "finding_line": finding_line,
        "source_path": str(source["path"]),
        "source_line": int(source["line"]),
        "source_content": str(source["content"]),
        "sink_path": str(sink["path"]),
        "sink_line": int(sink["line"]),
        "sink_content": str(sink["content"]),
    }


def collect_trace_facts(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    trace_facts: list[dict[str, Any]] = []
    for result in results:
        trace_fact = extract_trace_fact(result)
        if trace_fact is not None:
            trace_facts.append(trace_fact)
    return trace_facts


def trace_fact_matches_case(
    case: dict[str, Any],
    row: dict[str, Any] | None,
    trace_fact: dict[str, Any],
) -> bool:
    expected_rules = {normalize_rule_id(rule_id) for rule_id in coverage_values(case, "finding_rule_ids_any")}
    if expected_rules and trace_fact["rule_id"] not in expected_rules:
        return False

    expected_sources = coverage_values(case, "trace_source_strings_any")
    if not expected_sources:
        return False
    if not any(expected in trace_fact["source_content"] for expected in expected_sources):
        return False

    expected_sink_strings = coverage_values(case, "trace_sink_strings_any")
    expected_sink_locations = coverage_values(case, "trace_sink_locations_any")
    expected_bridge_reads = coverage_values(case, "bridge_read_locations_any")

    sink_location = format_location(trace_fact["sink_path"], trace_fact["sink_line"])
    sink_ok = False
    if expected_sink_strings and any(
        expected in trace_fact["sink_content"] for expected in expected_sink_strings
    ):
        sink_ok = True
    if expected_sink_locations and any(
        location_matches(sink_location, expected) for expected in expected_sink_locations
    ):
        sink_ok = True
    if expected_bridge_reads and summary_check_matches(
        row, "bridge_read_locations_any", expected_bridge_reads
    ):
        sink_ok = True
    return sink_ok


def summarize_trace_fact(trace_fact: dict[str, Any] | None) -> str:
    if not trace_fact:
        return "none"
    return (
        f"{trace_fact['rule_id']}: "
        f"{trace_fact['source_content']} @ {format_location(trace_fact['source_path'], trace_fact['source_line'])} "
        f"-> {trace_fact['sink_content']} @ {format_location(trace_fact['sink_path'], trace_fact['sink_line'])}"
    )


def derive_real_sink_status(
    case: dict[str, Any],
    row: dict[str, Any] | None,
    results: list[dict[str, Any]],
) -> tuple[str, str, dict[str, Any] | None]:
    if row is None:
        return "not_run", "case has no result row in the selected summary", None

    status = str(row.get("status", "")).strip()
    if status == "skipped_missing_plugin":
        return (
            "skipped_missing_plugin",
            str(row.get("reason", "")).strip() or "plugin fixture missing",
            None,
        )
    if status != "passed":
        return "not_found", f"scan status={status}", None

    if not case_has_sink_contract(case):
        return "not_found", "coverage contract does not yet assert a real sink location", None

    if not results:
        return "not_found", "scan passed but produced no readable semgrep findings", None

    if not case_has_trace_contract(case):
        return (
            "nearby_only",
            "scan hit the vulnerable area but the case does not yet require an explicit request-source to sink trace",
            None,
        )

    trace_facts = collect_trace_facts(results)
    for trace_fact in trace_facts:
        if trace_fact_matches_case(case, row, trace_fact):
            return "found", "scan passed with a matching request-source to sink trace", trace_fact

    return (
        "not_found",
        "no Semgrep dataflow trace matched the expected request source and sink contract",
        None,
    )


def matched_coverage_summary(row: dict[str, Any] | None) -> str:
    if row is None:
        return "none"
    coverage = row.get("coverage", {})
    if not isinstance(coverage, dict):
        return "none"
    checks = coverage.get("checks", [])
    if not isinstance(checks, list):
        return "none"
    parts = []
    for check in checks:
        if not isinstance(check, dict) or not check.get("ok"):
            continue
        kind = str(check.get("kind", "")).strip() or "check"
        matched = check.get("matched", [])
        if isinstance(matched, list) and matched:
            preview = ", ".join(str(item) for item in matched[:2])
            parts.append(f"{kind}={preview}")
        else:
            parts.append(kind)
    return "; ".join(parts) if parts else "none"


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        escaped = [value.replace("\n", " ").replace("|", "\\|") for value in row]
        lines.append("| " + " | ".join(escaped) + " |")
    return "\n".join(lines)


def build_report(manifest_path: Path, summary_path: Path) -> str:
    manifest_payload = load_json(manifest_path)
    cases = manifest_payload.get("cases", [])
    if not isinstance(cases, list):
        raise ValueError(f"invalid cases list in {manifest_path}")

    summary_payload = load_json(summary_path)
    rows = summary_payload.get("results", [])
    if not isinstance(rows, list):
        raise ValueError(f"invalid results list in {summary_path}")
    results_by_case = {
        str(row.get("case_id", "")).strip(): row
        for row in rows
        if isinstance(row, dict) and str(row.get("case_id", "")).strip()
    }

    overall_rule_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "lowered": 0, "target": 0, "cases": 0})
    matrix_rows: list[list[str]] = []
    detail_lines: list[str] = []

    found_count = 0
    nearby_count = 0
    not_found_count = 0
    skipped_count = 0
    not_run_count = 0

    sorted_cases = sorted(
        (case for case in cases if isinstance(case, dict)),
        key=lambda case: int(case.get("rank", 10**9) or 10**9),
    )

    for case in sorted_cases:
        case_id = str(case.get("case_id", "")).strip()
        row = results_by_case.get(case_id)
        case_output_dir = Path(str(row.get("output_dir", "")).strip()) if isinstance(row, dict) else Path()
        results = read_case_results(case_output_dir) if case_output_dir else []
        real_sink_status, sink_reason, trace_fact = derive_real_sink_status(case, row, results)
        if real_sink_status == "found":
            found_count += 1
        elif real_sink_status == "nearby_only":
            nearby_count += 1
        elif real_sink_status == "skipped_missing_plugin":
            skipped_count += 1
        elif real_sink_status == "not_run":
            not_run_count += 1
        else:
            not_found_count += 1

        per_rule_counts, evidence_paths = rule_ping_summary(results)
        seen_rule_ids: set[str] = set()
        for rule_id, counts in per_rule_counts.items():
            aggregate = overall_rule_counts[rule_id]
            aggregate["total"] += counts["total"]
            aggregate["lowered"] += counts["lowered"]
            aggregate["target"] += counts["target"]
            if rule_id not in seen_rule_ids:
                aggregate["cases"] += 1
                seen_rule_ids.add(rule_id)

        scan_status = str(row.get("status", "not_run")).strip() if isinstance(row, dict) else "not_run"
        matrix_rows.append(
            [
                str(case.get("rank", "")),
                case.get("cve_id", ""),
                f"{case.get('plugin_name', '')} {case.get('install_version', '')}".strip(),
                scan_status,
                real_sink_status,
                summarize_expected_rules(case),
                summarize_rule_counts(per_rule_counts),
                matched_coverage_summary(row),
                ", ".join(evidence_paths[:3]) if evidence_paths else "none",
            ]
        )

        detail_lines.extend(
            [
                f"### {case_id}",
                f"- CVE: `{case.get('cve_id', '')}`",
                f"- Plugin: `{case.get('plugin_name', '')}` `{case.get('install_version', '')}`",
                f"- Scan status: `{scan_status}`",
                f"- Real sink status: `{real_sink_status}`",
                f"- Reason: {sink_reason}",
                f"- Configs: {', '.join(Path(str(path)).name for path in row.get('config_paths', []) if isinstance(row, dict)) if isinstance(row, dict) else 'none'}",
                f"- Expected rules: {summarize_expected_rules(case)}",
                f"- Rule pings: {summarize_rule_counts(per_rule_counts)}",
                f"- Matched coverage: {matched_coverage_summary(row)}",
                f"- Trace proof: {summarize_trace_fact(trace_fact)}",
                f"- Evidence paths: {', '.join(evidence_paths) if evidence_paths else 'none'}",
            ]
        )
        if isinstance(row, dict):
            stderr_tail = str(row.get("stderr_tail", "")).strip()
            stdout_tail = str(row.get("stdout_tail", "")).strip()
            if stderr_tail:
                detail_lines.append(f"- stderr tail: `{stderr_tail}`")
            if stdout_tail:
                detail_lines.append(f"- stdout tail: `{stdout_tail}`")
        detail_lines.append("")

    rule_rows = [
        [
            rule_id,
            str(counts["total"]),
            str(counts["cases"]),
            str(counts["lowered"]),
            str(counts["target"]),
        ]
        for rule_id, counts in sorted(overall_rule_counts.items(), key=lambda item: (-item[1]["total"], item[0]))
    ]

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Semgrep CVE Test Report",
        "",
        f"- Generated: `{generated_at}`",
        f"- Manifest: `{manifest_path}`",
        f"- Summary source: `{summary_path}`",
        f"- Cases in manifest: `{len(sorted_cases)}`",
        f"- Real sink found: `{found_count}`",
        f"- Nearby only: `{nearby_count}`",
        f"- Real sink not found: `{not_found_count}`",
        f"- Skipped missing plugin: `{skipped_count}`",
        f"- Not run in selected summary: `{not_run_count}`",
        "",
        "## Overall Rule Pings",
        "",
        markdown_table(
            ["Rule", "Findings", "Cases", "Lowered", "Target"],
            rule_rows or [["none", "0", "0", "0", "0"]],
        ),
        "",
        "## Case Matrix",
        "",
        markdown_table(
            ["Rank", "CVE", "Plugin@Version", "Scan", "Real Sink", "Expected Rules", "Rule Pings", "Matched Coverage", "Evidence"],
            matrix_rows,
        ),
        "",
        "## Case Details",
        "",
        *detail_lines,
    ]
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    summary_path = Path(args.summary).resolve() if args.summary else find_latest_summary()
    output_path = Path(args.output).resolve()
    report_text = build_report(manifest_path, summary_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text, encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
