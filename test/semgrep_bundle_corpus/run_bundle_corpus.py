#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from corpus_lib import (
    CORPUS_ARTIFACTS_DIR,
    CORPUS_PLUGINS_DIR,
    DEFAULT_CONFIGS,
    LOWERED_RUNNER,
    MANIFEST_PATH,
    REPO_ROOT,
    WP_INSTALL_PLUGINS_DIR,
    case_matches,
    download_wporg_plugin,
    load_manifest,
    resolve_plugin_dir,
    utc_stamp,
    write_json,
)


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run run_semgrep_php_lowered_bundle.py across the semgrep bundle corpus."
    )
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--plugins-dir", default=str(CORPUS_PLUGINS_DIR))
    parser.add_argument("--local-plugins-dir", default=str(WP_INSTALL_PLUGINS_DIR))
    parser.add_argument("--output-root", default="")
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--slug", action="append", default=[])
    parser.add_argument("--config", action="append", default=[])
    parser.add_argument("--download-missing", action="store_true")
    parser.add_argument("--pro-intrafile", action="store_true")
    parser.add_argument("--full-lowered-bundle", action="store_true")
    parser.add_argument("--php-bin", default="php")
    parser.add_argument("--semgrep-bin", default="semgrep")
    return parser.parse_args()


def default_output_root(explicit: str) -> Path:
    if explicit:
        return Path(explicit).resolve()
    return (CORPUS_ARTIFACTS_DIR / utc_stamp()).resolve()


def validate_output_root(output_root: Path) -> None:
    repo_test_root = (REPO_ROOT / "test").resolve()
    repo_artifacts_root = (REPO_ROOT / "artifacts").resolve()
    if path_is_within(output_root, repo_test_root):
        raise CorpusError(
            f"output root must not be under {repo_test_root} because Semgrep rules exclude '**/test/**': {output_root}"
        )
    if path_is_within(output_root, repo_artifacts_root):
        raise CorpusError(
            f"output root must not be under {repo_artifacts_root} because nested .gitignore rules ignore generated artifacts there: {output_root}"
        )


def tail(value: str, limit: int = 400) -> str:
    stripped = value.strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[-limit:]


def load_json(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def collect_mapping_paths(mapping_path: Path) -> list[str]:
    payload = load_json(mapping_path)
    if not payload:
        return []
    segments = payload.get("segments", [])
    if not isinstance(segments, list):
        return []
    seen: set[str] = set()
    output: list[str] = []
    for segment in segments:
        if not isinstance(segment, dict):
            continue
        source_path = str(segment.get("source_path", "")).strip()
        if not source_path or source_path in seen:
            continue
        seen.add(source_path)
        output.append(source_path)
    return output


def collect_mapping_bridge_locations(mapping_path: Path) -> list[str]:
    payload = load_json(mapping_path)
    if not payload:
        return []
    segments = payload.get("segments", [])
    if not isinstance(segments, list):
        return []

    seen: set[str] = set()
    output: list[str] = []
    for segment in segments:
        if not isinstance(segment, dict):
            continue
        bridge_read_path = str(segment.get("bridge_read_path", "")).strip()
        bridge_read_line = segment.get("bridge_read_line")
        if not bridge_read_path or not isinstance(bridge_read_line, int):
            continue
        location = f"{bridge_read_path}:{bridge_read_line}"
        if location in seen:
            continue
        seen.add(location)
        output.append(location)
    return output


def resolve_case_configs(args: argparse.Namespace, case: dict[str, object]) -> list[Path]:
    if args.config:
        return [Path(path).resolve() for path in args.config]

    configured = [str(item).strip() for item in case.get("configs", []) if str(item).strip()]
    if not configured:
        return DEFAULT_CONFIGS

    output: list[Path] = []
    for item in configured:
        candidate = Path(item)
        if not candidate.is_absolute():
            candidate = (REPO_ROOT / candidate).resolve()
        output.append(candidate)
    return output


def collect_semgrep_results(results_path: Path) -> list[dict[str, object]]:
    payload = load_json(results_path)
    if not payload:
        return []
    results = payload.get("results", [])
    if not isinstance(results, list):
        return []
    output: list[dict[str, object]] = []
    for result in results:
        if isinstance(result, dict):
            output.append(result)
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


def evaluate_coverage(case: dict[str, object], case_output_dir: Path, plugin_dir: Path) -> dict[str, object]:
    coverage = case.get("coverage")
    if not isinstance(coverage, dict):
        return {"status": "not_configured", "checks": []}

    mapping_path = case_output_dir / "lowered-mapping.json"
    bundle_path = case_output_dir / "lowered-bundle.php"
    results_path = case_output_dir / "semgrep-results.json"
    mapping_paths = collect_mapping_paths(mapping_path)
    bridge_locations = collect_mapping_bridge_locations(mapping_path)
    bundle_text = bundle_path.read_text(encoding="utf-8", errors="replace") if bundle_path.exists() else ""
    semgrep_results = collect_semgrep_results(results_path)
    finding_paths = [str(item.get("path", "")).strip() for item in semgrep_results if str(item.get("path", "")).strip()]
    finding_rule_ids = [
        str(item.get("check_id", "")).strip() for item in semgrep_results if str(item.get("check_id", "")).strip()
    ]

    paths_any = [str(item).strip() for item in coverage.get("paths_any", []) if str(item).strip()]
    bundle_strings_any = [
        str(item).strip() for item in coverage.get("bundle_strings_any", []) if str(item).strip()
    ]
    source_strings_any = [
        str(item).strip() for item in coverage.get("source_strings_any", []) if str(item).strip()
    ]
    finding_paths_any = [str(item).strip() for item in coverage.get("finding_paths_any", []) if str(item).strip()]
    finding_rule_ids_any = [
        str(item).strip() for item in coverage.get("finding_rule_ids_any", []) if str(item).strip()
    ]
    bridge_read_locations_any = [
        str(item).strip() for item in coverage.get("bridge_read_locations_any", []) if str(item).strip()
    ]

    checks: list[dict[str, object]] = []
    passed = True
    missing_artifacts: list[str] = []

    if paths_any:
        if not mapping_path.exists():
            missing_artifacts.append(mapping_path.name)
            matched = []
        else:
            matched = [needle for needle in paths_any if any(needle in path for path in mapping_paths)]
        ok = bool(matched)
        checks.append(
            {
                "kind": "paths_any",
                "expected": paths_any,
                "matched": matched,
                "ok": ok,
            }
        )
        passed = passed and ok

    if bundle_strings_any:
        if not bundle_path.exists():
            missing_artifacts.append(bundle_path.name)
            matched = []
        else:
            matched = [needle for needle in bundle_strings_any if needle in bundle_text]
        ok = bool(matched)
        checks.append(
            {
                "kind": "bundle_strings_any",
                "expected": bundle_strings_any,
                "matched": matched,
                "ok": ok,
            }
        )
        passed = passed and ok

    if bridge_read_locations_any:
        if not mapping_path.exists():
            missing_artifacts.append(mapping_path.name)
            matched = []
        else:
            matched = [needle for needle in bridge_read_locations_any if any(needle in location for location in bridge_locations)]
        ok = bool(matched)
        checks.append(
            {
                "kind": "bridge_read_locations_any",
                "expected": bridge_read_locations_any,
                "matched": matched,
                "ok": ok,
            }
        )
        passed = passed and ok

    if source_strings_any:
        matched = collect_source_string_matches(plugin_dir, source_strings_any)
        ok = bool(matched)
        checks.append(
            {
                "kind": "source_strings_any",
                "expected": source_strings_any,
                "matched": matched,
                "ok": ok,
            }
        )
        passed = passed and ok

    if finding_paths_any:
        if not results_path.exists():
            missing_artifacts.append(results_path.name)
            matched = []
        else:
            matched = [needle for needle in finding_paths_any if any(needle in path for path in finding_paths)]
        ok = bool(matched)
        checks.append(
            {
                "kind": "finding_paths_any",
                "expected": finding_paths_any,
                "matched": matched,
                "ok": ok,
            }
        )
        passed = passed and ok

    if finding_rule_ids_any:
        if not results_path.exists():
            missing_artifacts.append(results_path.name)
            matched = []
        else:
            matched = [needle for needle in finding_rule_ids_any if needle in finding_rule_ids]
        ok = bool(matched)
        checks.append(
            {
                "kind": "finding_rule_ids_any",
                "expected": finding_rule_ids_any,
                "matched": matched,
                "ok": ok,
            }
        )
        passed = passed and ok

    if missing_artifacts:
        passed = False

    return {
        "status": "passed" if passed else "failed",
        "checks": checks,
        "missing_artifacts": missing_artifacts,
        "mapping_path_count": len(mapping_paths),
        "mapping_path_sample": mapping_paths[:10],
        "finding_count": len(semgrep_results),
        "finding_path_sample": finding_paths[:10],
        "finding_rule_id_sample": finding_rule_ids[:10],
    }


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    plugins_dir = Path(args.plugins_dir).resolve()
    local_plugins_dir = Path(args.local_plugins_dir).resolve()
    output_root = default_output_root(args.output_root)
    validate_output_root(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    selected_case_ids = {value.strip() for value in args.case_id if value.strip()}
    selected_slugs = {value.strip() for value in args.slug if value.strip()}

    results: list[dict[str, object]] = []
    for case in load_manifest(manifest_path):
        if not case_matches(case, selected_case_ids, selected_slugs):
            continue

        slug = str(case["slug"])
        case_id = str(case["case_id"])
        configs = resolve_case_configs(args, case)
        case_output_dir = output_root / case_id
        case_output_dir.mkdir(parents=True, exist_ok=True)
        plugin_dir = resolve_plugin_dir(case, [local_plugins_dir, plugins_dir])

        if plugin_dir is None and args.download_missing and str(case.get("source_type", "")) == "wporg":
            try:
                plugin_dir, _ = download_wporg_plugin(slug, plugins_dir, refresh=False)
            except Exception as exc:
                results.append(
                    {
                        "case_id": case_id,
                        "slug": slug,
                        "status": "skipped_missing_plugin",
                        "reason": str(exc),
                    }
                )
                continue

        if plugin_dir is None:
            results.append(
                {
                    "case_id": case_id,
                    "slug": slug,
                    "status": "skipped_missing_plugin",
                    "reason": str(case.get("notes", "")).strip() or str(case.get("source_type", "")),
                }
            )
            continue

        command = [
            sys.executable,
            str(LOWERED_RUNNER),
            str(plugin_dir),
            "--output-dir",
            str(case_output_dir),
            "--php-bin",
            args.php_bin,
            "--semgrep-bin",
            args.semgrep_bin,
        ]
        for config in configs:
            command.extend(["--config", str(config)])
        if args.pro_intrafile:
            command.append("--pro-intrafile")
        if args.full_lowered_bundle:
            command.append("--full-lowered-bundle")

        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        (case_output_dir / "runner.stdout.txt").write_text(completed.stdout, encoding="utf-8")
        (case_output_dir / "runner.stderr.txt").write_text(completed.stderr, encoding="utf-8")

        results_path = case_output_dir / "semgrep-results.json"
        mapping_path = case_output_dir / "lowered-mapping.json"
        findings = None
        segments = None
        skipped_files = None
        if results_path.exists():
            semgrep_results = json.loads(results_path.read_text(encoding="utf-8"))
            findings = len(semgrep_results.get("results", []))
        if mapping_path.exists():
            mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
            segments = len(mapping.get("segments", []))
            skipped_files = len(mapping.get("skipped_files", []))

        coverage_report = evaluate_coverage(case, case_output_dir, plugin_dir)
        scan_ok = completed.returncode == 0 and results_path.exists()
        coverage_ok = coverage_report["status"] in {"passed", "not_configured"}
        if scan_ok and coverage_ok:
            status = "passed"
        elif scan_ok:
            status = "failed_coverage"
        else:
            status = "failed_scan"

        results.append(
            {
                "case_id": case_id,
                "slug": slug,
                "plugin_dir": str(plugin_dir),
                "output_dir": str(case_output_dir),
                "config_paths": [str(config) for config in configs],
                "status": status,
                "returncode": completed.returncode,
                "findings": findings,
                "segments": segments,
                "skipped_files": skipped_files,
                "coverage": coverage_report,
                "stdout_tail": tail(completed.stdout),
                "stderr_tail": tail(completed.stderr),
            }
        )

    summary = {
        "manifest": str(manifest_path),
        "output_root": str(output_root),
        "config_mode": "cli_override" if args.config else "case_or_default",
        "results": results,
        "counts": {
            "passed": sum(1 for item in results if item["status"] == "passed"),
            "failed_scan": sum(1 for item in results if item["status"] == "failed_scan"),
            "failed_coverage": sum(1 for item in results if item["status"] == "failed_coverage"),
            "failed": sum(1 for item in results if item["status"] in {"failed_scan", "failed_coverage"}),
            "skipped_missing_plugin": sum(1 for item in results if item["status"] == "skipped_missing_plugin"),
        },
    }
    write_json(output_root / "summary.json", summary)
    with (output_root / "summary.jsonl").open("w", encoding="utf-8") as handle:
        for item in results:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    for item in results:
        coverage = item.get("coverage", {})
        coverage_status = coverage.get("status", "n/a") if isinstance(coverage, dict) else "n/a"
        print(f"{item['case_id']}: {item['status']} (coverage={coverage_status})")

    return 1 if any(item["status"] in {"failed_scan", "failed_coverage"} for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
